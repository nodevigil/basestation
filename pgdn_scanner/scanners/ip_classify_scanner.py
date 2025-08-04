"""
IP Classification scanner for cloud service identification and infrastructure analysis.

Based on ip_classy.py script, this scanner provides:
- Cloud provider detection (AWS, Cloudflare, Akamai, etc.)
- Reverse DNS lookup and hostname classification
- AWS service matching with region detection
- TLS certificate analysis
- HTTP header analysis for service identification
"""

import socket
import ssl
import requests
import ipaddress
import json
from typing import Dict, Any, Optional, List
from .base_scanner import BaseScanner


class IpClassifyScanner(BaseScanner):
    """IP Classification scanner for infrastructure analysis."""
    
    @property
    def scanner_type(self) -> str:
        return "ip_classify"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.timeout = self.config.get('timeout', 5)
        self.default_port = self.config.get('default_port', 443)
        self.ipinfo_url = self.config.get('ipinfo_url', "https://ipinfo.io/{ip}/json")
        self.aws_ranges_url = self.config.get('aws_ranges_url', "https://ip-ranges.amazonaws.com/ip-ranges.json")
        self._aws_ranges_cache = None
    
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Perform IP classification scan.
        
        Args:
            target: IP address(es) to classify - can be single IP or comma-separated list
            **kwargs: Additional scan parameters including scan_level
            
        Returns:
            IP classification scan results
        """
        scan_level = kwargs.get('scan_level', 1)
        
        # Handle multiple IPs
        if ',' in target:
            ips = [ip.strip() for ip in target.split(',') if ip.strip()]
            return self._scan_multiple_ips(ips, scan_level)
        else:
            return self._scan_single_ip(target.strip(), scan_level)
    
    def _scan_multiple_ips(self, ips: List[str], scan_level: int) -> Dict[str, Any]:
        """Scan multiple IP addresses."""
        results = []
        
        # Fetch AWS ranges once for all IPs
        aws_ranges = self._fetch_aws_ranges()
        
        for ip in ips:
            if ip:
                result = self._classify_ip(ip, self.default_port, aws_ranges, scan_level)
                results.append(result)
        
        return {
            "scanner_type": self.scanner_type,
            "scan_level": scan_level,
            "targets": ips,
            "results": results
        }
    
    def _scan_single_ip(self, target: str, scan_level: int) -> Dict[str, Any]:
        """Scan a single IP address."""
        # Resolve hostname to IP if needed
        try:
            ip_address = socket.gethostbyname(target)
        except socket.gaierror:
            return {
                "target": target,
                "scan_level": scan_level,
                "scanner_type": self.scanner_type,
                "error": "DNS resolution failed"
            }
        
        aws_ranges = self._fetch_aws_ranges()
        result = self._classify_ip(ip_address, self.default_port, aws_ranges, scan_level)
        
        # Add target info for single IP scans
        result["target"] = target
        result["scan_level"] = scan_level
        result["scanner_type"] = self.scanner_type
        
        return result
    
    def _classify_ip(self, ip: str, port: int, aws_ranges: List[Dict], scan_level: int) -> Dict[str, Any]:
        """
        Classify a single IP address.
        
        Args:
            ip: IP address to classify
            port: Port to test (default 443)
            aws_ranges: AWS IP ranges data
            scan_level: Scan detail level
            
        Returns:
            Classification results for the IP
        """
        result = {
            "ip": ip,
            "port": port,
            "reverse_dns": None,
            "ipinfo_org": None,
            "aws_service": None,
            "aws_region": None,
            "aws_prefix": None,
            "tls_common_name": None,
            "http_headers": {},
            "classification": None,
            "likely_role": "unclassified"
        }
        
        # Check if it's a private IP
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                result.update({
                    "classification": "Private Network",
                    "likely_role": "Private Network"
                })
                return result
        except ValueError:
            pass
        
        # Reverse DNS lookup
        rdns = self._reverse_dns(ip)
        result["reverse_dns"] = rdns
        
        # AWS service matching
        aws_service, aws_region, aws_prefix = self._match_aws_service(ip, aws_ranges)
        result["aws_service"] = aws_service
        result["aws_region"] = aws_region
        result["aws_prefix"] = aws_prefix
        
        # IPInfo lookup
        ipinfo = self._fetch_ipinfo(ip)
        result["ipinfo_org"] = ipinfo.get("org", "unknown")
        
        # Hostname classification
        result["classification"] = self._classify_hostname(rdns or '') or result["ipinfo_org"]
        
        # Level 2+ scans include TLS and HTTP analysis
        if scan_level >= 2:
            # TLS inspection
            tls_cn = self._tls_inspect(ip, port)
            result["tls_common_name"] = tls_cn
            
            # HTTP headers analysis
            headers = self._http_headers(ip)
            result["http_headers"] = headers
            
            # Determine likely role based on all data
            result["likely_role"] = self._determine_likely_role(result, headers, tls_cn)
        
        return result
    
    def _reverse_dns(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return None
        except Exception as e:
            self.logger.debug(f"Reverse DNS failed for {ip}: {e}")
            return None
    
    def _fetch_aws_ranges(self) -> List[Dict]:
        """Fetch AWS IP ranges data with caching."""
        if self._aws_ranges_cache is not None:
            return self._aws_ranges_cache
        
        try:
            response = requests.get(self.aws_ranges_url, timeout=self.timeout)
            self._aws_ranges_cache = response.json().get("prefixes", [])
            return self._aws_ranges_cache
        except Exception as e:
            self.logger.debug(f"Failed to fetch AWS ranges: {e}")
            self._aws_ranges_cache = []
            return []
    
    def _match_aws_service(self, ip: str, ranges: List[Dict]) -> tuple:
        """Match IP against AWS service ranges."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for entry in ranges:
                if ip_obj in ipaddress.ip_network(entry["ip_prefix"]):
                    return entry["service"], entry["region"], entry["ip_prefix"]
        except Exception as e:
            self.logger.debug(f"AWS matching failed for {ip}: {e}")
        
        return None, None, None
    
    def _fetch_ipinfo(self, ip: str) -> Dict[str, Any]:
        """Fetch IP information from ipinfo.io."""
        try:
            response = requests.get(self.ipinfo_url.format(ip=ip), timeout=self.timeout)
            return response.json()
        except Exception as e:
            self.logger.debug(f"IPInfo lookup failed for {ip}: {e}")
            return {}
    
    def _classify_hostname(self, hostname: str) -> str:
        """Classify hostname to determine service type."""
        if not hostname:
            return "unknown"
        
        hostname_lower = hostname.lower()
        
        if "cloudfront.net" in hostname_lower:
            return "CloudFront CDN"
        elif "elb.amazonaws.com" in hostname_lower:
            return "AWS ELB"
        elif "compute" in hostname_lower and "amazonaws" in hostname_lower:
            return "AWS EC2"
        elif "cloudflare" in hostname_lower:
            return "Cloudflare"
        elif "azure" in hostname_lower or "microsoft" in hostname_lower:
            return "Azure"
        elif "fastly" in hostname_lower:
            return "Fastly"
        elif "akamai" in hostname_lower:
            return "Akamai"
        elif "gcp" in hostname_lower or "googlecloud" in hostname_lower:
            return "Google Cloud"
        
        return "Unknown or custom"
    
    def _tls_inspect(self, ip: str, port: int = 443) -> Optional[str]:
        """Inspect TLS certificate to extract common name."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    if cert and 'subject' in cert:
                        subject = dict(x[0] for x in cert['subject'])
                        return subject.get('commonName', '')
        except Exception as e:
            self.logger.debug(f"TLS inspection failed for {ip}:{port}: {e}")
        
        return None
    
    def _http_headers(self, ip: str, port: int = 80) -> Dict[str, str]:
        """Fetch HTTP headers for service identification."""
        try:
            url = f"http://{ip}:{port}"
            response = requests.get(url, timeout=self.timeout, allow_redirects=False)
            return dict(response.headers)
        except Exception as e:
            self.logger.debug(f"HTTP headers fetch failed for {ip}:{port}: {e}")
            return {}
    
    def _determine_likely_role(self, result: Dict[str, Any], headers: Dict[str, str], tls_cn: Optional[str]) -> str:
        """Determine likely role based on all collected data."""
        # Check HTTP headers for specific indicators
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        if 'cf-ray' in headers_lower or 'cloudflare' in (result.get("ipinfo_org") or "").lower():
            return "Cloudflare WAF/CDN"
        elif 'x-amzn-trace-id' in headers_lower:
            return "AWS Load Balancer or API Gateway"
        elif 'akamai' in (result.get("ipinfo_org") or "").lower():
            return "Akamai Edge / WAF"
        elif tls_cn and 'cloudfront' in tls_cn.lower():
            return "CloudFront CDN"
        elif 'server' in headers_lower:
            server_header = headers_lower['server']
            if 'nginx' in server_header:
                return "Nginx Web Server"
            elif 'apache' in server_header:
                return "Apache Web Server"
            elif 'cloudflare' in server_header:
                return "Cloudflare CDN"
        
        # Fallback to classification
        classification = result.get("classification")
        if classification and classification != "unknown":
            return classification
        
        return "unclassified"