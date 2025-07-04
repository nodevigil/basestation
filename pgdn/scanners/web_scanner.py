"""
Web scanner for HTTP/HTTPS specific testing.
"""

from typing import Dict, Any, List, Optional
from .base_scanner import BaseScanner

# Optional import for HTTP functionality
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

# Optional import for requests (needed for WAF detection)
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class WebScanner(BaseScanner):
    """Web scanner for HTTP/HTTPS specific testing."""
    
    @property
    def scanner_type(self) -> str:
        return "web"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.timeout = self.config.get('timeout', 10)
        self.max_redirects = self.config.get('max_redirects', 5)
        self.user_agent = self.config.get('user_agent', 'PGDN-Scanner/1.0')
    
    def scan(self, target: str, ports: Optional[List[int]] = None, scan_level: int = 1, **kwargs) -> Dict[str, Any]:
        """Perform web scan based on scan level.
        
        Args:
            target: Target IP/hostname
            ports: List of web ports to scan
            scan_level: Scan level (1-3) determining aggressiveness
            **kwargs: Additional scan parameters
            
        Returns:
            Web scan results
        """
        self.logger.debug(f"Starting web scan of {target} at level {scan_level}")
        
        # Level 1: Basic HTTP headers and TLS check
        if scan_level == 1:
            return self._scan_level_1(target, ports, **kwargs)
        
        # Level 2: Misconfig checks, technology detection
        elif scan_level == 2:
            return self._scan_level_2(target, ports, **kwargs)
        
        # Level 3: Endpoint fuzzing, debug endpoint detection
        elif scan_level == 3:
            return self._scan_level_3(target, ports, **kwargs)
        
        else:
            raise ValueError(f"Invalid scan_level: {scan_level}. Must be 1, 2, or 3.")
    
    def _scan_level_1(self, target: str, ports: Optional[List[int]], **kwargs) -> Dict[str, Any]:
        """Level 1: Basic HTTP headers and SSL check."""
        web_ports = ports or [80, 443]
        results = {}
        
        for port in web_ports:
            for scheme in ['http', 'https']:
                if (scheme == 'https' and port in [443, 8443]) or (scheme == 'http' and port in [80, 8080]):
                    url = f"{scheme}://{target}:{port}"
                    scan_result = self._scan_url_basic(url)
                    if scan_result:
                        results[url] = scan_result
        
        return {
            "target": target,
            "scan_level": 1,
            "web_results": results,
            "scanner_type": self.scanner_type
        }
    
    def _scan_level_2(self, target: str, ports: Optional[List[int]], **kwargs) -> Dict[str, Any]:
        """Level 2: Enhanced technology detection and misconfig checks."""
        web_ports = ports or [80, 443, 8080, 8443]
        results = {}
        
        for port in web_ports:
            for scheme in ['http', 'https']:
                if (scheme == 'https' and port in [443, 8443]) or (scheme == 'http' and port in [80, 8080]):
                    url = f"{scheme}://{target}:{port}"
                    scan_result = self._scan_url_enhanced(url)
                    if scan_result:
                        results[url] = scan_result
        
        return {
            "target": target,
            "scan_level": 2,
            "web_results": results,
            "scanner_type": self.scanner_type
        }
    
    def _scan_level_3(self, target: str, ports: Optional[List[int]], **kwargs) -> Dict[str, Any]:
        """Level 3: Aggressive endpoint fuzzing and debug detection."""
        # Start with level 2 results
        results = self._scan_level_2(target, ports, **kwargs)
        results["scan_level"] = 3
        
        # Add fuzzing and debug endpoint detection
        for url, url_results in results["web_results"].items():
            if not url_results.get("error"):
                # Fuzz common endpoints
                fuzz_results = self._fuzz_endpoints(url)
                url_results["fuzzed_endpoints"] = fuzz_results
                
                # Check for debug/admin endpoints
                debug_results = self._check_debug_endpoints(url)
                url_results["debug_endpoints"] = debug_results
        
        return results
    
    def _scan_url_basic(self, url: str) -> Optional[Dict[str, Any]]:
        """Basic URL scan - just headers and status.
        
        Args:
            url: URL to scan
            
        Returns:
            Basic URL scan results or None if failed
        """
        if not HAS_HTTPX:
            return {"error": "httpx not available for web scanning"}
        
        try:
            headers = {'User-Agent': self.user_agent}
            
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
                max_redirects=self.max_redirects
            ) as client:
                response = client.get(url, headers=headers)
                
                return {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "content_length": len(response.content),
                    "redirects": len(response.history),
                    "final_url": str(response.url),
                    "server": response.headers.get('server'),
                    "waf": self._detect_waf(url)
                }
                
        except Exception as e:
            self.logger.debug(f"Web scan failed for {url}: {e}")
            return {"error": str(e)}
    
    def _scan_url_enhanced(self, url: str) -> Optional[Dict[str, Any]]:
        """Enhanced URL scan with technology detection and security checks.
        
        Args:
            url: URL to scan
            
        Returns:
            Enhanced URL scan results or None if failed
        """
        # Start with basic scan
        result = self._scan_url_basic(url)
        if not result or "error" in result:
            return result
        
        if not HAS_HTTPX:
            return result
        
        try:
            headers = {'User-Agent': self.user_agent}
            
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
                max_redirects=self.max_redirects
            ) as client:
                response = client.get(url, headers=headers)
                
                # Add enhanced detection
                result["technologies"] = self._detect_technologies(response)
                result["security_headers"] = self._check_security_headers(response.headers)
                
                # Add WAF detection
                waf_info = self._detect_waf(url)
                if waf_info:
                    result["waf"] = waf_info
                
                return result
                
        except Exception as e:
            self.logger.debug(f"Enhanced web scan failed for {url}: {e}")
            return {"error": str(e)}
    
    def _detect_technologies(self, response) -> List[str]:
        """Detect web technologies from response.
        
        Args:
            response: HTTP response object
            
        Returns:
            List of detected technologies
        """
        technologies = []
        headers = response.headers
        content = response.text if hasattr(response, 'text') else ""
        
        # Server header analysis
        server = headers.get('server', '').lower()
        if 'nginx' in server:
            technologies.append('nginx')
        if 'apache' in server:
            technologies.append('apache')
        if 'cloudflare' in server:
            technologies.append('cloudflare')
        
        # Framework detection from headers
        if headers.get('x-powered-by'):
            technologies.append(headers['x-powered-by'])
        
        # Content-based detection (basic)
        content_lower = content.lower()
        if 'wordpress' in content_lower:
            technologies.append('wordpress')
        if 'jquery' in content_lower:
            technologies.append('jquery')
        if 'bootstrap' in content_lower:
            technologies.append('bootstrap')
        
        return list(set(technologies))  # Remove duplicates
    
    def _check_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check for security headers.
        
        Args:
            headers: HTTP headers
            
        Returns:
            Security header analysis
        """
        security_headers = {
            'X-Content-Type-Options': headers.get('x-content-type-options'),
            'X-Frame-Options': headers.get('x-frame-options'),
            'X-XSS-Protection': headers.get('x-xss-protection'),
            'Content-Security-Policy': headers.get('content-security-policy'),
            'Strict-Transport-Security': headers.get('strict-transport-security'),
            'Referrer-Policy': headers.get('referrer-policy')
        }
        
        present = [k for k, v in security_headers.items() if v is not None]
        missing = [k for k, v in security_headers.items() if v is None]
        
        return {
            "present": present,
            "missing": missing,
            "headers": {k: v for k, v in security_headers.items() if v is not None}
        }
    
    def _fuzz_endpoints(self, base_url: str) -> List[Dict[str, Any]]:
        """Fuzz common endpoints for interesting responses.
        
        Args:
            base_url: Base URL to fuzz
            
        Returns:
            List of interesting endpoints found
        """
        if not HAS_HTTPX:
            return []
        
        common_paths = [
            '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
            '/api', '/api/v1', '/api/v2', '/graphql',
            '/metrics', '/health', '/status', '/info',
            '/debug', '/test', '/dev', '/staging',
            '/.env', '/.git', '/config', '/backup',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml'
        ]
        
        interesting_endpoints = []
        
        try:
            with httpx.Client(timeout=5, follow_redirects=False) as client:
                for path in common_paths:
                    url = base_url.rstrip('/') + path
                    try:
                        response = client.get(url, headers={'User-Agent': self.user_agent})
                        if response.status_code in [200, 301, 302, 401, 403]:
                            interesting_endpoints.append({
                                "path": path,
                                "url": url,
                                "status_code": response.status_code,
                                "content_length": len(response.content)
                            })
                    except Exception:
                        continue
        except Exception as e:
            self.logger.debug(f"Endpoint fuzzing failed for {base_url}: {e}")
        
        return interesting_endpoints
    
    def _check_debug_endpoints(self, base_url: str) -> List[Dict[str, Any]]:
        """Check for debug and development endpoints.
        
        Args:
            base_url: Base URL to check
            
        Returns:
            List of debug endpoints found
        """
        if not HAS_HTTPX:
            return []
        
        debug_paths = [
            '/debug', '/debug/vars', '/debug/pprof',
            '/metrics', '/actuator', '/actuator/health',
            '/server-status', '/server-info',
            '/phpinfo.php', '/info.php',
            '/__debug__', '/debug.php',
            '/trace', '/dump'
        ]
        
        debug_endpoints = []
        
        try:
            with httpx.Client(timeout=5, follow_redirects=False) as client:
                for path in debug_paths:
                    url = base_url.rstrip('/') + path
                    try:
                        response = client.get(url, headers={'User-Agent': self.user_agent})
                        if response.status_code == 200:
                            content = response.text.lower()
                            # Look for debug-related content
                            if any(keyword in content for keyword in ['debug', 'trace', 'dump', 'vars', 'goroutine', 'metrics']):
                                debug_endpoints.append({
                                    "path": path,
                                    "url": url,
                                    "status_code": response.status_code,
                                    "content_type": response.headers.get('content-type', ''),
                                    "indicators": [kw for kw in ['debug', 'trace', 'dump', 'vars', 'goroutine', 'metrics'] if kw in content]
                                })
                    except Exception:
                        continue
        except Exception as e:
            self.logger.debug(f"Debug endpoint check failed for {base_url}: {e}")
        
        return debug_endpoints

    def _detect_waf(self, url: str) -> Optional[Dict[str, Any]]:
        """Detect Web Application Firewall.
        
        Args:
            url: Base URL to test for WAF
            
        Returns:
            WAF detection results or None if no WAF detected
        """
        if not HAS_REQUESTS:
            self.logger.debug("requests library not available for WAF detection")
            return None
        
        try:
            # Test with suspicious payload to trigger WAF
            test_payloads = [
                "?id=1' OR '1'='1",
                "?test=<script>alert('xss')</script>",
                "?cmd=cat /etc/passwd",
                "?file=../../../../etc/passwd"
            ]
            
            waf_indicators = {
                "cloudflare": ["cloudflare", "cf-ray", "cf-cache", "cloudflare-nginx"],
                "akamai": ["akamai", "x-akamai", "akamai-ghost"],
                "aws": ["x-amzn", "cloudfront", "x-amz"],
                "sucuri": ["x-sucuri", "sucuri"],
                "incapsula": ["incap_ses", "incapsula", "x-iinfo"],
                "barracuda": ["barracuda", "barra"],
                "f5": ["f5", "bigip", "x-waf-event"],
                "imperva": ["imperva", "x-iinfo"],
                "mod_security": ["mod_security", "modsecurity"],
                "wordfence": ["wordfence", "x-wordfence"],
                "comodo": ["comodo", "x-protected-by"]
            }
            
            for payload in test_payloads:
                try:
                    test_url = url.rstrip('/') + payload
                    response = requests.get(
                        test_url, 
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=False,
                        headers={'User-Agent': self.user_agent}
                    )
                    
                    response_text = response.text.lower()
                    response_headers = {k.lower(): v.lower() for k, v in response.headers.items()}
                    
                    # Check for WAF signatures in headers and content
                    for waf_name, indicators in waf_indicators.items():
                        for indicator in indicators:
                            if (indicator in response_text or 
                                any(indicator in h for h in response_headers.keys()) or
                                any(indicator in v for v in response_headers.values())):
                                return {
                                    "detected": True, 
                                    "type": waf_name, 
                                    "method": "signature",
                                    "indicator": indicator,
                                    "payload": payload
                                }
                    
                    # Generic WAF detection based on response behavior
                    if response.status_code in [403, 406, 429, 418]:
                        # Check for common WAF block messages
                        block_indicators = [
                            "blocked", "denied", "forbidden", "not allowed",
                            "security", "firewall", "protection", "suspicious",
                            "malicious", "attack", "threat"
                        ]
                        
                        for block_word in block_indicators:
                            if block_word in response_text:
                                return {
                                    "detected": True, 
                                    "type": "unknown", 
                                    "method": "behavior",
                                    "status_code": response.status_code,
                                    "payload": payload,
                                    "block_indicator": block_word
                                }
                    
                except requests.exceptions.RequestException:
                    # Connection errors might indicate WAF blocking
                    continue
            
            return None
            
        except Exception as e:
            self.logger.debug(f"WAF detection failed for {url}: {e}")
            return None
