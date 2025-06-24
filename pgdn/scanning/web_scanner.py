"""
Web scanner for HTTP/HTTPS specific testing.
"""

import httpx
from typing import Dict, Any, List, Optional
from pgdn.scanning.base_scanner import BaseScanner


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
    
    def scan(self, target: str, ports: Optional[List[int]] = None, **kwargs) -> Dict[str, Any]:
        """Perform web scan.
        
        Args:
            target: Target IP/hostname
            ports: List of web ports to scan
            **kwargs: Additional scan parameters
            
        Returns:
            Web scan results
        """
        web_ports = ports or [80, 443, 8080, 8443]
        results = {}
        
        for port in web_ports:
            for scheme in ['http', 'https']:
                if (scheme == 'https' and port in [443, 8443]) or (scheme == 'http' and port in [80, 8080]):
                    url = f"{scheme}://{target}:{port}"
                    scan_result = self._scan_url(url)
                    if scan_result:
                        results[url] = scan_result
        
        return {
            "target": target,
            "web_results": results,
            "scanner_type": self.scanner_type
        }
    
    def _scan_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Scan a specific URL.
        
        Args:
            url: URL to scan
            
        Returns:
            URL scan results or None if failed
        """
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
                    "technologies": self._detect_technologies(response)
                }
                
        except Exception as e:
            self.logger.debug(f"Web scan failed for {url}: {e}")
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
