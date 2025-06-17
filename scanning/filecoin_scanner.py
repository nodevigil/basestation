"""
Filecoin-specific scanner for protocol-specific checks.
"""

import requests
import json
import logging
import socket
from typing import Dict, Any, Optional, List
from datetime import datetime
import concurrent.futures


class FilecoinSpecificScanner:
    """
    Filecoin-specific scanner for protocol-related checks.
    
    This scanner performs Filecoin-specific scans including:
    - Lotus API endpoint detection
    - Storage provider validation
    - Market API checks
    - Chain synchronization status
    - Authentication and security validation
    - SSL/TLS configuration analysis
    """
    
    def __init__(self, timeout: int = 10, debug: bool = False):
        """
        Initialize Filecoin scanner.
        
        Args:
            timeout: Request timeout in seconds
            debug: Enable debug logging
        """
        self.timeout = timeout
        self.debug = debug
        self.logger = self._setup_logging()
        
        # Expanded Filecoin ports based on real deployments
        self.lotus_api_ports = [1234, 3453, 8080, 80, 443, 8443]
        self.storage_api_ports = [2345, 1235, 8081]
        self.market_api_ports = [3456, 8082]
        self.p2p_ports = [1235, 4001, 9001]  # Libp2p networking
        self.metrics_ports = [9090, 9091, 8888]  # Prometheus metrics
        
        # Comprehensive Filecoin endpoints
        self.api_endpoints = [
            "/rpc/v1",
            "/rpc/v0",
            "/rpc",
            "/api/v1/version",
            "/api/v0/version",
            "/lotus/api/v1",
            "/lotus/api/v0",
            ""  # Root endpoint
        ]
        
        # Security-focused test methods
        self.test_methods = {
            'version': "Filecoin.Version",
            'chain_head': "Filecoin.ChainHead",
            'sync_state': "Filecoin.SyncState",
            'mpool_pending': "Filecoin.MpoolPending",
            'net_peers': "Filecoin.NetPeers"
        }
        
        # Sensitive methods that should require authentication
        self.sensitive_methods = [
            "Filecoin.WalletList",
            "Filecoin.WalletNew", 
            "Filecoin.WalletSign",
            "Filecoin.StorageList",
            "Filecoin.MarketImportDealData",
            "Filecoin.ClientImport"
        ]

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration based on debug mode."""
        logger = logging.getLogger(f"scanning.{self.__class__.__name__}")
        logger.setLevel(logging.DEBUG if self.debug else logging.INFO)
        
        # Remove existing handlers to avoid duplicates
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG if self.debug else logging.INFO)
        
        # Formatter
        if self.debug:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            )
        else:
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File handler for debug mode
        if self.debug:
            file_handler = logging.FileHandler(f'filecoin_scanner_debug_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            logger.debug("Debug logging enabled - logs will be saved to file")
        
        return logger
    
    def scan(self, ip_address: str) -> Dict[str, Any]:
        """
        Perform Filecoin-specific scan with enhanced logging.
        
        Args:
            ip_address: Target IP address
            
        Returns:
            Dictionary containing scan results
        """
        self.logger.info(f"🔍 Starting Filecoin-specific scan for {ip_address}")
        self.logger.debug(f"Scan configuration - timeout: {self.timeout}s, debug: {self.debug}")
        
        scan_start_time = datetime.utcnow()
        
        results = {
            'scan_type': 'filecoin_specific',
            'target_ip': ip_address,
            'scan_timestamp': scan_start_time.isoformat(),
            'lotus_api_exposed': False,
            'storage_api_exposed': False,
            'market_api_exposed': False,
            'p2p_ports_open': [],
            'metrics_exposed': False,
            'chain_sync_status': None,
            'node_info': None,
            'storage_provider_info': None,
            'authentication_required': False,
            'sensitive_methods_exposed': [],
            'security_headers': {},
            'ssl_issues': [],
            'security_score': 0,
            'errors': []
        }
        
        try:
            # Check Lotus API with enhanced security testing
            self.logger.info(f"🪷 Checking Lotus API for {ip_address}")
            self.logger.debug(f"Testing {len(self.lotus_api_ports)} ports: {self.lotus_api_ports}")
            lotus_result = self._check_lotus_api(ip_address)
            results.update(lotus_result)
            self.logger.info(f"🪷 Lotus API check complete - exposed: {lotus_result.get('lotus_api_exposed', False)}")
            
            # Check Storage API with security validation
            self.logger.info(f"💾 Checking Storage API for {ip_address}")
            self.logger.debug(f"Testing {len(self.storage_api_ports)} ports: {self.storage_api_ports}")
            storage_result = self._check_storage_api(ip_address)
            results.update(storage_result)
            self.logger.info(f"💾 Storage API check complete - exposed: {storage_result.get('storage_api_exposed', False)}")
            
            # Check Market API with security checks
            self.logger.info(f"🏪 Checking Market API for {ip_address}")
            self.logger.debug(f"Testing {len(self.market_api_ports)} ports: {self.market_api_ports}")
            market_result = self._check_market_api(ip_address)
            results.update(market_result)
            self.logger.info(f"🏪 Market API check complete - exposed: {market_result.get('market_api_exposed', False)}")
            
            # Check P2P and other ports
            self.logger.info(f"🌐 Checking network ports for {ip_address}")
            self.logger.debug(f"Testing P2P ports: {self.p2p_ports}, metrics ports: {self.metrics_ports}")
            network_result = self._check_network_ports(ip_address)
            results.update(network_result)
            self.logger.info(f"🌐 Network ports check complete - P2P open: {len(network_result.get('p2p_ports_open', []))}, metrics: {network_result.get('metrics_exposed', False)}")
            
            # Perform security analysis
            self.logger.info(f"🔒 Performing security analysis for {ip_address}")
            security_result = self._perform_security_analysis(ip_address, results)
            results.update(security_result)
            
            scan_duration = (datetime.utcnow() - scan_start_time).total_seconds()
            results['scan_duration'] = scan_duration
            
            self.logger.info(f"✅ Filecoin scan completed for {ip_address} in {scan_duration:.2f}s - Security Score: {security_result.get('security_score', 0)}/100")
            self.logger.debug(f"Final scan results: {results}")
            
        except Exception as e:
            self.logger.error(f"❌ Filecoin scan failed for {ip_address}: {str(e)}")
            self.logger.debug(f"Exception details: {type(e).__name__}", exc_info=True)
            results['errors'].append(f"Scan error: {str(e)}")
            results['scan_duration'] = (datetime.utcnow() - scan_start_time).total_seconds()
        
        return results
    
    def _check_lotus_api(self, ip_address: str) -> Dict[str, Any]:
        """Check for Lotus API endpoints with enhanced security testing."""
        self.logger.debug(f"🪷 Starting Lotus API check for {ip_address}")
        
        result = {
            'lotus_api_exposed': False,
            'lotus_api_url': None,
            'lotus_version': None,
            'chain_head': None,
            'lotus_auth_required': False,
            'lotus_methods_available': []
        }
        
        for port in self.lotus_api_ports:
            self.logger.debug(f"🪷 Testing port {port} for {ip_address}")
            
            for endpoint in self.api_endpoints:
                self.logger.debug(f"🪷 Trying endpoint {endpoint} on port {port}")
                
                try:
                    schemes = ['https', 'http'] if port in [443, 8443] else ['http', 'https']
                    
                    for scheme in schemes:
                        url = f"{scheme}://{ip_address}:{port}{endpoint}"
                        self.logger.debug(f"🪷 Testing URL: {url}")
                        
                        # Try to get version info
                        version_data = {
                            "jsonrpc": "2.0",
                            "method": "Filecoin.Version",
                            "params": [],
                            "id": 1
                        }
                        
                        self.logger.debug(f"🪷 Making POST request to {url}")
                        response = requests.post(
                            url,
                            json=version_data,
                            timeout=self.timeout,
                            headers={'Content-Type': 'application/json'},
                            verify=False  # For testing purposes
                        )
                        self.logger.debug(f"🪷 Response status: {response.status_code}")
                        
                        if response.status_code == 200:
                            try:
                                data = response.json()
                                if 'result' in data:
                                    self.logger.info(f"🪷 Found Lotus API at {url}")
                                    result['lotus_api_exposed'] = True
                                    result['lotus_api_url'] = url
                                    result['lotus_version'] = data['result'].get('Version', 'Unknown')
                                    self.logger.debug(f"🪷 Lotus version: {result['lotus_version']}")
                                    
                                    # Get chain head
                                    self.logger.debug(f"🪷 Getting chain head from {url}")
                                    head_data = {
                                        "jsonrpc": "2.0",
                                        "method": "Filecoin.ChainHead",
                                        "params": [],
                                        "id": 2
                                    }
                                    
                                    head_response = requests.post(url, json=head_data, timeout=self.timeout, verify=False)
                                    if head_response.status_code == 200:
                                        head_result = head_response.json()
                                        if 'result' in head_result:
                                            result['chain_head'] = head_result['result']
                                            self.logger.debug(f"🪷 Chain head retrieved successfully")
                                    
                                    # Test available methods
                                    self.logger.debug(f"🪷 Testing available methods")
                                    result['lotus_methods_available'] = self._test_available_methods(url)
                                    self.logger.debug(f"🪷 Available methods: {result['lotus_methods_available']}")
                                    
                                    # Check authentication requirements
                                    self.logger.debug(f"🪷 Checking authentication requirements")
                                    result['lotus_auth_required'] = self._check_authentication_required(url)
                                    self.logger.debug(f"🪷 Authentication required: {result['lotus_auth_required']}")
                                    
                                    return result
                            except json.JSONDecodeError as e:
                                self.logger.debug(f"🪷 JSON decode error for {url}: {str(e)}")
                                continue
                        
                        elif response.status_code == 401:
                            # API exists but requires authentication
                            result['lotus_api_exposed'] = True
                            result['lotus_api_url'] = url
                            result['lotus_auth_required'] = True
                            self.logger.info(f"🪷 Found authenticated Lotus API at {url}")
                            return result
                                
                except Exception as e:
                    self.logger.debug(f"🪷 Error testing {url}: {str(e)}")
                    continue
        
        self.logger.debug(f"🪷 No Lotus API found for {ip_address}")
        return result
    
    def _check_storage_api(self, ip_address: str) -> Dict[str, Any]:
        """Check for Storage API endpoints with security validation."""
        self.logger.debug(f"💾 Starting Storage API check for {ip_address}")
        
        result = {
            'storage_api_exposed': False,
            'storage_api_url': None,
            'storage_info': None,
            'storage_auth_required': False
        }
        
        for port in self.storage_api_ports:
            self.logger.debug(f"💾 Testing port {port} for {ip_address}")
            
            try:
                for scheme in ['http', 'https']:
                    url = f"{scheme}://{ip_address}:{port}/rpc/v0"
                    self.logger.debug(f"💾 Testing Storage API URL: {url}")
                    
                    # Try to get storage info
                    storage_data = {
                        "jsonrpc": "2.0",
                        "method": "Filecoin.StorageList",
                        "params": [],
                        "id": 1
                    }
                    
                    response = requests.post(
                        url,
                        json=storage_data,
                        timeout=self.timeout,
                        headers={'Content-Type': 'application/json'},
                        verify=False
                    )
                    self.logger.debug(f"💾 Storage API response status: {response.status_code}")
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if 'result' in data:
                                self.logger.info(f"💾 Found Storage API at {url}")
                                result['storage_api_exposed'] = True
                                result['storage_api_url'] = url
                                result['storage_info'] = data['result']
                                self.logger.debug(f"💾 Storage info retrieved: {len(str(data['result']))} chars")
                                break
                        except json.JSONDecodeError as e:
                            self.logger.debug(f"💾 JSON decode error for {url}: {str(e)}")
                            continue
                    elif response.status_code == 401:
                        result['storage_api_exposed'] = True
                        result['storage_api_url'] = url
                        result['storage_auth_required'] = True
                        self.logger.info(f"💾 Found authenticated Storage API at {url}")
                        break
                        
            except Exception as e:
                self.logger.debug(f"💾 Storage API error for {ip_address}:{port}: {str(e)}")
                continue
        
        self.logger.debug(f"💾 Storage API check complete for {ip_address}")
        return result
    
    def _check_market_api(self, ip_address: str) -> Dict[str, Any]:
        """Check for Market API endpoints with security assessment."""
        self.logger.debug(f"🏪 Starting Market API check for {ip_address}")
        
        result = {
            'market_api_exposed': False,
            'market_api_url': None,
            'market_info': None,
            'market_auth_required': False
        }
        
        for port in self.market_api_ports:
            self.logger.debug(f"🏪 Testing port {port} for {ip_address}")
            
            try:
                for scheme in ['http', 'https']:
                    url = f"{scheme}://{ip_address}:{port}/rpc/v0"
                    self.logger.debug(f"🏪 Testing Market API URL: {url}")
                    
                    # Try to get market info
                    market_data = {
                        "jsonrpc": "2.0",
                        "method": "Filecoin.MarketListIncompleteDeals",
                        "params": [],
                        "id": 1
                    }
                    
                    response = requests.post(
                        url,
                        json=market_data,
                        timeout=self.timeout,
                        headers={'Content-Type': 'application/json'},
                        verify=False
                    )
                    self.logger.debug(f"🏪 Market API response status: {response.status_code}")
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if 'result' in data:
                                self.logger.info(f"🏪 Found Market API at {url}")
                                result['market_api_exposed'] = True
                                result['market_api_url'] = url
                                result['market_info'] = data['result']
                                self.logger.debug(f"🏪 Market info retrieved: {len(str(data['result']))} chars")
                                break
                        except json.JSONDecodeError as e:
                            self.logger.debug(f"🏪 JSON decode error for {url}: {str(e)}")
                            continue
                    elif response.status_code == 401:
                        result['market_api_exposed'] = True
                        result['market_api_url'] = url
                        result['market_auth_required'] = True
                        self.logger.info(f"🏪 Found authenticated Market API at {url}")
                        break
                        
            except Exception as e:
                self.logger.debug(f"🏪 Market API error for {ip_address}:{port}: {str(e)}")
                continue
        
        self.logger.debug(f"🏪 Market API check complete for {ip_address}")
        return result
    
    def _check_network_ports(self, ip_address: str) -> Dict[str, Any]:
        """Check P2P and metrics ports."""
        self.logger.debug(f"🌐 Checking network ports for {ip_address}")
        
        result = {
            'p2p_ports_open': [],
            'metrics_exposed': False,
            'metrics_url': None
        }
        
        # Check P2P ports
        self.logger.debug(f"🌐 Testing P2P ports: {self.p2p_ports}")
        for port in self.p2p_ports:
            try:
                self.logger.debug(f"🌐 Testing P2P port {port}")
                with socket.create_connection((ip_address, port), timeout=self.timeout):
                    result['p2p_ports_open'].append(port)
                    self.logger.debug(f"🌐 P2P port {port} open on {ip_address}")
            except (socket.timeout, socket.error) as e:
                self.logger.debug(f"🌐 P2P port {port} closed or filtered: {str(e)}")
                continue
        
        # Check metrics ports
        self.logger.debug(f"🌐 Testing metrics ports: {self.metrics_ports}")
        for port in self.metrics_ports:
            try:
                for scheme in ['http', 'https']:
                    url = f"{scheme}://{ip_address}:{port}/metrics"
                    self.logger.debug(f"🌐 Testing metrics URL: {url}")
                    response = requests.get(url, timeout=self.timeout, verify=False)
                    if response.status_code == 200 and 'prometheus' in response.text.lower():
                        result['metrics_exposed'] = True
                        result['metrics_url'] = url
                        self.logger.info(f"🌐 Metrics exposed at {url}")
                        self.logger.debug(f"🌐 Metrics content length: {len(response.text)} chars")
                        break
            except Exception as e:
                self.logger.debug(f"🌐 Metrics check error for {ip_address}:{port}: {str(e)}")
                continue
        
        self.logger.debug(f"🌐 Network ports check complete - P2P: {result['p2p_ports_open']}, metrics: {result['metrics_exposed']}")
        return result
    
    def _test_available_methods(self, url: str) -> List[str]:
        """Test which API methods are available."""
        self.logger.debug(f"Testing available methods for {url}")
        available_methods = []
        
        for method_name, method_call in self.test_methods.items():
            try:
                self.logger.debug(f"Testing method: {method_call}")
                test_data = {
                    "jsonrpc": "2.0",
                    "method": method_call,
                    "params": [],
                    "id": 1
                }
                
                response = requests.post(
                    url,
                    json=test_data,
                    timeout=self.timeout,
                    headers={'Content-Type': 'application/json'},
                    verify=False
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'result' in data and 'error' not in data:
                            available_methods.append(method_name)
                            self.logger.debug(f"✅ Method available: {method_call}")
                        elif 'error' in data:
                            self.logger.debug(f"❌ Method error for {method_call}: {data['error']}")
                    except json.JSONDecodeError:
                        self.logger.debug(f"❌ JSON decode error for method {method_call}")
                        pass
                        
            except Exception as e:
                self.logger.debug(f"❌ Method test error for {method_call}: {str(e)}")
                continue
        
        self.logger.debug(f"Available methods: {available_methods}")
        return available_methods
    
    def _check_authentication_required(self, url: str) -> bool:
        """Check if the API requires authentication by testing sensitive methods."""
        self.logger.debug(f"Checking authentication requirements for {url}")
        
        for method in self.sensitive_methods[:3]:  # Test first 3 sensitive methods
            try:
                self.logger.debug(f"Testing sensitive method: {method}")
                test_data = {
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": [],
                    "id": 1
                }
                
                response = requests.post(
                    url,
                    json=test_data,
                    timeout=self.timeout,
                    headers={'Content-Type': 'application/json'},
                    verify=False
                )
                
                if response.status_code in [401, 403]:
                    self.logger.debug(f"✅ Authentication required (status {response.status_code})")
                    return True
                elif response.status_code == 200:
                    try:
                        data = response.json()
                        if 'result' in data and 'error' not in data:
                            # If sensitive method works without auth, that's a security issue
                            self.logger.warning(f"⚠️ Sensitive method {method} accessible without authentication!")
                            return False
                    except json.JSONDecodeError:
                        pass
                    
            except Exception as e:
                self.logger.debug(f"Auth check error for {method}: {str(e)}")
                continue
        
        self.logger.debug("Authentication requirement unclear - assuming required")
        return True  # Default to assuming auth is required
    
    def _perform_security_analysis(self, ip_address: str, results: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive security analysis."""
        self.logger.info(f"🔒 Performing security analysis for {ip_address}")
        
        security_result = {
            'sensitive_methods_exposed': [],
            'security_headers': {},
            'ssl_issues': [],
            'security_score': 100  # Start with perfect score, deduct points
        }
        
        # Check for exposed sensitive methods
        if results.get('lotus_api_exposed') and results.get('lotus_api_url'):
            url = results['lotus_api_url']
            self.logger.debug(f"🔒 Checking sensitive methods for {url}")
            
            for method in self.sensitive_methods:
                try:
                    self.logger.debug(f"🔒 Testing sensitive method: {method}")
                    test_data = {
                        "jsonrpc": "2.0",
                        "method": method,
                        "params": [],
                        "id": 1
                    }
                    
                    response = requests.post(
                        url,
                        json=test_data,
                        timeout=self.timeout,
                        headers={'Content-Type': 'application/json'},
                        verify=False
                    )
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if 'result' in data and 'error' not in data:
                                security_result['sensitive_methods_exposed'].append(method)
                                security_result['security_score'] -= 20  # Major security issue
                                self.logger.warning(f"⚠️ Sensitive method exposed: {method}")
                        except json.JSONDecodeError:
                            pass
                            
                except Exception as e:
                    self.logger.debug(f"🔒 Sensitive method test error for {method}: {str(e)}")
                    continue
            
            # Check security headers
            try:
                self.logger.debug(f"🔒 Checking security headers for {url}")
                response = requests.get(url.replace('/rpc', ''), timeout=self.timeout, verify=False)
                security_result['security_headers'] = self._analyze_security_headers(response.headers)
                
                # Deduct points for missing security headers
                missing_headers = len(security_result['security_headers'].get('missing', []))
                security_result['security_score'] -= (missing_headers * 5)
                self.logger.debug(f"🔒 Missing security headers: {missing_headers}")
                
            except Exception as e:
                self.logger.debug(f"🔒 Security headers check error: {str(e)}")
            
            # Check SSL configuration if HTTPS
            if url.startswith('https'):
                self.logger.debug(f"🔒 Checking SSL configuration for {url}")
                ssl_issues = self._check_ssl_configuration(ip_address, url)
                security_result['ssl_issues'] = ssl_issues
                security_result['security_score'] -= (len(ssl_issues) * 10)
                self.logger.debug(f"🔒 SSL issues found: {len(ssl_issues)}")
        
        # Deduct points for unnecessary exposed services
        if not results.get('lotus_auth_required', True):
            security_result['security_score'] -= 15
            self.logger.warning("⚠️ Lotus API does not require authentication")
            
        if not results.get('storage_auth_required', True) and results.get('storage_api_exposed'):
            security_result['security_score'] -= 15
            self.logger.warning("⚠️ Storage API does not require authentication")
            
        if not results.get('market_auth_required', True) and results.get('market_api_exposed'):
            security_result['security_score'] -= 15
            self.logger.warning("⚠️ Market API does not require authentication")
            
        if results.get('metrics_exposed'):
            security_result['security_score'] -= 10
            self.logger.warning("⚠️ Metrics endpoint exposed")
        
        # Ensure score doesn't go below 0
        security_result['security_score'] = max(0, security_result['security_score'])
        
        self.logger.info(f"🔒 Security analysis complete. Score: {security_result['security_score']}/100")
        if security_result['security_score'] < 70:
            self.logger.warning(f"⚠️ Low security score detected: {security_result['security_score']}/100")
        
        return security_result
    
    def _analyze_security_headers(self, headers) -> Dict[str, Any]:
        """Analyze HTTP security headers."""
        self.logger.debug("Analyzing security headers")
        
        security_headers = {
            'present': [],
            'missing': [],
            'values': {}
        }
        
        expected_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options', 
            'X-XSS-Protection',
            'Content-Security-Policy',
            'Strict-Transport-Security'
        ]
        
        for header in expected_headers:
            if header in headers:
                security_headers['present'].append(header)
                security_headers['values'][header] = headers[header]
                self.logger.debug(f"✅ Security header present: {header}")
            else:
                security_headers['missing'].append(header)
                self.logger.debug(f"❌ Security header missing: {header}")
        
        return security_headers
    
    def _check_ssl_configuration(self, ip_address: str, url: str) -> List[str]:
        """Check SSL configuration for issues."""
        self.logger.debug(f"Checking SSL configuration for {ip_address}")
        ssl_issues = []
        
        try:
            import ssl
            from urllib.parse import urlparse
            
            parsed_url = urlparse(url)
            port = parsed_url.port or 443
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip_address, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip_address) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    
                    self.logger.debug(f"SSL Protocol: {protocol}, Cipher: {cipher}")
                    
                    # Check certificate expiration
                    if cert:
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (not_after - datetime.now()).days
                        
                        if days_until_expiry < 30:
                            ssl_issues.append(f"Certificate expires in {days_until_expiry} days")
                            self.logger.warning(f"⚠️ Certificate expires soon: {days_until_expiry} days")
                    
                    # Check for weak ciphers
                    if cipher and ('RC4' in cipher[0] or 'DES' in cipher[0]):
                        ssl_issues.append(f"Weak cipher suite: {cipher[0]}")
                        self.logger.warning(f"⚠️ Weak cipher detected: {cipher[0]}")
                    
                    # Check protocol version
                    if protocol and protocol in ['TLSv1', 'TLSv1.1']:
                        ssl_issues.append(f"Outdated TLS protocol: {protocol}")
                        self.logger.warning(f"⚠️ Outdated TLS protocol: {protocol}")
                        
        except Exception as e:
            ssl_issues.append(f"SSL analysis error: {str(e)}")
            self.logger.debug(f"SSL analysis error: {str(e)}")
        
        return ssl_issues
