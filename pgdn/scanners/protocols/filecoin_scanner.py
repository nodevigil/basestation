"""
Filecoin-specific scanner with scan level support.
"""

import requests
import json
import logging
import socket
import time
from typing import Dict, Any, Optional, List
from datetime import datetime
from .base_protocol_scanner import ProtocolScanner


class FilecoinScanner(ProtocolScanner):
    """
    Filecoin-specific scanner for protocol-related checks with level support.
    
    Scan Levels:
    - Level 1: Basic Lotus API endpoint detection and version check
    - Level 2: Extended API checks (storage, market, metrics)
    - Level 3: Comprehensive security analysis and deep protocol inspection
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Filecoin scanner."""
        super().__init__(config)
        
        # Filecoin-specific configuration
        self.lotus_api_ports = self.config.get('lotus_api_ports', [1234, 3453, 8080, 80, 443, 8443])
        self.storage_api_ports = self.config.get('storage_api_ports', [2345, 1235, 8081])
        self.market_api_ports = self.config.get('market_api_ports', [3456, 8082])
        self.p2p_ports = self.config.get('p2p_ports', [1235, 4001, 9001])
        self.metrics_ports = self.config.get('metrics_ports', [9090, 9091, 8888])
        
        # API endpoints to test
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
        
        # Basic test methods
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
    
    @property
    def protocol_name(self) -> str:
        """Return the protocol name."""
        return "filecoin"
    
    def get_supported_levels(self) -> List[int]:
        """Filecoin scanner supports all three levels."""
        return [1, 2, 3]
    
    def describe_levels(self) -> Dict[int, str]:
        """Describe what each scan level does for Filecoin."""
        return {
            1: "Basic Lotus API endpoint detection and version check",
            2: "Extended API checks including storage, market APIs, and metrics detection",
            3: "Comprehensive security analysis with deep protocol inspection and vulnerability testing"
        }

    async def scan_protocol(self, target: str, scan_level: int, **kwargs) -> Dict[str, Any]:
        """Perform Filecoin-specific scan at the specified level."""
        self.logger.info(f"Starting Filecoin scan of {target} at level {scan_level}")
        scan_start_time = time.time()
        
        results = {
            'scan_type': 'filecoin_specific',
            'scan_level': scan_level,
            'target_ip': target,
            'lotus_api_exposed': False,
            'node_info': None,
            'lotus_auth_required': True,
            'errors': []
        }
        
        try:
            if scan_level == 1:
                level_results = await self._scan_level_1(target)
            elif scan_level == 2:
                level_results = await self._scan_level_2(target)
            elif scan_level == 3:
                level_results = await self._scan_level_3(target)
            else:
                raise ValueError(f"Invalid scan_level: {scan_level}")
            
            results.update(level_results)
            
            scan_duration = time.time() - scan_start_time
            results['scan_duration'] = scan_duration
            
            self.logger.info(f"Completed Filecoin scan of {target} at level {scan_level} in {scan_duration:.2f}s")
            
        except Exception as e:
            self.logger.error(f"Filecoin scan failed for {target}: {str(e)}")
            results['errors'].append(f"Scan error: {str(e)}")
            results['scan_duration'] = time.time() - scan_start_time
        
        return results

    async def _scan_level_1(self, target: str) -> Dict[str, Any]:
        """Level 1: Basic node info and RPC auth check."""
        self.logger.info(f"Level 1 Filecoin scan for {target}")
        
        results = {
            'lotus_api_exposed': False,
            'lotus_api_url': None,
            'node_info': None,
            'lotus_auth_required': True
        }
        
        # Only check common ports for level 1
        common_ports = [1234, 3453, 8080]
        
        for port in common_ports:
            for scheme in ['http', 'https']:
                url = f"{scheme}://{target}:{port}/rpc/v0"
                try:
                    node_data = {
                        "jsonrpc": "2.0",
                        "method": "Filecoin.Version",
                        "params": [],
                        "id": 1
                    }
                    
                    response = requests.post(
                        url,
                        json=node_data,
                        timeout=self.timeout,
                        headers={'Content-Type': 'application/json'},
                        verify=False
                    )
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if 'result' in data:
                                results['lotus_api_exposed'] = True
                                results['lotus_api_url'] = url
                                results['node_info'] = data['result']
                                results['lotus_auth_required'] = False
                                return results
                        except json.JSONDecodeError:
                            pass
                    elif response.status_code == 401:
                        results['lotus_api_exposed'] = True
                        results['lotus_api_url'] = url
                        results['lotus_auth_required'] = True
                        return results
                        
                except Exception:
                    continue
        
        return results

    async def _scan_level_2(self, target: str) -> Dict[str, Any]:
        """Level 2: Enhanced API checks and metrics detection."""
        self.logger.info(f"Level 2 Filecoin scan for {target}")
        
        results = {
            'lotus_api_exposed': False,
            'storage_api_exposed': False,
            'market_api_exposed': False,
            'metrics_exposed': False,
            'node_info': None,
            'lotus_auth_required': True,
            'storage_auth_required': True,
            'market_auth_required': True
        }
        
        # Check Lotus API
        lotus_result = await self._check_lotus_api_basic(target)
        results.update(lotus_result)
        
        # Check Storage API
        storage_result = await self._check_storage_api(target)
        results.update(storage_result)
        
        # Check Market API
        market_result = await self._check_market_api(target)
        results.update(market_result)
        
        # Check metrics
        metrics_result = await self._check_metrics(target)
        results.update(metrics_result)
        
        return results

    async def _scan_level_3(self, target: str) -> Dict[str, Any]:
        """Level 3: Deep protocol inspection with security analysis."""
        self.logger.info(f"Level 3 Filecoin scan for {target}")
        
        results = {
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
            'security_score': 0
        }
        
        # Comprehensive API scanning
        lotus_result = await self._check_lotus_api_comprehensive(target)
        results.update(lotus_result)
        
        storage_result = await self._check_storage_api(target)
        results.update(storage_result)
        
        market_result = await self._check_market_api(target)
        results.update(market_result)
        
        # Network analysis
        network_result = await self._check_network_ports(target)
        results.update(network_result)
        
        # Security analysis
        security_result = await self._perform_security_analysis(target, results)
        results.update(security_result)
        
        return results

    async def _check_lotus_api_basic(self, target: str) -> Dict[str, Any]:
        """Basic Lotus API check."""
        result = {
            'lotus_api_exposed': False,
            'lotus_api_url': None,
            'node_info': None,
            'lotus_auth_required': True
        }
        
        for port in self.lotus_api_ports[:3]:  # Limit to first 3 ports for level 2
            for endpoint in ["/rpc/v0", "/rpc/v1"]:
                for scheme in ['http', 'https']:
                    url = f"{scheme}://{target}:{port}{endpoint}"
                    try:
                        version_data = {
                            "jsonrpc": "2.0",
                            "method": "Filecoin.Version",
                            "params": [],
                            "id": 1
                        }
                        
                        response = requests.post(
                            url,
                            json=version_data,
                            timeout=self.timeout,
                            headers={'Content-Type': 'application/json'},
                            verify=False
                        )
                        
                        if response.status_code == 200:
                            try:
                                data = response.json()
                                if 'result' in data:
                                    result['lotus_api_exposed'] = True
                                    result['lotus_api_url'] = url
                                    result['node_info'] = data['result']
                                    result['lotus_auth_required'] = False
                                    return result
                            except json.JSONDecodeError:
                                pass
                        elif response.status_code == 401:
                            result['lotus_api_exposed'] = True
                            result['lotus_api_url'] = url
                            result['lotus_auth_required'] = True
                            return result
                            
                    except Exception:
                        continue
        
        return result

    async def _check_lotus_api_comprehensive(self, target: str) -> Dict[str, Any]:
        """Comprehensive Lotus API check for level 3."""
        result = {
            'lotus_api_exposed': False,
            'lotus_api_url': None,
            'lotus_version': None,
            'chain_head': None,
            'lotus_auth_required': False,
            'lotus_methods_available': []
        }
        
        for port in self.lotus_api_ports:
            for endpoint in self.api_endpoints:
                try:
                    schemes = ['https', 'http'] if port in [443, 8443] else ['http', 'https']
                    
                    for scheme in schemes:
                        url = f"{scheme}://{target}:{port}{endpoint}"
                        
                        # Test version method
                        version_data = {
                            "jsonrpc": "2.0",
                            "method": "Filecoin.Version",
                            "params": [],
                            "id": 1
                        }
                        
                        response = requests.post(
                            url,
                            json=version_data,
                            timeout=self.timeout,
                            headers={'Content-Type': 'application/json'},
                            verify=False
                        )
                        
                        if response.status_code == 200:
                            try:
                                data = response.json()
                                if 'result' in data:
                                    result['lotus_api_exposed'] = True
                                    result['lotus_api_url'] = url
                                    result['lotus_version'] = data['result'].get('Version', 'Unknown')
                                    
                                    # Test additional methods
                                    available_methods = []
                                    for method_name, method in self.test_methods.items():
                                        if self._test_method(url, method):
                                            available_methods.append(method_name)
                                    
                                    result['lotus_methods_available'] = available_methods
                                    return result
                            except json.JSONDecodeError:
                                pass
                        elif response.status_code == 401:
                            result['lotus_api_exposed'] = True
                            result['lotus_api_url'] = url
                            result['lotus_auth_required'] = True
                            return result
                            
                except Exception:
                    continue
        
        return result

    async def _check_storage_api(self, target: str) -> Dict[str, Any]:
        """Check for Storage Provider API."""
        result = {
            'storage_api_exposed': False,
            'storage_api_url': None,
            'storage_auth_required': True
        }
        
        for port in self.storage_api_ports:
            for scheme in ['http', 'https']:
                url = f"{scheme}://{target}:{port}/rpc/v0"
                try:
                    response = requests.post(
                        url,
                        json={"jsonrpc": "2.0", "method": "Filecoin.Version", "params": [], "id": 1},
                        timeout=self.timeout,
                        verify=False
                    )
                    
                    if response.status_code in [200, 401]:
                        result['storage_api_exposed'] = True
                        result['storage_api_url'] = url
                        result['storage_auth_required'] = response.status_code == 401
                        break
                except Exception:
                    continue
        
        return result

    async def _check_market_api(self, target: str) -> Dict[str, Any]:
        """Check for Market API."""
        result = {
            'market_api_exposed': False,
            'market_api_url': None,
            'market_auth_required': True
        }
        
        for port in self.market_api_ports:
            for scheme in ['http', 'https']:
                url = f"{scheme}://{target}:{port}/rpc/v0"
                try:
                    response = requests.post(
                        url,
                        json={"jsonrpc": "2.0", "method": "Filecoin.Version", "params": [], "id": 1},
                        timeout=self.timeout,
                        verify=False
                    )
                    
                    if response.status_code in [200, 401]:
                        result['market_api_exposed'] = True
                        result['market_api_url'] = url
                        result['market_auth_required'] = response.status_code == 401
                        break
                except Exception:
                    continue
        
        return result

    async def _check_metrics(self, target: str) -> Dict[str, Any]:
        """Check for metrics endpoints."""
        result = {
            'metrics_exposed': False,
            'metrics_url': None
        }
        
        for port in self.metrics_ports:
            try:
                for scheme in ['http', 'https']:
                    url = f"{scheme}://{target}:{port}/metrics"
                    response = requests.get(url, timeout=self.timeout, verify=False)
                    if response.status_code == 200 and 'prometheus' in response.text.lower():
                        result['metrics_exposed'] = True
                        result['metrics_url'] = url
                        return result
            except Exception:
                continue
        
        return result

    async def _check_network_ports(self, target: str) -> Dict[str, Any]:
        """Check P2P network ports."""
        result = {'p2p_ports_open': []}
        
        for port in self.p2p_ports:
            try:
                sock = socket.create_connection((target, port), timeout=2)
                sock.close()
                result['p2p_ports_open'].append(port)
            except Exception:
                continue
        
        return result

    async def _perform_security_analysis(self, target: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Perform security analysis for level 3."""
        result = {
            'sensitive_methods_exposed': [],
            'security_headers': {},
            'ssl_issues': [],
            'security_score': 100
        }
        
        # Test for exposed sensitive methods
        if scan_results.get('lotus_api_exposed') and not scan_results.get('lotus_auth_required'):
            api_url = scan_results.get('lotus_api_url')
            if api_url:
                for method in self.sensitive_methods:
                    if self._test_method(api_url, method):
                        result['sensitive_methods_exposed'].append(method)
                        result['security_score'] -= 20  # Severe penalty
        
        # Calculate final security score
        if result['sensitive_methods_exposed']:
            result['security_score'] = max(0, result['security_score'])
        
        return result

    def _test_method(self, url: str, method: str) -> bool:
        """Test if a specific RPC method is available."""
        try:
            response = requests.post(
                url,
                json={"jsonrpc": "2.0", "method": method, "params": [], "id": 1},
                timeout=self.timeout,
                verify=False
            )
            return response.status_code not in [404, 405]
        except Exception:
            return False
