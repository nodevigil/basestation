"""
Ethereum-specific scanner with scan level support.
"""

import requests
import json
import time
from typing import Dict, Any, Optional, List
from .base_protocol_scanner import ProtocolScanner


class EthereumScanner(ProtocolScanner):
    """
    Ethereum-specific scanner for protocol-related checks with level support.
    
    Scan Levels:
    - Level 1: Basic JSON-RPC endpoint detection and version check
    - Level 2: Extended node information and sync status
    - Level 3: Comprehensive node analysis and security assessment
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Ethereum scanner."""
        super().__init__(config)
        
        # Ethereum-specific configuration
        self.rpc_ports = self.config.get('rpc_ports', [8545, 8546, 443, 80])
        self.ws_ports = self.config.get('ws_ports', [8546, 8547])
        self.metrics_ports = self.config.get('metrics_ports', [9090, 9091, 6060])
        
        # API endpoints to test
        self.api_endpoints = [
            "/",
            "/rpc",
            "/v1",
            "/api/v1"
        ]
        
        # Basic test methods
        self.test_methods = {
            'version': "web3_clientVersion",
            'chain_id': "eth_chainId", 
            'block_number': "eth_blockNumber",
            'syncing': "eth_syncing",
            'peer_count': "net_peerCount"
        }
    
    @property
    def protocol_name(self) -> str:
        """Return the protocol name."""
        return "ethereum"
    
    def get_supported_levels(self) -> List[int]:
        """Ethereum scanner supports all three levels."""
        return [1, 2, 3]
    
    def describe_levels(self) -> Dict[int, str]:
        """Describe what each scan level does for Ethereum."""
        return {
            1: "Basic JSON-RPC endpoint detection and client version check",
            2: "Extended node information including sync status and peer count",
            3: "Comprehensive node analysis with security assessment and performance metrics"
        }

    def scan_protocol(self, target: str, hostname: Optional[str] = None, scan_level: int = 1, **kwargs) -> Dict[str, Any]:
        """Perform Ethereum-specific scan at the specified level."""
        self.logger.info(f"Starting Ethereum scan of {target} at level {scan_level}")
        scan_start_time = time.time()
        
        results = {
            'scan_type': 'ethereum_specific',
            'scan_level': scan_level,
            'target_ip': target,
            'rpc_exposed': False,
            'client_version': None,
            'chain_id': None,
            'errors': []
        }
        
        try:
            if scan_level == 1:
                level_results = self._scan_level_1(target)
            elif scan_level == 2:
                level_results = self._scan_level_2(target)
            elif scan_level == 3:
                level_results = self._scan_level_3(target)
            else:
                raise ValueError(f"Invalid scan_level: {scan_level}")
            
            results.update(level_results)
            
            scan_duration = time.time() - scan_start_time
            results['scan_duration'] = scan_duration
            
            self.logger.info(f"Completed Ethereum scan of {target} at level {scan_level} in {scan_duration:.2f}s")
            
        except Exception as e:
            self.logger.error(f"Ethereum scan failed for {target}: {str(e)}")
            results['errors'].append(f"Scan error: {str(e)}")
            results['scan_duration'] = time.time() - scan_start_time
        
        return results

    def _scan_level_1(self, target: str) -> Dict[str, Any]:
        """Level 1: Basic RPC endpoint detection."""
        self.logger.info(f"Level 1 Ethereum scan for {target}")
        
        results = {
            'rpc_exposed': False,
            'rpc_url': None,
            'client_version': None
        }
        
        # Check common RPC ports
        for port in self.rpc_ports[:2]:  # Limit for level 1
            for scheme in ['http', 'https']:
                url = f"{scheme}://{target}:{port}"
                try:
                    rpc_data = {
                        "jsonrpc": "2.0",
                        "method": "web3_clientVersion",
                        "params": [],
                        "id": 1
                    }
                    
                    response = requests.post(
                        url,
                        json=rpc_data,
                        timeout=self.timeout,
                        headers={'Content-Type': 'application/json'},
                        verify=False
                    )
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if 'result' in data:
                                results['rpc_exposed'] = True
                                results['rpc_url'] = url
                                results['client_version'] = data['result']
                                return results
                        except json.JSONDecodeError:
                            pass
                            
                except Exception:
                    continue
        
        return results

    def _scan_level_2(self, target: str) -> Dict[str, Any]:
        """Level 2: Extended node information."""
        # Get level 1 results first
        results = self._scan_level_1(target)
        
        if results.get('rpc_exposed'):
            url = results['rpc_url']
            
            # Get chain ID
            chain_id = self._call_rpc_method(url, "eth_chainId")
            if chain_id:
                results['chain_id'] = chain_id
            
            # Get sync status
            syncing = self._call_rpc_method(url, "eth_syncing")
            results['syncing'] = syncing
            
            # Get peer count
            peer_count = self._call_rpc_method(url, "net_peerCount")
            if peer_count:
                results['peer_count'] = int(peer_count, 16) if isinstance(peer_count, str) else peer_count
        
        return results

    def _scan_level_3(self, target: str) -> Dict[str, Any]:
        """Level 3: Comprehensive analysis."""
        # Get level 2 results first
        results = self._scan_level_2(target)
        
        if results.get('rpc_exposed'):
            url = results['rpc_url']
            
            # Get latest block
            block_number = self._call_rpc_method(url, "eth_blockNumber")
            if block_number:
                results['latest_block'] = int(block_number, 16) if isinstance(block_number, str) else block_number
            
            # Check available methods
            available_methods = []
            for method_name, method in self.test_methods.items():
                if self._test_rpc_method(url, method):
                    available_methods.append(method_name)
            
            results['available_methods'] = available_methods
            
            # Security score based on exposed methods
            results['security_score'] = self._calculate_security_score(results)
        
        return results

    def _call_rpc_method(self, url: str, method: str, params: List = None) -> Any:
        """Call an RPC method and return the result."""
        try:
            rpc_data = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params or [],
                "id": 1
            }
            
            response = requests.post(
                url,
                json=rpc_data,
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('result')
        except Exception:
            pass
        return None

    def _test_rpc_method(self, url: str, method: str) -> bool:
        """Test if an RPC method is available."""
        result = self._call_rpc_method(url, method)
        return result is not None

    def _calculate_security_score(self, results: Dict[str, Any]) -> int:
        """Calculate a security score based on scan results."""
        score = 100
        
        # Deduct points for various findings
        if results.get('rpc_exposed'):
            score -= 10  # RPC exposed publicly
        
        available_methods = results.get('available_methods', [])
        if len(available_methods) > 3:
            score -= 15  # Many methods available
        
        return max(0, score)
