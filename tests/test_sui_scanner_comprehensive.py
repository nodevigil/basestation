#!/usr/bin/env python3
"""
Comprehensive test suite for Sui scanner functionality with proper mocking.
This test suite verifies scanner behavior without making actual network requests.
"""

import pytest
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime
from typing import Dict, Any, List, Optional

# Import the scanner classes
from pgdn.scanners.protocols.sui_scanner import EnhancedSuiScanner, ScanLevel, SuiScanResult
from pgdn.scanners.protocols.base_protocol_scanner import ProtocolScanner


class TestSuiScannerComprehensive:
    """Comprehensive test suite for Sui scanner."""
    
    @pytest.fixture
    def scanner_config(self) -> Dict[str, Any]:
        """Provide test configuration for scanner."""
        return {
            'timeout': 5,
            'max_retries': 2,
            'rate_limit_delay': 0.1,  # Reduced for testing
        }
    
    @pytest.fixture
    def scanner(self, scanner_config) -> EnhancedSuiScanner:
        """Create scanner instance for testing."""
        return EnhancedSuiScanner(
            config=scanner_config,
            scan_level=ScanLevel.LITE,
            enable_reputation=False,  # Disable for testing
            enable_behavioral=False   # Disable for testing
        )
    
    @pytest.fixture
    def mock_system_state(self) -> Dict[str, Any]:
        """Mock Sui system state response."""
        return {
            "epoch": 123,
            "systemStateVersion": "1.15.0",
            "activeValidators": [
                {
                    "name": "validator1",
                    "stakingPoolSuiBalance": "1000000000",
                    "apy": 5.2
                },
                {
                    "name": "validator2", 
                    "stakingPoolSuiBalance": "2000000000",
                    "apy": 5.5
                }
            ]
        }
    
    @pytest.fixture
    def mock_checkpoints(self) -> Dict[str, Any]:
        """Mock Sui checkpoints response."""
        return {
            "data": [
                {
                    "sequenceNumber": "456789",
                    "transactions": ["tx1", "tx2", "tx3"]
                }
            ]
        }
    
    @pytest.fixture
    def mock_validators(self) -> Dict[str, Any]:
        """Mock validators response."""
        return {
            "result": [
                {
                    "name": "validator1",
                    "stakingPoolSuiBalance": "1000000000",
                    "apy": 5.2,
                    "commissionRate": 0.05
                },
                {
                    "name": "validator2",
                    "stakingPoolSuiBalance": "2000000000", 
                    "apy": 5.5,
                    "commissionRate": 0.03
                }
            ]
        }
    
    @pytest.fixture
    def mock_metrics(self) -> str:
        """Mock Prometheus metrics response."""
        return """# HELP sui_checkpoint_height Current checkpoint height
sui_checkpoint_height 456789
# HELP sui_transaction_rate Transaction processing rate
sui_transaction_rate 10.5
# HELP sui_gas_price Current gas price
sui_gas_price 1000
# HELP sui_network_peers Network peer count
sui_network_peers 25
# HELP narwhal_current_round Current Narwhal round
narwhal_current_round 12345
# HELP bullshark_dag_vertices Bullshark DAG vertices
bullshark_dag_vertices 500
# HELP consensus_commit_latency_ms Consensus commit latency
consensus_commit_latency_ms 2500
# HELP narwhal_mempool_size Narwhal mempool size
narwhal_mempool_size 100
# HELP narwhal_certificate_rate Certificate throughput rate
narwhal_certificate_rate 5.0
"""

    def test_scanner_initialization(self, scanner):
        """Test scanner initializes correctly."""
        assert scanner.protocol_name == "sui"
        assert scanner.scan_level == ScanLevel.LITE
        assert scanner.timeout == 5
        assert scanner.max_retries == 2
        assert len(scanner.default_ports) == 4
        assert 9000 in scanner.default_ports
        assert 9184 in scanner.default_ports

    def test_scanner_supported_levels(self, scanner):
        """Test scanner reports correct supported levels."""
        levels = scanner.get_supported_levels()
        assert levels == [1, 2, 3]
        
        descriptions = scanner.describe_levels()
        assert 1 in descriptions
        assert 2 in descriptions
        assert 3 in descriptions
        assert "health check" in descriptions[1].lower()

    @pytest.mark.asyncio
    async def test_scan_protocol_basic_success(self, scanner, mock_system_state, mock_checkpoints):
        """Test basic scan_protocol method with successful responses."""
        
        # Mock httpx.AsyncClient responses
        mock_responses = {
            '/v1/system_state': mock_system_state,
            '/v1/checkpoints': mock_checkpoints,
            '/v1/validators': {"result": []},
            '/v1/transactions': {"data": []},
            '/metrics': None  # Not JSON response
        }
        
        async def mock_get(url):
            """Mock GET request handler."""
            response_mock = AsyncMock()
            
            # Determine which endpoint is being requested
            for endpoint, data in mock_responses.items():
                if endpoint in url:
                    if data is not None:
                        response_mock.status_code = 200
                        response_mock.json.return_value = data
                    else:
                        # For metrics endpoint
                        response_mock.status_code = 200
                        response_mock.text = "sui_test_metric 42"
                    return response_mock
            
            # Default 404 response
            response_mock.status_code = 404
            return response_mock
        
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = mock_get
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client
            
            # Test scan
            result = await scanner.scan_protocol(
                target="127.0.0.1",
                scan_level=1,
                ports=[9000]
            )
            
            # Verify result structure
            assert 'target' in result
            assert 'scan_level' in result
            assert 'protocol' in result
            assert 'results' in result
            assert 'summary' in result
            
            assert result['target'] == "127.0.0.1"
            assert result['scan_level'] == 1
            assert result['protocol'] == "sui"

    @pytest.mark.asyncio
    async def test_scan_protocol_with_none_parameters(self, scanner):
        """Test scan_protocol handles None parameters correctly."""
        
        # This should reproduce the "NoneType has no len()" error
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client
            
            # Mock _perform_scan to avoid actual network calls
            with patch.object(scanner, '_perform_scan', return_value=[]):
                # Test with None ports parameter
                result = await scanner.scan_protocol(
                    target="127.0.0.1",
                    scan_level=1,
                    ports=None  # This could cause the len() error
                )
                
                # Should not raise an error and should use default ports
                assert 'results' in result
                assert isinstance(result['results'], list)

    @pytest.mark.asyncio
    async def test_scan_basic_level_1(self, scanner, mock_system_state, mock_checkpoints, mock_validators):
        """Test level 1 scan with mocked responses."""
        
        async def mock_robust_fetch(client, url, retries=None):
            """Mock _robust_fetch method."""
            if '/v1/system_state' in url:
                return mock_system_state
            elif '/v1/checkpoints' in url:
                return mock_checkpoints
            elif '/v1/validators' in url:
                return mock_validators
            elif '/v1/transactions' in url:
                return {"data": []}
            return None
        
        with patch.object(scanner, '_robust_fetch', side_effect=mock_robust_fetch):
            result = SuiScanResult(
                ip="127.0.0.1",
                port=9000,
                timestamp=datetime.utcnow(),
                scan_level=ScanLevel.LITE
            )
            
            # Mock httpx client
            mock_client = AsyncMock()
            
            # Test basic scan functionality
            success_count = await scanner._scan_sui_basic(mock_client, "http://127.0.0.1:9000", result)
            
            # Verify results
            assert success_count > 0
            assert result.epoch == 123
            assert result.sui_version == "1.15.0"
            assert result.validator_count == 2
            assert result.healthy is True

    @pytest.mark.asyncio
    async def test_scan_medium_level_2(self, scanner, mock_metrics):
        """Test level 2 scan with metrics parsing."""
        
        # Mock httpx response for metrics
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = mock_metrics
        
        async def mock_get(url):
            if '/metrics' in url:
                return mock_response
            # Return 404 for other endpoints
            resp = AsyncMock()
            resp.status_code = 404
            return resp
        
        mock_client = AsyncMock()
        mock_client.get = mock_get
        
        result = SuiScanResult(
            ip="127.0.0.1",
            port=9000,
            timestamp=datetime.utcnow(),
            scan_level=ScanLevel.MEDIUM,
            validator_list=[{"name": "test", "stakingPoolSuiBalance": "1000", "apy": 5.0}]
        )
        
        # Test medium scan functionality
        success_count = await scanner._scan_sui_medium(mock_client, "http://127.0.0.1:9000", result)
        
        # Verify metrics were parsed
        assert success_count > 0
        assert 'sui_checkpoint_height' in result.metrics
        assert result.metrics['sui_checkpoint_height'] == 456789
        assert result.transaction_processing_rate == 10.5
        assert result.peer_count == 25

    @pytest.mark.asyncio
    async def test_scan_ferocious_level_3(self, scanner):
        """Test level 3 scan with comprehensive analysis."""
        
        mock_client = AsyncMock()
        
        # Mock latency measurement responses
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"test": "data"}
        
        mock_client.get.return_value = mock_response
        mock_client.post.return_value = mock_response
        
        # Mock port scanning
        with patch.object(scanner, '_scan_sui_port_range', return_value=[9000, 22]):
            with patch.object(scanner, '_identify_service', return_value='ssh'):
                with patch.object(scanner, '_analyze_tls_config', return_value={'grade': 'A'}):
                    with patch.object(scanner, '_test_rpc_authentication', return_value={'auth_required': True}):
                        
                        result = SuiScanResult(
                            ip="127.0.0.1",
                            port=9000,
                            timestamp=datetime.utcnow(),
                            scan_level=ScanLevel.FEROCIOUS
                        )
                        
                        # Test ferocious scan functionality
                        success_count = await scanner._scan_sui_ferocious(
                            mock_client, "http://127.0.0.1:9000", result, hostname=None
                        )
                        
                        # Verify comprehensive analysis was performed
                        assert success_count > 0
                        assert result.open_ports == [9000, 22]
                        assert result.tls_grade == 'A'
                        assert result.rpc_auth_enabled is True

    def test_metrics_parsing(self, scanner, mock_metrics):
        """Test Sui metrics parsing functionality."""
        
        parsed_metrics = scanner._parse_sui_metrics(mock_metrics)
        
        # Verify key metrics were parsed correctly
        assert 'sui_checkpoint_height' in parsed_metrics
        assert parsed_metrics['sui_checkpoint_height'] == 456789
        assert parsed_metrics['sui_transaction_rate'] == 10.5
        assert parsed_metrics['narwhal_current_round'] == 12345
        assert parsed_metrics['consensus_commit_latency_ms'] == 2500

    def test_gini_coefficient_calculation(self, scanner):
        """Test Gini coefficient calculation for stake distribution."""
        
        # Test with equal distribution (should be 0)
        equal_stakes = [100, 100, 100, 100]
        gini_equal = scanner._calculate_gini_coefficient(equal_stakes)
        assert gini_equal == 0.0
        
        # Test with very unequal distribution
        unequal_stakes = [1000, 10, 10, 10]
        gini_unequal = scanner._calculate_gini_coefficient(unequal_stakes)
        assert gini_unequal > 0.5
        
        # Test edge cases
        assert scanner._calculate_gini_coefficient([]) == 0.0
        assert scanner._calculate_gini_coefficient([100]) == 0.0

    def test_validator_consistency_analysis(self, scanner, mock_system_state):
        """Test validator consistency analysis."""
        
        validator_list = [
            {"name": "validator1", "stakingPoolSuiBalance": "1000000000"},
            {"name": "validator2", "stakingPoolSuiBalance": "2000000000"}
        ]
        
        analysis = scanner._analyze_validator_consistency(validator_list, mock_system_state)
        
        assert 'inconsistencies' in analysis
        assert 'consistency_score' in analysis
        assert isinstance(analysis['inconsistencies'], list)
        assert 0.0 <= analysis['consistency_score'] <= 1.0

    def test_validator_behavior_scoring(self, scanner):
        """Test individual validator behavior scoring."""
        
        # Good validator
        good_validator = {
            "apy": 5.0,
            "stakingPoolSuiBalance": "1000000",
            "commissionRate": 0.05
        }
        good_score = scanner._calculate_validator_behavior_score(good_validator)
        assert good_score > 0.5
        
        # Bad validator
        bad_validator = {
            "apy": -1.0,  # Negative APY
            "stakingPoolSuiBalance": "0",  # No stake
            "commissionRate": 0.5  # High commission
        }
        bad_score = scanner._calculate_validator_behavior_score(bad_validator)
        assert bad_score < 0.5

    @pytest.mark.asyncio
    async def test_error_handling(self, scanner):
        """Test error handling in scan methods."""
        
        # Test scan with connection errors
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get.side_effect = Exception("Connection failed")
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client
            
            result = await scanner.scan("127.0.0.1", ports=[9000])
            
            # Should return empty results without crashing
            assert isinstance(result, list)
            assert len(result) == 0

    @pytest.mark.asyncio
    async def test_timeout_handling(self, scanner):
        """Test timeout handling."""
        
        # Test with very short timeout
        short_timeout_scanner = EnhancedSuiScanner(
            config={'timeout': 0.001},  # Very short timeout
            enable_reputation=False,
            enable_behavioral=False
        )
        
        with patch('asyncio.wait_for', side_effect=asyncio.TimeoutError):
            result = await short_timeout_scanner.scan("127.0.0.1")
            
            # Should handle timeout gracefully
            assert isinstance(result, list)
            assert len(result) == 0

    def test_trust_scoring_data_export(self, scanner):
        """Test trust scoring data extraction."""
        
        # Create a result with comprehensive data
        result = SuiScanResult(
            ip="127.0.0.1",
            port=9000,
            timestamp=datetime.utcnow(),
            scan_level=ScanLevel.FEROCIOUS,
            healthy=True,
            epoch=123,
            validator_count=10,
            total_stake=1000000.0,
            latency_ms=150.0,
            uptime_score=0.95
        )
        
        trust_data = scanner.get_trust_scoring_data(result)
        
        # Verify key trust scoring fields are present
        assert 'healthy' in trust_data
        assert 'epoch' in trust_data
        assert 'validator_count' in trust_data
        assert 'total_stake' in trust_data
        assert 'latency_ms' in trust_data
        assert 'scan_level' in trust_data
        
        assert trust_data['healthy'] is True
        assert trust_data['epoch'] == 123
        assert trust_data['validator_count'] == 10

    def test_export_formats(self, scanner):
        """Test different export formats."""
        
        results = [
            SuiScanResult(
                ip="127.0.0.1",
                port=9000,
                timestamp=datetime.utcnow(),
                scan_level=ScanLevel.LITE,
                healthy=True,
                epoch=123
            )
        ]
        
        # Test JSON export
        json_export = scanner.export_results(results, format='json')
        assert isinstance(json_export, str)
        parsed_json = json.loads(json_export)
        assert isinstance(parsed_json, list)
        assert len(parsed_json) == 1
        
        # Test trust scoring export
        trust_export = scanner.export_results(results, format='trust_scoring')
        assert isinstance(trust_export, str)
        trust_data = json.loads(trust_export)
        assert 'trust_inputs' in trust_data[0]
        
        # Test CSV export
        csv_export = scanner.export_results(results, format='csv')
        assert isinstance(csv_export, str)
        assert 'ip,port,healthy' in csv_export
        assert '127.0.0.1,9000,True' in csv_export

    @pytest.mark.asyncio
    async def test_reputation_client_integration(self, scanner_config):
        """Test reputation client integration (when enabled)."""
        
        # Create scanner with reputation enabled
        scanner_with_reputation = EnhancedSuiScanner(
            config=scanner_config,
            enable_reputation=True,
            enable_behavioral=False
        )
        
        # Mock reputation client
        mock_reputation = AsyncMock()
        mock_reputation.check_ip.return_value = {'malicious': False}
        mock_reputation.check_sui_node.return_value = {'flags': []}
        scanner_with_reputation.reputation_client = mock_reputation
        
        result = SuiScanResult(
            ip="127.0.0.1",
            port=9000,
            timestamp=datetime.utcnow(),
            scan_level=ScanLevel.LITE,
            node_id="test-node-id"
        )
        
        await scanner_with_reputation._check_reputation_intelligence(result)
        
        # Verify reputation was checked
        mock_reputation.check_ip.assert_called_once_with("127.0.0.1")
        assert result.malicious_ip is False

    def test_security_analysis(self, scanner):
        """Test security posture analysis."""
        
        result = SuiScanResult(
            ip="127.0.0.1",
            port=9000,
            timestamp=datetime.utcnow(),
            scan_level=ScanLevel.FEROCIOUS,
            metrics_publicly_exposed=True,
            rpc_auth_enabled=False,
            open_ports=[22, 3389, 9000]  # SSH, RDP, Sui
        )
        
        # Run security analysis
        asyncio.run(scanner._analyze_security_posture(result))
        
        # Verify security issues were detected
        assert result.config_security_score < 1.0  # Should be reduced
        assert "risky_ports_exposed" in result.compliance_flags

    @pytest.mark.asyncio
    async def test_consensus_health_analysis(self, scanner):
        """Test consensus health analysis."""
        
        result = SuiScanResult(
            ip="127.0.0.1",
            port=9000,
            timestamp=datetime.utcnow(),
            scan_level=ScanLevel.MEDIUM,
            consensus_latency_ms=6000,  # High latency
            bullshark_dag_size=5,       # Too small
            mempool_size=2000,          # Large backlog
            certificate_throughput=0.5  # Low throughput
        )
        
        await scanner._analyze_sui_consensus_health(result)
        
        # Verify consensus issues were detected
        assert "high_consensus_latency" in result.misconfigs
        assert "small_bullshark_dag" in result.consensus_anomalies
        assert "large_mempool_backlog" in result.misconfigs
        assert "low_certificate_throughput" in result.consensus_anomalies

    def test_none_parameter_handling(self, scanner):
        """Test handling of None parameters to fix the len() error."""
        
        # Test various None parameter scenarios
        result = SuiScanResult(
            ip="127.0.0.1",
            port=9000,
            timestamp=datetime.utcnow(),
            scan_level=ScanLevel.LITE
        )
        
        # Test with None values that might cause len() errors
        result.open_ports = None
        result.exposed_services = None
        result.reputation_flags = None
        
        # Trigger __post_init__ to ensure lists are initialized
        result.__post_init__()
        
        # Verify None values were converted to empty lists
        assert result.open_ports == []
        assert result.exposed_services == []
        assert result.reputation_flags == []

    @pytest.mark.asyncio
    async def test_scan_protocol_parameter_validation(self, scanner):
        """Test scan_protocol parameter validation to prevent NoneType errors."""
        
        with patch.object(scanner, '_perform_scan', return_value=[]):
            # Test with missing required parameters
            result = await scanner.scan_protocol(
                target="127.0.0.1",
                scan_level=1
                # ports is not provided, should use defaults
            )
            
            assert 'summary' in result
            assert result['summary']['total_ports_scanned'] == len(scanner.default_ports)

    def test_edge_case_handling(self, scanner):
        """Test various edge cases that could cause errors."""
        
        # Test empty validator list
        result = SuiScanResult(
            ip="127.0.0.1",
            port=9000,
            timestamp=datetime.utcnow(),
            scan_level=ScanLevel.LITE,
            validator_list=[]
        )
        
        # Should not crash with empty validator list
        analysis = scanner._analyze_validator_consistency([], {})
        assert analysis['consistency_score'] >= 0.0
        
        # Test None system state
        analysis = scanner._analyze_validator_consistency([], None)
        assert analysis is not None


if __name__ == "__main__":
    # Run specific tests for debugging
    pytest.main([__file__ + "::TestSuiScannerComprehensive::test_none_parameter_handling", "-v"])