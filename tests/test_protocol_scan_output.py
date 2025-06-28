"""
Test suite for protocol scan output in ScanOrchestrator.

Tests that protocol scanner results (Sui, Filecoin, Arweave) are properly
included in the structured output format.
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime
from typing import Dict, Any

from pgdn.scanners.scan_orchestrator import ScanOrchestrator


class TestProtocolScanOutput:
    """Test protocol scanner output integration."""
    
    @pytest.fixture
    def mock_sui_scanner_result(self):
        """Mock Sui scanner result with meaningful data."""
        return {
            'target': '127.0.0.1',
            'hostname': None,
            'scan_level': 1,
            'protocol': 'sui',
            'timestamp': datetime.utcnow().isoformat(),
            'results': [
                {
                    'ip': '127.0.0.1',
                    'port': 9000,
                    'healthy': False,
                    'sui_version': None,
                    'epoch': None,
                    'scan_success_rate': 0.2
                }
            ],
            'summary': {
                'total_ports_scanned': 4,
                'successful_scans': 1,
                'healthy_nodes': 0,
                'scan_success_rate': 0.25
            }
        }
    
    @pytest.fixture
    def mock_empty_sui_result(self):
        """Mock empty Sui scanner result."""
        return {
            'target': '127.0.0.1',
            'protocol': 'sui',
            'results': [],
            'summary': {
                'total_ports_scanned': 0,
                'successful_scans': 0,
                'healthy_nodes': 0,
                'scan_success_rate': 0.0
            }
        }
    
    @pytest.fixture
    def orchestrator(self):
        """Create ScanOrchestrator instance."""
        return ScanOrchestrator()
    
    def test_protocol_results_included_in_output(self, orchestrator, mock_sui_scanner_result):
        """Test that meaningful protocol scanner results are included in output."""
        # Mock the results structure that would come from scan()
        mock_results = {
            "target": "127.0.0.1",
            "hostname": None,
            "scan_level": 1,
            "protocol": "sui",
            "scan_start_time": 1640995200,
            "scan_end_time": 1640995300,
            "scan_results": {
                "generic": {"open_ports": []},
                "web": {"web_results": {}},
                "geo": {"country_name": "US"},
                "sui": mock_sui_scanner_result  # This should be included
            },
            "external_tools": {
                "whatweb": {"duration": 0},
                "ssl_test": {"error": "timeout"}
            }
        }
        
        # Convert to structured format
        structured_results = orchestrator._convert_to_structured_format(mock_results)
        
        # Verify basic structure
        assert "data" in structured_results
        assert "meta" in structured_results
        assert isinstance(structured_results["data"], list)
        
        # Extract data types
        data_types = {item["type"] for item in structured_results["data"]}
        
        # Verify protocol data is included
        assert "protocol" in data_types, f"Protocol section missing. Available types: {data_types}"
        
        # Find protocol section
        protocol_section = next(item for item in structured_results["data"] if item["type"] == "protocol")
        
        # Verify Sui results are in protocol section
        assert "sui" in protocol_section["payload"]
        assert protocol_section["payload"]["sui"] == mock_sui_scanner_result
        
        # Verify meta information
        meta = structured_results["meta"]
        assert meta["target"] == "127.0.0.1"
        assert meta["protocol"] == "sui"
        assert "sui" in meta["scanners_used"]
        assert "scan_start" in meta
        assert "scan_end" in meta
        assert "timestamp" not in meta  # Removed redundant timestamp
        assert "timestamp_unix" not in meta  # Removed redundant timestamp_unix
    
    def test_empty_protocol_results_excluded(self, orchestrator, mock_empty_sui_result):
        """Test that empty protocol scanner results are excluded from output."""
        mock_results = {
            "target": "127.0.0.1",
            "scan_level": 1,
            "protocol": "sui",
            "scan_start_time": 1640995200,
            "scan_end_time": 1640995300,
            "scan_results": {
                "generic": {"open_ports": []},
                "sui": mock_empty_sui_result  # This should be excluded (empty summary)
            },
            "external_tools": {}
        }
        
        structured_results = orchestrator._convert_to_structured_format(mock_results)
        
        # Extract data types
        data_types = {item["type"] for item in structured_results["data"]}
        
        # Verify protocol section is NOT included (because results are empty)
        assert "protocol" not in data_types, "Empty protocol results should be excluded"
    
    def test_multiple_protocol_scanners(self, orchestrator, mock_sui_scanner_result):
        """Test that multiple protocol scanners can be included simultaneously."""
        mock_filecoin_result = {
            'target': '127.0.0.1',
            'protocol': 'filecoin',
            'scan_type': 'filecoin_specific',
            'lotus_api_exposed': True,
            'summary': {
                'apis_found': 1,
                'total_checks': 5
            }
        }
        
        mock_results = {
            "target": "127.0.0.1",
            "scan_level": 2,
            "protocol": None,  # Multiple protocols, not specific to one
            "scan_start_time": 1640995200,
            "scan_end_time": 1640995300,
            "scan_results": {
                "generic": {"open_ports": [9000, 1234]},
                "sui": mock_sui_scanner_result,
                "filecoin": mock_filecoin_result
            },
            "external_tools": {}
        }
        
        structured_results = orchestrator._convert_to_structured_format(mock_results)
        
        # Find protocol section
        protocol_section = next(item for item in structured_results["data"] if item["type"] == "protocol")
        
        # Verify both protocol results are included
        assert "sui" in protocol_section["payload"]
        assert "filecoin" in protocol_section["payload"]
        assert protocol_section["payload"]["sui"] == mock_sui_scanner_result
        assert protocol_section["payload"]["filecoin"] == mock_filecoin_result
    
    def test_has_meaningful_results_protocol_format(self, orchestrator):
        """Test that _has_meaningful_results correctly identifies protocol scanner formats."""
        # Test meaningful protocol result
        meaningful_result = {
            'protocol': 'sui',
            'results': [{'port': 9000, 'healthy': False}],
            'summary': {
                'successful_scans': 1,
                'total_ports_scanned': 4
            }
        }
        assert orchestrator._has_meaningful_results(meaningful_result) is True
        
        # Test empty protocol result
        empty_result = {
            'protocol': 'sui',
            'results': [],
            'summary': {
                'successful_scans': 0,
                'total_ports_scanned': 0,
                'healthy_nodes': 0
            }
        }
        assert orchestrator._has_meaningful_results(empty_result) is False
        
        # Test legacy non-protocol result (should still work)
        legacy_result = {
            'open_ports': [80, 443],
            'banners': {'80': 'Apache'}
        }
        assert orchestrator._has_meaningful_results(legacy_result) is True
    
    def test_timestamp_fields_removed(self, orchestrator, mock_sui_scanner_result):
        """Test that redundant timestamp fields are removed from meta."""
        mock_results = {
            "target": "127.0.0.1",
            "scan_level": 1,
            "protocol": "sui",
            "scan_start_time": 1640995200,
            "scan_end_time": 1640995300,
            "scan_results": {"sui": mock_sui_scanner_result},
            "external_tools": {}
        }
        
        structured_results = orchestrator._convert_to_structured_format(mock_results)
        meta = structured_results["meta"]
        
        # Verify redundant fields are removed
        assert "timestamp" not in meta
        assert "timestamp_unix" not in meta
        
        # Verify renamed fields exist
        assert "scan_start" in meta
        assert "scan_end" in meta
        assert meta["scan_start"] == 1640995200
        assert meta["scan_end"] == 1640995300
    
    def test_simple_protocol_inclusion_verification(self, orchestrator, mock_sui_scanner_result):
        """Simple test to verify protocol scanner results are properly included."""
        # This is a simpler integration test that focuses on the specific functionality
        # we want to verify without complex mocking
        
        # Test that when we have meaningful protocol results, they get included
        mock_results = {
            "target": "127.0.0.1",
            "scan_level": 1,
            "protocol": "sui",
            "scan_start_time": 1640995200,
            "scan_end_time": 1640995300,
            "scan_results": {
                "generic": {"open_ports": []},
                "sui": mock_sui_scanner_result
            },
            "external_tools": {}
        }
        
        structured_results = orchestrator._convert_to_structured_format(mock_results)
        
        # Verify the protocol section exists and contains our Sui results
        protocol_sections = [item for item in structured_results["data"] if item["type"] == "protocol"]
        assert len(protocol_sections) == 1
        
        protocol_section = protocol_sections[0]
        assert "sui" in protocol_section["payload"]
        assert protocol_section["payload"]["sui"] == mock_sui_scanner_result
        
        # Verify meta information is correct
        meta = structured_results["meta"]
        assert meta["protocol"] == "sui"
        assert "sui" in meta["scanners_used"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])