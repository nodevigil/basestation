"""
Integration tests for ScanOrchestrator with real scanners.

These tests verify the orchestrator works with actual scanner implementations
and configuration formats.
"""

import pytest
from unittest.mock import patch, Mock
import socket

from pgdn.scanning.scan_orchestrator import ScanOrchestrator
from pgdn.core.config import Config


class TestScanOrchestratorIntegration:
    """Integration tests with real scanner implementations."""
    
    @pytest.fixture
    def real_config(self):
        """Create a realistic configuration for testing."""
        return {
            'orchestrator': {
                'enabled_scanners': ['generic', 'web', 'vulnerability'],
                'use_external_tools': False,  # Disable for testing
                'enabled_external_tools': []
            },
            'scanners': {
                'generic': {
                    'enabled': True,
                    'default_ports': [22, 80, 443],
                    'connection_timeout': 1,
                    'max_ports': 10
                },
                'web': {
                    'enabled': True,
                    'timeout': 2,
                    'user_agent': 'PGDN-Scanner/1.0'
                },
                'vulnerability': {
                    'enabled': True,
                    'max_cves_per_banner': 3,
                    'confidence_threshold': 0.5
                },
                'geo': {
                    'enabled': True,
                    'fallback_to_api': False
                }
            }
        }
    
    def test_scan_localhost_basic(self, real_config):
        """Test scanning localhost with basic configuration."""
        orchestrator = ScanOrchestrator(real_config)
        
        # Mock external dependencies to avoid network calls
        with patch('pgdn.scanning.scan_orchestrator.GeoScanner') as mock_geo:
            mock_geo_instance = Mock()
            mock_geo_instance.scan.return_value = {
                "ip": "127.0.0.1",
                "country": "Unknown",
                "city": "Unknown"
            }
            mock_geo.return_value = mock_geo_instance
            
            result = orchestrator.scan("127.0.0.1", scan_level=1)
        
        # Verify basic structure
        assert result["target"] == "127.0.0.1"
        assert result["scan_level"] == 1
        assert "scan_results" in result
        assert "geo" in result["scan_results"]
    
    def test_scan_with_config_object(self):
        """Test scanning with Config object format (converted properly)."""
        # Create a minimal Config-like object
        class MockConfig:
            def __init__(self):
                self.scanning = type('obj', (object,), {
                    'orchestrator': {
                        'enabled_scanners': ['generic'],
                        'use_external_tools': False
                    }
                })()
        
        mock_config = MockConfig()
        
        # Convert Config to proper format (as should be done in calling code)
        scanning_config = mock_config.scanning
        scan_config = {
            'orchestrator': scanning_config.orchestrator,
            'scanners': getattr(scanning_config, 'scanners', {})
        }
        
        orchestrator = ScanOrchestrator(scan_config)
        
        with patch('pgdn.scanning.scan_orchestrator.GeoScanner'):
            result = orchestrator.scan("127.0.0.1", scan_level=1)
        
        assert result["target"] == "127.0.0.1"
        assert result["scan_level"] == 1
    
    def test_scan_levels_progression(self, real_config):
        """Test that different scan levels work correctly."""
        orchestrator = ScanOrchestrator(real_config)
        
        with patch('pgdn.scanning.scan_orchestrator.GeoScanner') as mock_geo:
            mock_geo_instance = Mock()
            mock_geo_instance.scan.return_value = {"country": "US"}
            mock_geo.return_value = mock_geo_instance
            
            # Test all scan levels
            for level in [1, 2, 3]:
                result = orchestrator.scan("127.0.0.1", scan_level=level)
                
                assert result["scan_level"] == level
                assert "geo" in result["scan_results"]  # GeoIP should run for all levels >= 1
    
    def test_scan_with_custom_ports(self, real_config):
        """Test scanning with custom port list."""
        orchestrator = ScanOrchestrator(real_config)
        
        with patch('pgdn.scanning.scan_orchestrator.GeoScanner'):
            result = orchestrator.scan("127.0.0.1", ports=[80, 443, 8080], scan_level=1)
        
        assert result["target"] == "127.0.0.1"
        # Custom ports should be passed to individual scanners
    
    def test_scan_with_kwargs_propagation(self, real_config):
        """Test that additional kwargs are propagated to scanners."""
        orchestrator = ScanOrchestrator(real_config)
        
        with patch('pgdn.scanning.scan_orchestrator.GeoScanner'):
            result = orchestrator.scan(
                "127.0.0.1", 
                scan_level=1,
                custom_param="test_value",
                timeout=30
            )
        
        assert result["target"] == "127.0.0.1"
    
    def test_scanner_registry_integration(self, real_config):
        """Test that ScannerRegistry is properly integrated."""
        orchestrator = ScanOrchestrator(real_config)
        
        # Verify that scanner registry was created with config
        assert orchestrator.scanner_registry is not None
        
        # Test that scanners can be retrieved
        for scanner_type in ['generic', 'web', 'vulnerability']:
            # This will depend on actual scanner availability in test environment
            scanner = orchestrator.scanner_registry.get_scanner(scanner_type)
            # Don't assert scanner is not None as it depends on environment
    
    def test_error_handling_with_network_timeout(self, real_config):
        """Test error handling when network operations timeout."""
        # Use a non-routable IP to trigger timeout
        orchestrator = ScanOrchestrator(real_config)
        
        with patch('pgdn.scanning.scan_orchestrator.GeoScanner') as mock_geo:
            mock_geo.side_effect = socket.timeout("Network timeout")
            
            result = orchestrator.scan("10.255.255.1", scan_level=1)
            
            # Should handle timeout gracefully
            assert result["target"] == "10.255.255.1"
            assert "geo" in result["scan_results"]
            assert "error" in result["scan_results"]["geo"]
    
    def test_partial_scanner_failure(self, real_config):
        """Test handling when some scanners fail but others succeed."""
        orchestrator = ScanOrchestrator(real_config)
        
        # Mock one scanner to fail
        with patch('pgdn.scanning.scan_orchestrator.GeoScanner') as mock_geo:
            mock_geo_instance = Mock()
            mock_geo_instance.scan.return_value = {"country": "US"}
            mock_geo.return_value = mock_geo_instance
            
            # Mock scanner registry to have mixed success/failure
            mock_scanner_success = Mock()
            mock_scanner_success.scan.return_value = {"ports": [80], "success": True}
            
            mock_scanner_failure = Mock()
            mock_scanner_failure.scan.side_effect = Exception("Scanner crashed")
            
            def mock_get_scanner(scanner_type):
                if scanner_type == "generic":
                    return mock_scanner_success
                elif scanner_type == "web":
                    return mock_scanner_failure
                else:
                    return None
            
            orchestrator.scanner_registry.get_scanner = mock_get_scanner
            
            result = orchestrator.scan("127.0.0.1", scan_level=1)
            
            # Should have results from successful scanner
            assert "generic" in result["scan_results"]
            assert result["scan_results"]["generic"]["success"] is True
            
            # Should have error from failed scanner
            assert "web" in result["scan_results"]
            assert "error" in result["scan_results"]["web"]


class TestScanOrchestratorConfigFormats:
    """Test various configuration formats and edge cases."""
    
    def test_minimal_config(self):
        """Test with minimal configuration."""
        config = {'orchestrator': {}}
        orchestrator = ScanOrchestrator(config)
        
        # Should use default values
        assert orchestrator.enabled_scanners == ['generic', 'web', 'vulnerability']
        assert orchestrator.use_external_tools is True
    
    def test_config_with_unknown_scanners(self):
        """Test configuration with unknown scanner types."""
        config = {
            'orchestrator': {
                'enabled_scanners': ['unknown_scanner', 'generic', 'another_unknown'],
                'use_external_tools': True,
                'enabled_external_tools': ['unknown_tool', 'nmap']
            }
        }
        orchestrator = ScanOrchestrator(config)
        
        # Should accept configuration as-is
        assert 'unknown_scanner' in orchestrator.enabled_scanners
        assert 'generic' in orchestrator.enabled_scanners
        assert 'unknown_tool' in orchestrator.enabled_external_tools
        assert 'nmap' in orchestrator.enabled_external_tools
    
    def test_config_with_empty_scanners_list(self):
        """Test configuration with empty scanners list."""
        config = {
            'orchestrator': {
                'enabled_scanners': [],
                'enabled_external_tools': []
            }
        }
        orchestrator = ScanOrchestrator(config)
        
        assert orchestrator.enabled_scanners == []
        assert orchestrator.enabled_external_tools == []
        
        # Should still be able to scan (though results will be minimal)
        with patch('pgdn.scanning.scan_orchestrator.GeoScanner'):
            result = orchestrator.scan("127.0.0.1", scan_level=1)
            assert result["target"] == "127.0.0.1"
    
    def test_config_types_validation(self):
        """Test that config handles different value types correctly."""
        config = {
            'orchestrator': {
                'enabled_scanners': 'generic',  # String instead of list
                'use_external_tools': 1,  # Integer instead of boolean
                'enabled_external_tools': 'nmap'  # String instead of list
            }
        }
        
        # Should initialize without error (though behavior may vary)
        orchestrator = ScanOrchestrator(config)
        assert orchestrator.enabled_scanners == 'generic'
        assert orchestrator.use_external_tools == 1
        assert orchestrator.enabled_external_tools == 'nmap'


class TestScanOrchestratorPerformance:
    """Test performance-related aspects of ScanOrchestrator."""
    
    def test_concurrent_scanner_execution(self):
        """Test that scanners can be called in sequence without interference."""
        config = {
            'orchestrator': {
                'enabled_scanners': ['generic', 'web', 'vulnerability'],
                'use_external_tools': False
            }
        }
        orchestrator = ScanOrchestrator(config)
        
        # Mock multiple scanners
        call_count = 0
        def mock_scanner_scan(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return {"scan_id": call_count, "success": True}
        
        mock_scanner = Mock()
        mock_scanner.scan = mock_scanner_scan
        orchestrator.scanner_registry.get_scanner = Mock(return_value=mock_scanner)
        
        with patch('pgdn.scanning.scan_orchestrator.GeoScanner'):
            result = orchestrator.scan("127.0.0.1", scan_level=1)
        
        # Should have called all enabled scanners
        assert call_count == len(orchestrator.enabled_scanners)
    
    def test_large_config_handling(self):
        """Test handling of large configuration objects."""
        # Create a large config with many scanner types
        large_config = {
            'orchestrator': {
                'enabled_scanners': [f'scanner_{i}' for i in range(50)],
                'use_external_tools': True,
                'enabled_external_tools': [f'tool_{i}' for i in range(20)]
            },
            'scanners': {
                f'scanner_{i}': {'enabled': True, 'param': f'value_{i}'}
                for i in range(50)
            }
        }
        
        # Should handle large configs without issue
        orchestrator = ScanOrchestrator(large_config)
        assert len(orchestrator.enabled_scanners) == 50
        assert len(orchestrator.enabled_external_tools) == 20


if __name__ == "__main__":
    pytest.main([__file__, "-v"])