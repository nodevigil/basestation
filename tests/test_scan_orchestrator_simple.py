"""
Simplified pytest test suite for ScanOrchestrator.

Tests core functionality without assuming implementation details.
"""

import pytest
from unittest.mock import Mock, patch

from pgdn.scanning.scan_orchestrator import ScanOrchestrator


class TestScanOrchestratorBasic:
    """Test basic ScanOrchestrator functionality."""
    
    def test_init_with_defaults(self):
        """Test initialization with default configuration."""
        orchestrator = ScanOrchestrator()
        
        assert orchestrator.config == {}
        assert orchestrator.enabled_scanners == ['generic', 'web', 'vulnerability']
        assert orchestrator.use_external_tools is True
        assert 'nmap' in orchestrator.enabled_external_tools
        assert 'whatweb' in orchestrator.enabled_external_tools
    
    def test_init_with_custom_config(self):
        """Test initialization with custom configuration."""
        config = {
            'orchestrator': {
                'enabled_scanners': ['generic'],
                'use_external_tools': False,
                'enabled_external_tools': ['nmap']
            }
        }
        orchestrator = ScanOrchestrator(config)
        
        assert orchestrator.enabled_scanners == ['generic']
        assert orchestrator.use_external_tools is False
        assert orchestrator.enabled_external_tools == ['nmap']
    
    @patch('pgdn.scanning.scan_orchestrator.ScannerRegistry')
    def test_scanner_registry_created(self, mock_registry):
        """Test that ScannerRegistry is created during initialization."""
        config = {'test': 'value'}
        ScanOrchestrator(config)
        
        mock_registry.assert_called_once_with(config)
    
    def test_scan_returns_proper_structure(self):
        """Test that scan method returns proper result structure."""
        orchestrator = ScanOrchestrator({'orchestrator': {'enabled_scanners': []}})
        
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry'):
            with patch('pgdn.scanning.geo_scanner.GeoScanner') as mock_geo:
                mock_geo_instance = Mock()
                mock_geo_instance.scan.return_value = {"country": "US"}
                mock_geo.return_value = mock_geo_instance
                
                result = orchestrator.scan("127.0.0.1", scan_level=1)
        
        # Verify basic structure (legacy format)
        assert "ip" in result
        assert "scan_level" in result
        assert result["ip"] == "127.0.0.1"
        assert result["scan_level"] == 1
    
    def test_scan_calls_geo_scanner(self):
        """Test that scan calls GeoScanner for scan_level >= 1."""
        orchestrator = ScanOrchestrator({'orchestrator': {'enabled_scanners': []}})
        
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry'):
            with patch('pgdn.scanning.geo_scanner.GeoScanner') as mock_geo:
                mock_geo_instance = Mock()
                mock_geo_instance.scan.return_value = {"country": "US"}
                mock_geo.return_value = mock_geo_instance
                
                orchestrator.scan("127.0.0.1", scan_level=1)
                
                mock_geo.assert_called_once()
                mock_geo_instance.scan.assert_called_once()
    
    def test_scan_handles_geo_scanner_error(self):
        """Test that scan handles GeoScanner errors gracefully."""
        orchestrator = ScanOrchestrator({'orchestrator': {'enabled_scanners': []}})
        
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry'):
            with patch('pgdn.scanning.geo_scanner.GeoScanner') as mock_geo:
                mock_geo.side_effect = Exception("GeoIP failed")
                
                result = orchestrator.scan("127.0.0.1", scan_level=1)
                
                # Should not crash and should handle error
                assert "ip" in result
                assert result["ip"] == "127.0.0.1"
    
    def test_scan_with_enabled_scanners(self):
        """Test scan with enabled scanners."""
        config = {
            'orchestrator': {
                'enabled_scanners': ['generic', 'web'],
                'use_external_tools': False
            }
        }
        orchestrator = ScanOrchestrator(config)
        
        mock_scanner = Mock()
        mock_scanner.scan.return_value = {"success": True}
        
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry') as mock_registry:
            orchestrator.scanner_registry = mock_registry.return_value
            orchestrator.scanner_registry.get_scanner.return_value = mock_scanner
            
            with patch('pgdn.scanning.geo_scanner.GeoScanner'):
                result = orchestrator.scan("127.0.0.1", scan_level=1)
            
            # Should call get_scanner for each enabled scanner
            assert orchestrator.scanner_registry.get_scanner.call_count == 2
            assert mock_scanner.scan.call_count == 2
    
    def test_scan_with_no_external_tools(self):
        """Test scan with external tools disabled."""
        config = {
            'orchestrator': {
                'enabled_scanners': [],
                'use_external_tools': False
            }
        }
        orchestrator = ScanOrchestrator(config)
        
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry'):
            with patch('pgdn.scanning.geo_scanner.GeoScanner'):
                result = orchestrator.scan("127.0.0.1", scan_level=1)
        
        # Should not include external_tools in result when disabled
        assert "external_tools" not in result or not result.get("external_tools")
    
    def test_scan_level_parameter_passed(self):
        """Test that scan_level parameter is passed to scanners."""
        config = {
            'orchestrator': {
                'enabled_scanners': ['generic'],
                'use_external_tools': False
            }
        }
        orchestrator = ScanOrchestrator(config)
        
        mock_scanner = Mock()
        mock_scanner.scan.return_value = {"success": True}
        
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry') as mock_registry:
            orchestrator.scanner_registry = mock_registry.return_value
            orchestrator.scanner_registry.get_scanner.return_value = mock_scanner
            
            with patch('pgdn.scanning.geo_scanner.GeoScanner'):
                orchestrator.scan("127.0.0.1", scan_level=3)
            
            # Verify scan_level was passed
            call_args = mock_scanner.scan.call_args
            assert call_args[1]['scan_level'] == 3
    
    def test_scan_with_ports_parameter(self):
        """Test that ports parameter is passed to scanners."""
        config = {
            'orchestrator': {
                'enabled_scanners': ['generic'],
                'use_external_tools': False
            }
        }
        orchestrator = ScanOrchestrator(config)
        
        mock_scanner = Mock()
        mock_scanner.scan.return_value = {"success": True}
        
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry') as mock_registry:
            orchestrator.scanner_registry = mock_registry.return_value
            orchestrator.scanner_registry.get_scanner.return_value = mock_scanner
            
            with patch('pgdn.scanning.geo_scanner.GeoScanner'):
                orchestrator.scan("127.0.0.1", ports=[80, 443])
            
            # Verify ports were passed
            call_args = mock_scanner.scan.call_args
            assert call_args[1]['ports'] == [80, 443]
    
    def test_scan_with_additional_kwargs(self):
        """Test that additional kwargs are passed to scanners."""
        config = {
            'orchestrator': {
                'enabled_scanners': ['generic'],
                'use_external_tools': False
            }
        }
        orchestrator = ScanOrchestrator(config)
        
        mock_scanner = Mock()
        mock_scanner.scan.return_value = {"success": True}
        
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry') as mock_registry:
            orchestrator.scanner_registry = mock_registry.return_value
            orchestrator.scanner_registry.get_scanner.return_value = mock_scanner
            
            with patch('pgdn.scanning.geo_scanner.GeoScanner'):
                orchestrator.scan("127.0.0.1", custom_param="test", timeout=30)
            
            # Verify additional kwargs were passed
            call_args = mock_scanner.scan.call_args
            assert call_args[1]['custom_param'] == "test"
            assert call_args[1]['timeout'] == 30


class TestScanOrchestratorExternalTools:
    """Test external tools functionality."""
    
    @patch('pgdn.scanning.scan_orchestrator.nmap_scan')
    def test_nmap_tool_execution(self, mock_nmap):
        """Test nmap external tool execution."""
        config = {
            'orchestrator': {
                'enabled_scanners': [],
                'use_external_tools': True,
                'enabled_external_tools': ['nmap']
            }
        }
        orchestrator = ScanOrchestrator(config)
        
        mock_nmap.return_value = {"ports": [{"port": 80, "state": "open"}]}
        
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry'):
            with patch('pgdn.scanning.geo_scanner.GeoScanner'):
                result = orchestrator.scan("127.0.0.1", scan_level=1)
        
        mock_nmap.assert_called_once_with("127.0.0.1")
        assert "external_tools" in result
    
    @patch('pgdn.scanning.scan_orchestrator.nmap_scan')
    def test_nmap_tool_error_handling(self, mock_nmap):
        """Test nmap error handling."""
        config = {
            'orchestrator': {
                'enabled_scanners': [],
                'use_external_tools': True,
                'enabled_external_tools': ['nmap']
            }
        }
        orchestrator = ScanOrchestrator(config)
        
        mock_nmap.side_effect = Exception("Nmap failed")
        
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry'):
            with patch('pgdn.scanning.geo_scanner.GeoScanner'):
                result = orchestrator.scan("127.0.0.1", scan_level=1)
        
        # Should handle error gracefully
        assert "external_tools" in result
        assert "nmap" in result["external_tools"]
        assert "error" in result["external_tools"]["nmap"]


class TestScanOrchestratorErrorHandling:
    """Test error handling scenarios."""
    
    def test_scanner_not_available(self):
        """Test behavior when scanner is not available."""
        config = {
            'orchestrator': {
                'enabled_scanners': ['nonexistent_scanner'],
                'use_external_tools': False
            }
        }
        orchestrator = ScanOrchestrator(config)
        
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry') as mock_registry:
            orchestrator.scanner_registry = mock_registry.return_value
            orchestrator.scanner_registry.get_scanner.return_value = None
            
            with patch('pgdn.scanning.geo_scanner.GeoScanner'):
                result = orchestrator.scan("127.0.0.1", scan_level=1)
        
        # Should complete without error
        assert "ip" in result
        assert result["ip"] == "127.0.0.1"
    
    def test_scanner_exception(self):
        """Test handling of scanner exceptions."""
        config = {
            'orchestrator': {
                'enabled_scanners': ['generic'],
                'use_external_tools': False
            }
        }
        orchestrator = ScanOrchestrator(config)
        
        mock_scanner = Mock()
        mock_scanner.scan.side_effect = Exception("Scanner crashed")
        
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry') as mock_registry:
            orchestrator.scanner_registry = mock_registry.return_value
            orchestrator.scanner_registry.get_scanner.return_value = mock_scanner
            
            with patch('pgdn.scanning.geo_scanner.GeoScanner'):
                result = orchestrator.scan("127.0.0.1", scan_level=1)
        
        # Should handle scanner exception gracefully
        assert "ip" in result
        assert result["ip"] == "127.0.0.1"


class TestScanOrchestratorConfigVariations:
    """Test various configuration scenarios."""
    
    def test_empty_scanners_list(self):
        """Test with empty scanners list."""
        config = {
            'orchestrator': {
                'enabled_scanners': [],
                'use_external_tools': False
            }
        }
        orchestrator = ScanOrchestrator(config)
        
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry'):
            with patch('pgdn.scanning.geo_scanner.GeoScanner'):
                result = orchestrator.scan("127.0.0.1", scan_level=1)
        
        assert "ip" in result
        assert result["ip"] == "127.0.0.1"
    
    def test_minimal_config(self):
        """Test with minimal configuration."""
        config = {'orchestrator': {}}
        orchestrator = ScanOrchestrator(config)
        
        # Should use default values
        assert orchestrator.enabled_scanners == ['generic', 'web', 'vulnerability']
        assert orchestrator.use_external_tools is True
    
    def test_no_orchestrator_section(self):
        """Test configuration without orchestrator section."""
        config = {'other_section': {'value': 'test'}}
        orchestrator = ScanOrchestrator(config)
        
        # Should use default values
        assert orchestrator.enabled_scanners == ['generic', 'web', 'vulnerability']
        assert orchestrator.use_external_tools is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])