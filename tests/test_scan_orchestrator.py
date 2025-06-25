"""
Comprehensive pytest test suite for ScanOrchestrator.

Tests configuration handling, scan levels, external tools, error scenarios,
and legacy format conversion.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

from pgdn.scanning.scan_orchestrator import ScanOrchestrator


class TestScanOrchestratorInit:
    """Test ScanOrchestrator initialization and configuration."""
    
    def test_init_with_none_config(self):
        """Test initialization with None config."""
        orchestrator = ScanOrchestrator(None)
        
        assert orchestrator.config == {}
        assert orchestrator.enabled_scanners == ['generic', 'web', 'vulnerability']
        assert orchestrator.use_external_tools is True
        assert orchestrator.enabled_external_tools == ['nmap', 'whatweb', 'ssl_test', 'docker_exposure']
    
    def test_init_with_empty_config(self):
        """Test initialization with empty config."""
        orchestrator = ScanOrchestrator({})
        
        assert orchestrator.config == {}
        assert orchestrator.enabled_scanners == ['generic', 'web', 'vulnerability']
        assert orchestrator.use_external_tools is True
        assert orchestrator.enabled_external_tools == ['nmap', 'whatweb', 'ssl_test', 'docker_exposure']
    
    def test_init_with_orchestrator_config(self):
        """Test initialization with orchestrator configuration."""
        config = {
            'orchestrator': {
                'enabled_scanners': ['generic', 'web'],
                'use_external_tools': False,
                'enabled_external_tools': ['nmap']
            }
        }
        orchestrator = ScanOrchestrator(config)
        
        assert orchestrator.config == config
        assert orchestrator.enabled_scanners == ['generic', 'web']
        assert orchestrator.use_external_tools is False
        assert orchestrator.enabled_external_tools == ['nmap']
    
    def test_init_with_partial_orchestrator_config(self):
        """Test initialization with partial orchestrator configuration."""
        config = {
            'orchestrator': {
                'enabled_scanners': ['vulnerability']
            }
        }
        orchestrator = ScanOrchestrator(config)
        
        assert orchestrator.enabled_scanners == ['vulnerability']
        assert orchestrator.use_external_tools is True  # Default value
        assert orchestrator.enabled_external_tools == ['nmap', 'whatweb', 'ssl_test', 'docker_exposure']
    
    @patch('pgdn.scanning.scan_orchestrator.ScannerRegistry')
    def test_scanner_registry_initialization(self, mock_registry):
        """Test that ScannerRegistry is properly initialized."""
        config = {'scanners': {'generic': {'enabled': True}}}
        ScanOrchestrator(config)
        
        mock_registry.assert_called_once_with(config)


class TestScanOrchestratorScanMethod:
    """Test the main scan method functionality."""
    
    @pytest.fixture
    def mock_orchestrator(self):
        """Create a ScanOrchestrator with mocked dependencies."""
        config = {
            'orchestrator': {
                'enabled_scanners': ['generic', 'web'],
                'use_external_tools': False
            }
        }
        
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry') as mock_registry:
            orchestrator = ScanOrchestrator(config)
            orchestrator.scanner_registry = mock_registry.return_value
            yield orchestrator
    
    def test_scan_basic_functionality(self, mock_orchestrator):
        """Test basic scan functionality."""
        # Mock scanner
        mock_scanner = Mock()
        mock_scanner.scan.return_value = {"ports": [80, 443], "success": True}
        mock_orchestrator.scanner_registry.get_scanner.return_value = mock_scanner
        
        with patch('pgdn.scanning.geo_scanner.GeoScanner') as mock_geo:
            mock_geo_instance = Mock()
            mock_geo_instance.scan.return_value = {"country": "US", "city": "New York"}
            mock_geo.return_value = mock_geo_instance
            
            result = mock_orchestrator.scan("192.168.1.1", scan_level=1)
        
        # Verify target and scan_level are set
        assert result["target"] == "192.168.1.1"
        assert result["scan_level"] == 1
        
        # Verify scanners were called
        assert mock_orchestrator.scanner_registry.get_scanner.call_count == 2
        mock_scanner.scan.assert_called()
    
    def test_scan_with_scan_levels(self, mock_orchestrator):
        """Test that scan_level parameter is passed to scanners."""
        mock_scanner = Mock()
        mock_scanner.scan.return_value = {"success": True}
        mock_orchestrator.scanner_registry.get_scanner.return_value = mock_scanner
        
        with patch('pgdn.scanning.geo_scanner.GeoScanner'):
            mock_orchestrator.scan("192.168.1.1", scan_level=3)
        
        # Verify scan_level was passed to scanner
        call_args = mock_scanner.scan.call_args
        assert call_args[1]['scan_level'] == 3
    
    def test_scan_with_ports_parameter(self, mock_orchestrator):
        """Test that ports parameter is passed to scanners."""
        mock_scanner = Mock()
        mock_scanner.scan.return_value = {"success": True}
        mock_orchestrator.scanner_registry.get_scanner.return_value = mock_scanner
        
        with patch('pgdn.scanning.geo_scanner.GeoScanner'):
            mock_orchestrator.scan("192.168.1.1", ports=[80, 443])
        
        # Verify ports were passed to scanner
        call_args = mock_scanner.scan.call_args
        assert call_args[1]['ports'] == [80, 443]
    
    def test_scan_geo_scanner_level_1_and_above(self, mock_orchestrator):
        """Test that GeoScanner runs for scan level 1 and above."""
        mock_scanner = Mock()
        mock_scanner.scan.return_value = {"success": True}
        mock_orchestrator.scanner_registry.get_scanner.return_value = mock_scanner
        
        with patch('pgdn.scanning.geo_scanner.GeoScanner') as mock_geo:
            mock_geo_instance = Mock()
            mock_geo_instance.scan.return_value = {"country": "US"}
            mock_geo.return_value = mock_geo_instance
            
            # Test level 1
            result = mock_orchestrator.scan("192.168.1.1", scan_level=1)
            assert "geo" in result["scan_results"]
            
            # Test level 2
            result = mock_orchestrator.scan("192.168.1.1", scan_level=2)
            assert "geo" in result["scan_results"]
            
            # Test level 3
            result = mock_orchestrator.scan("192.168.1.1", scan_level=3)
            assert "geo" in result["scan_results"]
    
    def test_scan_geo_scanner_error_handling(self, mock_orchestrator):
        """Test error handling in GeoScanner."""
        mock_scanner = Mock()
        mock_scanner.scan.return_value = {"success": True}
        mock_orchestrator.scanner_registry.get_scanner.return_value = mock_scanner
        
        with patch('pgdn.scanning.geo_scanner.GeoScanner') as mock_geo:
            mock_geo.side_effect = Exception("GeoIP API unavailable")
            
            result = mock_orchestrator.scan("192.168.1.1", scan_level=1)
            
            # Should handle error gracefully
            assert "geo" in result["scan_results"]
            assert "error" in result["scan_results"]["geo"]
            assert "GeoIP API unavailable" in result["scan_results"]["geo"]["error"]
    
    def test_scan_scanner_not_available(self, mock_orchestrator):
        """Test handling when scanner is not available."""
        mock_orchestrator.scanner_registry.get_scanner.return_value = None
        
        with patch('pgdn.scanning.geo_scanner.GeoScanner'):
            result = mock_orchestrator.scan("192.168.1.1")
        
        # Should handle missing scanners gracefully
        assert result["target"] == "192.168.1.1"
    
    def test_scan_scanner_exception_handling(self, mock_orchestrator):
        """Test handling of scanner exceptions."""
        mock_scanner = Mock()
        mock_scanner.scan.side_effect = Exception("Scanner failed")
        mock_orchestrator.scanner_registry.get_scanner.return_value = mock_scanner
        
        with patch('pgdn.scanning.geo_scanner.GeoScanner'):
            result = mock_orchestrator.scan("192.168.1.1")
        
        # Should handle scanner exceptions gracefully
        for scanner_type in mock_orchestrator.enabled_scanners:
            assert "error" in result["scan_results"][scanner_type]
            assert "Scanner failed" in result["scan_results"][scanner_type]["error"]
    
    def test_scan_with_external_tools_disabled(self, mock_orchestrator):
        """Test scan with external tools disabled."""
        mock_orchestrator.use_external_tools = False
        mock_scanner = Mock()
        mock_scanner.scan.return_value = {"success": True}
        mock_orchestrator.scanner_registry.get_scanner.return_value = mock_scanner
        
        with patch('pgdn.scanning.geo_scanner.GeoScanner'):
            result = mock_orchestrator.scan("192.168.1.1")
        
        assert "external_tools" not in result
    
    def test_scan_timestamp_handling(self, mock_orchestrator):
        """Test that scan timestamp is properly handled."""
        mock_scanner = Mock()
        mock_scanner.scan.return_value = {"success": True}
        mock_orchestrator.scanner_registry.get_scanner.return_value = mock_scanner
        
        with patch('pgdn.scanning.geo_scanner.GeoScanner'):
            result = mock_orchestrator.scan("192.168.1.1", scan_timestamp="2023-01-01T00:00:00Z")
        
        assert result["scan_timestamp"] == "2023-01-01T00:00:00Z"


class TestScanOrchestratorExternalTools:
    """Test external tools functionality."""
    
    @pytest.fixture
    def orchestrator_with_external_tools(self):
        """Create orchestrator with external tools enabled."""
        config = {
            'orchestrator': {
                'enabled_scanners': ['generic'],
                'use_external_tools': True,
                'enabled_external_tools': ['nmap', 'whatweb', 'ssl_test', 'docker_exposure']
            }
        }
        
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry'):
            yield ScanOrchestrator(config)
    
    @patch('pgdn.scanning.scan_orchestrator.nmap_scan')
    def test_run_external_tools_nmap(self, mock_nmap, orchestrator_with_external_tools):
        """Test nmap external tool execution."""
        mock_nmap.return_value = {"open_ports": [80, 443]}
        scan_results = {"scan_results": {"generic": {"ports": [80]}}}
        
        result = orchestrator_with_external_tools._run_external_tools("192.168.1.1", scan_results)
        
        assert "nmap" in result
        assert result["nmap"]["open_ports"] == [80, 443]
        mock_nmap.assert_called_once_with("192.168.1.1")
    
    @patch('pgdn.scanning.scan_orchestrator.nmap_scan')
    def test_run_external_tools_nmap_error(self, mock_nmap, orchestrator_with_external_tools):
        """Test nmap error handling."""
        mock_nmap.side_effect = Exception("Nmap failed")
        scan_results = {"scan_results": {"generic": {"ports": [80]}}}
        
        result = orchestrator_with_external_tools._run_external_tools("192.168.1.1", scan_results)
        
        assert "nmap" in result
        assert "error" in result["nmap"]
        assert "Nmap failed" in result["nmap"]["error"]
    
    @patch('pgdn.scanning.scan_orchestrator.whatweb_scan')
    def test_run_external_tools_whatweb(self, mock_whatweb, orchestrator_with_external_tools):
        """Test whatweb external tool execution."""
        mock_whatweb.return_value = {"technologies": ["Apache", "PHP"]}
        
        # Mock _extract_web_ports to return web ports
        orchestrator_with_external_tools._extract_web_ports = Mock(return_value=[(80, "http"), (443, "https")])
        
        scan_results = {"scan_results": {"web": {"http_status": 200}}}
        result = orchestrator_with_external_tools._run_external_tools("192.168.1.1", scan_results)
        
        assert "whatweb" in result
        assert "http://192.168.1.1:80" in result["whatweb"]
        assert "https://192.168.1.1:443" in result["whatweb"]
    
    @patch('pgdn.scanning.scan_orchestrator.ssl_test')
    def test_run_external_tools_ssl_test(self, mock_ssl_test, orchestrator_with_external_tools):
        """Test SSL test external tool execution."""
        mock_ssl_test.return_value = {"ssl_version": "TLSv1.3", "valid": True}
        
        scan_results = {"scan_results": {"generic": {"ssl_ports": [443]}}}
        result = orchestrator_with_external_tools._run_external_tools("192.168.1.1", scan_results)
        
        assert "ssl_test" in result
    
    @patch('pgdn.scanning.scan_orchestrator.DockerExposureChecker')
    def test_run_external_tools_docker_exposure(self, mock_docker, orchestrator_with_external_tools):
        """Test Docker exposure checker."""
        mock_checker_instance = Mock()
        mock_checker_instance.check_exposure.return_value = {"docker_exposed": False}
        mock_docker.return_value = mock_checker_instance
        
        scan_results = {"scan_results": {"generic": {"ports": [2376]}}}
        result = orchestrator_with_external_tools._run_external_tools("192.168.1.1", scan_results)
        
        assert "docker_exposure" in result
        mock_checker_instance.check_exposure.assert_called_once_with("192.168.1.1")


class TestScanOrchestratorHelperMethods:
    """Test helper methods in ScanOrchestrator."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create basic orchestrator for testing."""
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry'):
            yield ScanOrchestrator({})
    
    def test_extract_web_ports_from_generic_scanner(self, orchestrator):
        """Test extracting web ports from generic scanner results."""
        scan_results = {
            "scan_results": {
                "generic": {
                    "open_ports": [22, 80, 443, 8080],
                    "port_info": {
                        "80": {"service": "http"},
                        "443": {"service": "https"},
                        "8080": {"service": "http-proxy"}
                    }
                }
            }
        }
        
        web_ports = orchestrator._extract_web_ports(scan_results)
        
        # Should detect common web ports
        expected_ports = {(80, "http"), (443, "https"), (8080, "http")}
        assert set(web_ports) == expected_ports
    
    def test_extract_web_ports_from_nmap(self, orchestrator):
        """Test extracting web ports from nmap results."""
        scan_results = {"scan_results": {}}
        nmap_results = {
            "ports": [
                {"port": 80, "state": "open", "service": "http"},
                {"port": 443, "state": "open", "service": "https"},
                {"port": 22, "state": "open", "service": "ssh"}
            ]
        }
        
        web_ports = orchestrator._extract_web_ports(scan_results, nmap_results)
        
        expected_ports = {(80, "http"), (443, "https")}
        assert set(web_ports) == expected_ports
    
    def test_extract_open_ports(self, orchestrator):
        """Test extracting open ports from scan results."""
        scan_results = {
            "scan_results": {
                "generic": {
                    "open_ports": [22, 80, 443, 993, 995]
                }
            }
        }
        
        open_ports = orchestrator._extract_open_ports(scan_results)
        
        expected_ports = [22, 80, 443, 993, 995]
        assert open_ports == expected_ports
    
    def test_convert_to_legacy_format(self, orchestrator):
        """Test conversion to legacy format."""
        modern_results = {
            "target": "192.168.1.1",
            "scan_level": 2,
            "scan_timestamp": "2023-01-01T00:00:00Z",
            "scan_results": {
                "generic": {"open_ports": [80, 443]},
                "web": {"http_status": 200},
                "geo": {"country": "US"}
            },
            "external_tools": {
                "nmap": {"scan_time": 5.2}
            }
        }
        
        legacy_results = orchestrator._convert_to_legacy_format(modern_results)
        
        # Should maintain key information in legacy format
        assert legacy_results["target"] == "192.168.1.1"
        assert legacy_results["scan_level"] == 2
        assert "generic_scan" in legacy_results
        assert "web_scan" in legacy_results
        assert "geo_scan" in legacy_results


class TestScanOrchestratorEdgeCases:
    """Test edge cases and error scenarios."""
    
    def test_scan_with_invalid_target(self):
        """Test scan with invalid target format."""
        orchestrator = ScanOrchestrator({})
        
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry'):
            # Should handle invalid targets gracefully
            result = orchestrator.scan("")
            assert result["target"] == ""
    
    def test_scan_with_invalid_scan_level(self):
        """Test scan with invalid scan level."""
        orchestrator = ScanOrchestrator({})
        
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry'):
            with patch('pgdn.scanning.geo_scanner.GeoScanner'):
                # Should handle invalid scan levels
                result = orchestrator.scan("192.168.1.1", scan_level=0)
                assert result["scan_level"] == 0
    
    def test_scan_with_very_large_scan_level(self):
        """Test scan with very large scan level."""
        orchestrator = ScanOrchestrator({})
        
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry'):
            with patch('pgdn.scanning.geo_scanner.GeoScanner'):
                result = orchestrator.scan("192.168.1.1", scan_level=999)
                assert result["scan_level"] == 999
    
    def test_config_with_invalid_scanner_types(self):
        """Test configuration with invalid scanner types."""
        config = {
            'orchestrator': {
                'enabled_scanners': ['invalid_scanner', 'generic'],
                'use_external_tools': True,
                'enabled_external_tools': ['invalid_tool', 'nmap']
            }
        }
        
        # Should initialize without error
        orchestrator = ScanOrchestrator(config)
        assert 'invalid_scanner' in orchestrator.enabled_scanners
        assert 'invalid_tool' in orchestrator.enabled_external_tools


if __name__ == "__main__":
    pytest.main([__file__, "-v"])