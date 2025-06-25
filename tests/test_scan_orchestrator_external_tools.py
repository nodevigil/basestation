"""
Focused tests for ScanOrchestrator external tools functionality.

Tests the integration with nmap, whatweb, SSL testing, and Docker exposure checking.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

from pgdn.scanning.scan_orchestrator import ScanOrchestrator


class TestScanOrchestratorExternalToolsDetailed:
    """Detailed tests for external tools functionality."""
    
    @pytest.fixture
    def orchestrator_with_all_tools(self):
        """Create orchestrator with all external tools enabled."""
        config = {
            'orchestrator': {
                'enabled_scanners': ['generic'],
                'use_external_tools': True,
                'enabled_external_tools': ['nmap', 'whatweb', 'ssl_test', 'docker_exposure']
            }
        }
        
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry'):
            orchestrator = ScanOrchestrator(config)
            yield orchestrator
    
    @pytest.fixture
    def sample_scan_results(self):
        """Sample scan results for testing external tools."""
        return {
            "scan_results": {
                "generic": {
                    "open_ports": [22, 80, 443, 8080, 2376],
                    "port_info": {
                        "22": {"service": "ssh", "banner": "OpenSSH_8.0"},
                        "80": {"service": "http", "banner": "Apache/2.4.41"},
                        "443": {"service": "https", "banner": "nginx/1.18.0"},
                        "8080": {"service": "http-proxy", "banner": "Jetty"},
                        "2376": {"service": "docker", "banner": "Docker"}
                    }
                },
                "web": {
                    "http_status": 200,
                    "https_status": 200,
                    "web_servers": ["Apache", "nginx"]
                }
            }
        }


class TestNmapIntegration:
    """Test nmap tool integration."""
    
    @patch('pgdn.scanning.scan_orchestrator.nmap_scan')
    def test_nmap_successful_scan(self, mock_nmap, orchestrator_with_all_tools, sample_scan_results):
        """Test successful nmap scan execution."""
        mock_nmap.return_value = {
            "ports": {
                "22/tcp": {"state": "open", "service": "ssh", "version": "OpenSSH 8.0"},
                "80/tcp": {"state": "open", "service": "http", "version": "Apache 2.4.41"},
                "443/tcp": {"state": "open", "service": "https", "version": "nginx 1.18.0"}
            },
            "scan_time": 12.5,
            "host_status": "up"
        }
        
        result = orchestrator_with_all_tools._run_external_tools("192.168.1.100", sample_scan_results)
        
        assert "nmap" in result
        assert "ports" in result["nmap"]
        assert "22/tcp" in result["nmap"]["ports"]
        assert result["nmap"]["ports"]["22/tcp"]["service"] == "ssh"
        assert result["nmap"]["scan_time"] == 12.5
        mock_nmap.assert_called_once_with("192.168.1.100")
    
    @patch('pgdn.scanning.scan_orchestrator.nmap_scan')
    def test_nmap_timeout_error(self, mock_nmap, orchestrator_with_all_tools, sample_scan_results):
        """Test nmap timeout handling."""
        mock_nmap.side_effect = TimeoutError("Nmap scan timed out")
        
        result = orchestrator_with_all_tools._run_external_tools("192.168.1.100", sample_scan_results)
        
        assert "nmap" in result
        assert "error" in result["nmap"]
        assert "timed out" in result["nmap"]["error"].lower()
    
    @patch('pgdn.scanning.scan_orchestrator.nmap_scan')
    def test_nmap_permission_error(self, mock_nmap, orchestrator_with_all_tools, sample_scan_results):
        """Test nmap permission error handling."""
        mock_nmap.side_effect = PermissionError("Nmap requires root privileges")
        
        result = orchestrator_with_all_tools._run_external_tools("192.168.1.100", sample_scan_results)
        
        assert "nmap" in result
        assert "error" in result["nmap"]
        assert "permission" in result["nmap"]["error"].lower() or "privileges" in result["nmap"]["error"].lower()
    
    def test_nmap_disabled(self, sample_scan_results):
        """Test behavior when nmap is disabled."""
        config = {
            'orchestrator': {
                'use_external_tools': True,
                'enabled_external_tools': ['whatweb', 'ssl_test']  # nmap not included
            }
        }
        
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry'):
            orchestrator = ScanOrchestrator(config)
            result = orchestrator._run_external_tools("192.168.1.100", sample_scan_results)
        
        assert "nmap" not in result


class TestWhatWebIntegration:
    """Test whatweb tool integration."""
    
    @patch('pgdn.scanning.scan_orchestrator.whatweb_scan')
    def test_whatweb_successful_scan(self, mock_whatweb, orchestrator_with_all_tools, sample_scan_results):
        """Test successful whatweb scan execution."""
        mock_whatweb.return_value = {
            "technologies": ["Apache", "PHP", "jQuery"],
            "title": "Test Website",
            "status_code": 200,
            "headers": {
                "Server": "Apache/2.4.41",
                "X-Powered-By": "PHP/7.4.3"
            }
        }
        
        # Mock web port extraction
        orchestrator_with_all_tools._extract_web_ports = Mock(return_value=[(80, "http"), (443, "https")])
        
        result = orchestrator_with_all_tools._run_external_tools("192.168.1.100", sample_scan_results)
        
        assert "whatweb" in result
        assert "http://192.168.1.100:80" in result["whatweb"]
        assert "https://192.168.1.100:443" in result["whatweb"]
        
        # Check one of the results
        http_result = result["whatweb"]["http://192.168.1.100:80"]
        assert "technologies" in http_result
        assert "Apache" in http_result["technologies"]
        
        # Verify whatweb was called for each web port
        assert mock_whatweb.call_count == 2
    
    @patch('pgdn.scanning.scan_orchestrator.whatweb_scan')
    def test_whatweb_no_web_ports(self, mock_whatweb, orchestrator_with_all_tools):
        """Test whatweb when no web ports are detected."""
        scan_results = {
            "scan_results": {
                "generic": {
                    "open_ports": [22, 25],  # No web ports
                    "port_info": {
                        "22": {"service": "ssh"},
                        "25": {"service": "smtp"}
                    }
                }
            }
        }
        
        # Mock web port extraction to return empty list
        orchestrator_with_all_tools._extract_web_ports = Mock(return_value=[])
        
        result = orchestrator_with_all_tools._run_external_tools("192.168.1.100", scan_results)
        
        # WhatWeb should not be included in results when no web ports
        assert "whatweb" not in result
        mock_whatweb.assert_not_called()
    
    @patch('pgdn.scanning.scan_orchestrator.whatweb_scan')
    def test_whatweb_partial_failure(self, mock_whatweb, orchestrator_with_all_tools, sample_scan_results):
        """Test whatweb when some ports succeed and others fail."""
        def mock_whatweb_side_effect(target, port=None, scheme=None):
            if port == 80:
                return {"technologies": ["Apache"], "status_code": 200}
            elif port == 443:
                raise ConnectionError("HTTPS connection failed")
            else:
                return None
        
        mock_whatweb.side_effect = mock_whatweb_side_effect
        orchestrator_with_all_tools._extract_web_ports = Mock(return_value=[(80, "http"), (443, "https")])
        
        result = orchestrator_with_all_tools._run_external_tools("192.168.1.100", sample_scan_results)
        
        # Should only include successful results
        assert "whatweb" in result
        assert "http://192.168.1.100:80" in result["whatweb"]
        assert "https://192.168.1.100:443" not in result["whatweb"]
    
    @patch('pgdn.scanning.scan_orchestrator.whatweb_scan')
    def test_whatweb_error_result_filtering(self, mock_whatweb, orchestrator_with_all_tools, sample_scan_results):
        """Test that whatweb error results are filtered out."""
        def mock_whatweb_side_effect(target, port=None, scheme=None):
            if port == 80:
                return {"error": "Connection refused"}
            elif port == 443:
                return {"technologies": ["nginx"], "status_code": 200}
            else:
                return None
        
        mock_whatweb.side_effect = mock_whatweb_side_effect
        orchestrator_with_all_tools._extract_web_ports = Mock(return_value=[(80, "http"), (443, "https")])
        
        result = orchestrator_with_all_tools._run_external_tools("192.168.1.100", sample_scan_results)
        
        # Should filter out error results
        assert "whatweb" in result
        assert "http://192.168.1.100:80" not in result["whatweb"]
        assert "https://192.168.1.100:443" in result["whatweb"]


class TestSSLTestIntegration:
    """Test SSL testing tool integration."""
    
    @patch('pgdn.scanning.scan_orchestrator.ssl_test')
    def test_ssl_test_successful(self, mock_ssl_test, orchestrator_with_all_tools, sample_scan_results):
        """Test successful SSL test execution."""
        mock_ssl_test.return_value = {
            "ssl_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "certificate": {
                "subject": "CN=example.com",
                "issuer": "Let's Encrypt",
                "valid_from": "2023-01-01",
                "valid_to": "2023-04-01",
                "is_valid": True
            },
            "vulnerabilities": []
        }
        
        # Mock SSL port extraction
        orchestrator_with_all_tools._extract_ssl_ports = Mock(return_value=[443, 8443])
        
        result = orchestrator_with_all_tools._run_external_tools("192.168.1.100", sample_scan_results)
        
        assert "ssl_test" in result
        assert "ssl_version" in result["ssl_test"]
        assert result["ssl_test"]["ssl_version"] == "TLSv1.3"
        assert result["ssl_test"]["certificate"]["is_valid"] is True
    
    @patch('pgdn.scanning.scan_orchestrator.ssl_test')
    def test_ssl_test_no_ssl_ports(self, mock_ssl_test, orchestrator_with_all_tools):
        """Test SSL test when no SSL ports are detected."""
        scan_results = {
            "scan_results": {
                "generic": {
                    "open_ports": [22, 80],  # No SSL ports
                    "port_info": {
                        "22": {"service": "ssh"},
                        "80": {"service": "http"}
                    }
                }
            }
        }
        
        orchestrator_with_all_tools._extract_ssl_ports = Mock(return_value=[])
        
        result = orchestrator_with_all_tools._run_external_tools("192.168.1.100", scan_results)
        
        # SSL test should not be included when no SSL ports
        assert "ssl_test" not in result
        mock_ssl_test.assert_not_called()
    
    @patch('pgdn.scanning.scan_orchestrator.ssl_test')
    def test_ssl_test_error_handling(self, mock_ssl_test, orchestrator_with_all_tools, sample_scan_results):
        """Test SSL test error handling."""
        mock_ssl_test.side_effect = Exception("SSL handshake failed")
        orchestrator_with_all_tools._extract_ssl_ports = Mock(return_value=[443])
        
        result = orchestrator_with_all_tools._run_external_tools("192.168.1.100", sample_scan_results)
        
        assert "ssl_test" in result
        assert "error" in result["ssl_test"]
        assert "handshake failed" in result["ssl_test"]["error"].lower()


class TestDockerExposureIntegration:
    """Test Docker exposure checking integration."""
    
    @patch('pgdn.scanning.scan_orchestrator.DockerExposureChecker')
    def test_docker_exposure_check_success(self, mock_docker_class, orchestrator_with_all_tools, sample_scan_results):
        """Test successful Docker exposure check."""
        mock_checker = Mock()
        mock_checker.check_exposure.return_value = {
            "docker_exposed": True,
            "api_version": "1.40",
            "containers": ["web_server", "database"],
            "images": ["nginx:latest", "postgres:13"],
            "security_warnings": ["Docker daemon exposed without authentication"]
        }
        mock_docker_class.return_value = mock_checker
        
        result = orchestrator_with_all_tools._run_external_tools("192.168.1.100", sample_scan_results)
        
        assert "docker_exposure" in result
        assert result["docker_exposure"]["docker_exposed"] is True
        assert "security_warnings" in result["docker_exposure"]
        mock_checker.check_exposure.assert_called_once_with("192.168.1.100")
    
    @patch('pgdn.scanning.scan_orchestrator.DockerExposureChecker')
    def test_docker_exposure_not_exposed(self, mock_docker_class, orchestrator_with_all_tools, sample_scan_results):
        """Test Docker exposure check when Docker is not exposed."""
        mock_checker = Mock()
        mock_checker.check_exposure.return_value = {
            "docker_exposed": False,
            "connection_error": "Connection refused on port 2376"
        }
        mock_docker_class.return_value = mock_checker
        
        result = orchestrator_with_all_tools._run_external_tools("192.168.1.100", sample_scan_results)
        
        assert "docker_exposure" in result
        assert result["docker_exposure"]["docker_exposed"] is False
    
    @patch('pgdn.scanning.scan_orchestrator.DockerExposureChecker')
    def test_docker_exposure_error_handling(self, mock_docker_class, orchestrator_with_all_tools, sample_scan_results):
        """Test Docker exposure check error handling."""
        mock_checker = Mock()
        mock_checker.check_exposure.side_effect = Exception("Docker check failed")
        mock_docker_class.return_value = mock_checker
        
        result = orchestrator_with_all_tools._run_external_tools("192.168.1.100", sample_scan_results)
        
        assert "docker_exposure" in result
        assert "error" in result["docker_exposure"]
        assert "Docker check failed" in result["docker_exposure"]["error"]


class TestExternalToolsPortExtraction:
    """Test port extraction methods for external tools."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create basic orchestrator for testing."""
        with patch('pgdn.scanning.scan_orchestrator.ScannerRegistry'):
            yield ScanOrchestrator({})
    
    def test_extract_web_ports_comprehensive(self, orchestrator):
        """Test comprehensive web port extraction."""
        scan_results = {
            "scan_results": {
                "generic": {
                    "open_ports": [22, 80, 443, 8080, 8443, 9000, 3000],
                    "port_info": {
                        "80": {"service": "http"},
                        "443": {"service": "https"},
                        "8080": {"service": "http-proxy"},
                        "8443": {"service": "https-alt"},
                        "9000": {"service": "unknown"},
                        "3000": {"service": "unknown"}
                    }
                }
            }
        }
        
        nmap_results = {
            "ports": {
                "3000/tcp": {"state": "open", "service": "http"},
                "9000/tcp": {"state": "open", "service": "fcgi"}
            }
        }
        
        web_ports = orchestrator._extract_web_ports(scan_results, nmap_results)
        
        # Should detect standard and non-standard web ports
        expected_ports = {(80, "http"), (443, "https"), (8080, "http"), (8443, "https"), (3000, "http")}
        assert set(web_ports) == expected_ports
    
    def test_extract_ssl_ports_comprehensive(self, orchestrator):
        """Test comprehensive SSL port extraction."""
        scan_results = {
            "scan_results": {
                "generic": {
                    "open_ports": [22, 80, 443, 993, 995, 465, 8443, 9443],
                    "port_info": {
                        "443": {"service": "https"},
                        "993": {"service": "imaps"},
                        "995": {"service": "pop3s"},
                        "465": {"service": "smtps"},
                        "8443": {"service": "https-alt"},
                        "9443": {"service": "ssl"}
                    }
                }
            }
        }
        
        ssl_ports = orchestrator._extract_ssl_ports(scan_results)
        
        expected_ports = {443, 993, 995, 465, 8443, 9443}
        assert set(ssl_ports) == expected_ports
    
    def test_extract_ports_from_nmap_only(self, orchestrator):
        """Test port extraction when only nmap results are available."""
        scan_results = {"scan_results": {}}
        nmap_results = {
            "ports": {
                "80/tcp": {"state": "open", "service": "http"},
                "443/tcp": {"state": "open", "service": "https"},
                "22/tcp": {"state": "open", "service": "ssh"},
                "8080/tcp": {"state": "open", "service": "http-proxy"}
            }
        }
        
        web_ports = orchestrator._extract_web_ports(scan_results, nmap_results)
        
        expected_ports = {(80, "http"), (443, "https"), (8080, "http")}
        assert set(web_ports) == expected_ports
    
    def test_extract_ports_no_results(self, orchestrator):
        """Test port extraction when no scan results are available."""
        scan_results = {"scan_results": {}}
        
        web_ports = orchestrator._extract_web_ports(scan_results)
        ssl_ports = orchestrator._extract_ssl_ports(scan_results)
        
        assert web_ports == []
        assert ssl_ports == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])