"""
Tests for Scanner class hostname parameter functionality.
Tests the hostname parameter handling in the main Scanner class.
"""
import pytest
import socket
from unittest.mock import patch, MagicMock
from datetime import datetime

from pgdn.scanner import Scanner
from pgdn.core.config import Config
from pgdn.core.result import DictResult
from pgdn.scanners.scan_orchestrator import ScanOrchestrator


class TestScannerHostnameParameter:
    """Test class for Scanner hostname parameter functionality."""
    
    @pytest.fixture
    def mock_config(self):
        """Create a mock configuration."""
        config = MagicMock(spec=Config)
        config.scanning = MagicMock()
        config.scanning.orchestrator = {}
        config.scanning.scanners = {}
        return config

    @pytest.fixture
    def mock_orchestrator(self):
        """Create a mock scan orchestrator."""
        orchestrator = MagicMock(spec=ScanOrchestrator)
        orchestrator.scan.return_value = {
            "target": "192.168.1.1",
            "hostname": "example.com",
            "scan_level": 1,
            "scan_result": {"open_ports": [80, 443]},
            "timestamp": "2025-06-28T10:00:00Z",
            "node_id": "test-node-123"
        }
        return orchestrator

    def test_scanner_init_with_config(self, mock_config):
        """Test Scanner initialization with config."""
        with patch('pgdn.scanner.ScanOrchestrator') as MockOrchestrator:
            scanner = Scanner(mock_config)
            assert scanner.config == mock_config
            MockOrchestrator.assert_called_once()

    def test_scanner_init_without_config(self):
        """Test Scanner initialization without config."""
        with patch('pgdn.scanner.ScanOrchestrator') as MockOrchestrator:
            scanner = Scanner()
            assert scanner.config is None
            MockOrchestrator.assert_called_once_with()

    def test_scan_with_hostname_parameter(self, mock_orchestrator):
        """Test scan method with hostname parameter."""
        with patch('pgdn.scanner.ScanOrchestrator', return_value=mock_orchestrator), \
             patch('socket.gethostbyname', return_value='192.168.1.1'):
            
            scanner = Scanner()
            result = scanner.scan(
                target='192.168.1.1',
                hostname='example.com',
                scan_level=2,
                protocol='sui'
            )
            
            # Verify orchestrator was called with hostname
            mock_orchestrator.scan.assert_called_once()
            call_args = mock_orchestrator.scan.call_args
            assert call_args[1]['target'] == '192.168.1.1'
            assert call_args[1]['hostname'] == 'example.com'
            assert call_args[1]['scan_level'] == 2
            assert call_args[1]['protocol'] == 'sui'
            
            # Verify result is success
            assert isinstance(result, DictResult)
            assert result.is_success()

    def test_scan_without_hostname_parameter(self, mock_orchestrator):
        """Test scan method without hostname parameter."""
        with patch('pgdn.scanner.ScanOrchestrator', return_value=mock_orchestrator), \
             patch('socket.gethostbyname', return_value='192.168.1.1'):
            
            scanner = Scanner()
            result = scanner.scan(target='192.168.1.1', scan_level=1)
            
            # Verify orchestrator was called with None hostname
            mock_orchestrator.scan.assert_called_once()
            call_args = mock_orchestrator.scan.call_args
            assert call_args[1]['target'] == '192.168.1.1'
            assert call_args[1]['hostname'] is None
            assert call_args[1]['scan_level'] == 1

    def test_scan_hostname_with_domain_target(self, mock_orchestrator):
        """Test scan with domain as target and separate hostname."""
        with patch('pgdn.scanner.ScanOrchestrator', return_value=mock_orchestrator), \
             patch('socket.gethostbyname', return_value='192.168.1.1'):
            
            scanner = Scanner()
            result = scanner.scan(
                target='example.com',
                hostname='api.example.com',
                scan_level=1
            )
            
            # Verify DNS resolution was called
            socket.gethostbyname.assert_called_once_with('example.com')
            
            # Verify orchestrator was called with resolved IP and hostname
            mock_orchestrator.scan.assert_called_once()
            call_args = mock_orchestrator.scan.call_args
            assert call_args[1]['target'] == '192.168.1.1'
            assert call_args[1]['hostname'] == 'api.example.com'

    def test_scan_dns_resolution_failure(self):
        """Test scan when DNS resolution fails."""
        with patch('socket.gethostbyname', side_effect=socket.gaierror("DNS resolution failed")):
            
            scanner = Scanner()
            result = scanner.scan(
                target='invalid.domain',
                hostname='test.example.com',
                scan_level=1
            )
            
            # Verify result contains error
            assert isinstance(result, DictResult)
            assert result.is_success()  # Returns success with error in meta
            assert 'error' in result.meta
            assert 'DNS resolution failed' in result.meta['error']
            assert result.meta['target'] == 'invalid.domain'

    def test_scan_orchestrator_exception(self):
        """Test scan when orchestrator raises exception."""
        mock_orchestrator = MagicMock()
        mock_orchestrator.scan.side_effect = Exception("Orchestrator failed")
        
        with patch('pgdn.scanner.ScanOrchestrator', return_value=mock_orchestrator), \
             patch('socket.gethostbyname', return_value='192.168.1.1'):
            
            scanner = Scanner()
            result = scanner.scan(
                target='192.168.1.1',
                hostname='example.com',
                scan_level=1
            )
            
            # Verify result contains error
            assert isinstance(result, DictResult)
            assert result.is_success()  # Returns success with error in meta
            assert 'error' in result.meta
            assert 'Orchestration error: Orchestrator failed' in result.meta['error']

    def test_scan_with_all_parameters(self, mock_orchestrator):
        """Test scan with all parameters including hostname."""
        with patch('pgdn.scanner.ScanOrchestrator', return_value=mock_orchestrator), \
             patch('socket.gethostbyname', return_value='10.0.0.1'):
            
            scanner = Scanner()
            result = scanner.scan(
                target='10.0.0.1',
                hostname='test.internal.com',
                scan_level=3,
                protocol='filecoin',
                enabled_scanners=['web', 'vulnerability'],
                enabled_external_tools=['nmap', 'ssl_test'],
                debug=True
            )
            
            # Verify all parameters were passed to orchestrator
            mock_orchestrator.scan.assert_called_once()
            call_args = mock_orchestrator.scan.call_args
            assert call_args[1]['target'] == '10.0.0.1'
            assert call_args[1]['hostname'] == 'test.internal.com'
            assert call_args[1]['scan_level'] == 3
            assert call_args[1]['protocol'] == 'filecoin'

    def test_scan_config_override_with_hostname(self, mock_config):
        """Test scan with configuration overrides and hostname."""
        mock_orchestrator = MagicMock()
        mock_orchestrator.scan.return_value = {"target": "192.168.1.1", "hostname": "example.com"}
        
        with patch('pgdn.scanner.ScanOrchestrator', return_value=mock_orchestrator), \
             patch('socket.gethostbyname', return_value='192.168.1.1'):
            
            scanner = Scanner(mock_config)
            scanner._update_orchestrator_config(['web'], ['whatweb'])
            
            result = scanner.scan(
                target='192.168.1.1',
                hostname='example.com',
                enabled_scanners=['web'],
                enabled_external_tools=['whatweb']
            )
            
            # Verify orchestrator configuration was updated
            assert mock_orchestrator.enabled_scanners == ['web']
            assert mock_orchestrator.use_external_tools is True
            assert mock_orchestrator.enabled_external_tools == ['whatweb']

    def test_scan_empty_external_tools_with_hostname(self, mock_orchestrator):
        """Test scan with empty external tools list and hostname."""
        with patch('pgdn.scanner.ScanOrchestrator', return_value=mock_orchestrator), \
             patch('socket.gethostbyname', return_value='192.168.1.1'):
            
            scanner = Scanner()
            result = scanner.scan(
                target='192.168.1.1',
                hostname='example.com',
                enabled_external_tools=[]
            )
            
            # Verify external tools were disabled
            assert mock_orchestrator.use_external_tools is False
            assert mock_orchestrator.enabled_external_tools == []
            
            # Verify hostname was still passed
            call_args = mock_orchestrator.scan.call_args
            assert call_args[1]['hostname'] == 'example.com'


class TestScannerHostnameIntegration:
    """Test Scanner hostname integration with realistic scenarios."""
    
    def test_ip_with_hostname_ssl_scanning(self):
        """Test IP target with hostname for SSL/SNI scanning."""
        mock_orchestrator = MagicMock()
        mock_orchestrator.scan.return_value = {
            "target": "93.184.216.34",
            "hostname": "example.com",
            "external_tools": {
                "ssl_test": {
                    "certificate_subject": "CN=example.com",
                    "sni_enabled": True,
                    "grade": "A+"
                }
            }
        }
        
        with patch('pgdn.scanner.ScanOrchestrator', return_value=mock_orchestrator), \
             patch('socket.gethostbyname', return_value='93.184.216.34'):
            
            scanner = Scanner()
            result = scanner.scan(
                target='93.184.216.34',
                hostname='example.com',
                enabled_external_tools=['ssl_test']
            )
            
            # Verify SSL test would receive hostname for SNI
            call_args = mock_orchestrator.scan.call_args
            assert call_args[1]['hostname'] == 'example.com'
            assert result.is_success()

    def test_localhost_with_virtual_host(self):
        """Test localhost IP with virtual host hostname."""
        mock_orchestrator = MagicMock()
        mock_orchestrator.scan.return_value = {
            "target": "127.0.0.1",
            "hostname": "dev.api.local",
            "scan_results": {
                "web": {
                    "virtual_host": "dev.api.local",
                    "response_headers": {
                        "Server": "nginx/1.18.0"
                    }
                }
            }
        }
        
        with patch('pgdn.scanner.ScanOrchestrator', return_value=mock_orchestrator), \
             patch('socket.gethostbyname', return_value='127.0.0.1'):
            
            scanner = Scanner()
            result = scanner.scan(
                target='127.0.0.1',
                hostname='dev.api.local',
                enabled_scanners=['web']
            )
            
            call_args = mock_orchestrator.scan.call_args
            assert call_args[1]['target'] == '127.0.0.1'
            assert call_args[1]['hostname'] == 'dev.api.local'

    def test_cdn_bypass_scenario(self):
        """Test CDN bypass scenario with IP and original hostname."""
        mock_orchestrator = MagicMock()
        mock_orchestrator.scan.return_value = {
            "target": "104.16.132.229",  # Cloudflare IP
            "hostname": "protected-site.com",
            "scan_results": {
                "web": {
                    "cdn_detected": "cloudflare",
                    "origin_server": "104.16.132.229",
                    "host_header": "protected-site.com"
                }
            }
        }
        
        with patch('pgdn.scanner.ScanOrchestrator', return_value=mock_orchestrator), \
             patch('socket.gethostbyname', return_value='104.16.132.229'):
            
            scanner = Scanner()
            result = scanner.scan(
                target='104.16.132.229',
                hostname='protected-site.com',
                enabled_scanners=['web'],
                enabled_external_tools=['whatweb']
            )
            
            call_args = mock_orchestrator.scan.call_args
            assert call_args[1]['target'] == '104.16.132.229'
            assert call_args[1]['hostname'] == 'protected-site.com'

    def test_internal_corporate_network(self):
        """Test internal corporate network with internal hostname."""
        mock_orchestrator = MagicMock()
        mock_orchestrator.scan.return_value = {
            "target": "10.0.1.100",
            "hostname": "internal-api.corp.local",
            "scan_results": {
                "web": {
                    "authentication_required": True,
                    "internal_hostname": "internal-api.corp.local"
                },
                "vulnerability": {
                    "ssl_issues": ["weak_cipher_suites"],
                    "internal_exposure": True
                }
            }
        }
        
        with patch('pgdn.scanner.ScanOrchestrator', return_value=mock_orchestrator), \
             patch('socket.gethostbyname', return_value='10.0.1.100'):
            
            scanner = Scanner()
            result = scanner.scan(
                target='10.0.1.100',
                hostname='internal-api.corp.local',
                scan_level=2,
                enabled_scanners=['web', 'vulnerability']
            )
            
            call_args = mock_orchestrator.scan.call_args
            assert call_args[1]['hostname'] == 'internal-api.corp.local'
            assert call_args[1]['scan_level'] == 2