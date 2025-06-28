"""
Integration tests for hostname functionality across the entire PGDN scanner.
Tests end-to-end hostname parameter flow from CLI to scanners.
"""
import pytest
import json
import subprocess
import tempfile
import os
from unittest.mock import patch, MagicMock

from cli import main
from pgdn.scanner import Scanner
from pgdn.scanners.scan_orchestrator import ScanOrchestrator
from pgdn.core.config import Config


class TestHostnameIntegrationEndToEnd:
    """End-to-end integration tests for hostname functionality."""
    
    def test_cli_to_scanner_hostname_flow(self):
        """Test complete flow from CLI argument to Scanner method."""
        # Mock the entire scanner chain
        mock_orchestrator_result = {
            "target": "192.168.1.1",
            "hostname": "test.example.com",
            "scan_level": 1,
            "scan_results": {
                "web": {
                    "hostname_used": "test.example.com",
                    "virtual_host_detected": True,
                    "response_code": 200
                }
            },
            "external_tools": {
                "whatweb": {
                    "hostname": "test.example.com",
                    "technologies": ["nginx", "PHP"]
                }
            }
        }
        
        # Mock at the Scanner level instead of ScanOrchestrator to avoid real scanning
        with patch('sys.argv', ['pgdn', '--target', '192.168.1.1', '--hostname', 'test.example.com', '--json']), \
             patch('cli.Scanner') as MockScanner, \
             patch('sys.exit') as mock_exit, \
             patch('builtins.print') as mock_print:
            
            # Setup mock scanner
            mock_scanner = MockScanner.return_value
            from pgdn.core.result import DictResult
            mock_scanner.scan.return_value = DictResult.success(mock_orchestrator_result)
            
            main()
            
            # Verify scanner was called with hostname
            mock_scanner.scan.assert_called_once()
            call_args = mock_scanner.scan.call_args
            assert call_args[1]['target'] == '192.168.1.1'
            assert call_args[1]['hostname'] == 'test.example.com'
            
            # Verify successful exit
            mock_exit.assert_called_once_with(0)

    def test_hostname_propagation_through_layers(self):
        """Test hostname propagation through all layers: CLI -> Scanner -> Orchestrator."""
        # Create a real Scanner instance to test actual propagation
        scanner = Scanner()
        
        # Mock the orchestrator within the scanner
        with patch.object(scanner, 'orchestrator') as mock_orchestrator, \
             patch('socket.gethostbyname', return_value='10.0.0.1'):
            
            mock_orchestrator.scan.return_value = {
                "target": "10.0.0.1",
                "hostname": "api.internal.com",
                "scan_results": {}
            }
            
            result = scanner.scan(
                target='10.0.0.1',
                hostname='api.internal.com',
                scan_level=2,
                protocol='sui'
            )
            
            # Verify hostname was passed through correctly
            mock_orchestrator.scan.assert_called_once()
            call_kwargs = mock_orchestrator.scan.call_args[1]
            assert call_kwargs['target'] == '10.0.0.1'
            assert call_kwargs['hostname'] == 'api.internal.com'
            assert call_kwargs['scan_level'] == 2
            assert call_kwargs['protocol'] == 'sui'
            
            # Verify result structure
            assert result.is_success()
            assert result.data['hostname'] == 'api.internal.com'

    def test_hostname_with_dns_resolution(self):
        """Test hostname behavior when target requires DNS resolution."""
        scanner = Scanner()
        
        with patch.object(scanner, 'orchestrator') as mock_orchestrator, \
             patch('socket.gethostbyname', return_value='1.2.3.4') as mock_dns:
            
            mock_orchestrator.scan.return_value = {
                "target": "1.2.3.4",
                "hostname": "override.example.com",
                "scan_results": {}
            }
            
            result = scanner.scan(
                target='example.com',  # Domain that needs resolution
                hostname='override.example.com',  # Different hostname
                scan_level=1
            )
            
            # Verify DNS resolution occurred
            mock_dns.assert_called_once_with('example.com')
            
            # Verify orchestrator received resolved IP and separate hostname
            call_kwargs = mock_orchestrator.scan.call_args[1]
            assert call_kwargs['target'] == '1.2.3.4'  # Resolved IP
            assert call_kwargs['hostname'] == 'override.example.com'  # Override hostname

    def test_hostname_with_scanner_configuration_override(self):
        """Test hostname with scanner configuration overrides."""
        config = {
            'orchestrator': {
                'enabled_scanners': ['web', 'vulnerability'],
                'enabled_external_tools': ['whatweb', 'ssl_test']
            }
        }
        
        scanner = Scanner()
        
        with patch.object(scanner, 'orchestrator') as mock_orchestrator, \
             patch('socket.gethostbyname', return_value='192.168.1.100'):
            
            mock_orchestrator.scan.return_value = {
                "target": "192.168.1.100",
                "hostname": "secure.internal.com",
                "scan_results": {}
            }
            
            result = scanner.scan(
                target='192.168.1.100',
                hostname='secure.internal.com',
                enabled_scanners=['web'],
                enabled_external_tools=['ssl_test'],
                scan_level=3
            )
            
            # Verify configuration overrides were applied
            assert mock_orchestrator.enabled_scanners == ['web']
            assert mock_orchestrator.enabled_external_tools == ['ssl_test']
            
            # Verify hostname was still passed correctly
            call_kwargs = mock_orchestrator.scan.call_args[1]
            assert call_kwargs['hostname'] == 'secure.internal.com'

    def test_hostname_error_handling_integration(self):
        """Test hostname-related error handling integration."""
        scanner = Scanner()
        
        # Test DNS resolution failure
        with patch('socket.gethostbyname', side_effect=Exception("DNS failed")):
            result = scanner.scan(
                target='invalid.domain',
                hostname='test.com',
                scan_level=1
            )
            
            # Verify error is handled gracefully
            assert result.is_success()  # Scanner returns success with error in meta
            assert 'error' in result.meta
            assert 'DNS failed' in result.meta['error']

    def test_hostname_with_multiple_external_tools(self):
        """Test hostname integration with multiple external tools."""
        orchestrator = ScanOrchestrator({
            'orchestrator': {
                'enabled_external_tools': ['nmap', 'whatweb', 'ssl_test', 'docker_exposure']
            }
        })
        
        # Mock all external tool functions
        with patch('pgdn.scanners.scan_orchestrator.nmap_scan') as mock_nmap, \
             patch('pgdn.scanners.scan_orchestrator.whatweb_scan') as mock_whatweb, \
             patch('pgdn.scanners.scan_orchestrator.ssl_test') as mock_ssl, \
             patch('pgdn.scanners.scan_orchestrator.DockerExposureChecker') as mock_docker, \
             patch('pgdn.scanners.scan_orchestrator.get_scanners_for_level', return_value=['nmap', 'whatweb', 'ssl_test', 'docker_exposure']), \
             patch.object(orchestrator, '_has_meaningful_results', return_value=True), \
             patch.object(orchestrator, '_convert_to_structured_format', side_effect=lambda x: x):
            
            # Setup mock returns
            mock_nmap.return_value = {"open_ports": [22, 80, 443]}
            mock_whatweb.return_value = {"technologies": ["nginx"]}
            mock_ssl.return_value = {"grade": "A+"}
            mock_docker_instance = mock_docker.return_value
            mock_docker_instance.check.return_value = {"exposed": False}
            
            result = orchestrator.scan(
                target='10.0.1.50',
                hostname='services.corp.local',
                scan_level=1
            )
            
            # Verify all tools were called
            mock_nmap.assert_called_once_with('10.0.1.50')
            mock_whatweb.assert_called_once_with('10.0.1.50')
            mock_ssl.assert_called_once_with('10.0.1.50', 443)
            mock_docker_instance.check.assert_called_once_with('10.0.1.50', 2375)
            
            # Verify hostname is preserved in results
            assert result['hostname'] == 'services.corp.local'
            assert 'external_tools' in result


class TestHostnameRealWorldScenarios:
    """Test hostname functionality with realistic real-world scenarios."""
    
    def test_cdn_bypass_scenario(self):
        """Test CDN bypass scenario: direct IP access with original hostname."""
        scanner = Scanner()
        
        with patch.object(scanner, 'orchestrator') as mock_orchestrator, \
             patch('socket.gethostbyname', return_value='104.16.132.229'):  # Cloudflare IP
            
            mock_orchestrator.scan.return_value = {
                "target": "104.16.132.229",
                "hostname": "protected-site.com",
                "scan_results": {
                    "web": {
                        "cdn_detected": "cloudflare",
                        "origin_response": True,
                        "host_header": "protected-site.com"
                    }
                },
                "external_tools": {
                    "whatweb": {
                        "cdn_bypass": True,
                        "technologies": ["Apache", "WordPress"]
                    }
                }
            }
            
            result = scanner.scan(
                target='104.16.132.229',
                hostname='protected-site.com',
                enabled_scanners=['web'],
                enabled_external_tools=['whatweb']
            )
            
            # Verify CDN bypass scenario works
            assert result.is_success()
            assert result.data['hostname'] == 'protected-site.com'
            assert 'cdn_detected' in result.data['scan_results']['web']

    def test_virtual_host_enumeration(self):
        """Test virtual host enumeration scenario."""
        scanner = Scanner()
        
        with patch.object(scanner, 'orchestrator') as mock_orchestrator, \
             patch('socket.gethostbyname', return_value='192.168.1.10'):
            
            mock_orchestrator.scan.return_value = {
                "target": "192.168.1.10",
                "hostname": "app1.internal.local",
                "scan_results": {
                    "web": {
                        "virtual_hosts": [
                            "app1.internal.local",
                            "app2.internal.local", 
                            "admin.internal.local"
                        ],
                        "current_host": "app1.internal.local",
                        "response_differs": True
                    }
                }
            }
            
            result = scanner.scan(
                target='192.168.1.10',
                hostname='app1.internal.local',
                scan_level=2
            )
            
            # Verify virtual host detection
            assert result.data['hostname'] == 'app1.internal.local'
            assert 'virtual_hosts' in result.data['scan_results']['web']

    def test_ssl_sni_scanning(self):
        """Test SSL/TLS scanning with SNI requirements."""
        scanner = Scanner()
        
        with patch.object(scanner, 'orchestrator') as mock_orchestrator, \
             patch('socket.gethostbyname', return_value='93.184.216.34'):
            
            mock_orchestrator.scan.return_value = {
                "target": "93.184.216.34",
                "hostname": "example.com",
                "external_tools": {
                    "ssl_test": {
                        "sni_required": True,
                        "certificate_subject": "CN=example.com",
                        "certificate_san": ["example.com", "www.example.com"],
                        "grade": "A+",
                        "hostname_verification": "PASS"
                    }
                }
            }
            
            result = scanner.scan(
                target='93.184.216.34',
                hostname='example.com',
                enabled_external_tools=['ssl_test']
            )
            
            # Verify SSL/SNI testing
            assert result.data['hostname'] == 'example.com'
            ssl_results = result.data['external_tools']['ssl_test']
            assert ssl_results['sni_required'] is True
            assert 'example.com' in ssl_results['certificate_subject']

    def test_internal_corporate_network(self):
        """Test internal corporate network scanning."""
        scanner = Scanner()
        
        with patch.object(scanner, 'orchestrator') as mock_orchestrator, \
             patch('socket.gethostbyname', return_value='10.0.1.100'):
            
            mock_orchestrator.scan.return_value = {
                "target": "10.0.1.100",
                "hostname": "intranet.corp.local",
                "scan_results": {
                    "web": {
                        "internal_network": True,
                        "authentication_required": True,
                        "domain": "corp.local",
                        "hostname_resolved": "intranet.corp.local"
                    },
                    "vulnerability": {
                        "internal_exposure": True,
                        "network_segment": "corporate_dmz"
                    }
                }
            }
            
            result = scanner.scan(
                target='10.0.1.100',
                hostname='intranet.corp.local',
                scan_level=3,
                enabled_scanners=['web', 'vulnerability']
            )
            
            # Verify internal network scanning
            assert result.data['hostname'] == 'intranet.corp.local'
            assert result.data['scan_results']['web']['internal_network'] is True

    def test_blockchain_node_scanning(self):
        """Test blockchain node scanning with hostname."""
        scanner = Scanner()
        
        with patch.object(scanner, 'orchestrator') as mock_orchestrator, \
             patch('socket.gethostbyname', return_value='45.32.123.45'):
            
            mock_orchestrator.scan.return_value = {
                "target": "45.32.123.45",
                "hostname": "sui-fullnode.example.org",
                "protocol": "sui",
                "scan_results": {
                    "sui": {
                        "rpc_endpoint": "https://sui-fullnode.example.org:9000",
                        "websocket_endpoint": "wss://sui-fullnode.example.org:9001",
                        "node_info": {
                            "version": "1.0.0",
                            "network": "mainnet"
                        },
                        "tls_enabled": True,
                        "hostname_used": "sui-fullnode.example.org"
                    }
                }
            }
            
            result = scanner.scan(
                target='45.32.123.45',
                hostname='sui-fullnode.example.org',
                protocol='sui',
                scan_level=2
            )
            
            # Verify blockchain node scanning
            assert result.data['hostname'] == 'sui-fullnode.example.org'
            assert result.data['protocol'] == 'sui'
            sui_results = result.data['scan_results']['sui']
            assert 'sui-fullnode.example.org' in sui_results['rpc_endpoint']


class TestHostnameConfigurationIntegration:
    """Test hostname functionality with different configuration scenarios."""
    
    def test_hostname_with_custom_config_file(self):
        """Test hostname with custom configuration file."""
        # Create temporary config file
        config_data = {
            "scanning": {
                "orchestrator": {
                    "enabled_scanners": ["web", "vulnerability"],
                    "enabled_external_tools": ["whatweb", "ssl_test"]
                },
                "scanners": {
                    "web": {
                        "timeout": 30,
                        "follow_redirects": True
                    }
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            config_path = f.name
        
        try:
            # Mock CLI with config file
            with patch('sys.argv', [
                'pgdn', '--target', '172.16.1.50', '--hostname', 'app.test.local',
                '--config', config_path, '--json'
            ]), \
            patch('pgdn.scanners.scan_orchestrator.ScanOrchestrator') as MockOrchestrator, \
            patch('socket.gethostbyname', return_value='172.16.1.50'), \
            patch('sys.exit'), \
            patch('builtins.print'):
                
                mock_orchestrator = MockOrchestrator.return_value
                mock_orchestrator.scan.return_value = {
                    "target": "172.16.1.50",
                    "hostname": "app.test.local",
                    "scan_results": {}
                }
                
                main()
                
                # Verify hostname was passed with custom config
                call_kwargs = mock_orchestrator.scan.call_args[1]
                assert call_kwargs['hostname'] == 'app.test.local'
                
        finally:
            os.unlink(config_path)

    def test_hostname_with_scanner_overrides(self):
        """Test hostname with CLI scanner overrides."""
        with patch('sys.argv', [
            'pgdn', '--target', '192.168.2.100', '--hostname', 'override.local',
            '--scanners', 'web', '--external-tools', 'ssl_test', '--json'
        ]), \
        patch('pgdn.scanners.scan_orchestrator.ScanOrchestrator') as MockOrchestrator, \
        patch('socket.gethostbyname', return_value='192.168.2.100'), \
        patch('sys.exit'), \
        patch('builtins.print'):
            
            mock_orchestrator = MockOrchestrator.return_value
            mock_orchestrator.scan.return_value = {
                "target": "192.168.2.100",
                "hostname": "override.local"
            }
            
            main()
            
            # Verify scanner overrides were applied with hostname
            assert mock_orchestrator.enabled_scanners == ['web']
            assert mock_orchestrator.enabled_external_tools == ['ssl_test']
            
            call_kwargs = mock_orchestrator.scan.call_args[1]
            assert call_kwargs['hostname'] == 'override.local'