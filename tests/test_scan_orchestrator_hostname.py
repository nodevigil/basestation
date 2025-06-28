"""
Tests for ScanOrchestrator hostname parameter functionality.
Tests the hostname parameter handling in the ScanOrchestrator class.
"""
import pytest
import time
from unittest.mock import patch, MagicMock, AsyncMock
from typing import Dict, Any, List, Optional

from pgdn.scanners.scan_orchestrator import ScanOrchestrator
from pgdn.scanners.base_scanner import ScannerRegistry


class TestScanOrchestratorHostnameParameter:
    """Test class for ScanOrchestrator hostname parameter functionality."""
    
    @pytest.fixture
    def mock_config(self):
        """Create a mock configuration."""
        return {
            'orchestrator': {
                'enabled_scanners': ['generic', 'web'],
                'use_external_tools': True,
                'enabled_external_tools': ['nmap', 'whatweb']
            },
            'scanners': {}
        }

    @pytest.fixture
    def mock_scanner_registry(self):
        """Create a mock scanner registry."""
        registry = MagicMock(spec=ScannerRegistry)
        registry.get_registered_scanners.return_value = ['generic', 'web', 'vulnerability']
        return registry

    @pytest.fixture
    def mock_scanner(self):
        """Create a mock scanner."""
        scanner = MagicMock()
        scanner.scan.return_value = {
            "scanner_type": "web",
            "target": "192.168.1.1",
            "hostname": "example.com",
            "results": {"open_ports": [80, 443]}
        }
        return scanner

    def test_orchestrator_init_with_config(self, mock_config):
        """Test ScanOrchestrator initialization with config."""
        with patch('pgdn.scanners.scan_orchestrator.ScannerRegistry'):
            orchestrator = ScanOrchestrator(mock_config)
            assert orchestrator.config == mock_config
            assert orchestrator.enabled_scanners == ['generic', 'web']
            assert orchestrator.use_external_tools is True

    def test_orchestrator_init_without_config(self):
        """Test ScanOrchestrator initialization without config."""
        with patch('pgdn.scanners.scan_orchestrator.ScannerRegistry'):
            orchestrator = ScanOrchestrator()
            assert orchestrator.config == {}
            # Should use defaults
            assert 'generic' in orchestrator.enabled_scanners

    def test_scan_with_hostname_parameter(self, mock_config, mock_scanner):
        """Test scan method with hostname parameter."""
        with patch('pgdn.scanners.scan_orchestrator.ScannerRegistry') as MockRegistry, \
             patch('pgdn.scanners.scan_orchestrator.get_scanners_for_level', return_value=['web']), \
             patch.object(ScanOrchestrator, '_run_external_tools', return_value={}), \
             patch.object(ScanOrchestrator, '_convert_to_structured_format', side_effect=lambda x: x):
            
            # Setup mock registry
            mock_registry = MockRegistry.return_value
            mock_registry.get_registered_scanners.return_value = ['web']
            mock_registry.get_scanner.return_value = mock_scanner
            
            orchestrator = ScanOrchestrator(mock_config)
            result = orchestrator.scan(
                target='192.168.1.1',
                hostname='example.com',
                scan_level=1,
                protocol='sui'
            )
            
            # Verify hostname is in results
            assert result['target'] == '192.168.1.1'
            assert result['hostname'] == 'example.com'
            assert result['scan_level'] == 1
            assert result['protocol'] == 'sui'
            
            # Verify scanner was called with hostname
            mock_scanner.scan.assert_called_once()
            call_args = mock_scanner.scan.call_args
            assert call_args[0][0] == '192.168.1.1'  # target
            assert 'hostname' in call_args[1]
            assert call_args[1]['hostname'] == 'example.com'

    def test_scan_without_hostname_parameter(self, mock_config, mock_scanner):
        """Test scan method without hostname parameter."""
        with patch('pgdn.scanners.scan_orchestrator.ScannerRegistry') as MockRegistry, \
             patch('pgdn.scanners.scan_orchestrator.get_scanners_for_level', return_value=['web']), \
             patch.object(ScanOrchestrator, '_run_external_tools', return_value={}), \
             patch.object(ScanOrchestrator, '_convert_to_structured_format', side_effect=lambda x: x):
            
            # Setup mock registry
            mock_registry = MockRegistry.return_value
            mock_registry.get_registered_scanners.return_value = ['web']
            mock_registry.get_scanner.return_value = mock_scanner
            
            orchestrator = ScanOrchestrator(mock_config)
            result = orchestrator.scan(
                target='192.168.1.1',
                scan_level=1
            )
            
            # Verify hostname is None in results
            assert result['hostname'] is None
            
            # Verify scanner was called with None hostname
            call_args = mock_scanner.scan.call_args
            assert call_args[1]['hostname'] is None

    def test_scan_async_protocol_scanner_with_hostname(self, mock_config):
        """Test scan with async protocol scanner and hostname."""
        # Create async scanner
        async_scanner = MagicMock()
        async_scanner.scan_protocol = True  # Mark as async scanner
        
        # Create async scan method
        async def mock_async_scan(target, hostname=None, **kwargs):
            return {
                "scanner_type": "sui",
                "target": target,
                "hostname": hostname,
                "protocol_results": {"rpc_endpoints": ["http://192.168.1.1:9000"]}
            }
        
        async_scanner.scan = mock_async_scan
        
        with patch('pgdn.scanners.scan_orchestrator.ScannerRegistry') as MockRegistry, \
             patch('pgdn.scanners.scan_orchestrator.get_scanners_for_level', return_value=['sui']), \
             patch.object(ScanOrchestrator, '_run_external_tools', return_value={}), \
             patch.object(ScanOrchestrator, '_convert_to_structured_format', side_effect=lambda x: x), \
             patch('asyncio.run') as mock_asyncio_run:
            
            # Setup asyncio.run to actually call the async function
            def run_async(coro):
                import asyncio
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    return loop.run_until_complete(coro)
                finally:
                    loop.close()
            
            mock_asyncio_run.side_effect = run_async
            
            # Setup mock registry
            mock_registry = MockRegistry.return_value
            mock_registry.get_registered_scanners.return_value = ['sui']
            mock_registry.get_scanner.return_value = async_scanner
            
            orchestrator = ScanOrchestrator(mock_config)
            result = orchestrator.scan(
                target='192.168.1.1',
                hostname='sui-node.example.com',
                scan_level=2,
                protocol='sui'
            )
            
            # Verify hostname was passed to async scanner
            assert result['hostname'] == 'sui-node.example.com'
            assert 'scan_results' in result
            assert 'sui' in result['scan_results']

    def test_external_tools_receive_hostname(self, mock_config):
        """Test that external tools receive hostname parameter."""
        mock_external_tools_result = {
            "whatweb": {
                "target": "192.168.1.1",
                "hostname": "example.com",
                "technologies": ["nginx", "PHP"]
            },
            "ssl_test": {
                "target": "192.168.1.1", 
                "hostname": "example.com",
                "certificate_subject": "CN=example.com",
                "sni_enabled": True
            }
        }
        
        with patch('pgdn.scanners.scan_orchestrator.ScannerRegistry') as MockRegistry, \
             patch('pgdn.scanners.scan_orchestrator.get_scanners_for_level', return_value=['nmap', 'whatweb']), \
             patch.object(ScanOrchestrator, '_convert_to_structured_format', side_effect=lambda x: x):
            
            # Setup mock registry
            mock_registry = MockRegistry.return_value
            mock_registry.get_registered_scanners.return_value = []
            
            orchestrator = ScanOrchestrator(mock_config)
            
            # Mock the _run_external_tools method to capture arguments
            def mock_run_external_tools(target, hostname, scan_results, enabled_tools):
                assert target == '192.168.1.1'
                assert hostname == 'example.com'
                assert enabled_tools == ['nmap', 'whatweb']
                return mock_external_tools_result
            
            orchestrator._run_external_tools = mock_run_external_tools
            
            result = orchestrator.scan(
                target='192.168.1.1',
                hostname='example.com',
                scan_level=1
            )
            
            # Verify external tools received hostname
            assert result['external_tools'] == mock_external_tools_result

    def test_scanner_exception_with_hostname(self, mock_config):
        """Test scanner exception handling with hostname."""
        failing_scanner = MagicMock()
        failing_scanner.scan.side_effect = Exception("Scanner failed")
        
        with patch('pgdn.scanners.scan_orchestrator.ScannerRegistry') as MockRegistry, \
             patch('pgdn.scanners.scan_orchestrator.get_scanners_for_level', return_value=['web']), \
             patch.object(ScanOrchestrator, '_run_external_tools', return_value={}), \
             patch.object(ScanOrchestrator, '_convert_to_structured_format', side_effect=lambda x: x):
            
            # Setup mock registry
            mock_registry = MockRegistry.return_value
            mock_registry.get_registered_scanners.return_value = ['web']
            mock_registry.get_scanner.return_value = failing_scanner
            
            orchestrator = ScanOrchestrator(mock_config)
            result = orchestrator.scan(
                target='192.168.1.1',
                hostname='example.com',
                scan_level=1
            )
            
            # Verify hostname is preserved in results even with scanner failure
            assert result['hostname'] == 'example.com'
            assert 'scan_results' in result
            assert 'web' in result['scan_results']
            assert 'error' in result['scan_results']['web']

    def test_scan_level_support_check_with_hostname(self, mock_config):
        """Test scanner level support checking with hostname."""
        level_aware_scanner = MagicMock()
        level_aware_scanner.can_handle_level.return_value = False
        level_aware_scanner.get_supported_levels.return_value = [1, 2]
        
        with patch('pgdn.scanners.scan_orchestrator.ScannerRegistry') as MockRegistry, \
             patch('pgdn.scanners.scan_orchestrator.get_scanners_for_level', return_value=['advanced_scanner']), \
             patch.object(ScanOrchestrator, '_run_external_tools', return_value={}), \
             patch.object(ScanOrchestrator, '_convert_to_structured_format', side_effect=lambda x: x):
            
            # Setup mock registry
            mock_registry = MockRegistry.return_value
            mock_registry.get_registered_scanners.return_value = ['advanced_scanner']
            mock_registry.get_scanner.return_value = level_aware_scanner
            
            orchestrator = ScanOrchestrator(mock_config)
            result = orchestrator.scan(
                target='192.168.1.1',
                hostname='example.com',
                scan_level=3  # Unsupported level
            )
            
            # Verify hostname is preserved even when scanner is skipped
            assert result['hostname'] == 'example.com'
            
            # Verify scanner was not called due to level mismatch
            level_aware_scanner.scan.assert_not_called()

    def test_protocol_filtering_with_hostname(self, mock_config):
        """Test protocol scanner filtering with hostname."""
        with patch('pgdn.scanners.scan_orchestrator.ScannerRegistry') as MockRegistry, \
             patch('pgdn.scanners.scan_orchestrator.get_scanners_for_level', return_value=['generic', 'web', 'sui']), \
             patch.object(ScanOrchestrator, '_filter_infrastructure_scanners', return_value=['generic', 'web']), \
             patch.object(ScanOrchestrator, '_run_external_tools', return_value={}), \
             patch.object(ScanOrchestrator, '_convert_to_structured_format', side_effect=lambda x: x):
            
            # Setup mock registry
            mock_registry = MockRegistry.return_value
            mock_registry.get_registered_scanners.return_value = ['generic', 'web', 'sui']
            
            orchestrator = ScanOrchestrator(mock_config)
            result = orchestrator.scan(
                target='192.168.1.1',
                hostname='example.com',
                scan_level=1,
                protocol=None  # No protocol specified
            )
            
            # Verify hostname is preserved and filtering occurred
            assert result['hostname'] == 'example.com'
            assert result['protocol'] is None


class TestScanOrchestratorExternalToolsHostname:
    """Test ScanOrchestrator external tools hostname integration."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create a ScanOrchestrator instance."""
        config = {
            'orchestrator': {
                'enabled_external_tools': ['nmap', 'whatweb', 'ssl_test']
            }
        }
        with patch('pgdn.scanners.scan_orchestrator.ScannerRegistry'):
            return ScanOrchestrator(config)

    def test_run_external_tools_with_hostname(self, orchestrator):
        """Test _run_external_tools method with hostname parameter."""
        scan_results = {"web": {"open_ports": [80, 443]}}
        enabled_tools = ['nmap', 'whatweb']
        
        # Mock individual tool functions
        with patch('pgdn.scanners.scan_orchestrator.nmap_scan') as mock_nmap, \
             patch('pgdn.scanners.scan_orchestrator.whatweb_scan') as mock_whatweb, \
             patch.object(orchestrator, '_has_meaningful_results', return_value=True):
            
            mock_nmap.return_value = {"open_ports": [22, 80, 443]}
            mock_whatweb.return_value = {"technologies": ["nginx", "PHP"]}
            
            result = orchestrator._run_external_tools(
                target='192.168.1.1',
                hostname='example.com',
                scan_results=scan_results,
                enabled_tools=enabled_tools
            )
            
            # Verify tools were called
            mock_nmap.assert_called_once_with('192.168.1.1')
            mock_whatweb.assert_called_once_with('192.168.1.1')
            
            # Verify results contain tool outputs
            assert 'nmap' in result
            assert 'whatweb' in result
            assert result['nmap']['open_ports'] == [22, 80, 443]

    def test_run_external_tools_ssl_test_with_hostname(self, orchestrator):
        """Test SSL test external tool with hostname parameter."""
        scan_results = {}
        enabled_tools = ['ssl_test']
        
        with patch('pgdn.scanners.scan_orchestrator.ssl_test') as mock_ssl_test, \
             patch.object(orchestrator, '_has_meaningful_results', return_value=True):
            
            mock_ssl_test.return_value = {
                "certificate_subject": "CN=example.com",
                "sni_enabled": True,
                "grade": "A+"
            }
            
            result = orchestrator._run_external_tools(
                target='192.168.1.1',
                hostname='example.com',
                scan_results=scan_results,
                enabled_tools=enabled_tools
            )
            
            # Verify SSL test was called with IP (current behavior)
            mock_ssl_test.assert_called_once_with('192.168.1.1', 443)
            
            # Note: In future, SSL test should use hostname for SNI
            assert 'ssl_test' in result

    def test_run_external_tools_docker_exposure_with_hostname(self, orchestrator):
        """Test Docker exposure checker with hostname parameter."""
        scan_results = {}
        enabled_tools = ['docker_exposure']
        
        with patch('pgdn.scanners.scan_orchestrator.DockerExposureChecker') as MockDockerChecker, \
             patch.object(orchestrator, '_has_meaningful_results', return_value=True):
            
            mock_checker = MockDockerChecker.return_value
            mock_checker.check.return_value = {
                "docker_exposed": True,
                "api_version": "1.40"
            }
            
            result = orchestrator._run_external_tools(
                target='192.168.1.1',
                hostname='docker.example.com',
                scan_results=scan_results,
                enabled_tools=enabled_tools
            )
            
            # Verify Docker checker was called
            mock_checker.check.assert_called_once_with('192.168.1.1', 2375)
            
            assert 'docker_exposure' in result

    def test_run_external_tools_exception_handling(self, orchestrator):
        """Test external tools exception handling with hostname."""
        scan_results = {}
        enabled_tools = ['nmap']
        
        with patch('pgdn.scanners.scan_orchestrator.nmap_scan') as mock_nmap:
            mock_nmap.side_effect = Exception("Nmap failed")
            
            result = orchestrator._run_external_tools(
                target='192.168.1.1',
                hostname='example.com',
                scan_results=scan_results,
                enabled_tools=enabled_tools
            )
            
            # Verify error handling
            assert 'nmap' in result
            assert 'error' in result['nmap']
            assert 'Nmap failed' in result['nmap']['error']

    def test_run_external_tools_timing_with_hostname(self, orchestrator):
        """Test external tools timing tracking with hostname."""
        scan_results = {}
        enabled_tools = ['whatweb']
        
        with patch('pgdn.scanners.scan_orchestrator.whatweb_scan') as mock_whatweb, \
             patch.object(orchestrator, '_has_meaningful_results', return_value=True), \
             patch('time.time', side_effect=[1000, 1005]):  # Mock timing
            
            mock_whatweb.return_value = {"technologies": ["nginx"]}
            
            result = orchestrator._run_external_tools(
                target='192.168.1.1',
                hostname='example.com',
                scan_results=scan_results,
                enabled_tools=enabled_tools
            )
            
            # Verify timing information is included
            assert 'whatweb' in result
            assert 'start_time' in result['whatweb']
            assert 'end_time' in result['whatweb']
            assert 'duration' in result['whatweb']
            assert result['whatweb']['duration'] == 5