"""
Tests for CLI hostname argument functionality.
Tests the hostname parameter parsing and propagation through the CLI.
"""
import pytest
import sys
from unittest.mock import patch, MagicMock
from argparse import Namespace

from cli import parse_arguments, main
from pgdn.scanner import Scanner
from pgdn.core.result import DictResult


class TestCLIHostnameArgument:
    """Test class for CLI hostname argument functionality."""
    
    def test_hostname_argument_parsing(self):
        """Test that --hostname argument is properly parsed."""
        test_args = ['pgdn', '--target', '192.168.1.1', '--hostname', 'example.com']
        
        with patch('sys.argv', test_args):
            args = parse_arguments()
            assert hasattr(args, 'hostname')
            assert args.hostname == 'example.com'
            assert args.target == '192.168.1.1'

    def test_hostname_argument_optional(self):
        """Test that --hostname is optional."""
        test_args = ['pgdn', '--target', '192.168.1.1']
        
        with patch('sys.argv', test_args):
            args = parse_arguments()
            assert hasattr(args, 'hostname')
            assert args.hostname is None

    def test_hostname_with_other_arguments(self):
        """Test --hostname works with other CLI arguments."""
        test_args = [
            'pgdn', '--target', '10.0.0.1', '--hostname', 'test.example.com',
            '--scan-level', '2', '--protocol', 'sui', '--json'
        ]
        
        with patch('sys.argv', test_args):
            args = parse_arguments()
            assert args.hostname == 'test.example.com'
            assert args.target == '10.0.0.1'
            assert args.scan_level == 2
            assert args.protocol == 'sui'
            assert args.json is True

    def test_hostname_argument_help(self):
        """Test that --hostname has proper help text."""
        test_args = ['pgdn', '--help']
        
        with patch('sys.argv', test_args):
            with pytest.raises(SystemExit):
                with patch('sys.stdout') as mock_stdout:
                    parse_arguments()
                    # Verify help text contains hostname information
                    help_output = ''.join(call.args[0] for call in mock_stdout.write.call_args_list)
                    assert '--hostname' in help_output
                    assert 'hostname associated with the target IP' in help_output


class TestCLIHostnameIntegration:
    """Test hostname parameter integration in CLI main function."""
    
    @pytest.fixture
    def mock_scanner_success(self):
        """Create a mock scanner that returns successful results."""
        mock_scanner = MagicMock(spec=Scanner)
        mock_result_data = {
            "target": "192.168.1.1",
            "hostname": "example.com",
            "scan_level": 1,
            "scan_result": {
                "open_ports": [80, 443],
                "services": {"80": "http", "443": "https"}
            },
            "timestamp": "2025-06-28T10:00:00Z",
            "node_id": "test-node-123"
        }
        mock_scanner.scan.return_value = DictResult.success(mock_result_data)
        return mock_scanner

    @pytest.fixture
    def mock_scanner_error(self):
        """Create a mock scanner that returns an error."""
        mock_scanner = MagicMock(spec=Scanner)
        mock_scanner.scan.return_value = DictResult.from_error("Scanner failed")
        return mock_scanner

    def test_main_with_hostname_success(self, mock_scanner_success):
        """Test main function with hostname argument - success case."""
        test_args = [
            'pgdn', '--target', '192.168.1.1', '--hostname', 'example.com', '--json'
        ]
        
        with patch('sys.argv', test_args), \
             patch('cli.Scanner', return_value=mock_scanner_success), \
             patch('pgdn.core.config.Config.from_file', return_value=None), \
             patch('sys.exit') as mock_exit, \
             patch('builtins.print') as mock_print:
            
            main()
            
            # Verify scanner was called with hostname
            mock_scanner_success.scan.assert_called_once_with(
                target='192.168.1.1',
                hostname='example.com',
                scan_level=1,
                protocol=None,
                enabled_scanners=None,
                enabled_external_tools=None,
                debug=False
            )
            
            # Verify success exit code
            mock_exit.assert_called_once_with(0)
            
            # Verify JSON output was printed
            assert mock_print.called

    def test_main_with_hostname_no_target_error(self):
        """Test main function with hostname but no target - should error."""
        test_args = ['pgdn', '--hostname', 'example.com']
        
        with patch('sys.argv', test_args), \
             patch('sys.exit') as mock_exit, \
             patch('builtins.print') as mock_print:
            
            main()
            
            # Verify error exit code
            mock_exit.assert_called_once_with(1)
            
            # Verify error message was printed
            mock_print.assert_called_with("❌ Error: --target is required unless using --list-protocols")

    def test_main_with_hostname_scanner_error(self, mock_scanner_error):
        """Test main function with hostname - scanner error case."""
        test_args = [
            'pgdn', '--target', '192.168.1.1', '--hostname', 'example.com', '--json'
        ]
        
        with patch('sys.argv', test_args), \
             patch('cli.Scanner', return_value=mock_scanner_error), \
             patch('pgdn.core.config.Config.from_file', return_value=None), \
             patch('sys.exit') as mock_exit, \
             patch('builtins.print') as mock_print:
            
            main()
            
            # Verify scanner was called with hostname
            mock_scanner_error.scan.assert_called_once_with(
                target='192.168.1.1',
                hostname='example.com',
                scan_level=1,
                protocol=None,
                enabled_scanners=None,
                enabled_external_tools=None,
                debug=False
            )
            
            # Verify error exit code
            mock_exit.assert_called_once_with(1)

    def test_main_without_hostname(self, mock_scanner_success):
        """Test main function without hostname argument."""
        test_args = ['pgdn', '--target', '192.168.1.1', '--json']
        
        with patch('sys.argv', test_args), \
             patch('cli.Scanner', return_value=mock_scanner_success), \
             patch('pgdn.core.config.Config.from_file', return_value=None), \
             patch('sys.exit') as mock_exit, \
             patch('builtins.print') as mock_print:
            
            main()
            
            # Verify scanner was called with None hostname
            mock_scanner_success.scan.assert_called_once_with(
                target='192.168.1.1',
                hostname=None,
                scan_level=1,
                protocol=None,
                enabled_scanners=None,
                enabled_external_tools=None,
                debug=False
            )
            
            # Verify success exit code
            mock_exit.assert_called_once_with(0)

    def test_main_with_hostname_human_output(self, mock_scanner_success):
        """Test main function with hostname and human-readable output."""
        test_args = [
            'pgdn', '--target', '192.168.1.1', '--hostname', 'example.com', '--human'
        ]
        
        with patch('sys.argv', test_args), \
             patch('cli.Scanner', return_value=mock_scanner_success), \
             patch('pgdn.core.config.Config.from_file', return_value=None), \
             patch('sys.exit') as mock_exit, \
             patch('cli.print_human_readable') as mock_print_human:
            
            main()
            
            # Verify scanner was called with hostname
            mock_scanner_success.scan.assert_called_once_with(
                target='192.168.1.1',
                hostname='example.com',
                scan_level=1,
                protocol=None,
                enabled_scanners=None,
                enabled_external_tools=None,
                debug=False
            )
            
            # Verify human-readable output was called
            mock_print_human.assert_called_once()
            
            # Verify success exit code
            mock_exit.assert_called_once_with(0)

    def test_main_with_config_file_and_hostname(self, mock_scanner_success):
        """Test main function with config file and hostname."""
        test_args = [
            'pgdn', '--target', '192.168.1.1', '--hostname', 'example.com',
            '--config', '/path/to/config.json', '--json'
        ]
        
        mock_config = MagicMock()
        
        with patch('sys.argv', test_args), \
             patch('cli.Scanner', return_value=mock_scanner_success), \
             patch('pgdn.core.config.Config.from_file', return_value=mock_config), \
             patch('sys.exit') as mock_exit, \
             patch('builtins.print') as mock_print:
            
            main()
            
            # Verify config was loaded
            from pgdn.core.config import Config
            Config.from_file.assert_called_once_with('/path/to/config.json')
            
            # Verify scanner was created with config
            from cli import Scanner
            Scanner.assert_called_once_with(mock_config)
            
            # Verify scanner was called with hostname
            mock_scanner_success.scan.assert_called_once_with(
                target='192.168.1.1',
                hostname='example.com',
                scan_level=1,
                protocol=None,
                enabled_scanners=None,
                enabled_external_tools=None,
                debug=False
            )


class TestCLIHostnameExamples:
    """Test realistic hostname usage examples."""
    
    def test_ip_with_hostname_example(self):
        """Test realistic example: IP address with associated hostname."""
        test_args = [
            'pgdn', '--target', '93.184.216.34', '--hostname', 'example.com',
            '--scan-level', '2', '--protocol', 'sui'
        ]
        
        with patch('sys.argv', test_args):
            args = parse_arguments()
            assert args.target == '93.184.216.34'
            assert args.hostname == 'example.com'
            assert args.scan_level == 2
            assert args.protocol == 'sui'

    def test_localhost_with_hostname_example(self):
        """Test localhost IP with hostname for virtual host testing."""
        test_args = [
            'pgdn', '--target', '127.0.0.1', '--hostname', 'localhost.example.com',
            '--scanners', 'web', 'vulnerability'
        ]
        
        with patch('sys.argv', test_args):
            args = parse_arguments()
            assert args.target == '127.0.0.1'
            assert args.hostname == 'localhost.example.com'
            assert args.scanners == ['web', 'vulnerability']

    def test_private_ip_with_internal_hostname(self):
        """Test private IP with internal hostname."""
        test_args = [
            'pgdn', '--target', '10.0.1.100', '--hostname', 'internal-api.company.local',
            '--external-tools', 'whatweb', 'ssl_test'
        ]
        
        with patch('sys.argv', test_args):
            args = parse_arguments()
            assert args.target == '10.0.1.100'
            assert args.hostname == 'internal-api.company.local'
            assert args.external_tools == ['whatweb', 'ssl_test']

    def test_subdomain_hostname_example(self):
        """Test subdomain hostname for CDN/WAF testing."""
        test_args = [
            'pgdn', '--target', '192.168.1.50', '--hostname', 'api.blockchain.example.com',
            '--scan-level', '3', '--debug'
        ]
        
        with patch('sys.argv', test_args):
            args = parse_arguments()
            assert args.target == '192.168.1.50'
            assert args.hostname == 'api.blockchain.example.com'
            assert args.scan_level == 3
            assert args.debug is True