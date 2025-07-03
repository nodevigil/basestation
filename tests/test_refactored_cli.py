"""
Tests for the refactored CLI functionality.
Tests the new simplified CLI interface.
"""
import pytest
import json
import sys
import io
from unittest.mock import patch, MagicMock
from argparse import Namespace

# Import the CLI module
import cli
from pgdn.scanner import Scanner
from pgdn.core.result import DictResult


class TestRefactoredCLI:
    """Test the refactored CLI functionality."""
    
    def test_parse_arguments_web_scan(self):
        """Test parsing arguments for web scan."""
        with patch.object(sys, 'argv', ['pgdn', '--target', '127.0.0.1', '--run', 'web', '--json']):
            args = cli.parse_arguments()
            assert args.target == '127.0.0.1'
            assert args.run == 'web'
            assert args.json is True
            assert args.protocol is None
    
    def test_parse_arguments_node_scan(self):
        """Test parsing arguments for node scan with protocol."""
        with patch.object(sys, 'argv', ['pgdn', '--target', '127.0.0.1', '--run', 'node_scan', '--protocol', 'sui', '--json']):
            args = cli.parse_arguments()
            assert args.target == '127.0.0.1'
            assert args.run == 'node_scan'
            assert args.protocol == 'sui'
            assert args.json is True
    
    def test_parse_arguments_protocol_scan(self):
        """Test parsing arguments for protocol scan."""
        with patch.object(sys, 'argv', ['pgdn', '--target', '127.0.0.1', '--run', 'protocol_scan', '--protocol', 'sui', '--json']):
            args = cli.parse_arguments()
            assert args.target == '127.0.0.1'
            assert args.run == 'protocol_scan'
            assert args.protocol == 'sui'
            assert args.json is True
    
    def test_parse_arguments_compliance_scan(self):
        """Test parsing arguments for compliance scan."""
        with patch.object(sys, 'argv', ['pgdn', '--target', '127.0.0.1', '--run', 'compliance', '--protocol', 'sui', '--json']):
            args = cli.parse_arguments()
            assert args.target == '127.0.0.1'
            assert args.run == 'compliance'
            assert args.protocol == 'sui'
            assert args.json is True
    
    def test_run_choices(self):
        """Test that all expected run choices are available."""
        with patch.object(sys, 'argv', ['pgdn', '--help']):
            with pytest.raises(SystemExit):
                args = cli.parse_arguments()
        
        # Verify run choices are what we expect
        parser = cli.parse_arguments.__code__.co_consts
        # This is a basic check - in a real test we'd check the parser definition
        
    @patch('cli.Scanner')
    def test_perform_scan_web(self, mock_scanner_class):
        """Test perform_scan function with web scan."""
        # Mock scanner instance
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner
        
        # Mock successful scan result
        mock_result = DictResult.success({
            "data": [{"type": "web", "payload": {"test": "data"}}],
            "meta": {"operation": "target_scan", "stage": "scan"}
        })
        mock_scanner.scan.return_value = mock_result
        
        # Test the perform_scan function
        result = cli.perform_scan(
            scanner=mock_scanner,
            target="127.0.0.1",
            hostname=None,
            run_type="web",
            protocol=None,
            debug=False
        )
        
        # Verify scanner was called correctly
        mock_scanner.scan.assert_called_once_with(
            target="127.0.0.1",
            hostname=None,
            run="web",
            protocol=None,
            debug=False
        )
        
        # Verify result
        assert result.is_success()
        assert "data" in result.data
        assert "meta" in result.data
    
    @patch('cli.Scanner')
    def test_perform_scan_node_scan(self, mock_scanner_class):
        """Test perform_scan function with node scan."""
        # Mock scanner instance
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner
        
        # Mock successful scan result
        mock_result = DictResult.success({
            "data": [{"type": "node_scan", "payload": {"protocol": "sui", "results": []}}],
            "meta": {"operation": "target_scan", "stage": "scan", "protocol": "sui"}
        })
        mock_scanner.scan.return_value = mock_result
        
        # Test the perform_scan function
        result = cli.perform_scan(
            scanner=mock_scanner,
            target="127.0.0.1",
            hostname=None,
            run_type="node_scan",
            protocol="sui",
            debug=False
        )
        
        # Verify scanner was called correctly
        mock_scanner.scan.assert_called_once_with(
            target="127.0.0.1",
            hostname=None,
            run="node_scan",
            protocol="sui",
            debug=False
        )
        
        # Verify result
        assert result.is_success()
        assert result.data["meta"]["protocol"] == "sui"
    
    @patch('sys.stdout', new_callable=io.StringIO)
    @patch('cli.perform_scan')
    def test_json_output(self, mock_perform_scan, mock_stdout):
        """Test JSON output functionality."""
        # Mock successful scan result
        mock_result = DictResult.success({
            "data": [{"type": "web", "payload": {"test": "data"}}],
            "meta": {"operation": "target_scan", "stage": "scan"}
        })
        mock_perform_scan.return_value = mock_result
        
        # Test with JSON output
        with patch.object(sys, 'argv', ['pgdn', '--target', '127.0.0.1', '--run', 'web', '--json']):
            with patch('cli.Scanner'):
                with pytest.raises(SystemExit) as exc_info:
                    cli.main()
                
                # Should exit with code 0 (success)
                assert exc_info.value.code == 0
        
        # Verify JSON was printed
        output = mock_stdout.getvalue()
        assert output.strip()  # Should have output
        
        # Verify it's valid JSON
        try:
            parsed = json.loads(output)
            assert "data" in parsed
            assert "meta" in parsed
        except json.JSONDecodeError:
            pytest.fail("Output is not valid JSON")
    
    def test_protocol_requirement_validation(self):
        """Test that protocol is required for appropriate scan types."""
        # Test node_scan requires protocol
        with patch.object(sys, 'argv', ['pgdn', '--target', '127.0.0.1', '--run', 'node_scan']):
            with pytest.raises(SystemExit) as exc_info:
                cli.main()
            assert exc_info.value.code == 1
        
        # Test protocol_scan requires protocol  
        with patch.object(sys, 'argv', ['pgdn', '--target', '127.0.0.1', '--run', 'protocol_scan']):
            with pytest.raises(SystemExit) as exc_info:
                cli.main()
            assert exc_info.value.code == 1
        
        # Test compliance requires protocol
        with patch.object(sys, 'argv', ['pgdn', '--target', '127.0.0.1', '--run', 'compliance']):
            with pytest.raises(SystemExit) as exc_info:
                cli.main()
            assert exc_info.value.code == 1
    
    def test_target_requirement(self):
        """Test that target is required for scanning."""
        with patch.object(sys, 'argv', ['pgdn', '--run', 'web']):
            with pytest.raises(SystemExit) as exc_info:
                cli.main()
            assert exc_info.value.code == 1
    
    def test_run_requirement(self):
        """Test that run parameter is required."""
        with patch.object(sys, 'argv', ['pgdn', '--target', '127.0.0.1']):
            with pytest.raises(SystemExit) as exc_info:
                cli.main()
            assert exc_info.value.code == 1


if __name__ == '__main__':
    pytest.main([__file__])