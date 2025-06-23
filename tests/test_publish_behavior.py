"""
Tests for publish behavior to ensure correct separation of concerns.

These tests verify:
1. Default publish behavior only publishes to ledger
2. Reports are not published unless explicitly requested
3. Walrus publishing is completely independent
4. No duplicate publishing occurs
"""

import pytest
import os
import sys
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from agents.publish.publisher_agent import PublisherAgent
from agents.publish.publish_ledger_agent import PublishLedgerAgent
from pgdn.core.config import Config


class TestPublishBehavior:
    """Test suite for publish behavior."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = Config()
        self.scan_id = 123
        
    @patch('agents.publish.publisher_agent.PublishLedgerAgent')
    @patch('agents.publish.publisher_agent.PublishReportAgent')
    def test_default_publish_only_calls_ledger(self, mock_report_agent_class, mock_ledger_agent_class):
        """Test that default publish behavior only calls ledger agent, not report agent."""
        # Setup mocks
        mock_ledger_agent = Mock()
        mock_ledger_agent.execute.return_value = {
            'success': True,
            'transaction_hash': 'test_hash',
            'already_published': False
        }
        mock_ledger_agent_class.return_value = mock_ledger_agent
        
        # Create publisher agent
        publisher = PublisherAgent(self.config)
        
        # Execute default publish behavior
        result = publisher.execute(scan_id=self.scan_id)
        
        # Verify only ledger agent was called
        mock_ledger_agent_class.assert_called_once()
        mock_ledger_agent.execute.assert_called_once_with(scan_id=self.scan_id)
        
        # Verify report agent was never instantiated or called
        mock_report_agent_class.assert_not_called()
        
        # Verify success
        assert result is True

    @patch('agents.publish.publisher_agent.PublishLedgerAgent')
    @patch('agents.publish.publisher_agent.PublishReportAgent')
    def test_ledger_failure_prevents_report_publishing(self, mock_report_agent_class, mock_ledger_agent_class):
        """Test that if ledger publishing fails, report publishing is not attempted."""
        # Setup mocks - ledger fails
        mock_ledger_agent = Mock()
        mock_ledger_agent.execute.return_value = {
            'success': False,
            'error': 'Ledger connection failed'
        }
        mock_ledger_agent_class.return_value = mock_ledger_agent
        
        # Create publisher agent
        publisher = PublisherAgent(self.config)
        
        # Execute publish
        result = publisher.execute(scan_id=self.scan_id)
        
        # Verify ledger agent was called
        mock_ledger_agent_class.assert_called_once()
        mock_ledger_agent.execute.assert_called_once_with(scan_id=self.scan_id)
        
        # Verify report agent was never called (because ledger failed)
        mock_report_agent_class.assert_not_called()
        
        # Verify failure
        assert result is False

    @patch('agents.publish.publish_ledger_agent.ScanRepository')
    @patch('agents.publish.publish_ledger_agent.LedgerRepository')
    def test_ledger_agent_checks_for_duplicate_publishing(self, mock_ledger_repo_class, mock_scan_repo_class):
        """Test that ledger agent checks for existing publications to prevent duplicates."""
        # Setup mocks
        mock_ledger_repo = Mock()
        mock_ledger_repo.is_scan_published.return_value = True
        mock_ledger_repo.get_scan_publish_status.return_value = {
            'published': True,
            'transaction_hash': 'existing_hash',
            'confirmed': True
        }
        mock_ledger_repo_class.return_value = mock_ledger_repo
        
        # Create ledger agent with mocked blockchain connection
        with patch.object(PublishLedgerAgent, '_initialize_blockchain_connection'):
            ledger_agent = PublishLedgerAgent(self.config)
            ledger_agent.w3 = Mock()
            ledger_agent.contract = Mock()
            ledger_agent.is_publisher = True
        
        # Execute
        result = ledger_agent.execute(scan_id=self.scan_id)
        
        # Verify duplicate check was performed
        mock_ledger_repo.is_scan_published.assert_called_once_with(self.scan_id)
        mock_ledger_repo.get_scan_publish_status.assert_called_once_with(self.scan_id)
        
        # Verify no new blockchain transaction was attempted
        mock_scan_repo_class.assert_not_called()
        
        # Verify result indicates already published
        assert result['success'] is True
        assert result['already_published'] is True
        assert result['transaction_hash'] == 'existing_hash'

    def test_publisher_agent_does_not_import_walrus_by_default(self):
        """Test that PublisherAgent does not import or reference Walrus components by default."""
        # This test ensures no Walrus-related imports happen during normal operation
        publisher = PublisherAgent(self.config)
        
        # Check that no Walrus-related attributes exist
        assert not hasattr(publisher, 'walrus_client')
        assert not hasattr(publisher, 'walrus_config')
        
        # Verify the class doesn't have Walrus imports at module level
        import agents.publish.publisher_agent as publisher_module
        module_code = str(publisher_module.__dict__)
        assert 'walrus' not in module_code.lower()

    @patch.dict(os.environ, {'PUBLISHING_DESTINATIONS': 'walrus,local_file'})
    def test_walrus_in_config_does_not_trigger_automatic_publishing(self):
        """Test that having Walrus in config doesn't automatically trigger Walrus publishing."""
        # Even if Walrus is in the config, default behavior should not use it
        config = Config()
        publisher = PublisherAgent(config)
        
        with patch('agents.publish.publisher_agent.PublishLedgerAgent') as mock_ledger_class:
            mock_ledger_agent = Mock()
            mock_ledger_agent.execute.return_value = {'success': True, 'already_published': False}
            mock_ledger_class.return_value = mock_ledger_agent
            
            # Execute default publish
            result = publisher.execute(scan_id=self.scan_id)
            
            # Should only call ledger agent
            mock_ledger_class.assert_called_once()
            assert result is True

    def test_cli_help_reflects_new_behavior(self):
        """Test that CLI help text accurately reflects the new publishing behavior."""
        # Import CLI module to check help text
        import cli
        
        # This is a documentation test - the help should clearly indicate:
        # 1. Default publish only does ledger
        # 2. Reports require explicit flag
        # 3. Walrus requires explicit flag
        
        # We can check this by looking at the argument help text
        parser = cli.create_parser()
        
        # Find publish-related arguments
        publish_ledger_action = None
        publish_report_action = None
        publish_walrus_action = None
        
        for action in parser._actions:
            if hasattr(action, 'dest'):
                if action.dest == 'publish_ledger':
                    publish_ledger_action = action
                elif action.dest == 'publish_report':
                    publish_report_action = action
                elif action.dest == 'publish_walrus':
                    publish_walrus_action = action
        
        # Verify all publish options exist
        assert publish_ledger_action is not None, "Missing --publish-ledger option"
        assert publish_report_action is not None, "Missing --publish-report option"
        assert publish_walrus_action is not None, "Missing --publish-walrus option"
        
        # Verify help text makes the behavior clear
        assert 'ledger' in publish_ledger_action.help.lower()
        assert 'report' in publish_report_action.help.lower()
        assert 'walrus' in publish_walrus_action.help.lower()


class TestLedgerOnlyBehavior:
    """Test suite specifically for ledger-only publishing behavior."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = Config()
        self.scan_id = 456

    @patch('agents.publish.publish_ledger_agent.ScanRepository')
    @patch('agents.publish.publish_ledger_agent.LedgerRepository')
    @patch('agents.publish.publish_ledger_agent.Web3')
    def test_ledger_agent_retrieves_scan_from_database(self, mock_web3, mock_ledger_repo_class, mock_scan_repo_class):
        """Test that ledger agent properly retrieves scan data from database."""
        # Setup mocks
        mock_scan_repo = Mock()
        mock_scan = Mock()
        mock_scan.id = self.scan_id
        mock_scan.validator_address_id = 123
        mock_scan.score = 85
        mock_scan.scan_date = datetime.utcnow()
        mock_scan.failed = False
        mock_scan.scan_results = {'test': 'data'}
        mock_scan_repo.get_scan_by_id.return_value = mock_scan
        mock_scan_repo_class.return_value.__enter__.return_value = mock_scan_repo
        
        mock_ledger_repo = Mock()
        mock_ledger_repo.is_scan_published.return_value = False
        mock_ledger_repo_class.return_value = mock_ledger_repo
        
        # Create ledger agent with mocked blockchain connection
        with patch.object(PublishLedgerAgent, '_initialize_blockchain_connection'):
            ledger_agent = PublishLedgerAgent(self.config)
            ledger_agent.w3 = Mock()
            ledger_agent.contract = Mock()
            ledger_agent.is_publisher = True
            
            # Mock the blockchain transaction
            with patch.object(ledger_agent, 'publish_single_scan') as mock_publish:
                mock_publish.return_value = {
                    'success': True,
                    'transaction_hash': 'test_hash',
                    'confirmed': True
                }
                
                # Execute
                result = ledger_agent.execute(scan_id=self.scan_id)
        
        # Verify scan was retrieved from database
        mock_scan_repo.get_scan_by_id.assert_called_once_with(self.scan_id)
        
        # Verify duplicate check was performed
        mock_ledger_repo.is_scan_published.assert_called_once_with(self.scan_id)
        
        # Verify success
        assert result['success'] is True


class TestWalrusIndependence:
    """Test suite to ensure Walrus publishing is completely independent."""

    def test_walrus_agent_import_isolation(self):
        """Test that Walrus-related code doesn't interfere with core publishing."""
        # Import core publishing modules
        from agents.publish.publisher_agent import PublisherAgent
        from agents.publish.publish_ledger_agent import PublishLedgerAgent
        
        # These should work even if Walrus dependencies are missing
        config = Config()
        publisher = PublisherAgent(config)
        
        with patch.object(PublishLedgerAgent, '_initialize_blockchain_connection'):
            ledger_agent = PublishLedgerAgent(config)
        
        # Verify objects were created successfully
        assert publisher is not None
        assert ledger_agent is not None

    def test_missing_walrus_dependencies_do_not_break_ledger_publishing(self):
        """Test that missing Walrus dependencies don't break ledger functionality."""
        # Simulate missing Walrus dependencies
        with patch.dict('sys.modules', {'storage.walrus_provider': None}):
            # This should still work
            from agents.publish.publisher_agent import PublisherAgent
            
            config = Config()
            publisher = PublisherAgent(config)
            
            # Should be able to create without Walrus
            assert publisher is not None


if __name__ == '__main__':
    pytest.main([__file__])
