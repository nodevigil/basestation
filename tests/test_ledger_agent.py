"""
Test suite for the PublishLedgerAgent and LedgerRepository.

This test suite covers:
- Database operations with the ledger repository
- Ledger agent functionality with mocked blockchain interactions
- Integration tests with the test database
- Error handling and edge cases
"""

import os
import sys
import pytest
import unittest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import json

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set test database environment
os.environ['DATABASE_URL'] = 'postgresql://simon@localhost/test_depin'

from agents.publish.publish_ledger_agent import PublishLedgerAgent, DePINLedgerError
from pgdn.repositories.ledger_repository import LedgerRepository
from pgdn.models.ledger import LedgerPublishLog, LedgerBatch, LedgerConnectionLog
from pgdn.core.config import Config


class TestLedgerRepository(unittest.TestCase):
    """Test cases for the LedgerRepository class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.repo = LedgerRepository()
        # Test data cleanup is handled automatically by conftest.py
    
    # No tearDown needed - handled automatically by conftest.py
    # Manual cleanup method removed - handled by conftest.py
    
    def test_create_publish_log(self):
        """Test creating a publish log entry."""
        log_entry = self.repo.create_publish_log(
            scan_id=1,  # Use valid scan ID
            publishing_agent='TestAgent',
            success=True,
            transaction_hash='0x123abc',
            host_uid='test_host_001',
            trust_score=85
        )
        
        self.assertIsNotNone(log_entry)
        self.assertEqual(log_entry.scan_id, 1)
        self.assertEqual(log_entry.publishing_agent, 'TestAgent')
        self.assertTrue(log_entry.success)
        self.assertEqual(log_entry.transaction_hash, '0x123abc')
        self.assertEqual(log_entry.host_uid, 'test_host_001')
        self.assertEqual(log_entry.trust_score, 85)
        self.assertIsNotNone(log_entry.uuid)
        self.assertIsNotNone(log_entry.attempt_timestamp)
    
    def test_update_publish_log(self):
        """Test updating a publish log entry."""
        # Create initial log
        log_entry = self.repo.create_publish_log(
            scan_id=2,  # Use valid scan ID
            publishing_agent='TestAgent',
            success=False
        )
        
        # Update the log
        updated_log = self.repo.update_publish_log(
            log_entry.id,
            success=True,
            transaction_hash='0x456def',
            block_number=123456,
            gas_used=21000
        )
        
        self.assertIsNotNone(updated_log)
        self.assertTrue(updated_log.success)
        self.assertEqual(updated_log.transaction_hash, '0x456def')
        self.assertEqual(updated_log.block_number, 123456)
        self.assertEqual(updated_log.gas_used, 21000)
    
    def test_get_publish_logs_for_scan(self):
        """Test retrieving logs for a specific scan."""
        scan_id = 3  # Use valid scan ID
        
        # Create multiple logs for the same scan
        log1 = self.repo.create_publish_log(scan_id=scan_id, publishing_agent='TestAgent')
        log2 = self.repo.create_publish_log(scan_id=scan_id, publishing_agent='TestAgent')
        
        # Create log for different scan
        self.repo.create_publish_log(scan_id=10, publishing_agent='TestAgent')  # Use valid scan ID instead of 99999
        
        logs = self.repo.get_publish_logs_for_scan(scan_id)
        
        self.assertEqual(len(logs), 2)
        self.assertTrue(all(log.scan_id == scan_id for log in logs))
    
    def test_create_batch_log(self):
        """Test creating a batch log entry."""
        batch_log = self.repo.create_batch_log(
            batch_size=5,
            successful_publishes=4,
            failed_publishes=1,
            transaction_hash='0x789ghi',
            extra_data={'test': True}
        )
        
        self.assertIsNotNone(batch_log)
        self.assertEqual(batch_log.batch_size, 5)
        self.assertEqual(batch_log.successful_publishes, 4)
        self.assertEqual(batch_log.failed_publishes, 1)
        self.assertEqual(batch_log.transaction_hash, '0x789ghi')
        self.assertEqual(batch_log.extra_data['test'], True)
    
    def test_create_connection_log(self):
        """Test creating a connection log entry."""
        connection_log = self.repo.create_connection_log(
            agent_name='TestAgent',
            connection_successful=True,
            contract_loaded=True,
            is_authorized_publisher=False,
            rpc_url='https://test.rpc.url',
            account_address='0xtest123'
        )
        
        self.assertIsNotNone(connection_log)
        self.assertEqual(connection_log.agent_name, 'TestAgent')
        self.assertTrue(connection_log.connection_successful)
        self.assertTrue(connection_log.contract_loaded)
        self.assertFalse(connection_log.is_authorized_publisher)
        self.assertEqual(connection_log.rpc_url, 'https://test.rpc.url')
    
    def test_get_publish_stats(self):
        """Test getting publish statistics."""
        # Create some test logs with different outcomes
        now = datetime.utcnow()
        
        # Successful logs
        for i in range(3):
            self.repo.create_publish_log(
                scan_id=4 + i,  # Use valid scan IDs: 4, 5, 6
                publishing_agent='TestAgent',
                success=True,
                processing_duration_ms=1000 + i * 100
            )
        
        # Failed logs
        for i in range(2):
            self.repo.create_publish_log(
                scan_id=7 + i,  # Use valid scan IDs: 7, 8
                publishing_agent='TestAgent',
                success=False
            )
        
        stats = self.repo.get_publish_stats(hours_back=1)
        
        self.assertEqual(stats['total_publish_attempts'], 5)
        self.assertEqual(stats['successful_publishes'], 3)
        self.assertEqual(stats['failed_publishes'], 2)
        self.assertEqual(stats['publish_success_rate'], 60.0)
        self.assertEqual(stats['unique_scans_published'], 3)
        self.assertIsNotNone(stats['average_processing_time_ms'])


class TestPublishLedgerAgentUnit(unittest.TestCase):
    """Unit tests for PublishLedgerAgent with mocked dependencies."""
    
    def setUp(self):
        """Set up test fixtures with mocked blockchain connection."""
        # Mock environment variables
        self.env_patcher = patch.dict(os.environ, {
            'ZKSYNC_RPC_URL': 'https://test.rpc.url',
            'CONTRACT_ADDRESS': '0x1234567890123456789012345678901234567890',
            'PRIVATE_KEY': '0x' + '1' * 64  # Fake private key
        })
        self.env_patcher.start()
        
        # Mock Web3 and blockchain components
        self.web3_patcher = patch('agents.publish.publish_ledger_agent.Web3')
        self.mock_web3_class = self.web3_patcher.start()
        
        self.account_patcher = patch('agents.publish.publish_ledger_agent.Account')
        self.mock_account_class = self.account_patcher.start()
        
        # Configure mocks
        self.mock_web3 = Mock()
        self.mock_web3.is_connected.return_value = True
        self.mock_web3.to_checksum_address.return_value = '0x1234567890123456789012345678901234567890'
        self.mock_web3.from_wei.return_value = 1.5
        self.mock_web3.to_wei.return_value = 250000000  # 0.25 gwei
        self.mock_web3.eth.get_balance.return_value = 1500000000000000000  # 1.5 ETH
        self.mock_web3.eth.get_transaction_count.return_value = 42
        self.mock_web3.eth.send_raw_transaction.return_value.hex.return_value = '0xabc123'
        
        # Create a mock receipt object with proper attributes for unit tests
        mock_receipt = Mock()
        mock_receipt.status = 1
        mock_receipt.__getitem__ = lambda self, key: {
            'status': 1,
            'blockNumber': 123456,
            'gasUsed': 21000,
            'logs': []
        }[key]
        mock_receipt.__contains__ = lambda self, key: key in ['status', 'blockNumber', 'gasUsed', 'logs']
        mock_receipt.keys = lambda: ['status', 'blockNumber', 'gasUsed', 'logs']
        mock_receipt.items = lambda: [('status', 1), ('blockNumber', 123456), ('gasUsed', 21000), ('logs', [])]
        self.mock_web3.eth.wait_for_transaction_receipt.return_value = mock_receipt
        
        self.mock_web3_class.HTTPProvider.return_value = Mock()
        self.mock_web3_class.return_value = self.mock_web3
        
        self.mock_account = Mock()
        self.mock_account.address = '0xpublisher123'
        self.mock_account_class.from_key.return_value = self.mock_account
        
        # Mock contract
        self.mock_contract = Mock()
        self.mock_contract.functions.authorizedPublishers.return_value.call.return_value = True
        self.mock_contract.functions.getContractInfo.return_value.call.return_value = [
            '3.0.0', False, 100, 300, 50, 25
        ]
        
        self.mock_web3.eth.contract.return_value = self.mock_contract
    
    def tearDown(self):
        """Clean up patches."""
        self.env_patcher.stop()
        self.web3_patcher.stop()
        self.account_patcher.stop()
    
    def test_agent_initialization(self):
        """Test agent initialization with mocked blockchain."""
        agent = PublishLedgerAgent()
        
        self.assertEqual(agent.agent_name, 'PublishLedgerAgent')
        self.assertIsNotNone(agent.ledger_repo)
        self.assertTrue(agent.w3.is_connected())
        self.assertTrue(agent.is_publisher)
        self.assertEqual(agent.account.address, '0xpublisher123')
    
    def test_abi_loading(self):
        """Test ABI loading functionality."""
        agent = PublishLedgerAgent()
        
        # Test that ABI loading doesn't crash
        abi = agent._load_abi_from_file()
        self.assertIsInstance(abi, list)
        self.assertTrue(len(abi) > 0)
    
    def test_scan_formatting(self):
        """Test scan result formatting for ledger."""
        agent = PublishLedgerAgent()
        
        test_scan = {
            'scan_id': 123,
            'host_uid': 'test_host_001',
            'scan_time': 1719072000,
            'trust_score': 85,
            'vulnerabilities': [{'cve': 'CVE-2024-1234', 'severity': 'high'}],
            'open_ports': [22, 80, 443],
            'services': ['ssh', 'http', 'https']
        }
        
        formatted = agent._format_scan_for_ledger(test_scan)
        
        self.assertEqual(formatted['host_uid'], 'test_host_001')
        self.assertEqual(formatted['scan_time'], 1719072000)
        self.assertEqual(formatted['score'], 85)
        self.assertIn('summary_hash', formatted)
        self.assertIn('report_pointer', formatted)
        self.assertTrue(formatted['summary_hash'].startswith('0x'))
        self.assertEqual(len(formatted['summary_hash']), 66)  # 0x + 64 hex chars
    
    @patch('agents.publish.publish_ledger_agent.LedgerRepository')
    def test_publish_single_scan_success(self, mock_repo_class):
        """Test successful single scan publishing."""
        # Mock repository
        mock_repo = Mock()
        mock_log_entry = Mock()
        mock_log_entry.id = 123
        mock_repo.create_publish_log.return_value = mock_log_entry
        mock_repo_class.return_value = mock_repo
        
        # Mock transaction building and sending
        mock_function_call = Mock()
        mock_function_call.build_transaction.return_value = {'nonce': 42}
        self.mock_contract.functions.publishScanSummary.return_value = mock_function_call
        
        # Mock account signing
        mock_signed_txn = Mock()
        mock_signed_txn.raw_transaction = b'\\x01\\x02\\x03'
        self.mock_account.sign_transaction.return_value = mock_signed_txn
        
        agent = PublishLedgerAgent()
        
        test_scan = {
            'scan_id': 123,
            'host_uid': 'test_host_001',
            'scan_time': 1719072000,
            'trust_score': 85
        }
        
        result = agent.publish_single_scan(test_scan, wait_for_confirmation=False)
        
        self.assertTrue(result['success'])
        self.assertIn('transaction_hash', result)
        self.assertEqual(result['host_uid'], 'test_host_001')
        self.assertEqual(result['score'], 85)
        
        # Verify repository interactions
        mock_repo.create_publish_log.assert_called_once()
        mock_repo.update_publish_log.assert_called()
    
    def test_publish_single_scan_unauthorized(self):
        """Test publishing when not authorized."""
        # Make the agent unauthorized
        self.mock_contract.functions.authorizedPublishers.return_value.call.return_value = False
        
        agent = PublishLedgerAgent()
        
        test_scan = {'scan_id': 123, 'host_uid': 'test_host_001'}
        
        with self.assertRaises(DePINLedgerError) as context:
            agent.publish_single_scan(test_scan)
        
        self.assertIn("not authorized", str(context.exception))
    
    def test_get_ledger_status(self):
        """Test getting ledger status."""
        agent = PublishLedgerAgent()
        
        status = agent.get_ledger_status()
        
        self.assertTrue(status['connected'])
        self.assertEqual(status['rpc_url'], 'https://test.rpc.url')
        self.assertEqual(status['account_address'], '0xpublisher123')
        self.assertTrue(status['is_publisher'])
        self.assertIn('contract_info', status)


class TestPublishLedgerAgentIntegration(unittest.TestCase):
    """Integration tests with real database but mocked blockchain."""
    
    def setUp(self):
        """Set up integration test fixtures."""
        # Mock blockchain but use real database
        self.env_patcher = patch.dict(os.environ, {
            'DATABASE_URL': 'postgresql://simon@localhost/test_depin',
            'ZKSYNC_RPC_URL': 'https://test.rpc.url',
            'CONTRACT_ADDRESS': '0x1234567890123456789012345678901234567890',
            'PRIVATE_KEY': '0x' + '1' * 64
        })
        self.env_patcher.start()
        
        # Mock Web3 components
        self.web3_patcher = patch('agents.publish.publish_ledger_agent.Web3')
        self.mock_web3_class = self.web3_patcher.start()
        
        self.account_patcher = patch('agents.publish.publish_ledger_agent.Account')
        self.mock_account_class = self.account_patcher.start()
        
        # Configure blockchain mocks (same as unit tests)
        self._setup_blockchain_mocks()
        
        # Set up real repository for database operations
        self.repo = LedgerRepository()
        # Cleanup handled automatically by conftest.py
    
    def tearDown(self):
        """Clean up after integration tests."""
        # Cleanup handled automatically by conftest.py
        self.env_patcher.stop()
        self.web3_patcher.stop()
        self.account_patcher.stop()
    
    def _setup_blockchain_mocks(self):
        """Set up blockchain mocks (shared with unit tests)."""
        self.mock_web3 = Mock()
        self.mock_web3.is_connected.return_value = True
        self.mock_web3.to_checksum_address.return_value = '0x1234567890123456789012345678901234567890'
        self.mock_web3.from_wei.return_value = 1.5
        self.mock_web3.to_wei.return_value = 250000000
        self.mock_web3.eth.get_balance.return_value = 1500000000000000000
        self.mock_web3.eth.get_transaction_count.return_value = 42
        
        mock_tx_hash = Mock()
        mock_tx_hash.hex.return_value = '0xintegrationtest123'
        self.mock_web3.eth.send_raw_transaction.return_value = mock_tx_hash
        
        # Create a mock receipt object with proper attributes
        mock_receipt = Mock()
        mock_receipt.status = 1
        mock_receipt.__getitem__ = lambda self, key: {
            'status': 1,
            'blockNumber': 123456,
            'gasUsed': 21000,
            'logs': []
        }[key]
        mock_receipt.__contains__ = lambda self, key: key in ['status', 'blockNumber', 'gasUsed', 'logs']
        mock_receipt.keys = lambda: ['status', 'blockNumber', 'gasUsed', 'logs']
        mock_receipt.items = lambda: [('status', 1), ('blockNumber', 123456), ('gasUsed', 21000), ('logs', [])]
        self.mock_web3.eth.wait_for_transaction_receipt.return_value = mock_receipt
        
        self.mock_web3_class.HTTPProvider.return_value = Mock()
        self.mock_web3_class.return_value = self.mock_web3
        
        # Ensure Web3.to_checksum_address returns a string, not a mock
        self.mock_web3_class.to_checksum_address.return_value = '0x1234567890123456789012345678901234567890'
        
        self.mock_account = Mock()
        self.mock_account.address = '0xintegrationtest'
        self.mock_account_class.from_key.return_value = self.mock_account
        
        # Mock contract
        self.mock_contract = Mock()
        self.mock_contract.functions.authorizedPublishers.return_value.call.return_value = True
        self.mock_contract.functions.getContractInfo.return_value.call.return_value = [
            '3.0.0', False, 100, 300, 50, 25
        ]
        
        mock_function_call = Mock()
        mock_function_call.build_transaction.return_value = {
            'nonce': 42,
            'gas': 2000000,
            'gasPrice': 250000000
        }
        self.mock_contract.functions.publishScanSummary.return_value = mock_function_call
        
        # Mock transaction signing
        mock_signed_txn = Mock()
        mock_signed_txn.raw_transaction = b'\\x01\\x02\\x03'
        self.mock_account.sign_transaction.return_value = mock_signed_txn
        
        self.mock_web3.eth.contract.return_value = self.mock_contract
        
        # Cleanup handled automatically by conftest.py
    
    def test_full_publish_workflow_with_database(self):
        """Test complete publish workflow with database logging."""
        agent = PublishLedgerAgent()
        
        test_scan = {
            'scan_id': 9,  # Use valid scan ID
            'host_uid': 'integration_test_host',
            'scan_time': int(datetime.utcnow().timestamp()),
            'trust_score': 92,
            'vulnerabilities': [{'cve': 'CVE-2024-9999', 'severity': 'low'}],
            'open_ports': [22, 443],
            'services': ['ssh', 'https']
        }
        
        # Publish scan
        result = agent.publish_single_scan(test_scan, wait_for_confirmation=True)
        
        # Verify result
        self.assertTrue(result['success'])
        self.assertTrue(result['confirmed'])
        self.assertIn('log_id', result)
        
        # Verify database logging using the specific log ID returned
        log_id = result['log_id']
        log = self.repo.get_publish_log_by_id(log_id)
        self.assertIsNotNone(log)
        
        self.assertEqual(log.scan_id, 9)
        self.assertEqual(log.host_uid, 'integration_test_host')
        self.assertTrue(log.success)
        self.assertTrue(log.transaction_confirmed)
        self.assertIsNotNone(log.transaction_hash)
        self.assertEqual(log.transaction_hash, '0xintegrationtest123')
        self.assertIsNotNone(log.block_number)
        self.assertIsNotNone(log.gas_used)
    
    def test_connection_logging(self):
        """Test that connection attempts are logged to database."""
        # Create agent (this should log the connection)
        agent = PublishLedgerAgent()
        
        # Check connection logs
        connection_logs = self.repo.get_recent_connection_logs(limit=10)
        
        # Find our connection log
        our_log = None
        for log in connection_logs:
            if log.account_address == '0xintegrationtest':
                our_log = log
                break
        
        self.assertIsNotNone(our_log, "Connection log not found")
        self.assertTrue(our_log.connection_successful)
        self.assertTrue(our_log.contract_loaded)
        self.assertTrue(our_log.is_authorized_publisher)
        self.assertEqual(our_log.agent_name, 'PublishLedgerAgent')


if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)
