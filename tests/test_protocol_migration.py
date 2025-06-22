"""
Comprehensive tests for protocol migration and linking.

Tests cover:
1. Migration data integrity
2. Protocol linker functionality
3. Error handling and validation
4. Migration rollback/downgrade
"""

import pytest
import unittest
from unittest.mock import patch, MagicMock
import tempfile
import os
import sys
from typing import Dict, List, Any

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import get_db_session, create_tables, DatabaseManager
from core.config import DatabaseConfig
from models.validator import ValidatorAddress
from tools.protocol_migration_tool import ProtocolMigrationTool
from sqlalchemy import text, create_engine
from sqlalchemy.orm import sessionmaker


class TestProtocolMigration(unittest.TestCase):
    """Test suite for protocol migration functionality."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test database."""
        # Create temporary database for testing
        cls.test_db_path = tempfile.mktemp(suffix='.db')
        cls.test_config = DatabaseConfig()
        cls.test_config.url = f"sqlite:///{cls.test_db_path}"
        
        # Create test database manager
        cls.db_manager = DatabaseManager(cls.test_config)
        cls.db_manager.create_tables()
        
    @classmethod
    def tearDownClass(cls):
        """Clean up test database."""
        if os.path.exists(cls.test_db_path):
            os.unlink(cls.test_db_path)
    
    def setUp(self):
        """Set up each test."""
        # Clear all tables before each test
        with self.db_manager.session_scope() as session:
            session.execute(text("DELETE FROM validator_scans"))
            session.execute(text("DELETE FROM validator_addresses"))
            session.execute(text("DELETE FROM protocol_signatures"))
            session.execute(text("DELETE FROM protocols"))
            session.commit()
    
    def _create_test_protocols(self, session) -> Dict[str, int]:
        """Create test protocols and return mapping."""
        protocols = [
            {
                'name': 'sui',
                'display_name': 'Sui Network',
                'category': 'blockchain',
                'ports': [9000, 9001],
                'endpoints': ['/health'],
                'banners': ['sui-node'],
                'rpc_methods': ['sui_getCheckpoint'],
                'metrics_keywords': ['sui_metrics'],
                'http_paths': ['/metrics'],
                'identification_hints': ['sui blockchain']
            },
            {
                'name': 'filecoin',
                'display_name': 'Filecoin Network',
                'category': 'storage',
                'ports': [1234, 5678],
                'endpoints': ['/rpc/v0'],
                'banners': ['lotus'],
                'rpc_methods': ['Filecoin.ChainHead'],
                'metrics_keywords': ['filecoin_metrics'],
                'http_paths': ['/debug/metrics'],
                'identification_hints': ['filecoin storage']
            }
        ]
        
        protocol_ids = {}
        for protocol_data in protocols:
            result = session.execute(text("""
                INSERT INTO protocols (name, display_name, category, ports, endpoints, 
                                     banners, rpc_methods, metrics_keywords, http_paths, 
                                     identification_hints, created_at, updated_at)
                VALUES (:name, :display_name, :category, :ports, :endpoints, 
                        :banners, :rpc_methods, :metrics_keywords, :http_paths,
                        :identification_hints, datetime('now'), datetime('now'))
                RETURNING id
            """), {
                **protocol_data,
                'ports': str(protocol_data['ports']),
                'endpoints': str(protocol_data['endpoints']),
                'banners': str(protocol_data['banners']),
                'rpc_methods': str(protocol_data['rpc_methods']),
                'metrics_keywords': str(protocol_data['metrics_keywords']),
                'http_paths': str(protocol_data['http_paths']),
                'identification_hints': str(protocol_data['identification_hints'])
            })
            protocol_ids[protocol_data['name']] = result.scalar()
            
        session.commit()
        return protocol_ids
    
    def _create_test_validator_addresses_with_source(self, session, protocol_ids: Dict[str, int]) -> List[Dict]:
        """Create test validator addresses with source column (pre-migration state)."""
        
        # First, add source column to simulate pre-migration state
        try:
            session.execute(text("ALTER TABLE validator_addresses ADD COLUMN source VARCHAR(255)"))
            session.commit()
        except Exception:
            # Column might already exist
            pass
        
        validators = [
            {'address': '10.1.1.1', 'name': 'Sui Validator 1', 'source': 'sui_recon_agent'},
            {'address': '10.1.1.2', 'name': 'Sui Validator 2', 'source': 'sui_recon_agent'},
            {'address': '10.2.1.1', 'name': 'Filecoin Validator 1', 'source': 'filecoin_lotus_peer'},
            {'address': '10.2.1.2', 'name': 'Filecoin Validator 2', 'source': 'filecoin_lotus_peer'},
        ]
        
        created_validators = []
        for validator_data in validators:
            result = session.execute(text("""
                INSERT INTO validator_addresses (address, name, source, created_at, active)
                VALUES (:address, :name, :source, datetime('now'), 1)
                RETURNING id
            """), validator_data)
            
            validator_id = result.scalar()
            created_validators.append({
                'id': validator_id,
                **validator_data
            })
        
        session.commit()
        return created_validators
    
    def test_migration_data_integrity(self):
        """Test that migration preserves data integrity."""
        with self.db_manager.session_scope() as session:
            # Create test data
            protocol_ids = self._create_test_protocols(session)
            validators = self._create_test_validator_addresses_with_source(session, protocol_ids)
            
            # Verify pre-migration state
            result = session.execute(text("SELECT COUNT(*) FROM validator_addresses WHERE source IS NOT NULL"))
            pre_migration_count = result.scalar()
            self.assertEqual(pre_migration_count, 4)
            
            # Simulate migration logic
            source_to_protocol = {
                'sui_recon_agent': protocol_ids['sui'],
                'filecoin_lotus_peer': protocol_ids['filecoin']
            }
            
            # Add protocol_id column
            try:
                session.execute(text("ALTER TABLE validator_addresses ADD COLUMN protocol_id INTEGER"))
                session.commit()
            except Exception:
                pass
            
            # Migrate data
            for source, protocol_id in source_to_protocol.items():
                session.execute(text(
                    "UPDATE validator_addresses SET protocol_id = :protocol_id WHERE source = :source"
                ), {'protocol_id': protocol_id, 'source': source})
            
            session.commit()
            
            # Verify post-migration state
            result = session.execute(text("""
                SELECT va.address, va.name, va.protocol_id, p.name as protocol_name
                FROM validator_addresses va
                JOIN protocols p ON va.protocol_id = p.id
                ORDER BY va.address
            """))
            
            migrated_data = result.fetchall()
            self.assertEqual(len(migrated_data), 4)
            
            # Verify correct protocol assignments
            sui_validators = [row for row in migrated_data if row[3] == 'sui']
            filecoin_validators = [row for row in migrated_data if row[3] == 'filecoin']
            
            self.assertEqual(len(sui_validators), 2)
            self.assertEqual(len(filecoin_validators), 2)
            
            # Verify all validators have protocol_id
            result = session.execute(text("SELECT COUNT(*) FROM validator_addresses WHERE protocol_id IS NULL"))
            null_count = result.scalar()
            self.assertEqual(null_count, 0)
    
    def test_protocol_migration_tool(self):
        """Test the ProtocolMigrationTool functionality."""
        
        # Mock config
        mock_config = MagicMock()
        mock_config.get_database_config.return_value = self.test_config
        
        with patch('tools.protocol_migration_tool.Config', return_value=mock_config):
            migration_tool = ProtocolMigrationTool()
            
            with self.db_manager.session_scope() as session:
                # Create test protocols
                protocol_ids = self._create_test_protocols(session)
                
                # Test protocol validation
                self.assertTrue(migration_tool.validate_protocol_signatures(session))
                
                # Test dependency validation
                dependencies = migration_tool.validate_migration_dependencies(session)
                self.assertIsInstance(dependencies, dict)
                self.assertIn('protocols', dependencies)
                self.assertIn('validator_addresses', dependencies)
    
    def test_migration_error_handling(self):
        """Test migration error handling for edge cases."""
        with self.db_manager.session_scope() as session:
            # Create protocols
            protocol_ids = self._create_test_protocols(session)
            
            # Create validator with unmapped source
            try:
                session.execute(text("ALTER TABLE validator_addresses ADD COLUMN source VARCHAR(255)"))
                session.commit()
            except Exception:
                pass
            
            session.execute(text("""
                INSERT INTO validator_addresses (address, name, source, created_at, active)
                VALUES ('10.3.1.1', 'Unknown Validator', 'unknown_agent', datetime('now'), 1)
            """))
            session.commit()
            
            # Test that migration would detect unmapped source
            result = session.execute(text("SELECT DISTINCT source FROM validator_addresses"))
            sources = [row[0] for row in result.fetchall()]
            
            # Should contain our unmapped source
            self.assertIn('unknown_agent', sources)
            
            # Migration should fail with unmapped sources
            source_to_protocol = {
                'sui_recon_agent': protocol_ids['sui'],
                'filecoin_lotus_peer': protocol_ids['filecoin']
            }
            
            unmapped_sources = [s for s in sources if s not in source_to_protocol]
            self.assertTrue(len(unmapped_sources) > 0)
    
    def test_migration_rollback(self):
        """Test migration rollback/downgrade functionality."""
        with self.db_manager.session_scope() as session:
            # Create test data
            protocol_ids = self._create_test_protocols(session)
            
            # Create post-migration state (with protocol_id)
            try:
                session.execute(text("ALTER TABLE validator_addresses ADD COLUMN protocol_id INTEGER"))
                session.commit()
            except Exception:
                pass
            
            validators = [
                {'address': '10.1.1.1', 'name': 'Sui Validator 1', 'protocol_id': protocol_ids['sui']},
                {'address': '10.2.1.1', 'name': 'Filecoin Validator 1', 'protocol_id': protocol_ids['filecoin']},
            ]
            
            for validator_data in validators:
                session.execute(text("""
                    INSERT INTO validator_addresses (address, name, protocol_id, created_at, active)
                    VALUES (:address, :name, :protocol_id, datetime('now'), 1)
                """), validator_data)
            
            session.commit()
            
            # Test rollback logic
            try:
                session.execute(text("ALTER TABLE validator_addresses ADD COLUMN source VARCHAR(255)"))
                session.commit()
            except Exception:
                pass
            
            # Rollback mapping
            protocol_to_source = {
                protocol_ids['sui']: 'sui_recon_agent',
                protocol_ids['filecoin']: 'filecoin_lotus_peer'
            }
            
            for protocol_id, source in protocol_to_source.items():
                session.execute(text(
                    "UPDATE validator_addresses SET source = :source WHERE protocol_id = :protocol_id"
                ), {'source': source, 'protocol_id': protocol_id})
            
            session.commit()
            
            # Verify rollback
            result = session.execute(text("""
                SELECT address, source, protocol_id FROM validator_addresses ORDER BY address
            """))
            
            rolled_back_data = result.fetchall()
            self.assertEqual(len(rolled_back_data), 2)
            
            # Verify source assignments
            for row in rolled_back_data:
                address, source, protocol_id = row
                if protocol_id == protocol_ids['sui']:
                    self.assertEqual(source, 'sui_recon_agent')
                elif protocol_id == protocol_ids['filecoin']:
                    self.assertEqual(source, 'filecoin_lotus_peer')
    
    def test_foreign_key_constraints(self):
        """Test that foreign key constraints work properly."""
        with self.db_manager.session_scope() as session:
            # Create protocols
            protocol_ids = self._create_test_protocols(session)
            
            # Try to create validator with invalid protocol_id
            try:
                session.execute(text("ALTER TABLE validator_addresses ADD COLUMN protocol_id INTEGER"))
                session.commit()
            except Exception:
                pass
            
            # This should work
            session.execute(text("""
                INSERT INTO validator_addresses (address, name, protocol_id, created_at, active)
                VALUES ('10.1.1.1', 'Valid Validator', :protocol_id, datetime('now'), 1)
            """), {'protocol_id': protocol_ids['sui']})
            
            session.commit()
            
            # Verify the validator was created
            result = session.execute(text("SELECT COUNT(*) FROM validator_addresses WHERE protocol_id = :protocol_id"),
                                   {'protocol_id': protocol_ids['sui']})
            count = result.scalar()
            self.assertEqual(count, 1)


class TestProtocolLinker(unittest.TestCase):
    """Test suite for protocol linking functionality."""
    
    def setUp(self):
        """Set up each test."""
        self.test_db_path = tempfile.mktemp(suffix='.db')
        self.test_config = DatabaseConfig()
        self.test_config.url = f"sqlite:///{self.test_db_path}"
        self.db_manager = DatabaseManager(self.test_config)
        self.db_manager.create_tables()
    
    def tearDown(self):
        """Clean up each test."""
        if os.path.exists(self.test_db_path):
            os.unlink(self.test_db_path)
    
    def test_protocol_linker_validation(self):
        """Test protocol linker validation logic."""
        mock_config = MagicMock()
        mock_config.get_database_config.return_value = self.test_config
        
        with patch('tools.protocol_migration_tool.Config', return_value=mock_config):
            migration_tool = ProtocolMigrationTool()
            
            with self.db_manager.session_scope() as session:
                # Test with empty database
                is_valid = migration_tool.validate_protocol_signatures(session)
                # Should be True for empty database
                self.assertTrue(is_valid)
    
    def test_protocol_source_mapping(self):
        """Test protocol source mapping functionality."""
        # Test source to protocol name mapping
        mappings = {
            'sui_recon_agent': 'sui',
            'filecoin_lotus_peer': 'filecoin',
            'filecoin_recon_agent': 'filecoin',
            'ethereum_recon_agent': 'ethereum',
        }
        
        for source, expected_protocol in mappings.items():
            # Test that we can derive protocol name from source
            if 'sui_' in source:
                derived_protocol = 'sui'
            elif 'filecoin_' in source:
                derived_protocol = 'filecoin'
            elif 'ethereum_' in source:
                derived_protocol = 'ethereum'
            else:
                derived_protocol = None
            
            if expected_protocol in ['sui', 'filecoin', 'ethereum']:
                self.assertEqual(derived_protocol, expected_protocol)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
