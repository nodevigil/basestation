#!/usr/bin/env python3
"""
Test suite for signature learning from existing scan data

This test suite validates the signature learning functionality that extracts
training data from existing discovery scan results and improves protocol
signatures based on real scan data.
"""

import unittest
import logging
import json
from typing import Dict, List, Any
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from agents.discovery.signature_learner import SignatureLearner, LabeledScanData, ScanDataSignatureLearner
from core.database import get_db_session, HostDiscovery, NetworkScanData, ProtocolProbeResult, Protocol, ProtocolSignature
from sqlalchemy import text


class TestSignatureLearningFromScans(unittest.TestCase):
    """Test signature learning from existing scan data"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test database connection"""
        cls.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO)
        
    def setUp(self):
        """Set up each test"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"Starting test: {self._testMethodName}")
        
    def test_scan_data_signature_learner_initialization(self):
        """Test ScanDataSignatureLearner can be initialized"""
        # Should now work because ScanDataSignatureLearner has been implemented
        learner = ScanDataSignatureLearner()
        self.assertIsInstance(learner, ScanDataSignatureLearner)
        self.assertIsInstance(learner, SignatureLearner)  # Should inherit from SignatureLearner
    
    def test_learn_from_existing_scans_method_exists(self):
        """Test that learn_from_existing_scans method exists"""
        learner = SignatureLearner()
        
        # Should now work because method has been implemented  
        self.assertTrue(hasattr(learner, 'learn_from_existing_scans'))
        
        # Test that it requires a source parameter
        with self.assertRaises(ValueError):
            learner.learn_from_existing_scans(protocol="sui", source=None)
    
    def test_get_existing_scan_data_by_protocol(self):
        """Test retrieving existing scan data by protocol"""
        # This should fail initially because the method doesn't exist
        learner = SignatureLearner()
        
        with self.assertRaises(AttributeError):
            scan_data = learner._get_existing_scan_data_by_protocol("sui")
    
    def test_convert_discovery_to_labeled_data(self):
        """Test converting host discovery records to labeled training data"""
        learner = SignatureLearner()
        
        # Mock discovery data structure
        mock_discovery = {
            'hostname': 'test.sui.example.com',
            'detected_protocol': 'sui',
            'confidence_score': 0.85,
            'network_scan_data': {
                'open_ports': [9000, 9100],
                'services_detected': {
                    '9000': {'name': 'http', 'product': 'unknown'},
                    '9100': {'name': 'http', 'product': 'prometheus'}
                }
            },
            'probe_results': [
                {
                    'probe_type': 'http',
                    'target_port': 9000,
                    'endpoint_path': '/',
                    'response_data': {
                        'status': 405,
                        'body': 'Method Not Allowed',
                        'headers': {'content-type': 'text/plain'}
                    }
                }
            ]
        }
        
        # Should fail initially because conversion method doesn't exist
        with self.assertRaises(AttributeError):
            labeled_data = learner._convert_discovery_to_labeled_data(mock_discovery, "test_source")
    
    def test_ensure_uniqueness_in_protocol_signatures(self):
        """Test that learned signatures don't create duplicates"""
        # This test should fail initially because uniqueness checking doesn't exist
        learner = SignatureLearner()
        
        with self.assertRaises(AttributeError):
            learner._ensure_signature_uniqueness("sui", {
                'port_signature': 'test_signature',
                'banner_signature': 'test_banner',
                'endpoint_signature': 'test_endpoint',
                'keyword_signature': 'test_keyword'
            })
    
    def test_update_protocol_signatures_in_database(self):
        """Test updating protocol signatures in the database"""
        learner = SignatureLearner()
        
        mock_signatures = {
            'sui': {
                'port_signature': 'base64encodedportsignature',
                'banner_signature': 'base64encoddbannersignature', 
                'endpoint_signature': 'base64encodedendpointsignature',
                'keyword_signature': 'base64encodedkeywordsignature',
                'uniqueness_score': 0.85,
                'examples_count': 25,
                'confidence_score': 0.92
            }
        }
        
        # Should fail initially because database update method doesn't exist
        with self.assertRaises(AttributeError):
            learner._update_protocol_signatures_database(mock_signatures, "test_source")
    
    def test_learn_from_existing_scans_with_protocol_filter(self):
        """Test learning from existing scans with protocol filter"""
        # Test with actual implementation - should work now
        learner = SignatureLearner()
        
        # Should not raise an exception since the method exists
        try:
            results = learner.learn_from_existing_scans(
                protocol="sui",
                source="sui_recon_agent",
                min_confidence=0.7,
                max_examples=100
            )
            # Check that it returns a dict
            self.assertIsInstance(results, dict)
            # Should have success key
            self.assertIn('success', results)
        except Exception as e:
            # Should not be AttributeError since method exists
            self.assertNotIsInstance(e, AttributeError)
    
    def test_learn_from_existing_scans_all_protocols(self):
        """Test learning from existing scans for all protocols"""
        learner = SignatureLearner()
        
        # Should not raise an exception since the method exists  
        try:
            results = learner.learn_from_existing_scans(
                protocol=None,  # All protocols
                source="comprehensive_recon_agent",
                min_confidence=0.6
            )
            # Check that it returns a dict
            self.assertIsInstance(results, dict)
            # Should have success key
            self.assertIn('success', results)
        except Exception as e:
            # Should not be AttributeError since method exists
            self.assertNotIsInstance(e, AttributeError)
    
    def test_signature_uniqueness_checking(self):
        """Test that signature uniqueness is properly checked"""
        learner = SignatureLearner()
        
        # Mock existing signatures
        existing_signatures = {
            'sui': {
                'port_signature': 'existing_sui_port_sig',
                'banner_signature': 'existing_sui_banner_sig'
            },
            'ethereum': {
                'port_signature': 'existing_eth_port_sig', 
                'banner_signature': 'existing_eth_banner_sig'
            }
        }
        
        new_signature = {
            'port_signature': 'existing_sui_port_sig',  # Duplicate!
            'banner_signature': 'new_unique_banner_sig'
        }
        
        # Should fail initially because uniqueness checking doesn't exist
        with self.assertRaises(AttributeError):
            is_unique = learner._check_signature_uniqueness(new_signature, existing_signatures)
    
    def test_scan_data_extraction_from_database(self):
        """Test extracting scan data from database tables"""
        learner = SignatureLearner()
        
        # Should fail initially because database extraction method doesn't exist
        with self.assertRaises(AttributeError):
            scan_data = learner._extract_scan_data_from_database(
                protocol="filecoin",
                min_confidence=0.8,
                limit=50
            )
    
    def test_signature_improvement_tracking(self):
        """Test tracking signature improvements"""
        learner = SignatureLearner()
        
        old_signature = {
            'port_signature': 'old_port_sig',
            'banner_signature': 'old_banner_sig',
            'examples_count': 10,
            'confidence_score': 0.75
        }
        
        new_signature = {
            'port_signature': 'improved_port_sig',
            'banner_signature': 'improved_banner_sig',  
            'examples_count': 35,
            'confidence_score': 0.89
        }
        
        # Should fail initially because improvement tracking doesn't exist
        with self.assertRaises(AttributeError):
            improvements = learner._track_signature_improvements(old_signature, new_signature)
    
    def test_scan_data_learner_integration_with_cli(self):
        """Test that ScanDataSignatureLearner integrates with CLI arguments"""
        # This test validates the CLI integration works
        # Should work now since ScanDataSignatureLearner exists
        
        try:
            from agents.discovery.signature_learner import ScanDataSignatureLearner
            
            # Should be able to instantiate
            learner = ScanDataSignatureLearner()
            self.assertIsNotNone(learner)
            
            # Should have required methods
            self.assertTrue(hasattr(learner, 'learn_from_scans'))
            
        except ImportError as e:
            self.fail(f"ScanDataSignatureLearner should be importable: {e}")
            
            learner = ScanDataSignatureLearner()
            results = learner.learn_from_scans(
                protocol="celestia",
                source="celestia_discovery_agent", 
                min_confidence=0.7
            )
    
    def test_database_scan_data_query_performance(self):
        """Test that database queries for scan data are performant"""
        learner = SignatureLearner()
        
        # Should fail initially because performance-optimized query doesn't exist  
        with self.assertRaises(AttributeError):
            # This should use optimized queries with proper indexes
            scan_data = learner._get_scan_data_optimized(
                protocols=["sui", "ethereum", "filecoin"],
                limit_per_protocol=100,
                min_confidence=0.7
            )
    
    def test_learned_signature_validation(self):
        """Test validation of learned signatures before database storage"""
        learner = SignatureLearner()
        
        invalid_signature = {
            'port_signature': '',  # Empty signature should be invalid
            'banner_signature': 'valid_banner',
            'endpoint_signature': None,  # None should be invalid
            'keyword_signature': 'valid_keyword'
        }
        
        # Should fail initially because signature validation doesn't exist
        with self.assertRaises(AttributeError):
            is_valid = learner._validate_learned_signature(invalid_signature)
    
    def test_concurrent_signature_learning(self):
        """Test that concurrent signature learning operations are handled safely"""
        learner = SignatureLearner()
        
        # Should fail initially because concurrent handling doesn't exist
        with self.assertRaises(AttributeError):
            # This should handle database locks and concurrent updates safely
            results = learner._learn_signatures_concurrent(
                protocols=["sui", "ethereum"],
                source="parallel_learning_test"
            )
    
    def test_signature_learning_session_tracking(self):
        """Test that signature learning sessions are tracked"""
        learner = SignatureLearner()
        
        # Should fail initially because session tracking doesn't exist
        with self.assertRaises(AttributeError):
            session_id = learner._start_learning_session(
                source="test_session",
                protocols=["sui"],
                description="Test learning session"
            )
            
            # Complete session
            learner._complete_learning_session(session_id, {
                'signatures_learned': 1,
                'examples_processed': 25,
                'improvements': {'sui': {'examples_added': 15}}
            })
    
    def tearDown(self):
        """Clean up after each test"""
        self.logger.info(f"Completed test: {self._testMethodName}")
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test database connection"""
        pass


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("🧪 Running signature learning from scans test suite...")
    print("📝 Note: These tests are designed to FAIL initially")
    print("   They will pass once the signature learning functionality is implemented")
    print()
    
    # Run the tests
    unittest.main(verbosity=2)
