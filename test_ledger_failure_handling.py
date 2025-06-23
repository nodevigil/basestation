#!/usr/bin/env python3
"""
Test script to verify ledger publishing failure handling.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from repositories.ledger_repository import LedgerRepository
from datetime import datetime

def test_failed_attempts_tracking():
    """Test that failed publish attempts are properly tracked."""
    
    print("🔍 Testing ledger publish failure tracking...")
    
    # Initialize repository
    ledger_repo = LedgerRepository()
    
    # Test scan ID (using a non-existent scan for testing)
    test_scan_id = 99999
    
    # Clean up any existing test data
    try:
        with ledger_repo.db_config.get_session() as session:
            from models.ledger import LedgerPublishLog
            session.query(LedgerPublishLog).filter(
                LedgerPublishLog.scan_id == test_scan_id
            ).delete()
            session.commit()
        print(f"✅ Cleaned up existing test data for scan {test_scan_id}")
    except Exception as e:
        print(f"⚠️  Could not clean up test data: {e}")
    
    # Test 1: Check scan is not published initially
    is_published_before = ledger_repo.is_scan_published(test_scan_id)
    print(f"📊 Scan {test_scan_id} published before test: {is_published_before}")
    
    # Test 2: Create a failed publish attempt
    print(f"📊 Creating failed publish attempt for scan {test_scan_id}...")
    failed_log = ledger_repo.create_publish_log(
        scan_id=test_scan_id,
        success=False,
        error_message="Test transaction failure",
        error_type="TestError",
        transaction_hash=None,
        host_uid=f"test_host_{test_scan_id}",
        trust_score=50
    )
    print(f"✅ Created failed log entry: {failed_log.id}")
    
    # Test 3: Check scan is still not considered published
    is_published_after_failure = ledger_repo.is_scan_published(test_scan_id)
    print(f"📊 Scan {test_scan_id} published after failure: {is_published_after_failure}")
    
    # Test 4: Get failed attempts
    failed_attempts = ledger_repo.get_failed_attempts_for_scan(test_scan_id)
    print(f"📊 Failed attempts for scan {test_scan_id}: {len(failed_attempts)}")
    if failed_attempts:
        latest_failure = failed_attempts[0]
        print(f"📊 Latest failure: {latest_failure.error_message}")
    
    # Test 5: Get publish status
    publish_status = ledger_repo.get_scan_publish_status(test_scan_id)
    print(f"📊 Publish status: {publish_status}")
    
    # Test 6: Create a successful publish attempt
    print(f"📊 Creating successful publish attempt for scan {test_scan_id}...")
    success_log = ledger_repo.create_publish_log(
        scan_id=test_scan_id,
        success=True,
        transaction_hash="0x1234567890abcdef",
        summary_hash="0xabcdef1234567890",
        transaction_confirmed=True,
        host_uid=f"test_host_{test_scan_id}",
        trust_score=75
    )
    print(f"✅ Created successful log entry: {success_log.id}")
    
    # Test 7: Check scan is now considered published
    is_published_after_success = ledger_repo.is_scan_published(test_scan_id)
    print(f"📊 Scan {test_scan_id} published after success: {is_published_after_success}")
    
    # Test 8: Get updated publish status
    publish_status_after = ledger_repo.get_scan_publish_status(test_scan_id)
    print(f"📊 Updated publish status: {publish_status_after}")
    
    # Test 9: Get retry count
    retry_count = ledger_repo.get_scan_retry_count(test_scan_id)
    print(f"📊 Total retry count: {retry_count}")
    
    # Clean up test data
    try:
        with ledger_repo.db_config.get_session() as session:
            from models.ledger import LedgerPublishLog
            session.query(LedgerPublishLog).filter(
                LedgerPublishLog.scan_id == test_scan_id
            ).delete()
            session.commit()
        print(f"✅ Cleaned up test data for scan {test_scan_id}")
    except Exception as e:
        print(f"⚠️  Could not clean up test data: {e}")
    
    # Verify results
    expected_results = {
        'published_before': False,
        'published_after_failure': False,
        'published_after_success': True,
        'failed_attempts_count': 1,
        'total_attempts': 2
    }
    
    actual_results = {
        'published_before': is_published_before,
        'published_after_failure': is_published_after_failure, 
        'published_after_success': is_published_after_success,
        'failed_attempts_count': len(failed_attempts),
        'total_attempts': retry_count
    }
    
    print(f"\n📋 Test Results:")
    print(f"Expected: {expected_results}")
    print(f"Actual:   {actual_results}")
    
    success = actual_results == expected_results
    print(f"\n{'✅ All tests passed!' if success else '❌ Some tests failed!'}")
    
    return success

if __name__ == "__main__":
    test_failed_attempts_tracking()
