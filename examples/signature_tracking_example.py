#!/usr/bin/env python3
"""
Example: Protocol Signature Creation Tracking

This example demonstrates how to use the new signature_created flag
to track which scans have been processed for protocol signature generation.
"""

import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import get_db_session
from core.config import Config
from services.scan_service import ScanService
from models.validator import ValidatorScan

def example_signature_tracking():
    """
    Demonstrate the signature creation tracking functionality.
    """
    print("🔍 Protocol Signature Creation Tracking Example")
    print("=" * 60)
    
    # Initialize the scan service
    scan_service = ScanService()
    
    # 1. Show current signature creation statistics
    print("\n📊 1. Current Signature Creation Statistics:")
    stats = scan_service.get_signature_creation_stats()
    
    print(f"   • Total scans: {stats['total_scans']}")
    print(f"   • Signatures created: {stats['signatures_created']}")
    print(f"   • Signatures pending: {stats['pending_signatures']}")
    print(f"   • Completion rate: {stats['completion_rate']:.1%}")
    
    if stats['protocol_breakdown']:
        print("\n   Protocol breakdown:")
        for protocol_stat in stats['protocol_breakdown']:
            protocol = protocol_stat['protocol']
            total = protocol_stat['total_scans']
            created = protocol_stat['signatures_created']
            pending = protocol_stat['pending']
            
            print(f"     • {protocol}: {created}/{total} ({created/total*100:.1f}% complete)")
    
    # 2. Get scans that need signature creation
    print(f"\n🔍 2. Getting Scans Pending Signature Creation:")
    
    # Example: Get all pending scans
    pending_scans = scan_service.get_scans_pending_signature_creation()
    print(f"   Found {len(pending_scans)} scans pending signature creation")
    
    # Example: Get pending scans for a specific protocol
    sui_pending = scan_service.get_scans_pending_signature_creation(protocol_filter='sui')
    print(f"   Found {len(sui_pending)} Sui scans pending signature creation")
    
    # 3. Demonstrate marking a scan as signature created
    if pending_scans:
        print(f"\n✅ 3. Marking Sample Scan as Signature Created:")
        sample_scan = pending_scans[0]
        
        print(f"   Sample scan ID: {sample_scan.id}")
        print(f"   IP address: {sample_scan.ip_address}")
        print(f"   Scan date: {sample_scan.scan_date}")
        
        # Get detected protocol from scan results
        detected_protocol = 'unknown'
        if sample_scan.scan_results:
            detected_protocol = sample_scan.scan_results.get('detected_protocol', 'unknown')
        print(f"   Detected protocol: {detected_protocol}")
        
        # Mark as signature created (only if we have a definitive protocol)
        if detected_protocol and detected_protocol != 'unknown':
            success = scan_service.mark_signature_created(sample_scan.id)
            if success:
                print(f"   ✅ Successfully marked scan {sample_scan.id} as signature created")
            else:
                print(f"   ❌ Failed to mark scan {sample_scan.id}")
        else:
            print(f"   ⏭️  Skipping scan (no definitive protocol detected)")
    
    # 4. Show updated statistics
    print(f"\n📈 4. Updated Statistics:")
    updated_stats = scan_service.get_signature_creation_stats()
    
    print(f"   • Total scans: {updated_stats['total_scans']}")
    print(f"   • Signatures created: {updated_stats['signatures_created']}")
    print(f"   • Signatures pending: {updated_stats['pending_signatures']}")
    print(f"   • Completion rate: {updated_stats['completion_rate']:.1%}")
    
    # 5. Show example database queries
    print(f"\n🗄️  5. Example Database Queries:")
    
    try:
        with get_db_session() as session:
            # Count scans by signature creation status
            total_scans = session.query(ValidatorScan).filter(
                ValidatorScan.failed == False,
                ValidatorScan.scan_results.isnot(None)
            ).count()
            
            created_count = session.query(ValidatorScan).filter(
                ValidatorScan.failed == False,
                ValidatorScan.signature_created == True
            ).count()
            
            pending_count = session.query(ValidatorScan).filter(
                ValidatorScan.failed == False,
                ValidatorScan.signature_created == False,
                ValidatorScan.scan_results.isnot(None)
            ).count()
            
            print(f"   • Direct SQL counts:")
            print(f"     - Total valid scans: {total_scans}")
            print(f"     - Signatures created: {created_count}")
            print(f"     - Signatures pending: {pending_count}")
            
            # Example: Get recent scans that need signature creation
            from sqlalchemy import text
            recent_pending = session.execute(text("""
                SELECT id, ip_address, scan_date, 
                       scan_results->>'detected_protocol' as protocol
                FROM validator_scans 
                WHERE failed = false 
                  AND signature_created = false
                  AND scan_results IS NOT NULL
                  AND scan_results->>'detected_protocol' IS NOT NULL
                  AND scan_results->>'detected_protocol' != 'unknown'
                ORDER BY scan_date DESC 
                LIMIT 5
            """)).fetchall()
            
            print(f"\n   • Recent scans needing signature creation:")
            for scan in recent_pending:
                print(f"     - Scan {scan.id}: {scan.ip_address} ({scan.protocol}) - {scan.scan_date}")
    
    except Exception as e:
        print(f"   ❌ Database query error: {e}")
    
    print(f"\n💡 CLI Usage Examples:")
    print(f"   # Show signature statistics")
    print(f"   python cli.py --show-signature-stats")
    print(f"   ")
    print(f"   # Update signature flags for all protocols")
    print(f"   python cli.py --update-signature-flags")
    print(f"   ")
    print(f"   # Update signature flags for specific protocol")
    print(f"   python cli.py --update-signature-flags --protocol-filter sui")
    print(f"   ")
    print(f"   # Mark specific scan as signature created")
    print(f"   python cli.py --mark-signature-created 123")
    print(f"   ")
    print(f"   # Learn signatures from existing scans")
    print(f"   python cli.py --learn-signatures-from-scans --protocol sui")


if __name__ == "__main__":
    try:
        example_signature_tracking()
        print(f"\n🎉 Example completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Example failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
