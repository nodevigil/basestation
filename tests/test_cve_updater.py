#!/usr/bin/env python3
"""
Test script for CVE updater functionality.
"""

import sys
import os
from pathlib import Path

# Add the parent directory to the Python path so we can import modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.cve_updater import CVEUpdater
from core.logging import setup_logging

def test_cve_updater():
    """Test the CVE updater functionality."""
    print("🧪 Testing CVE Updater...")
    
    # Setup basic logging
    logging_config = {
        "level": "INFO",
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    }
    setup_logging(logging_config)
    
    try:
        with CVEUpdater(timeout=10) as updater:
            print("✅ CVE Updater initialized successfully")
            
            # Test fetching CVEs for a specific software
            print("\n🔍 Testing CVE fetch for nginx...")
            nginx_cves = updater.fetch_nvd_cves("nginx", limit=5)
            print(f"   Found {len(nginx_cves)} CVEs for nginx")
            
            # Test parsing CVE data
            if nginx_cves:
                print("\n📊 Testing CVE data parsing...")
                parsed = updater.parse_cve_data(nginx_cves[:2])  # Parse first 2 CVEs
                print(f"   Parsed {len(parsed)} vulnerabilities")
                
                for software, cve_desc in list(parsed.items())[:3]:  # Show first 3
                    print(f"   • {software}: {cve_desc[:80]}...")
            
            # Test backup functionality
            print("\n💾 Testing vulnerability backup...")
            current_vulns = updater.backup_current_vulns()
            print(f"   Backed up {len(current_vulns)} existing vulnerabilities")
            
            print("\n✅ All tests passed!")
            return True
            
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_cve_updater()
    sys.exit(0 if success else 1)
