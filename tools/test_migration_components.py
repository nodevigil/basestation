#!/usr/bin/env python3
"""
Test script for protocol migration tool functionality.
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_imports():
    """Test that all required modules can be imported."""
    print("🧪 Testing imports...")
    
    try:
        from core.database import (
            get_db_session, Protocol, ProtocolSignature, ValidatorAddress, 
            SignatureMatchResult
        )
        print("✅ Core database models imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import core database models: {e}")
        return False
    
    try:
        from core.config import Config
        print("✅ Config imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import config: {e}")
        return False
    
    try:
        from protocol_seeder import DePINProtocolSeeder
        print("✅ Protocol seeder imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import protocol seeder: {e}")
        return False
    
    try:
        from agents.signature.protocol_signature_generator_agent import ProtocolSignatureGeneratorAgent
        print("✅ Signature generator imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import signature generator: {e}")
        return False
    
    return True

def test_basic_functionality():
    """Test basic functionality."""
    print("\n🧪 Testing basic functionality...")
    
    # Import modules for testing
    from core.database import get_db_session, Protocol
    from protocol_seeder import DePINProtocolSeeder
    from agents.signature.protocol_signature_generator_agent import ProtocolSignatureGeneratorAgent
    
    try:
        # Test database connection
        with get_db_session() as session:
            protocol_count = session.query(Protocol).count()
            print(f"✅ Database connection successful ({protocol_count} protocols found)")
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False
    
    try:
        # Test protocol seeder initialization
        seeder = DePINProtocolSeeder()
        print("✅ Protocol seeder initialization successful")
    except Exception as e:
        print(f"❌ Protocol seeder initialization failed: {e}")
        return False
    
    try:
        # Test signature generator initialization
        generator = ProtocolSignatureGeneratorAgent()
        print("✅ Signature generator initialization successful")
    except Exception as e:
        print(f"❌ Signature generator initialization failed: {e}")
        return False
    
    return True

def main():
    """Main test function."""
    print("🔧 Protocol Migration Tool - Component Test")
    print("=" * 50)
    
    success = True
    
    # Test imports
    if not test_imports():
        success = False
    
    # Test basic functionality
    if success and not test_basic_functionality():
        success = False
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 All tests passed! Migration tool should work correctly.")
        print("\nNext steps:")
        print("1. python tools/protocol_migration_tool.py --check-dependencies")
        print("2. python tools/protocol_migration_tool.py --full-migration")
    else:
        print("❌ Some tests failed. Please check the errors above.")
        
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
