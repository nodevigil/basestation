#!/usr/bin/env python3
"""
Test to reproduce and fix the ScanLevel JSON serialization error.
"""

import json
import sys
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime

# Add the project root to sys.path so we can import the modules
sys.path.insert(0, '/Users/simon/Documents/Code/pgdn-network/pgdn-scanner')

from pgdn.scanners.protocols.sui_scanner import ScanLevel, SuiScanResult, EnhancedSuiScanner


def test_scan_level_serialization():
    """Test that demonstrates the ScanLevel JSON serialization issue."""
    print("🧪 Testing ScanLevel JSON serialization...")
    
    # Create a ScanLevel enum
    scan_level = ScanLevel.LITE
    print(f"ScanLevel: {scan_level}")
    print(f"ScanLevel.value: {scan_level.value}")
    print(f"ScanLevel type: {type(scan_level)}")
    
    # Try to serialize it directly
    try:
        json_str = json.dumps(scan_level)
        print(f"✅ Direct serialization works: {json_str}")
    except TypeError as e:
        print(f"❌ Direct serialization fails: {e}")
    
    # Try with default handler
    def enum_serializer(obj):
        from enum import Enum
        if isinstance(obj, Enum):
            return obj.value
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
    
    try:
        json_str = json.dumps(scan_level, default=enum_serializer)
        print(f"✅ Serialization with enum handler works: {json_str}")
    except TypeError as e:
        print(f"❌ Serialization with enum handler fails: {e}")


def test_sui_scan_result_serialization():
    """Test SuiScanResult serialization to find where ScanLevel is embedded."""
    print("\n🧪 Testing SuiScanResult JSON serialization...")
    
    # Create a minimal SuiScanResult
    result = SuiScanResult(
        ip="127.0.0.1",
        port=9000,
        timestamp=datetime.utcnow(),
        scan_level=ScanLevel.LITE
    )
    
    print(f"SuiScanResult created with scan_level: {result.scan_level}")
    
    # Try to serialize using asdict (what the code does)
    from dataclasses import asdict
    try:
        result_dict = asdict(result)
        print(f"✅ asdict() works")
        print(f"scan_level in dict: {result_dict['scan_level']} (type: {type(result_dict['scan_level'])})")
        
        # Now try to JSON serialize the dict
        try:
            json_str = json.dumps(result_dict)
            print(f"❌ This should fail but didn't: {json_str}")
        except TypeError as e:
            print(f"✅ JSON serialization fails as expected: {e}")
            
        # Try with custom serializer
        def custom_serializer(obj):
            from enum import Enum
            from datetime import datetime
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, Enum):
                return obj.value
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
        
        try:
            json_str = json.dumps(result_dict, default=custom_serializer)
            print(f"✅ JSON serialization with custom handler works")
            # print(f"Result: {json_str}")
        except TypeError as e:
            print(f"❌ JSON serialization with custom handler still fails: {e}")
            
    except Exception as e:
        print(f"❌ asdict() fails: {e}")


async def test_scanner_scan_protocol_method():
    """Test the actual scan_protocol method to see where serialization happens."""
    print("\n🧪 Testing EnhancedSuiScanner.scan_protocol() method...")
    
    # Create a mock scanner
    scanner = EnhancedSuiScanner()
    
    # Mock the scan method to avoid actual network calls
    with patch.object(scanner, 'scan', new_callable=AsyncMock) as mock_scan:
        # Create a mock result
        mock_result = SuiScanResult(
            ip="127.0.0.1",
            port=9000,
            timestamp=datetime.utcnow(),
            scan_level=ScanLevel.LITE
        )
        mock_scan.return_value = [mock_result]
        
        try:
            # Call scan_protocol
            result = await scanner.scan_protocol("127.0.0.1", 1)
            print(f"✅ scan_protocol returned result")
            print(f"Result keys: {result.keys()}")
            print(f"scan_level in result: {result.get('scan_level')}")
            
            # Try to serialize the result
            try:
                json_str = json.dumps(result)
                print(f"❌ This should fail: JSON serialization worked")
            except TypeError as e:
                print(f"✅ JSON serialization fails as expected: {e}")
                
                # Check what object is causing the issue
                def find_non_serializable(obj, path=""):
                    """Recursively find non-serializable objects."""
                    try:
                        json.dumps(obj)
                        return None
                    except TypeError as e:
                        if isinstance(obj, dict):
                            for key, value in obj.items():
                                result = find_non_serializable(value, f"{path}.{key}")
                                if result:
                                    return result
                        elif isinstance(obj, list):
                            for i, value in enumerate(obj):
                                result = find_non_serializable(value, f"{path}[{i}]")
                                if result:
                                    return result
                        else:
                            return f"{path}: {type(obj)} = {obj}"
                    return None
                
                problematic_path = find_non_serializable(result)
                print(f"🔍 Non-serializable object found at: {problematic_path}")
                
        except Exception as e:
            print(f"❌ scan_protocol failed: {e}")
            import traceback
            traceback.print_exc()


def main():
    """Run all tests."""
    print("🚀 Starting ScanLevel JSON serialization debugging tests...")
    
    test_scan_level_serialization()
    test_sui_scan_result_serialization()
    
    # Run async test
    asyncio.run(test_scanner_scan_protocol_method())
    
    print("\n✅ All tests completed!")


if __name__ == "__main__":
    main()