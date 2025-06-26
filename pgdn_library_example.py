#!/usr/bin/env python3
"""
PGDN Library Usage Examples

This module demonstrates how to use the PGDN library for various DePIN infrastructure
scanning operations without using the CLI interface.
"""

# Example 1: Basic Configuration Loading
def example_basic_setup():
    """Example of basic configuration loading using the library."""
    from lib import Config
    
    # Load configuration from file
    config = Config.from_file("config.json")
    
    print("✅ Configuration loaded successfully")
    print(f"   Scan orchestrator config: {hasattr(config.scanning, 'orchestrator')}")
    print(f"   Available protocols: {list(config.protocols.keys()) if hasattr(config, 'protocols') else 'None'}")
    return config


# Example 2: Running a Full Scan
def example_full_scan():
    """Example of running a full scan using the library."""
    from lib import Scanner, Config
    
    # Load configuration
    config = Config.from_file("config.json")
    
    # Create scanner
    scanner = Scanner(config)
    
    # Run scan
    result = scanner.scan(
        target="example.com",
        protocol="sui"
    )
    
    if result.get('success', False):
        print(f"✅ Scan completed successfully!")
        print(f"   Target: {result.get('target')}")
        print(f"   Results: {len(result.get('results', []))} findings")
        return result
    else:
        print(f"❌ Scan failed: {result.get('error', 'Unknown error')}")
        return None


# Example 3: Direct Target Scanning with Custom Configuration
def example_target_scanning():
    """Example of scanning specific targets directly."""
    from lib import Scanner, Config
    
    # Setup
    config = Config.from_file("config.json")
    
    # Create scanner
    scanner = Scanner(config)
    
    # Scan a specific target with custom parameters
    target_result = scanner.scan(
        target="139.84.148.36",
        protocol="filecoin",
        scan_level=2
    )
    
    if target_result.get('success', False):
        print(f"✅ Target scan successful")
        print(f"   Target: {target_result.get('target')}")
        print(f"   Scan level: {target_result.get('scan_level')}")
        print(f"   Results: {len(target_result.get('results', []))} findings")
    else:
        print(f"❌ Target scan failed: {target_result.get('error')}")


if __name__ == "__main__":
    """Run a simple example."""
    print("🚀 Running PGDN library example...")
    
    try:
        # Basic setup example
        config = example_basic_setup()
        print(f"Configuration loaded: {type(config)}")
        
        # Run a simple scan
        print("\n🔍 Running example scan...")
        example_full_scan()
        
    except Exception as e:
        print(f"❌ Example failed: {e}")
        import traceback
        traceback.print_exc()