"""
Simplified CLI for DePIN Infrastructure Scanner

Clean, single entry point that uses the refactored Scanner class.
"""

import argparse
import sys
import json
import traceback
from typing import Dict, Any

from pgdn.scanner import Scanner
from pgdn.core.config import Config
from pgdn.core.result import Result, DictResult


def main():
    """Main CLI entry point."""
    args = parse_arguments()
    
    # Handle list-protocols command
    if args.list_protocols:
        list_protocol_scanners()
        return
    
    # Require target for normal scanning
    if not args.target:
        print("❌ Error: --target is required unless using --list-protocols")
        sys.exit(1)
    
    try:
        # Load configuration
        config = None
        if args.config:
            config = Config.from_file(args.config)
        
        # Create scanner
        scanner = Scanner(config)
        
        # Perform scan
        result = scanner.scan(
            target=args.target,
            hostname=args.hostname,
            scan_level=args.scan_level,
            protocol=args.protocol,
            enabled_scanners=args.scanners,
            enabled_external_tools=args.external_tools,
            debug=args.debug
        )
        
        # Output results
        # Validate that we got a Result object
        if not isinstance(result, Result):
            # Handle case where scanner returns unexpected type
            result = DictResult.from_error(f"Scanner returned unexpected type: {type(result)}")
        
        if args.json:
            import json
            if result.is_success() and isinstance(result.data, dict):
                # Output the scanner's structured data directly (already has "data" and "meta" at root)
                print(json.dumps(result.data, indent=2))
            else:
                # Fallback to the Result structure for errors/warnings
                print(result.to_json(indent=2))
        elif args.human:
            print_human_readable(result)
        else:
            # Default: Result structure (not JSON)
            print(result)
            
        # Exit with appropriate code
        sys.exit(0 if result.is_success() else 1)
        
    except KeyboardInterrupt:
        error_result = DictResult.from_error("Operation cancelled by user")
        if args.json:
            print(error_result.to_json())
        elif args.human:
            print(f"\n⚠️  {error_result.error}")
        else:
            print(error_result.to_json())
        sys.exit(1)
        
    except Exception as e:
        # Log raw traceback optionally if debug mode is on
        if args.debug:
            print(f"Debug traceback:\n{traceback.format_exc()}", file=sys.stderr)
        
        error_result = DictResult.from_error(f"Unexpected error: {str(e)}")
        if args.json:
            print(error_result.to_json())
        elif args.human:
            print(f"❌ {error_result.error}")
        else:
            print(error_result.to_json())
        sys.exit(1)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="PGDN - DePIN Infrastructure Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scans (default output: Result structure)
  pgdn --target example.com
  pgdn --target example.com --protocol sui
  pgdn --target example.com --scan-level 3
  
  # Scanner selection
  pgdn --target example.com --scanners generic web
  pgdn --target example.com --external-tools nmap
  
  # Output formats
  pgdn --target example.com --json     # Pure JSON
  pgdn --target example.com --human    # Human-readable
        """
    )
    
    parser.add_argument(
        '--target',
        help='Target IP address or hostname to scan'
    )
    
    parser.add_argument(
        '--hostname',
        help='Hostname associated with the target IP (optional, for scans that work better with hostnames)'
    )
    
    parser.add_argument(
        '--list-protocols',
        action='store_true',
        help='List available protocol scanners and their supported levels'
    )
    
    parser.add_argument(
        '--scan-level',
        type=int,
        choices=[1, 2, 3],
        default=1,
        help='Scan level: 1 (basic), 2 (standard), 3 (comprehensive)'
    )
    
    parser.add_argument(
        '--protocol',
        choices=['filecoin', 'sui', 'ethereum'],
        help='Run protocol-specific scanner'
    )
    
    parser.add_argument(
        '--scanners',
        nargs='*',
        choices=['generic', 'web', 'vulnerability', 'geo', 'sui', 'filecoin', 'ethereum'],
        help='Specific scanner modules to run'
    )
    
    parser.add_argument(
        '--external-tools',
        nargs='*',
        choices=['nmap', 'whatweb', 'ssl_test', 'docker_exposure'],
        help='Specific external tools to run'
    )
    
    parser.add_argument(
        '--config',
        help='Path to configuration file (JSON format)'
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help='Return results in pure JSON format'
    )
    
    parser.add_argument(
        '--human',
        action='store_true',
        help='Return results in human-readable format'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    return parser.parse_args()


def print_human_readable(result: DictResult):
    """Print results in human-readable format."""
    if result.is_success():
        data = result.data
        meta = result.meta or {}
        
        print("✅ Scan completed successfully")
        print(f"🎯 Target: {data.get('target')} → {data.get('resolved_ip')}")
        print(f"📊 Scan Level: {data.get('scan_level')}")
        
        if data.get('protocol'):
            print(f"🔧 Protocol: {data.get('protocol')}")
        
        # Show timing information
        if data.get('scan_start_timestamp_unix') and data.get('scan_end_timestamp_unix'):
            duration = data.get('scan_end_timestamp_unix') - data.get('scan_start_timestamp_unix')
            print(f"⏱️  Scan Duration: {duration} seconds")
            print(f"🕐 Start Time: {data.get('scan_start_timestamp_unix')} (Unix)")
            print(f"🕑 End Time: {data.get('scan_end_timestamp_unix')} (Unix)")
        
        # Show stage timings if available
        stage_timings = data.get('stage_timings', {})
        if stage_timings:
            print("📈 Stage Timings:")
            for stage_name, timing in stage_timings.items():
                if isinstance(timing, dict) and 'start_time' in timing and 'end_time' in timing:
                    print(f"   • {stage_name}: {timing['duration']}s ({timing['start_time']} → {timing['end_time']})")
        
        scan_result = data.get('scan_result', {})
        if scan_result.get('open_ports'):
            print(f"🔓 Open Ports: {scan_result['open_ports']}")
        
        if scan_result.get('geoip'):
            geo = scan_result['geoip']
            print(f"🌍 Location: {geo.get('city_name', 'Unknown')}, {geo.get('country_name', 'Unknown')}")
        
        print(f"⏰ Timestamp: {data.get('timestamp')}")
        print(f"🆔 Node ID: {data.get('node_id')}")
        
        if meta:
            print(f"📈 Meta: {meta}")
            
    elif result.is_warning():
        data = result.data
        meta = result.meta or {}
        
        print("⚠️  Scan completed with warnings")
        print(f"🎯 Target: {data.get('target')} → {data.get('resolved_ip')}")
        print(f"📊 Scan Level: {data.get('scan_level')}")
        print(f"⚠️  Warning: {result.error}")
        
        if data and data.get('protocol'):
            print(f"🔧 Protocol: {data.get('protocol')}")
        
        # Show timing information for warnings too
        if data and data.get('scan_start_timestamp_unix') and data.get('scan_end_timestamp_unix'):
            duration = data.get('scan_end_timestamp_unix') - data.get('scan_start_timestamp_unix')
            print(f"⏱️  Scan Duration: {duration} seconds")
            print(f"🕐 Start Time: {data.get('scan_start_timestamp_unix')} (Unix)")
            print(f"🕑 End Time: {data.get('scan_end_timestamp_unix')} (Unix)")
        
        if data:
            scan_result = data.get('scan_result', {})
            if scan_result.get('open_ports'):
                print(f"🔓 Open Ports: {scan_result['open_ports']}")
            
            if scan_result.get('geoip'):
                geo = scan_result['geoip']
                print(f"🌍 Location: {geo.get('city_name', 'Unknown')}, {geo.get('country_name', 'Unknown')}")
            
            print(f"⏰ Timestamp: {data.get('timestamp')}")
            print(f"🆔 Node ID: {data.get('node_id')}")
        
        if meta:
            print(f"📈 Meta: {meta}")
        
    else:
        print("❌ Scan failed")
        print(f"⚠️  Error: {result.error}")


def list_protocol_scanners():
    """List available protocol scanners and their supported levels."""
    try:
        from pgdn.scanners.protocols.sui_scanner import EnhancedSuiScanner
        from pgdn.scanners.protocols.filecoin_scanner import FilecoinScanner
        from pgdn.scanners.protocols.arweave_scanner import EnhancedArweaveScanner
        # from pgdn.scanners.protocols.ethereum_scanner import EthereumScanner
        
        print("📋 Available Protocol Scanners:")
        print("=" * 50)
        
        scanners = [
            (EnhancedSuiScanner, "Sui blockchain nodes"),
            (FilecoinScanner, "Filecoin network nodes"),
            (EnhancedArweaveScanner, "Arweave network nodes"),
            # (EthereumScanner, "Ethereum blockchain nodes")
        ]
        
        for scanner_class, description in scanners:
            scanner = scanner_class()
            protocol_name = scanner.protocol_name
            supported_levels = scanner.get_supported_levels()
            level_descriptions = scanner.describe_levels()
            
            print(f"\n🔧 {protocol_name.upper()}")
            print(f"   Description: {description}")
            print(f"   Supported Levels: {supported_levels}")
            
            for level in supported_levels:
                desc = level_descriptions.get(level, "No description available")
                print(f"   • Level {level}: {desc}")
                
        print("\n📝 Usage:")
        print("   pgdn --target <ip> --protocol sui --scan-level 2")
        print("   pgdn --target <ip> --protocol filecoin --scan-level 3")
        print("   pgdn --target <ip> --protocol ethereum --scan-level 1")
        
    except Exception as e:
        print(f"❌ Error listing protocol scanners: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
