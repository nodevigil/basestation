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


def perform_scan(scanner, target: str, hostname: str, run_type: str, 
                protocol: str, debug: bool) -> Result:
    """
    Perform scan based on run type.
    
    Args:
        scanner: Scanner instance
        target: Target IP or hostname
        hostname: Optional hostname
        run_type: Type of scan to run
        protocol: Protocol for compliance/node_scan/protocol_scan
        debug: Debug mode
        
    Returns:
        Result object
    """
    # Use the new 'run' parameter instead of legacy enabled_scanners/enabled_external_tools
    return scanner.scan(
        target=target,
        hostname=hostname,
        run=run_type,
        protocol=protocol,
        debug=debug
    )


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
    
    # Require --run parameter
    if not args.run:
        print("❌ Error: --run parameter is required. Choose from: web, whatweb, geo, ssl_test, compliance, node_scan, protocol_scan")
        sys.exit(1)
    
    # Validate protocol-requiring scans
    if args.run in ['compliance', 'node_scan', 'protocol_scan']:
        if not args.protocol:
            print(f"❌ Error: --protocol is required when using --run {args.run}")
            if args.run == 'compliance':
                print("Available protocols: sui, arweave, filecoin, etc.")
            elif args.run == 'node_scan':
                print("Available protocols: sui, arweave, filecoin (built-in) or custom protocols from pgdn/protocols/ directory")
            elif args.run == 'protocol_scan':
                print("Available protocols: sui, arweave, filecoin (advanced protocol scanners)")
            sys.exit(1)
    
    try:
        # Load configuration
        config = None
        if args.config:
            config = Config.from_file(args.config)
        
        # Create scanner
        scanner = Scanner(config)
        
        # Perform scan based on --run parameter
        result = perform_scan(
            scanner=scanner,
            target=args.target,
            hostname=args.hostname,
            run_type=args.run,
            protocol=args.protocol,
            debug=args.debug
        )
        
        # Output results
        # Validate that we got a Result object
        if not isinstance(result, Result):
            # Handle case where scanner returns unexpected type
            result = DictResult.from_error(f"Scanner returned unexpected type: {type(result)}")
        
        if args.json:
            import json
            from datetime import datetime
            
            def datetime_serializer(obj):
                """Custom JSON serializer for datetime objects and enums."""
                if isinstance(obj, datetime):
                    return obj.isoformat()
                from enum import Enum
                if isinstance(obj, Enum):
                    return obj.value
                raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
            
            if result.is_success() and isinstance(result.data, dict):
                # Output the scanner's structured data directly (already has "data" and "meta" at root)
                print(json.dumps(result.data, indent=2, default=datetime_serializer))
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
  # Individual scanner runs
  pgdn --target example.com --run web
  pgdn --target example.com --run whatweb
  pgdn --target example.com --run geo
  pgdn --target example.com --run ssl_test
  
  # Node scanning with protocol-specific probes
  pgdn --target example.com --run node_scan --protocol sui
  pgdn --target example.com --run node_scan --protocol arweave
  pgdn --target example.com --run node_scan --protocol filecoin

  # Advanced protocol-specific scanning
  pgdn --target example.com --run protocol_scan --protocol sui
  pgdn --target example.com --run protocol_scan --protocol filecoin

  # Compliance scanning
  pgdn --target example.com --run compliance --protocol sui
  pgdn --target example.com --run compliance --protocol filecoin
  
  
  # Output formats
  pgdn --target example.com --run web --json     # Pure JSON
  pgdn --target example.com --run web --human    # Human-readable
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
        '--run',
        choices=['web', 'whatweb', 'geo', 'ssl_test', 'compliance', 'node_scan', 'protocol_scan'],
        help='Run specific scanner type'
    )
    
    parser.add_argument(
        '--protocol',
        help='Protocol to scan (required for compliance, node_scan, and protocol_scan). Available protocols loaded from protocols/ directory or built-in (sui, arweave, filecoin)'
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
        from pgdn.protocol_loader import ProtocolLoader
        
        print("📋 Available Scanner Types:")
        print("=" * 50)
        
        print("\n🔧 INDIVIDUAL SCANNERS:")
        print("   • web        - Web service detection")
        print("   • whatweb    - Web technology fingerprinting")
        print("   • geo        - Geographic location detection")
        print("   • ssl_test   - SSL/TLS certificate analysis")
        print("   • node_scan  - Multi-protocol DePIN node scanning")
        
        print("\n🔧 PROTOCOL COMPLIANCE SCANNERS:")
        loader = ProtocolLoader()
        protocols = loader.list_available_protocols()
        
        if protocols:
            for protocol in protocols:
                info = loader.get_protocol_info(protocol)
                if info:
                    print(f"   • {protocol:<12} - {info['name']} ({info['network_type']})")
                    print(f"     {'':15} Ports: {info['default_ports']}")
                    print(f"     {'':15} Probes: {info['probes_count']}, Signatures: {info['signatures_count']}")
        else:
            print("   No protocol configurations found in protocols/ directory")
        
        print("\n📝 USAGE EXAMPLES:")
        print("   # Individual scanners")
        print("   pgdn --target example.com --run web")
        print("   pgdn --target example.com --run whatweb")
        print("   pgdn --target example.com --run geo")
        print("   pgdn --target example.com --run ssl_test")
        print("   pgdn --target example.com --run node_scan --protocol sui")
        
        print("\n   # Protocol compliance scans")
        if protocols:
            for protocol in protocols[:2]:  # Show first 2 as examples
                print(f"   pgdn --target example.com --run compliance --protocol {protocol} --level 1")
                print(f"   pgdn --target example.com --run compliance --protocol {protocol} --level 3")
        
        print("\n📊 SCAN LEVELS (for compliance and node_scan):")
        print("   • --level 1  - Basic detection")
        print("   • --level 2  - Standard analysis") 
        print("   \n   Legacy options:")
        print("   • --type basic  - Equivalent to --level 1")
        print("   • --type full   - Equivalent to --level 2")
        
    except Exception as e:
        print(f"❌ Error listing protocol scanners: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
