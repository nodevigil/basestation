"""
Simplified CLI for DePIN Infrastructure Scanner

Clean, single entry point that uses the refactored Scanner class.
"""

import argparse
import sys
import json
import traceback
from typing import Dict, Any

from lib.scanner import Scanner
from lib.core.config import Config
from lib.core.result import Result, DictResult


def main():
    """Main CLI entry point."""
    args = parse_arguments()
    
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
        required=True,
        help='Target IP address or hostname to scan'
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
        choices=['filecoin', 'sui'],
        help='Run protocol-specific scanner'
    )
    
    parser.add_argument(
        '--scanners',
        nargs='*',
        choices=['generic', 'web', 'vulnerability', 'geo', 'sui', 'filecoin'],
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


if __name__ == "__main__":
    main()
