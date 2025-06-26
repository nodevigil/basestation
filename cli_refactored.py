"""
Simplified CLI - Single Entry Point

This replaces the complex CLI with multiple classes with a clean, simple interface.
"""

import argparse
import sys
import json
from typing import Dict, Any

from lib import Config, load_config
from lib.scanner_refactored import Scanner


def main():
    """Main CLI entry point."""
    args = parse_arguments()
    
    try:
        # Load configuration
        config = load_config(
            config_file=args.config,
            log_level=args.log_level,
            use_docker_config=False
        )
        
        # Create scanner
        scanner = Scanner(config)
        
        # Perform scan
        result = scanner.scan(
            target=args.target,
            org_id=args.org_id,
            scan_level=args.scan_level,
            protocol=args.protocol,
            enabled_scanners=args.scanners,
            enabled_external_tools=args.external_tools,
            debug=args.debug
        )
        
        # Output results
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print_human_readable(result)
        
        # Exit with error code if scan failed
        if not result.get('success', False):
            sys.exit(1)
            
    except KeyboardInterrupt:
        error_msg = "Operation cancelled by user"
        if args.json:
            print(json.dumps({"error": error_msg}))
        else:
            print(f"\n⚠️  {error_msg}")
        sys.exit(1)
    
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        if args.json:
            print(json.dumps({"error": error_msg}))
        else:
            print(f"❌ {error_msg}")
        sys.exit(1)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="PGDN - DePIN Infrastructure Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  pgdn --target example.com --org-id myorg
  
  # Protocol-specific scan
  pgdn --target example.com --org-id myorg --protocol sui
  
  # Comprehensive scan
  pgdn --target example.com --org-id myorg --scan-level 3
  
  # Custom scanner selection
  pgdn --target example.com --org-id myorg --scanners generic web
        """
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help='Return results in JSON format'
    )
    
    parser.add_argument(
        '--org-id',
        required=True,
        help='Organization ID (required)'
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
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Set logging level'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    return parser.parse_args()


def print_human_readable(result: Dict[str, Any]):
    """Print results in human-readable format."""
    if result.get('success'):
        print(f"✅ Scan completed for {result['target']}")
        print(f"   Resolved IP: {result['resolved_ip']}")
        print(f"   Scan Level: {result['scan_level']}")
        print(f"   Protocol: {result.get('protocol', 'None')}")
        
        scan_result = result.get('scan_result', {})
        if 'open_ports' in scan_result:
            ports = scan_result['open_ports']
            print(f"   Open Ports: {ports if ports else 'None'}")
    else:
        print(f"❌ Scan failed for {result['target']}")
        print(f"   Error: {result.get('error', 'Unknown error')}")


if __name__ == "__main__":
    main()
