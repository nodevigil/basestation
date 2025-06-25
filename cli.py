"""
DePIN Infrastructure Scanner - Scanning Library Interface

A library interface providing access to scanning functionality.
Focuses on scanning operations only.
Returns JSON data for consumption by external applications.

Example usage as a library:

    from cli import ScannerLibrary
    
    # Initialize scanner
    scanner = ScannerLibrary(config_file='config.json')
    
    # Run scanning operations
    scan_result = scanner.run_scan(
        target='192.168.1.1',
        org_id='myorg',
        scan_level=2,
        force_protocol='sui'
    )
    
    # Run processing of scan results
    process_result = scanner.run_process(org_id='myorg')
    
    # Custom scanners (sui, filecoin) are automatically available
"""

import argparse
import sys
import os
import json
import traceback
from typing import Optional, List, Dict, Any

# Import the library components
from lib import (
    ApplicationCore, load_config, setup_environment, initialize_application,
    Config, PipelineOrchestrator, Scanner
)
from lib.scanner import load_targets_from_file

# Export the main library interface
__all__ = ['ScannerLibrary']


class ScannerLibrary:
    """
    Main library interface for DePIN infrastructure scanning.
    
    This class provides a simple interface to the scanning functionality
    while keeping custom scanners like Sui and Filecoin available.
    """
    
    def __init__(self, config_file: str = None, log_level: str = 'INFO'):
        """
        Initialize the scanner library.
        
        Args:
            config_file: Path to configuration file
            log_level: Logging level
        """
        self.config = load_config(
            config_file=config_file,
            log_level=log_level,
            use_docker_config=os.getenv('USE_DOCKER_CONFIG', '').lower() in ('true', '1', 'yes')
        )
        self.orchestrator = PipelineOrchestrator(self.config)
    
    def run_scan(self, target: str = None, org_id: str = None, scan_level: int = 1, 
                 force_protocol: str = None, debug: bool = False, 
                 enabled_scanners: List[str] = None, enabled_external_tools: List[str] = None,
                 limit: int = None) -> Dict[str, Any]:
        """
        Run scanning stage.
        
        Args:
            target: Specific target to scan
            org_id: Organization ID to filter operations
            scan_level: Scan intensity level (1-3)
            force_protocol: Force specific protocol scanner (sui, filecoin)
            debug: Enable debug logging
            enabled_scanners: List of specific scanners to run
            enabled_external_tools: List of specific external tools to run
            limit: Limit number of targets to scan
            
        Returns:
            Dict containing scan results
        """
        return self.orchestrator.run_scan_stage(
            target=target,
            org_id=org_id,
            scan_level=scan_level,
            force_protocol=force_protocol,
            debug=debug,
            enabled_scanners=enabled_scanners,
            enabled_external_tools=enabled_external_tools,
            limit=limit
        )
    
    def run_process(self, org_id: str = None) -> Dict[str, Any]:
        """
        Run processing stage.
        
        Args:
            org_id: Organization ID to filter operations
            
        Returns:
            Dict containing processing results
        """
        return self.orchestrator.run_process_stage(org_id=org_id)


# CLI interface functions below


def setup_environment_cli(config: Config) -> None:
    """
    Setup the application environment with CLI output.
    
    Args:
        config: Configuration instance
    """
    # Use library function for the actual setup
    setup_environment(config)
    
    # CLI-specific output
    print("� PGDN - DePIN Infrastructure Scanner Library")
    print("="*50)


def print_result(result: Dict[str, Any], json_output: bool = False) -> None:
    """
    Print result in appropriate format.
    
    Args:
        result: Result dictionary to print
        json_output: Whether to print as JSON
    """
    if json_output:
        print(json.dumps(result, indent=2))
    else:
        # Handle error cases
        if not result.get('success', False):
            print(f"❌ {result.get('error', 'Operation failed')}")
            return
        
        # Handle different result types
        operation = result.get('operation', result.get('stage', 'operation'))
        
        if operation in ['scan', 'process']:
            print_stage_result(result)
        elif operation == 'target_scan':
            print_target_scan_result(result)
        else:
            # Generic success message
            print(f"✅ {operation.replace('_', ' ').title()} completed successfully!")
            if 'results_count' in result:
                print(f"   Results: {result['results_count']} items")


def print_stage_result(result: Dict[str, Any]) -> None:
    """Print single stage results."""
    stage = result.get('stage', 'stage')
    count = result.get('results_count', 0)
    print(f"✅ {stage.title()} completed: {count} items processed")


def print_target_scan_result(result: Dict[str, Any]) -> None:
    """Print target scan results."""
    target = result.get('target', 'unknown')
    resolved_ip = result.get('resolved_ip')
    
    print(f"✅ Scan completed for {target}")
    if resolved_ip and resolved_ip != target:
        print(f"   Resolved to: {resolved_ip}")
    
    # Print scan summary if available
    scan_result = result.get('scan_result', {})
    if scan_result:
        print(f"📊 Results Summary:")
        
        # Generic scan summary
        if scan_result.get('generic_scan') and 'open_ports' in scan_result['generic_scan']:
            ports = scan_result['generic_scan']['open_ports']
            print(f"   🔓 Open ports: {ports}")
        
        # Protocol scan summary
        if scan_result.get('protocol_scan'):
            protocol_result = scan_result['protocol_scan']
            if isinstance(protocol_result, dict) and not protocol_result.get('error'):
                if protocol_result.get('metrics_exposed'):
                    metrics_url = protocol_result.get('metrics_url', 'Unknown')
                    print(f"   📊 Protocol metrics: ✅ EXPOSED at {metrics_url}")
                else:
                    print(f"   📊 Protocol metrics: ❌ Not exposed")
                
                if protocol_result.get('rpc_exposed'):
                    rpc_url = protocol_result.get('rpc_url', 'Unknown')
                    print(f"   🔌 RPC endpoint: ✅ EXPOSED at {rpc_url}")
                else:
                    print(f"   🔌 RPC endpoint: ❌ Not exposed")


def execute_command(config: Config, args) -> Dict[str, Any]:
    """
    Execute command using the scanner library.
    
    Args:
        config: Configuration instance
        args: Parsed command line arguments
        
    Returns:
        Dict containing execution results
    """
    # Create library instance
    library = ScannerLibrary()
    library.config = config
    library.orchestrator = PipelineOrchestrator(config)
    
    # Handle stage-based commands
    if args.stage:
        return _execute_single_stage_with_library(library, args)
    else:
        # Default: run scan stage
        return library.run_scan(org_id=args.org_id)


def _execute_single_stage_with_library(library: ScannerLibrary, args) -> Dict[str, Any]:
    """Execute single stage using the library."""
    stage = args.stage
    
    if stage == 'scan':
        # Parse scanner selection options
        enabled_scanners = getattr(args, 'scanners', None)
        enabled_external_tools = getattr(args, 'external_tools', None)
        
        # Handle scan type shortcuts
        if hasattr(args, 'type') and args.type:
            if args.type == 'nmap':
                enabled_scanners = []
                enabled_external_tools = ['nmap']
            elif args.type == 'geo':
                enabled_scanners = ['geo']
                enabled_external_tools = []
            elif args.type == 'generic':
                enabled_scanners = ['generic']
                enabled_external_tools = []
            elif args.type == 'web':
                enabled_scanners = ['web']
                enabled_external_tools = []
            elif args.type == 'vulnerability':
                enabled_scanners = ['vulnerability']
                enabled_external_tools = []
            elif args.type == 'ssl':
                enabled_scanners = []
                enabled_external_tools = ['ssl_test']
            elif args.type == 'docker':
                enabled_scanners = []
                enabled_external_tools = ['docker_exposure']
            elif args.type == 'whatweb':
                enabled_scanners = ['web']  # Enable web scanner to detect web services
                enabled_external_tools = ['whatweb']
            elif args.type == 'full':
                # Use default configuration (don't override)
                enabled_scanners = None
                enabled_external_tools = None
        
        return library.run_scan(
            target=getattr(args, 'target', None),
            org_id=args.org_id,
            scan_level=getattr(args, 'scan_level', 1),
            force_protocol=getattr(args, 'force_protocol', None),
            debug=getattr(args, 'debug', False),
            enabled_scanners=enabled_scanners,
            enabled_external_tools=enabled_external_tools,
            limit=getattr(args, 'limit', None)
        )
    
    elif stage == 'process':
        return library.run_process(org_id=args.org_id)
    
    else:
        return {
            "success": False,
            "error": f"Unknown stage: {stage}. Available stages: scan, process"
        }


def main():
    """Main CLI entry point."""
    args = parse_arguments()
    
    # Handle JSON output mode
    json_output = args.json
    
    try:
        # Load configuration
        config = load_config_cli(args, json_output)
        
        # Setup environment (unless in JSON mode)
        if not json_output:
            setup_environment_cli(config)
        
        # Execute command
        result = execute_command(config, args)
        
        # Print results
        if result:
            print_result(result, json_output)
            
            # Exit with error code if operation failed
            if not result.get('success', False):
                sys.exit(1)
        
    except KeyboardInterrupt:
        error_msg = "Operation cancelled by user"
        if json_output:
            print(json.dumps({"error": error_msg}))
        else:
            print(f"\n⚠️  {error_msg}")
        sys.exit(1)
    
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        if json_output:
            print(json.dumps({"error": error_msg}))
        else:
            print(f"❌ {error_msg}")
            if not json_output:
                traceback.print_exc()
        sys.exit(1)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="PGDN - DePIN Infrastructure Scanner Library",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Standard Operations
  pgdn                              # Run scanning (default)
  pgdn --stage scan                 # Run only scanning (scan level 1 by default)
  pgdn --stage scan --scan-level 2  # Run scanning with GeoIP enrichment
  pgdn --stage scan --scan-level 3  # Run comprehensive scanning with advanced analysis
  pgdn --stage scan --org-id myorg  # Scan targets for specific organization
  pgdn --stage scan --org-id myorg --limit 5 # Scan only 5 targets for organization
  pgdn --stage scan --org-id myorg --limit 10 --scan-level 2 # Scan 10 validators with GeoIP
  pgdn --stage process              # Run only processing

  # Target Scanning
  pgdn --stage scan --target example.com --org-id myorg                       # Infrastructure scan of target
  pgdn --stage scan --target example.com --org-id myorg --force-protocol sui  # Infrastructure + Sui protocol scan
  pgdn --stage scan --target example.com --org-id myorg --scan-level 3        # Comprehensive target scan

  # Scanner Type Selection (for testing and debugging)
  pgdn --stage scan --target example.com --org-id myorg --type nmap           # Only run nmap scan
  pgdn --stage scan --target example.com --org-id myorg --type geo            # Only run GeoIP lookup
  pgdn --stage scan --target example.com --org-id myorg --type web            # Only run web analysis
  pgdn --stage scan --target example.com --org-id myorg --type vulnerability  # Only run vulnerability scan
  pgdn --stage scan --target example.com --org-id myorg --type ssl            # Only run SSL/TLS test
  pgdn --stage scan --target example.com --org-id myorg --type docker         # Only check Docker exposure
  pgdn --stage scan --target example.com --org-id myorg --type whatweb        # Only run web tech fingerprinting
  pgdn --stage scan --target example.com --org-id myorg --type full           # Run all scanners (default)
  pgdn --stage scan --target example.com --org-id myorg --debug --type nmap   # Debug nmap issues
  
  # Advanced scanner control (for developers)
  pgdn --stage scan --target example.com --org-id myorg --scanners generic web
  pgdn --stage scan --target example.com --org-id myorg --external-tools nmap whatweb
  pgdn --stage scan --target example.com --org-id myorg --scanners geo --external-tools nmap
  
  # Organization-specific Operations
  pgdn --org-id myorg               # Run scanning for specific organization
        """
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help='Return results in JSON format instead of human-readable output'
    )
    
    parser.add_argument(
        '--org-id',
        help='Organization ID to filter scanning operations by organization'
    )
    
    parser.add_argument(
        '--stage',
        choices=['scan', 'process'],
        help='Run only the specified stage'
    )
    
    parser.add_argument(
        '--target',
        help='Scan a specific IP address or hostname (requires --org-id when used with --stage scan)'
    )
    
    parser.add_argument(
        '--scan-level',
        type=int,
        choices=[1, 2, 3],
        default=1,
        help='Scan level: 1 (basic), 2 (standard with geo), 3 (comprehensive with advanced analysis)'
    )
    
    parser.add_argument(
        '--limit',
        type=int,
        help='Limit the number of targets to scan (useful for testing or resource management)'
    )
    
    parser.add_argument(
        '--type',
        choices=['nmap', 'geo', 'generic', 'web', 'vulnerability', 'ssl', 'docker', 'whatweb', 'full'],
        help='Scan type to run. Available: nmap (port scan only), geo (GeoIP only), generic (basic port scan), web (HTTP analysis), vulnerability (CVE lookup), ssl (SSL/TLS test), docker (Docker exposure check), whatweb (web tech fingerprinting), full (all scanners and tools - default)'
    )
    
    parser.add_argument(
        '--scanners',
        nargs='*',
        choices=['generic', 'web', 'vulnerability', 'geo', 'sui', 'filecoin'],
        help='Advanced: Specific scanner modules to run (space-separated). Use --type for common scan types instead.'
    )
    
    parser.add_argument(
        '--external-tools',
        nargs='*',
        choices=['nmap', 'whatweb', 'ssl_test', 'docker_exposure'],
        help='Advanced: Specific external tools to run (space-separated). Use --type for common scan types instead.'
    )
    
    parser.add_argument(
        '--force-protocol',
        choices=['filecoin', 'sui'],
        help='Force run protocol-specific scanner even if protocol is unknown (e.g., filecoin, sui)'
    )
    
    parser.add_argument(
        '--config',
        help='Path to configuration file (JSON format)'
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
        help='Enable debug logging for scanners (creates detailed log files)'
    )
    
    return parser.parse_args()


def load_config_cli(args, json_output: bool = False) -> Config:
    """
    Load configuration with CLI-specific output and error handling.
    
    Args:
        args: Parsed command line arguments
        json_output: Whether to suppress output for JSON mode
        
    Returns:
        Configuration instance
    """
    # Determine configuration parameters from CLI args
    config_file = args.config
    use_docker_config = os.getenv('USE_DOCKER_CONFIG', '').lower() in ('true', '1', 'yes')
    
    try:
        # Print configuration info (CLI-specific)
        if not json_output:
            if use_docker_config:
                if os.path.exists('config.docker.json'):
                    print("🐳 Docker configuration requested via USE_DOCKER_CONFIG")
                else:
                    print("🐳 Docker config requested but config.docker.json not found, using default config")
            
            if config_file:
                print(f"📄 Loading configuration from: {config_file}")
            elif os.path.exists('config.json'):
                print(f"📄 Loading configuration from: config.json")
            else:
                print("📄 No config file found, using defaults and environment variables")
        
        # Use library function for actual loading
        config = load_config(
            config_file=config_file,
            log_level=args.log_level,
            use_docker_config=use_docker_config
        )
        
        return config
        
    except FileNotFoundError as e:
        error_msg = str(e)
        if not json_output:
            print(f"❌ {error_msg}")
        sys.exit(1)
    except ValueError as e:
        error_msg = f"Invalid configuration: {str(e)}"
        if not json_output:
            print(f"❌ {error_msg}")
        sys.exit(1)
    except Exception as e:
        error_msg = f"Failed to load configuration: {str(e)}"
        if not json_output:
            print(f"❌ {error_msg}")
        sys.exit(1)


if __name__ == "__main__":
    main()
