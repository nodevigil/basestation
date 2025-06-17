"""
New main.py - DePIN Infrastructure Scanner with Agentic Architecture
"""

import argparse
import sys
from typing import Optional, List
from datetime import datetime

from core.config import Config
from core.logging import setup_logging
from core.database import create_tables
from utils.pipeline import create_orchestrator
from utils.agent_registry import get_agent_registry


def setup_environment(config: Config) -> None:
    """
    Setup the application environment.
    
    Args:
        config: Configuration instance
    """
    # Setup logging
    setup_logging(config.logging)
    
    # Create database tables
    create_tables(config.database)
    
    print("🚀 DePIN Infrastructure Scanner - Agentic Architecture")
    print("="*60)


def run_full_pipeline(config: Config, recon_agents: Optional[List[str]] = None) -> None:
    """
    Run the complete four-stage pipeline.
    
    Args:
        config: Configuration instance
        recon_agents: Optional list of specific recon agents to run
    """
    orchestrator = create_orchestrator(config)
    
    print("📋 Running full pipeline with all stages:")
    print("   🔍 Stage 1: Reconnaissance (Node Discovery)")
    print("   🛡️  Stage 2: Scanning (Security Analysis)")
    print("   📊 Stage 3: Processing (Trust Score & Enrichment)")
    print("   📤 Stage 4: Publishing (Results Output)")
    print()
    
    results = orchestrator.run_full_pipeline(recon_agents=recon_agents)
    
    if results['success']:
        print(f"✅ Pipeline completed successfully!")
        print(f"   Execution ID: {results['execution_id']}")
        print(f"   Total time: {results['execution_time_seconds']:.2f} seconds")
        
        # Print stage summaries
        stages = results.get('stages', {})
        for stage_name, stage_results in stages.items():
            if stage_name in ['recon', 'scan', 'process']:
                count = len(stage_results) if isinstance(stage_results, list) else 'N/A'
                print(f"   {stage_name.title()}: {count} items")
            elif stage_name == 'publish':
                status = 'Success' if stage_results else 'Failed'
                print(f"   {stage_name.title()}: {status}")
    else:
        print(f"❌ Pipeline failed: {results.get('error', 'Unknown error')}")
        sys.exit(1)


def run_single_stage(
    config: Config,
    stage: str,
    agent_name: Optional[str] = None,
    recon_agents: Optional[List[str]] = None
) -> None:
    """
    Run a single pipeline stage.
    
    Args:
        config: Configuration instance
        stage: Stage name to run
        agent_name: Specific agent name to use
        recon_agents: List of recon agents (for recon stage)
    """
    orchestrator = create_orchestrator(config)
    
    print(f"🎯 Running single stage: {stage}")
    
    # Show config info for scan stage
    if stage == 'scan':
        scan_mode = "sequential" if config.scanning.max_concurrent_scans <= 1 else f"concurrent (max={config.scanning.max_concurrent_scans})"
        print(f"🔧 Scan mode: {scan_mode}")
        print(f"⏱️  Sleep between scans: {config.scanning.sleep_between_scans}s")
        print(f"⏰ Scan timeout: {config.scanning.timeout_seconds}s")
    
    try:
        if stage == 'recon':
            results = orchestrator.run_single_stage(stage, agent_names=recon_agents)
            print(f"✅ Reconnaissance completed: {len(results)} nodes discovered")
            
        elif stage == 'scan':
            results = orchestrator.run_single_stage(stage, agent_name)
            print(f"✅ Scanning completed: {len(results)} nodes scanned")
            
        elif stage == 'process':
            results = orchestrator.run_single_stage(stage, agent_name)
            print(f"✅ Processing completed: {len(results)} results processed")
            
        elif stage == 'publish':
            success = orchestrator.run_single_stage(stage, agent_name)
            status = "Success" if success else "Failed"
            print(f"✅ Publishing completed: {status}")
            
        else:
            print(f"❌ Unknown stage: {stage}")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Stage {stage} failed: {e}")
        sys.exit(1)


def list_agents() -> None:
    """List all available agents."""
    registry = get_agent_registry()
    agents = registry.list_all_agents()
    
    print("📋 Available Agents:")
    print("="*40)
    
    for category, agent_list in agents.items():
        print(f"\n{category.upper()} AGENTS:")
        if agent_list:
            for agent in agent_list:
                print(f"  • {agent}")
        else:
            print("  (none available)")
    
    print("\nUsage examples:")
    print("  # Run full pipeline")
    print("  python main.py")
    print("  ")
    print("  # Run only reconnaissance stage")
    print("  python main.py --stage recon")
    print("  ")
    print("  # Run specific recon agent")
    print("  python main.py --stage recon --recon-agents SuiReconAgent")


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="DePIN Infrastructure Scanner - Agentic Architecture",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                              # Run full pipeline
  python main.py --stage recon                # Run only reconnaissance
  python main.py --stage scan                 # Run only scanning
  python main.py --stage process              # Run only processing
  python main.py --stage publish              # Run only publishing
  python main.py --scan-target 139.84.148.36 # Scan specific IP/hostname
  python main.py --list-agents                # List available agents
  python main.py --recon-agents SuiReconAgent # Run specific recon agent
        """
    )
    
    parser.add_argument(
        '--stage',
        choices=['recon', 'scan', 'process', 'publish'],
        help='Run only the specified stage'
    )
    
    parser.add_argument(
        '--agent',
        help='Specific agent name to use for the stage'
    )
    
    parser.add_argument(
        '--scan-target',
        help='Scan a specific IP address or hostname (bypasses database)'
    )
    
    parser.add_argument(
        '--recon-agents',
        nargs='+',
        help='List of reconnaissance agents to run'
    )
    
    parser.add_argument(
        '--list-agents',
        action='store_true',
        help='List all available agents and exit'
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
    
    return parser.parse_args()


def load_config(args) -> Config:
    """
    Load configuration from arguments and environment.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        Configuration instance
    """
    config = Config()
    
    # Try to load config.json automatically if it exists
    config_file = args.config if args.config else 'config.json'
    
    try:
        import json
        import os
        
        if os.path.exists(config_file):
            print(f"📄 Loading configuration from: {config_file}")
            with open(config_file, 'r') as f:
                config_data = json.load(f)
                config = Config(config_overrides=config_data)
        elif args.config:
            # Only error if user explicitly specified a config file that doesn't exist
            print(f"❌ Config file not found: {args.config}")
            sys.exit(1)
        else:
            print("📄 No config.json found, using defaults and environment variables")
            
    except Exception as e:
        print(f"❌ Failed to load config file {config_file}: {e}")
        sys.exit(1)
    
    # Override log level if specified on command line (takes precedence)
    if args.log_level:
        config.logging.level = args.log_level
    
    # Validate configuration
    if not config.validate():
        print("❌ Invalid configuration")
        sys.exit(1)
    
    return config


def scan_target(config: Config, target: str) -> None:
    """
    Scan a specific target (IP or hostname) directly.
    
    Args:
        config: Configuration instance
        target: IP address or hostname to scan
    """
    from scanning.scanner import Scanner
    from scanning.sui_scanner import SuiSpecificScanner
    import socket
    import json
    
    print(f"🎯 Direct target scan: {target}")
    
    try:
        # Resolve hostname to IP if needed
        try:
            ip_address = socket.gethostbyname(target)
            print(f"🌍 Resolved {target} to IP: {ip_address}")
        except socket.gaierror:
            print(f"❌ DNS resolution failed for {target}")
            return
        
        # Initialize scanners
        generic_scanner = Scanner()
        sui_scanner = SuiSpecificScanner()
        
        print(f"🛡️  Running generic security scan...")
        generic_result = generic_scanner.scan(ip_address)
        
        print(f"🔍 Running Sui-specific scan...")
        sui_result = sui_scanner.scan(ip_address)
        
        # Combine results
        scan_result = {
            'target': target,
            'ip_address': ip_address,
            'generic_scan': generic_result,
            'sui_scan': sui_result,
            'scan_timestamp': datetime.utcnow().isoformat()
        }
        
        print(f"\n✅ Scan completed for {target}")
        print(f"📊 Results Summary:")
        
        # Generic scan summary
        if generic_result and 'open_ports' in generic_result:
            ports = generic_result['open_ports']
            print(f"   🔓 Open ports: {ports}")
        
        # Sui scan summary
        if sui_result:
            if sui_result.get('metrics_exposed'):
                metrics_url = sui_result.get('metrics_url', 'Unknown')
                sui_count = sui_result.get('sui_metrics_count', 0)
                print(f"   📊 Sui metrics: ✅ EXPOSED at {metrics_url} ({sui_count} sui metrics)")
            else:
                print(f"   📊 Sui metrics: ❌ Not exposed")
            
            if sui_result.get('rpc_exposed'):
                rpc_url = sui_result.get('rpc_url', 'Unknown')
                print(f"   🔗 Sui RPC: ✅ EXPOSED at {rpc_url}")
            else:
                print(f"   🔗 Sui RPC: ❌ Not exposed")
        
        # Optionally save to file
        output_file = f"scan_result_{target.replace('.', '_').replace(':', '_')}.json"
        with open(output_file, 'w') as f:
            json.dump(scan_result, f, indent=2)
        print(f"💾 Full results saved to: {output_file}")
        
    except Exception as e:
        print(f"❌ Scan failed for {target}: {e}")
        sys.exit(1)


def main():
    """Main entry point."""
    try:
        args = parse_arguments()
        
        # List agents and exit
        if args.list_agents:
            list_agents()
            return
        
        # Load configuration
        config = load_config(args)
        
        # Setup environment
        setup_environment(config)
        
        # Run pipeline based on arguments
        if args.scan_target:
            # Scan specific target
            scan_target(config, args.scan_target)
        elif args.stage:
            # Run single stage
            run_single_stage(
                config,
                args.stage,
                args.agent,
                args.recon_agents
            )
        else:
            # Run full pipeline
            run_full_pipeline(config, args.recon_agents)
        
        print("\n🎉 Execution completed successfully!")
        
    except KeyboardInterrupt:
        print("\n⚠️  Execution interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
