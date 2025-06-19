"""
DePIN Infrastructure Scanner - Command Line Interface
"""

import argparse
import sys
import os
from typing import Optional, List
from datetime import datetime

from core.config import Config
from core.logging import setup_logging
from core.database import create_tables
from utils.pipeline import create_orchestrator
from utils.agent_registry import get_agent_registry
from utils.cve_updater import update_cves_database, get_cve_stats


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
    recon_agents: Optional[List[str]] = None,
    protocol_filter: Optional[str] = None,
    debug: bool = False,
    force_rescore: bool = False
) -> None:
    """
    Run a single pipeline stage.
    
    Args:
        config: Configuration instance
        stage: Stage name to run
        agent_name: Specific agent name to use
        recon_agents: List of recon agents (for recon stage)
        protocol_filter: Protocol filter for scanning (e.g., 'filecoin', 'sui')
        debug: Enable debug logging for scanners
    """
    print(f"🎯 Running single stage: {stage}")
    if debug:
        print("🐛 Debug mode enabled - detailed logs will be created")
    
    # Show config info for scan stage
    if stage == 'scan':
        scan_mode = "sequential" if config.scanning.max_concurrent_scans <= 1 else f"concurrent (max={config.scanning.max_concurrent_scans})"
        print(f"🔧 Scan mode: {scan_mode}")
        print(f"⏱️  Sleep between scans: {config.scanning.sleep_between_scans}s")
        print(f"⏰ Scan timeout: {config.scanning.timeout_seconds}s")
        if protocol_filter:
            print(f"🔍 Protocol filter: {protocol_filter}")
    
    try:
        if stage == 'recon':
            orchestrator = create_orchestrator(config)
            results = orchestrator.run_single_stage(stage, agent_names=recon_agents)
            print(f"✅ Reconnaissance completed: {len(results)} nodes discovered")
            
        elif stage == 'scan':
            # For scanning, we'll use the scanner agent directly to support protocol filtering
            from agents.scan.node_scanner_agent import NodeScannerAgent
            
            scanner_agent = NodeScannerAgent(config, protocol_filter=protocol_filter, debug=debug)
            results = scanner_agent.scan_nodes()
            print(f"✅ Scanning completed: {len(results)} nodes scanned")
            
        elif stage == 'process':
            orchestrator = create_orchestrator(config)
            results = orchestrator.run_single_stage(stage, agent_name)
            print(f"✅ Processing completed: {len(results)} results processed")
            
        elif stage == 'score':
            orchestrator = create_orchestrator(config)
            results = orchestrator.run_scoring_stage(agent_name or 'ScoringAgent', force_rescore=force_rescore)
            print(f"✅ Scoring completed: {len(results)} results scored")
            
        elif stage == 'publish':
            orchestrator = create_orchestrator(config)
            success = orchestrator.run_single_stage(stage, agent_name)
            status = "Success" if success else "Failed"
            print(f"✅ Publishing completed: {status}")
            
        elif stage == 'report':
            # Report stage needs access to args, so we'll handle it differently
            print("✅ Report stage will be handled in main function")
            
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
    print("  pgdn")
    print("  ")
    print("  # Run only reconnaissance stage")
    print("  pgdn --stage recon")
    print("  ")
    print("  # Run specific recon agent")
    print("  pgdn --stage recon --recon-agents SuiReconAgent")


def update_cve_database(replace_existing: bool = False, offline: bool = False, 
                        initial_populate: bool = False) -> None:
    """Update the CVE database with latest vulnerability data.
    
    Args:
        replace_existing: Whether to replace existing CVEs or merge them
        offline: Whether to use offline CVE data without API calls  
        initial_populate: Whether to perform initial database population
    """
    print("🔄 Updating CVE database...")
    
    if offline:
        print("   ⚠️  Offline mode not supported for database updates")
        print("   💡 Use --initial flag for initial database population instead")
        return
    
    if initial_populate:
        print("   📥 Performing initial CVE database population...")
        print("   ⏱️  This may take several minutes...")
    else:
        print("   🔍 Checking for CVE updates from NVD API...")
    
    try:
        success = update_cves_database(
            force_update=replace_existing,
            initial_populate=initial_populate,
            days_back=7 if not initial_populate else 30
        )
        
        if success:
            print("✅ CVE database updated successfully!")
            
            # Show database statistics
            stats = get_cve_stats()
            print("📊 Database Statistics:")
            print(f"   • Total CVEs: {stats.get('total_cves', 'Unknown')}")
            print(f"   • High Severity CVEs: {stats.get('high_severity_count', 'Unknown')}")
            print(f"   • Recent CVEs (30 days): {stats.get('recent_cves_30_days', 'Unknown')}")
            
            if stats.get('last_update'):
                print(f"   • Last Update: {stats['last_update']}")
                print(f"   • New CVEs Added: {stats.get('last_update_new_cves', 0)}")
                print(f"   • CVEs Updated: {stats.get('last_update_updated_cves', 0)}")
            
            if initial_populate:
                print("   🎉 Initial database population completed!")
            else:
                print("   📈 CVE database is now up to date")
        else:
            print("❌ CVE database update failed. Check logs for details.")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Error updating CVE database: {e}")
        sys.exit(1)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="DePIN Infrastructure Scanner - Agentic Architecture",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pgdn                              # Run full pipeline
  pgdn --stage recon                # Run only reconnaissance
  pgdn --stage scan                 # Run only scanning
  pgdn --stage scan --protocol filecoin # Scan only Filecoin nodes
  pgdn --stage scan --protocol filecoin --debug # Scan with debug logging
  pgdn --stage scan --protocol sui  # Scan only Sui nodes
  pgdn --stage process              # Run only processing
  pgdn --stage score                # Run only scoring
  pgdn --stage publish              # Run only publishing
  pgdn --stage report               # Generate AI security analysis report
  pgdn --stage report --report-input scan_result.json # Generate report from specific scan
  pgdn --stage report --report-email # Generate with email notification
  pgdn --stage report --auto-save-report # Auto-save with timestamp
  pgdn --scan-target 139.84.148.36 # Scan specific IP/hostname
  pgdn --scan-target 139.84.148.36 --debug # Scan target with debug
  pgdn --list-agents                # List available agents
  pgdn --recon-agents SuiReconAgent # Run specific recon agent
  pgdn --update-cves                # Update CVE database with latest data
  pgdn --update-cves --replace-cves # Force update of CVE database
  pgdn --update-cves --initial-cves # Initial CVE database population
  pgdn --start-cve-scheduler        # Start daily CVE update scheduler
  pgdn --update-cves --offline-cves # Use offline CVE data (no API calls)
        """
    )
    
    parser.add_argument(
        '--stage',
        choices=['recon', 'scan', 'process', 'score', 'publish', 'report'],
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
        '--protocol',
        choices=['filecoin', 'sui'],
        help='Protocol filter for scanning (e.g., filecoin, sui)'
    )
    
    parser.add_argument(
        '--list-agents',
        action='store_true',
        help='List all available agents and exit'
    )
    
    parser.add_argument(
        '--update-cves',
        action='store_true',
        help='Update CVE database with latest vulnerability data'
    )
    
    parser.add_argument(
        '--replace-cves',
        action='store_true',
        help='Force update of CVE database (use with --update-cves)'
    )
    
    parser.add_argument(
        '--initial-cves',
        action='store_true',
        help='Perform initial CVE database population (use with --update-cves)'
    )
    
    parser.add_argument(
        '--start-cve-scheduler',
        action='store_true',
        help='Start the CVE update scheduler (runs daily at 2 AM)'
    )
    
    parser.add_argument(
        '--cve-update-time',
        default='02:00',
        help='Time for daily CVE updates (HH:MM format, default: 02:00)'
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
    
    parser.add_argument(
        '--force-rescore',
        action='store_true',
        help='Force re-scoring of results that already have scores (use with --stage score)'
    )
    
    # Report stage arguments
    parser.add_argument(
        '--report-input',
        help='Input file for report generation (JSON scan results)'
    )
    
    parser.add_argument(
        '--report-output',
        help='Output file for report results (JSON format)'
    )
    
    parser.add_argument(
        '--report-format',
        choices=['json', 'summary'],
        default='json',
        help='Report output format (default: json)'
    )
    
    parser.add_argument(
        '--report-email',
        action='store_true',
        help='Generate email notification in report'
    )
    
    parser.add_argument(
        '--recipient-email',
        help='Recipient email address for notification'
    )
    
    parser.add_argument(
        '--auto-save-report',
        action='store_true',
        help='Auto-save report with timestamp filename'
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
    import json
    
    config = Config()
    
    # Determine config file: explicit > environment flag > default
    if args.config:
        config_file = args.config
    elif os.getenv('USE_DOCKER_CONFIG', '').lower() in ('true', '1', 'yes'):
        # Only use Docker config if explicitly requested
        config_file = 'config.docker.json' if os.path.exists('config.docker.json') else 'config.json'
        if config_file == 'config.docker.json':
            print("🐳 Docker configuration requested via USE_DOCKER_CONFIG")
        else:
            print("🐳 Docker config requested but config.docker.json not found, using default config")
    else:
        config_file = 'config.json'
    
    try:
        
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
            print("📄 No config file found, using defaults and environment variables")
            
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


def scan_target(config: Config, target: str, debug: bool = False) -> None:
    """
    Scan a specific target (IP or hostname) directly using the agent architecture.
    
    Args:
        config: Configuration instance
        target: IP address or hostname to scan
    """
    from agents.scan.node_scanner_agent import NodeScannerAgent
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
        
        # Create a mock node entry for the scanner agent
        mock_node = {
            'id': 0,
            'address': target,
            'source': 'manual_scan',  # Generic source since we don't know the protocol
            'name': f'Direct scan of {target}'
        }
        
        # Initialize scanner agent
        scanner_agent = NodeScannerAgent(config, debug=debug)
        
        print(f"�️  Running comprehensive security scan...")
        
        # Run the scan using the agent
        scan_results = scanner_agent.scan_nodes([mock_node])
        
        if scan_results:
            scan_result = scan_results[0]
            print(f"\n✅ Scan completed for {target}")
            print(f"📊 Results Summary:")
            
            # Generic scan summary
            if scan_result.get('generic_scan') and 'open_ports' in scan_result['generic_scan']:
                ports = scan_result['generic_scan']['open_ports']
                print(f"   🔓 Open ports: {ports}")
            
            # Protocol scan summary (if available)
            if scan_result.get('protocol_scan'):
                protocol_result = scan_result['protocol_scan']
                if isinstance(protocol_result, dict) and not protocol_result.get('error'):
                    if protocol_result.get('metrics_exposed'):
                        metrics_url = protocol_result.get('metrics_url', 'Unknown')
                        protocol_metrics_count = protocol_result.get('sui_metrics_count', 0)
                        print(f"   📊 Protocol metrics: ✅ EXPOSED at {metrics_url} ({protocol_metrics_count} metrics)")
                    else:
                        print(f"   📊 Protocol metrics: ❌ Not exposed")
                    
                    if protocol_result.get('rpc_exposed'):
                        rpc_url = protocol_result.get('rpc_url', 'Unknown')
                        print(f"   🔌 RPC endpoint: ✅ EXPOSED at {rpc_url}")
                    else:
                        print(f"   🔌 RPC endpoint: ❌ Not exposed")
            
            # Web probes summary
            if scan_result.get('web_probes'):
                web_probes = scan_result['web_probes']
                for endpoint, probe_result in web_probes.items():
                    if isinstance(probe_result, dict) and not probe_result.get('error'):
                        waf_detected = probe_result.get('waf', {}).get('detected', False)
                        waf_name = probe_result.get('waf', {}).get('name', 'Unknown')
                        if waf_detected:
                            print(f"   🛡️  WAF detected on {endpoint}: {waf_name}")
                        else:
                            print(f"   🌐 Web service on {endpoint}: No WAF detected")
            
            # Save results to file
            output_file = f"scan_result_{ip_address.replace('.', '_')}.json"
            with open(output_file, 'w') as f:
                json.dump(scan_result, f, indent=2)
            print(f"💾 Results saved to: {output_file}")
        else:
            print(f"❌ Scan failed for {target}")
    
    except Exception as e:
        print(f"❌ Error scanning {target}: {e}")
        import traceback
        traceback.print_exc()


def run_report_stage(config: Config, args) -> None:
    """
    Run the report generation stage using the report agent.
    
    Args:
        config: Configuration instance
        args: Parsed command line arguments containing report options
    """
    print("📊 Running report generation stage")
    
    try:
        from agents.report.report_agent import ReportAgent
        
        # Initialize the report agent
        report_agent = ReportAgent(config)
        
        # Configure report options
        report_options = {
            'input_file': args.report_input,
            'output_file': args.report_output,
            'format': args.report_format or 'json',
            'auto_save': args.auto_save_report,
            'email_report': args.report_email,
            'recipient_email': args.recipient_email
        }
        
        # Generate and output the report
        report_agent.generate_and_output_report(report_options)
        
        print("✅ Report generation completed successfully!")
        
    except Exception as e:
        print(f"❌ Report generation failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def main():
    """Main entry point."""
    try:
        args = parse_arguments()
        
        # List agents and exit
        if args.list_agents:
            list_agents()
            return
        
        # Update CVE database and exit
        if args.update_cves:
            update_cve_database(args.replace_cves, False, args.initial_cves)
            return
        
        # Start CVE scheduler and exit
        if args.start_cve_scheduler:
            from utils.cve_scheduler import start_cve_scheduler
            print(f"🕐 Starting CVE scheduler with daily updates at {args.cve_update_time}")
            print("   Press Ctrl+C to stop the scheduler")
            start_cve_scheduler(args.cve_update_time, enabled=True)
            
            try:
                while True:
                    import time
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n⏹️  Stopping CVE scheduler...")
                from utils.cve_scheduler import stop_cve_scheduler
                stop_cve_scheduler()
                print("   CVE scheduler stopped")
            return
        
        # Load configuration
        config = load_config(args)
        
        # Setup environment
        setup_environment(config)
        
        # Run pipeline based on arguments
        if args.scan_target:
            # Scan specific target
            scan_target(config, args.scan_target, args.debug)
        elif args.stage:
            if args.stage == 'score':
                orchestrator = create_orchestrator(config)
                results = orchestrator.run_scoring_stage(args.agent or 'ScoringAgent', force_rescore=args.force_rescore)
                print(f"✅ Scoring completed: {len(results)} results scored")
            elif args.stage == 'report':
                # Report stage needs special handling with args
                run_report_stage(config, args)
            else:
                # Run single stage
                run_single_stage(
                    config,
                    args.stage,
                    args.agent,
                    args.recon_agents,
                    args.protocol,
                    args.debug,
                    args.force_rescore
                )
        else:
            # Run full pipeline
            run_full_pipeline(config, args.recon_agents)
        
        # Update CVE database if requested
        if args.update_cves:
            update_cve_database(args.replace_cves, args.offline_cves)
        
        print("\n🎉 Execution completed successfully!")
        
    except KeyboardInterrupt:
        print("\n⚠️  Execution interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
