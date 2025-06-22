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
    force_rescore: bool = False,
    host: Optional[str] = None
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
        host: Host/IP address for network topology discovery (required for discovery stage)
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
            orchestrator = create_orchestrator(config)
            # For single stage report, use basic options
            report_options = {
                'format': 'summary',  # Default to summary for single stage
                'auto_save': False
            }
            results = orchestrator.run_report_stage(agent_name or 'ReportAgent', report_options)
            print(f"✅ Report generation completed successfully!")
        
        elif stage == 'signature':
            orchestrator = create_orchestrator(config)
            results = orchestrator.run_signature_stage(agent_name or 'ProtocolSignatureGeneratorAgent')
            print(f"✅ Protocol signature generation completed: {len(results)} signatures processed")
            
        elif stage == 'discovery':
            if not host:
                print("❌ Discovery stage requires --host argument")
                print("   Example: pgdn --stage discovery --host 192.168.1.1")
                sys.exit(1)
            orchestrator = create_orchestrator(config)
            results = orchestrator.run_discovery_stage(agent_name or 'DiscoveryAgent', host=host)
            print(f"✅ Network topology discovery completed: {len(results)} discoveries processed")
            
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
  # Standard Operations
  pgdn                              # Run full pipeline
  pgdn --stage recon                # Run only reconnaissance
  pgdn --stage scan                 # Run only scanning
  pgdn --stage scan --protocol filecoin # Scan only Filecoin nodes
  pgdn --stage scan --protocol filecoin --debug # Scan with debug logging
  pgdn --stage scan --protocol sui  # Scan only Sui nodes
  pgdn --stage process              # Run only processing
  pgdn --stage score                # Run only scoring
  pgdn --stage signature            # Generate protocol signatures
  pgdn --stage discovery --host 192.168.1.1 # Run network topology discovery for specific host
  pgdn --stage publish              # Run only publishing
  pgdn --stage report               # Generate AI security analysis report for all unprocessed scans
  pgdn --stage report --scan-id 123 # Generate report for specific scan ID
  pgdn --stage report --force-report # Generate reports for all scans (even if already processed)
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
  
  # Queue Operations (Background Processing)
  pgdn --queue                      # Queue full pipeline for background processing
  pgdn --stage scan --queue         # Queue scan stage for background processing
  pgdn --scan-target 139.84.148.36 --queue # Queue target scan for background processing
  pgdn --queue --wait-for-completion # Queue job and wait for completion
  pgdn --task-id abc123-def456      # Check status of queued task
  pgdn --cancel-task abc123-def456  # Cancel a queued task
  pgdn --list-tasks                 # List all active queued tasks
  
  # Parallel Processing
  pgdn --parallel-targets 192.168.1.100 192.168.1.101 192.168.1.102 # Scan multiple targets in parallel
  pgdn --parallel-targets 10.0.0.1 10.0.0.2 --queue --max-parallel 3 # Queue parallel scans with concurrency limit
  pgdn --target-file targets.txt --queue # Scan targets from file in parallel
  pgdn --parallel-stages recon scan --queue # Run multiple independent stages in parallel
  pgdn --parallel-stages recon scan --queue --wait-for-completion # Run and wait for completion
  
  # Signature Learning from Existing Scans
  pgdn --learn-signatures-from-scans --protocol sui # Learn Sui signatures from existing scans
  pgdn --learn-signatures-from-scans --protocol filecoin # Learn Filecoin signatures
  pgdn --learn-signatures-from-scans --protocol ethereum --signature-learning-min-confidence 0.8 # Learn with higher confidence threshold
  pgdn --learn-signatures-from-scans --protocol sui --signature-learning-max-examples 500 # Limit examples
        """
    )
    
    parser.add_argument(
        '--stage',
        choices=['recon', 'scan', 'process', 'score', 'publish', 'report', 'signature', 'discovery'],
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
        '--host',
        help='Host/IP address for network topology discovery (required for discovery stage)'
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
        '--scan-id',
        type=int,
        help='Specific scan ID to generate report for (if not provided, will run for all unprocessed scans)'
    )
    
    parser.add_argument(
        '--force-report',
        action='store_true',
        help='Force generation of report even if scan has already been processed'
    )
    
    parser.add_argument(
        '--force',
        action='store_true',
        help='Force operation to bypass caching/recent result checks'
    )
    
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
    
    parser.add_argument(
        '--queue',
        action='store_true',
        help='Queue the job for background processing using Celery (requires Redis/Celery worker)'
    )

    parser.add_argument(
        '--task-id',
        help='Check status of a specific queued task'
    )

    parser.add_argument(
        '--batch-size',
        type=int,
        default=10,
        help='Batch size for queued operations (default: 10)'
    )

    parser.add_argument(
        '--wait-for-completion',
        action='store_true',
        help='Wait for queued tasks to complete before exiting (use with --queue)'
    )

    parser.add_argument(
        '--list-tasks',
        action='store_true',
        help='List all active queued tasks and their status'
    )

    parser.add_argument(
        '--cancel-task',
        help='Cancel a specific queued task by ID'
    )
    
    parser.add_argument(
        '--parallel-targets',
        nargs='+',
        help='Scan multiple targets in parallel (space-separated list of IPs/hostnames)'
    )

    parser.add_argument(
        '--max-parallel',
        type=int,
        default=5,
        help='Maximum number of parallel tasks/scans (default: 5)'
    )

    parser.add_argument(
        '--parallel-stages',
        nargs='+',
        choices=['recon', 'scan', 'process', 'score', 'publish', 'report', 'signature', 'discovery'],
        help='Run multiple stages in parallel (space-separated list)'
    )

    parser.add_argument(
        '--target-file',
        help='File containing list of targets to scan (one per line)'
    )
    
    parser.add_argument(
        '--learn-signatures-from-scans',
        action='store_true',
        help='Learn improved protocol signatures from existing scan data'
    )
    
    parser.add_argument(
        '--protocol',
        help='Protocol name for signature learning (required with --learn-signatures-from-scans). Examples: sui, filecoin, ethereum'
    )
    
    parser.add_argument(
        '--signature-learning-min-confidence',
        type=float,
        default=0.7,
        help='Minimum confidence threshold for scans to include in learning (default: 0.7)'
    )
    
    parser.add_argument(
        '--signature-learning-max-examples',
        type=int,
        default=1000,
        help='Maximum examples to process per protocol (default: 1000)'
    )
    
    parser.add_argument(
        '--update-signature-flags',
        action='store_true',
        help='Update signature_created flags for scans that have been processed for signature generation'
    )
    
    parser.add_argument(
        '--protocol-filter',
        help='Protocol filter for signature flag updates (e.g., sui, filecoin, ethereum)'
    )
    
    parser.add_argument(
        '--mark-signature-created',
        type=int,
        help='Mark a specific scan ID as having its signature created'
    )
    
    parser.add_argument(
        '--show-signature-stats',
        action='store_true',
        help='Show statistics about signature creation status for scans'
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


def check_task_status(task_id: str) -> None:
    """
    Check the status of a queued task.
    
    Args:
        task_id: Task ID to check
    """
    try:
        from utils.queue_manager import create_queue_manager
        from core.config import Config
        
        config = Config()
        queue_manager = create_queue_manager(config)
        
        status = queue_manager.get_task_status(task_id)
        
        print(f"📋 Task Status for {task_id}:")
        print(f"   Status: {status['status']}")
        print(f"   Ready: {'✅' if status['ready'] else '⏳'}")
        
        if status['successful']:
            print(f"   Result: ✅ Completed successfully")
            if status['result']:
                result_info = status['result']
                if isinstance(result_info, dict):
                    if 'execution_id' in result_info:
                        print(f"   Execution ID: {result_info['execution_id']}")
                    if 'results_count' in result_info:
                        print(f"   Results Count: {result_info['results_count']}")
        elif status['failed']:
            print(f"   Result: ❌ Failed")
            print(f"   Error: {status['error']}")
        elif not status['ready']:
            print(f"   Result: ⏳ Pending/Running")
            
    except Exception as e:
        print(f"❌ Error checking task status: {e}")


def cancel_task(task_id: str) -> None:
    """
    Cancel a queued task.
    
    Args:
        task_id: Task ID to cancel
    """
    try:
        from utils.queue_manager import create_queue_manager
        from core.config import Config
        
        config = Config()
        queue_manager = create_queue_manager(config)
        
        success = queue_manager.cancel_task(task_id)
        
        if success:
            print(f"✅ Task {task_id} has been cancelled")
        else:
            print(f"❌ Failed to cancel task {task_id}")
            
    except Exception as e:
        print(f"❌ Error cancelling task: {e}")


def list_task_status() -> None:
    """
    List all active task statuses (placeholder - would need task tracking).
    """
    print("📋 Task Status Listing:")
    print("   This feature requires additional task tracking implementation.")
    print("   Use --task-id <id> to check specific task status.")


def run_with_queue(config: Config, args) -> None:
    """
    Run operations using Celery queue.
    
    Args:
        config: Configuration instance
        args: Parsed command line arguments
    """
    try:
        from utils.queue_manager import create_queue_manager
        
        queue_manager = create_queue_manager(config)
        task_id = None
        
        print("🚀 Queueing job for background processing...")
        
        if args.scan_target:
            # Queue target scan
            task_id = queue_manager.queue_target_scan(args.scan_target, args.debug)
            print(f"   📤 Queued target scan for {args.scan_target}")
            
        elif args.stage:
            # Queue single stage
            if args.stage == 'report':
                # Configure report options from args
                report_options = {
                    'input_file': args.report_input,
                    'output_file': args.report_output,
                    'format': args.report_format or 'json',
                    'auto_save': args.auto_save_report,
                    'email_report': args.report_email,
                    'recipient_email': args.recipient_email,
                    'scan_id': args.scan_id,
                    'force_report': args.force_report
                }
                task_id = queue_manager.queue_single_stage(
                    args.stage,
                    args.agent,
                    args.recon_agents,
                    args.protocol,
                    args.debug,
                    args.force_rescore,
                    args.host,
                    report_options=report_options,
                    force=args.force
                )
            else:
                task_id = queue_manager.queue_single_stage(
                    args.stage,
                    args.agent,
                    args.recon_agents,
                    args.protocol,
                    args.debug,
                    args.force_rescore,
                    args.host,
                    force=args.force
                )
            print(f"   📤 Queued single stage: {args.stage}")
            
        else:
            # Queue full pipeline
            task_id = queue_manager.queue_full_pipeline(args.recon_agents)
            print(f"   📤 Queued full pipeline")
        
        if task_id:
            print(f"✅ Task queued successfully!")
            print(f"   Task ID: {task_id}")
            print(f"   Check status: pgdn --task-id {task_id}")
            print(f"   Cancel task: pgdn --cancel-task {task_id}")
            
            # Wait for completion if requested
            if args.wait_for_completion:
                print("⏳ Waiting for task completion...")
                try:
                    results = queue_manager.wait_for_tasks(task_id, timeout=3600)  # 1 hour timeout
                    if task_id in results:
                        result = results[task_id]
                        if 'error' in result:
                            print(f"❌ Task failed: {result['error']}")
                        else:
                            print(f"✅ Task completed successfully!")
                            if isinstance(result, dict) and 'execution_id' in result:
                                print(f"   Execution ID: {result['execution_id']}")
                except Exception as e:
                    print(f"⚠️  Timeout or error waiting for task: {e}")
                    print(f"   Task is still running. Check status with: pgdn --task-id {task_id}")
        else:
            print("❌ Failed to queue task")
            
    except ImportError:
        print("❌ Celery not available. Install with: pip install celery redis")
        print("   Also ensure Redis server is running and Celery worker is started.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error queueing job: {e}")
        sys.exit(1)


def run_parallel_scans(config: Config, targets: List[str], args) -> None:
    """
    Run parallel scans for multiple targets.
    
    Args:
        config: Configuration instance
        targets: List of targets to scan
        args: Parsed command line arguments
    """
    if not targets:
        print("❌ No targets provided for parallel scanning")
        return
    
    print(f"🚀 Running parallel scans for {len(targets)} targets")
    print(f"   Max parallel: {args.max_parallel}")
    if args.protocol:
        print(f"   Protocol filter: {args.protocol}")
    
    if args.queue:
        # Queue parallel scans
        try:
            from utils.queue_manager import create_queue_manager
            
            queue_manager = create_queue_manager(config)
            result = queue_manager.queue_parallel_scans(
                targets, 
                args.max_parallel,
                args.protocol,
                args.debug
            )
            
            print(f"✅ Queued {len(result['task_ids'])} parallel scan tasks")
            print(f"   Task IDs:")
            for i, task_id in enumerate(result['task_ids'], 1):
                print(f"     {i}. {task_id}")
            
            if args.wait_for_completion:
                print("\n⏳ Waiting for all tasks to complete...")
                results = queue_manager.wait_for_tasks(result['task_ids'])
                
                successful = sum(1 for r in results.values() if not isinstance(r, dict) or 'error' not in r)
                print(f"✅ Parallel scans completed: {successful}/{len(targets)} successful")
            
        except Exception as e:
            print(f"❌ Error queueing parallel scans: {e}")
            sys.exit(1)
    else:
        # Run parallel scans directly (not recommended for many targets)
        print("⚠️  Running parallel scans directly (consider using --queue for better performance)")
        
        from agents.scan.node_scanner_agent import NodeScannerAgent
        import concurrent.futures
        import threading
        
        scanner_agent = NodeScannerAgent(config, protocol_filter=args.protocol, debug=args.debug)
        
        def scan_target(target):
            try:
                mock_node = {
                    'id': 0,
                    'address': target,
                    'source': 'parallel_direct',
                    'name': f'Direct parallel scan of {target}'
                }
                
                results = scanner_agent.scan_nodes([mock_node])
                print(f"✅ Completed scan for {target}")
                return {'target': target, 'success': True, 'result': results[0] if results else None}
                
            except Exception as e:
                print(f"❌ Failed to scan {target}: {e}")
                return {'target': target, 'success': False, 'error': str(e)}
        
        # Use ThreadPoolExecutor for parallel execution
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_parallel) as executor:
            futures = {executor.submit(scan_target, target): target for target in targets}
            results = []
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                results.append(result)
        
        successful = sum(1 for r in results if r['success'])
        print(f"\n✅ Parallel scans completed: {successful}/{len(targets)} successful")


def run_parallel_stages(config: Config, stages: List[str], args) -> None:
    """
    Run multiple stages in parallel.
    
    Args:
        config: Configuration instance
        stages: List of stages to run in parallel
        args: Parsed command line arguments
    """
    print(f"🚀 Running {len(stages)} stages in parallel: {', '.join(stages)}")
    
    # Validate that stages can run in parallel (some have dependencies)
    dependent_stages = {
        'scan': ['recon'],  # scan depends on recon
        'process': ['scan'],  # process depends on scan
        'score': ['process'],  # score depends on process
        'publish': ['score', 'process'],  # publish depends on processing
        'report': ['scan', 'process']  # report depends on scan and process
    }
    
    # Check for dependencies
    for stage in stages:
        deps = dependent_stages.get(stage, [])
        for dep in deps:
            if dep not in stages:
                print(f"⚠️  Warning: Stage '{stage}' typically depends on '{dep}' which is not included")
    
    if args.queue:
        # Queue parallel stages
        try:
            from utils.queue_manager import create_queue_manager
            
            queue_manager = create_queue_manager(config)
            
            # Build stage configurations
            stage_configs = {}
            for stage in stages:
                stage_configs[stage] = {
                    'agent_name': args.agent,
                    'recon_agents': args.recon_agents,
                    'protocol_filter': args.protocol,
                    'debug': args.debug,
                    'force_rescore': args.force_rescore,
                    'host': args.host
                }
            
            stage_task_ids = queue_manager.queue_parallel_stages(stages, stage_configs)
            
            print(f"✅ Queued {len(stages)} parallel stage tasks")
            for stage, task_id in stage_task_ids.items():
                print(f"   {stage}: {task_id}")
            
            if args.wait_for_completion:
                print("\n⏳ Waiting for all stages to complete...")
                results = queue_manager.wait_for_tasks(list(stage_task_ids.values()))
                
                successful = sum(1 for r in results.values() if not isinstance(r, dict) or 'error' not in r)
                print(f"✅ Parallel stages completed: {successful}/{len(stages)} successful")
            
        except Exception as e:
            print(f"❌ Error queueing parallel stages: {e}")
            sys.exit(1)
    else:
        print("❌ Parallel stages require queue mode. Use --queue flag.")
        sys.exit(1)


def load_targets_from_file(file_path: str) -> List[str]:
    """
    Load targets from a file.
    
    Args:
        file_path: Path to file containing targets (one per line)
        
    Returns:
        List of targets
    """
    try:
        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        print(f"📁 Loaded {len(targets)} targets from {file_path}")
        return targets
        
    except FileNotFoundError:
        print(f"❌ Target file not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error reading target file: {e}")
        sys.exit(1)


def learn_signatures_from_scans(args) -> None:
    """
    Learn improved protocol signatures from existing scan data.
    
    Args:
        args: Parsed command line arguments
    """
    if not args.signature_learning_protocol:
        print("❌ Error: --protocol is required when using --learn-signatures-from-scans")
        print("   Examples:")
        print("     --protocol sui")
        print("     --protocol filecoin")
        print("     --protocol ethereum")
        sys.exit(1)
    
    print("🎓 Learning Protocol Signatures from Existing Scan Data")
    print("="*60)
    print(f"   Protocol: {args.signature_learning_protocol}")
    print(f"   Min confidence: {args.signature_learning_min_confidence}")
    print(f"   Max examples: {args.signature_learning_max_examples}")
    print()
    
    try:
        from agents.discovery.signature_learner import ScanDataSignatureLearner
        
        # Initialize the signature learner
        learner = ScanDataSignatureLearner()
        
        print("📊 Analyzing existing scan data...")
        
        # Learn signatures from scans using protocol instead of source
        results = learner.learn_from_scans(
            protocol=args.signature_learning_protocol,
            min_confidence=args.signature_learning_min_confidence,
            max_examples=args.signature_learning_max_examples
        )
        
        if results['success']:
            stats = results['statistics']
            print(f"✅ Signature learning completed successfully!")
            print(f"   Session ID: {results['session_id']}")
            print()
            print("📈 Learning Results:")
            print(f"   • Signatures learned: {stats['signatures_learned']}")
            print(f"   • Examples processed: {stats['examples_processed']}")
            print(f"   • Protocols affected: {len(stats['protocols_affected'])}")
            
            if stats['protocols_affected']:
                print(f"   • Protocol list: {', '.join(stats['protocols_affected'])}")
            
            print()
            print("💾 Database Updates:")
            db_updates = stats['database_updates']
            if db_updates['updated']:
                print(f"   • Updated signatures: {', '.join(db_updates['updated'])}")
            if db_updates['created']:
                print(f"   • Created signatures: {', '.join(db_updates['created'])}")
            if db_updates['errors']:
                print(f"   • Errors: {len(db_updates['errors'])}")
                for error in db_updates['errors'][:3]:  # Show first 3 errors
                    print(f"     - {error}")
                if len(db_updates['errors']) > 3:
                    print(f"     ... and {len(db_updates['errors']) - 3} more")
            
            print()
            print("🔄 Signature Improvements:")
            improvements = stats['improvements']
            if improvements:
                for protocol, improvement in improvements.items():
                    print(f"   • {protocol}:")
                    if 'examples_added' in improvement:
                        print(f"     - Examples added: {improvement['examples_added']}")
                    if 'confidence_improvement' in improvement:
                        print(f"     - Confidence improvement: {improvement['confidence_improvement']:.3f}")
            else:
                print("   No specific improvements tracked")
            
            print()
            print("💡 Next Steps:")
            print("   1. Run protocol discovery to test improved signatures")
            print("   2. Validate signatures against known hosts")
            print("   3. Monitor signature performance in production")
            print(f"   4. Check session results: {results['session_id']}")
            
        else:
            print(f"❌ Signature learning failed: {results.get('error', 'Unknown error')}")
            sys.exit(1)
            
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("   Make sure the signature learning module is properly installed")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error during signature learning: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def update_signature_flags(args) -> None:
    """
    Update signature_created flags for scans that have been processed for signature generation.
    
    Args:
        args: Parsed command line arguments
    """
    print("🔄 Updating Signature Creation Flags")
    print("="*50)
    
    if args.signature_protocol_filter:
        print(f"   Protocol filter: {args.signature_protocol_filter}")
    else:
        print("   Processing all protocols")
    print()
    
    try:
        from services.scan_service import ScanService
        
        scan_service = ScanService()
        
        print("📊 Getting scans pending signature creation...")
        
        # Get scans that need signature creation
        pending_scans = scan_service.get_scans_pending_signature_creation(
            protocol_filter=args.signature_protocol_filter
        )
        
        if not pending_scans:
            print("✅ No scans found that need signature creation")
            return
        
        print(f"🔍 Found {len(pending_scans)} scans pending signature creation")
        
        # Process each scan that has a definitive protocol
        processed_count = 0
        skipped_count = 0
        
        for scan in pending_scans:
            try:
                scan_results = scan.scan_results
                detected_protocol = scan_results.get('detected_protocol') if scan_results else None
                
                # Only process scans where we definitely know the protocol
                if detected_protocol and detected_protocol != 'unknown':
                    success = scan_service.mark_signature_created(scan.id)
                    if success:
                        processed_count += 1
                        print(f"✅ Marked scan {scan.id} ({detected_protocol}) as signature created")
                    else:
                        print(f"❌ Failed to mark scan {scan.id}")
                        skipped_count += 1
                else:
                    skipped_count += 1
                    print(f"⏭️  Skipped scan {scan.id} (protocol: {detected_protocol or 'unknown'})")
                    
            except Exception as e:
                print(f"❌ Error processing scan {scan.id}: {e}")
                skipped_count += 1
        
        print()
        print("📈 Update Results:")
        print(f"   • Scans processed: {processed_count}")
        print(f"   • Scans skipped: {skipped_count}")
        print(f"   • Total scans: {len(pending_scans)}")
        
        if processed_count > 0:
            print()
            print("💡 Next Steps:")
            print("   1. Run --show-signature-stats to see updated statistics")
            print("   2. Continue with signature learning if needed")
        
    except Exception as e:
        print(f"❌ Error updating signature flags: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def mark_scan_signature_created(scan_id: int) -> None:
    """
    Mark a specific scan ID as having its signature created.
    
    Args:
        scan_id: The scan ID to mark
    """
    print(f"🏷️  Marking Scan {scan_id} as Signature Created")
    print("="*50)
    
    try:
        from services.scan_service import ScanService
        
        scan_service = ScanService()
        
        success = scan_service.mark_signature_created(scan_id)
        
        if success:
            print(f"✅ Successfully marked scan {scan_id} as signature created")
        else:
            print(f"❌ Failed to mark scan {scan_id} (scan may not exist or already marked)")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Error marking scan: {e}")
        sys.exit(1)


def show_signature_stats() -> None:
    """
    Show statistics about signature creation status for scans.
    """
    print("📊 Signature Creation Statistics")
    print("="*50)
    
    try:
        from services.scan_service import ScanService
        
        scan_service = ScanService()
        
        stats = scan_service.get_signature_creation_stats()
        
        print("📈 Overall Statistics:")
        print(f"   • Total scans: {stats['total_scans']}")
        print(f"   • Signatures created: {stats['signatures_created']}")
        print(f"   • Signatures pending: {stats['pending_signatures']}")
        print(f"   • Completion rate: {stats['completion_rate']:.1%}")
        print()
        
        if stats['protocol_breakdown']:
            print("🔍 Protocol Breakdown:")
            for protocol_stat in stats['protocol_breakdown']:
                protocol = protocol_stat['protocol']
                total = protocol_stat['total_scans']
                created = protocol_stat['signatures_created']
                pending = protocol_stat['pending']
                rate = (created / total * 100) if total > 0 else 0
                
                print(f"   • {protocol}:")
                print(f"     - Total scans: {total}")
                print(f"     - Signatures created: {created}")
                print(f"     - Pending: {pending}")
                print(f"     - Completion rate: {rate:.1f}%")
        else:
            print("🔍 No protocol-specific data available")
        
        print()
        print("💡 Available Actions:")
        if stats['pending_signatures'] > 0:
            print("   • Run --update-signature-flags to mark processed scans")
            print("   • Run --learn-signatures-from-scans to improve signatures")
        print("   • Run --mark-signature-created <scan_id> to mark specific scans")
        
    except Exception as e:
        print(f"❌ Error getting signature statistics: {e}")
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
        
        # Learn signatures from existing scans and exit
        if args.learn_signatures_from_scans:
            learn_signatures_from_scans(args)
            return
        
        # Handle signature flag management commands and exit
        if args.update_signature_flags:
            update_signature_flags(args)
            return
        
        if args.mark_signature_created:
            mark_scan_signature_created(args.mark_signature_created)
            return
        
        if args.show_signature_stats:
            show_signature_stats()
            return
        
        # Handle queue-related arguments first
        if args.task_id:
            check_task_status(args.task_id)
            return
        
        if args.cancel_task:
            cancel_task(args.cancel_task)
            return
        
        if args.list_tasks:
            list_task_status()
            return
        
        # Load configuration
        config = load_config(args)
        
        # Check if queue mode is requested
        if args.queue:
            run_with_queue(config, args)
            return
        
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
                # Report stage now uses orchestrator pattern like score stage
                orchestrator = create_orchestrator(config)
                
                # Configure report options from args
                report_options = {
                    'input_file': args.report_input,
                    'output_file': args.report_output,
                    'format': args.report_format or 'json',
                    'auto_save': args.auto_save_report,
                    'email_report': args.report_email,
                    'recipient_email': args.recipient_email,
                    'scan_id': args.scan_id,
                    'force_report': args.force_report
                }
                
                results = orchestrator.run_report_stage(args.agent or 'ReportAgent', report_options)
                print(f"✅ Report generation completed successfully!")
            elif args.stage == 'signature':
                # Signature generation stage
                orchestrator = create_orchestrator(config)
                results = orchestrator.run_signature_stage(args.agent or 'ProtocolSignatureGeneratorAgent')
                print(f"✅ Protocol signature generation completed: {len(results)} signatures processed")
            elif args.stage == 'discovery':
                # Discovery stage requires host argument
                if not args.host:
                    print("❌ Discovery stage requires --host argument")
                    print("   Example: pgdn --stage discovery --host 192.168.1.1")
                    sys.exit(1)
                orchestrator = create_orchestrator(config)
                results = orchestrator.run_discovery_stage(args.agent or 'DiscoveryAgent', host=args.host, force=args.force)
                print(f"✅ Network topology discovery completed: {len(results)} discoveries processed")
            else:
                # Run single stage
                run_single_stage(
                    config,
                    args.stage,
                    args.agent,
                    args.recon_agents,
                    args.protocol,
                    args.debug,
                    args.force_rescore,
                    args.host
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
