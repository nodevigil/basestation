"""
DePIN Infrastructure Scanner - Command Line Interface

A thin CLI wrapper around the PGDN library providing command-line access
to all scanning, reporting, and management functionality.
"""

import argparse
import sys
import os
import json
import traceback
from typing import Optional, List, Dict, Any

# Import the library components
from pgdn import (
    ApplicationCore, load_config, setup_environment, initialize_application,
    PipelineOrchestrator, Scanner, ReportManager, CVEManager, 
    SignatureManager, QueueManager, AgentManager, ParallelOperations
)
from pgdn.scanner import load_targets_from_file
from pgdn.core.config import Config


def setup_environment_cli(config: Config) -> None:
    """
    Setup the application environment with CLI output.
    
    Args:
        config: Configuration instance
    """
    # Use library function for the actual setup
    setup_environment(config)
    
    # CLI-specific output
    print("🐦 PGND - Agentic DePIN Infrastructure Scanner")
    print("="*60)


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
        
        if operation == 'full_pipeline':
            print_pipeline_result(result)
        elif operation in ['recon', 'scan', 'process', 'score', 'publish', 'signature', 'discovery']:
            print_stage_result(result)
        elif operation == 'target_scan':
            print_target_scan_result(result)
        elif operation == 'parallel_scans':
            print_parallel_scan_result(result)
        elif operation == 'report':
            print_report_result(result)
        elif operation == 'cve_update':
            print_cve_result(result)
        elif operation == 'list_agents':
            print_agents_result(result)
        else:
            # Generic success message
            print(f"✅ {operation.replace('_', ' ').title()} completed successfully!")
            if 'results_count' in result:
                print(f"   Results: {result['results_count']} items")


def print_pipeline_result(result: Dict[str, Any]) -> None:
    """Print full pipeline results."""
    print(f"✅ Pipeline completed successfully!")
    print(f"   Execution ID: {result.get('execution_id', 'N/A')}")
    print(f"   Total time: {result.get('execution_time_seconds', 0):.2f} seconds")
    
    # Print stage summaries
    stages = result.get('stages', {})
    for stage_name, stage_results in stages.items():
        if stage_name in ['recon', 'scan', 'process']:
            count = len(stage_results) if isinstance(stage_results, list) else 'N/A'
            print(f"   {stage_name.title()}: {count} items")
        elif stage_name == 'publish':
            status = 'Success' if stage_results else 'Failed'
            print(f"   {stage_name.title()}: {status}")


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


def print_parallel_scan_result(result: Dict[str, Any]) -> None:
    """Print parallel scan results."""
    successful = result.get('successful', 0)
    total = result.get('total', 0)
    print(f"✅ Parallel scans completed: {successful}/{total} successful")


def print_report_result(result: Dict[str, Any]) -> None:
    """Print report generation results."""
    scan_id = result.get('scan_id')
    if scan_id:
        print(f"✅ Report generated for scan {scan_id}")
    else:
        print(f"✅ Report generation completed!")


def print_cve_result(result: Dict[str, Any]) -> None:
    """Print CVE update results."""
    stats = result.get('statistics', {})
    initial = result.get('initial_populate', False)
    
    print("✅ CVE database updated successfully!")
    print("📊 Database Statistics:")
    print(f"   • Total CVEs: {stats.get('total_cves', 'Unknown')}")
    print(f"   • High Severity CVEs: {stats.get('high_severity_count', 'Unknown')}")
    print(f"   • Recent CVEs (30 days): {stats.get('recent_cves_30_days', 'Unknown')}")
    
    if stats.get('last_update'):
        print(f"   • Last Update: {stats['last_update']}")
        print(f"   • New CVEs Added: {stats.get('last_update_new_cves', 0)}")
        print(f"   • CVEs Updated: {stats.get('last_update_updated_cves', 0)}")
    
    if initial:
        print("   🎉 Initial database population completed!")
    else:
        print("   📈 CVE database is now up to date")


def print_agents_result(result: Dict[str, Any]) -> None:
    """Print available agents."""
    agents = result.get('agents', {})
    
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


def run_full_pipeline_command(config: Config, args) -> Dict[str, Any]:
    """Run full pipeline command."""
    # Check if queue mode is requested
    if getattr(args, 'queue', False):
        return run_queue_command(config, args)
    
    orchestrator = PipelineOrchestrator(config)
    return orchestrator.run_full_pipeline(
        recon_agents=args.recon_agents,
        org_id=args.org_id
    )


def run_single_stage_command(config: Config, args) -> Dict[str, Any]:
    """Run single stage command."""
    stage = args.stage
    
    # Check if queue mode is requested
    if getattr(args, 'queue', False):
        return run_queue_command(config, args)
    
    if stage == 'recon':
        orchestrator = PipelineOrchestrator(config)
        return orchestrator.run_recon_stage(
            agent_names=args.recon_agents,
            org_id=args.org_id
        )
    
    elif stage == 'scan':
        # Parse scanner selection options
        enabled_scanners = args.scanners
        enabled_external_tools = args.external_tools
        
        # Handle scan type shortcuts
        if args.type:
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
                enabled_scanners = []
                enabled_external_tools = ['whatweb']
            elif args.type == 'full':
                # Use default configuration (don't override)
                enabled_scanners = None
                enabled_external_tools = None
        
        # Use new orchestration approach
        orchestrator = PipelineOrchestrator(config)
        return orchestrator.run_scan_stage(
            target=args.target,
            org_id=args.org_id,
            scan_level=args.scan_level,
            protocol_filter=args.protocol,
            debug=args.debug,
            enabled_scanners=enabled_scanners,
            enabled_external_tools=enabled_external_tools
        )
    
    elif stage == 'process':
        orchestrator = PipelineOrchestrator(config)
        return orchestrator.run_process_stage(
            agent_name=args.agent,
            org_id=args.org_id
        )
    
    elif stage == 'score':
        orchestrator = PipelineOrchestrator(config)
        return orchestrator.run_scoring_stage(
            agent_name=args.agent or 'ScoringAgent',
            force_rescore=args.force_rescore,
            org_id=args.org_id
        )
    
    elif stage == 'publish':
        if not args.scan_id:
            return {
                "success": False,
                "error": "Publish stage requires --scan-id argument",
                "suggestion": "Example: pgdn --stage publish --scan-id 123"
            }
        
        # Determine agent
        if sum([args.publish_ledger, args.publish_report]) > 1:
            return {
                "success": False,
                "error": "Cannot specify multiple publish flags simultaneously",
                "suggestion": "Use one of: --publish-ledger or --publish-report"
            }
        elif args.publish_ledger:
            agent_name = 'PublishLedgerAgent'
        elif args.publish_report:
            agent_name = 'PublishReportAgent'
        else:
            agent_name = 'PublishLedgerAgent'  # Default
        
        orchestrator = PipelineOrchestrator(config)
        return orchestrator.run_publish_stage(
            agent_name, 
            scan_id=args.scan_id,
            org_id=args.org_id
        )
    
    elif stage == 'report':
        report_manager = ReportManager(config)
        return report_manager.generate_report(
            agent_name=args.agent or 'ReportAgent',
            scan_id=getattr(args, 'scan_id', None),
            input_file=getattr(args, 'report_input', None),
            output_file=getattr(args, 'report_output', None),
            report_format=getattr(args, 'report_format', 'json'),
            auto_save=getattr(args, 'auto_save_report', False),
            email_report=getattr(args, 'report_email', False),
            recipient_email=getattr(args, 'recipient_email', None),
            force_report=getattr(args, 'force_report', False),
            org_id=args.org_id
        )
    
    elif stage == 'signature':
        orchestrator = PipelineOrchestrator(config)
        return orchestrator.run_signature_stage(
            agent_name=args.agent or 'ProtocolSignatureGeneratorAgent',
            org_id=args.org_id
        )
    
    elif stage == 'discovery':
        # Handle node-based discovery workflow
        if args.node_id:
            # Discovery for specific node (part of orchestration workflow)
            if not args.host:
                return {
                    "success": False,
                    "error": "Discovery with --node-id requires --host argument",
                    "suggestion": "Example: pgdn --stage discovery --node-id abc123-def456 --host 192.168.1.1"
                }
            
            try:
                from pgdn.agent_modules.discovery.discovery_agent import DiscoveryAgent
                discovery_agent = DiscoveryAgent(config)
                
                return discovery_agent.discover_node(
                    node_id=args.node_id,
                    host=args.host
                )
            except ImportError as e:
                return {
                    "success": False,
                    "error": f"Discovery agent not available: {str(e)}"
                }
                
        elif not args.host:
            return {
                "success": False,
                "error": "Discovery stage requires --host argument",
                "suggestion": "Example: pgdn --stage discovery --host 192.168.1.1"
            }
        else:
            # Legacy discovery mode
            orchestrator = PipelineOrchestrator(config)
            return orchestrator.run_discovery_stage(
                agent_name=args.agent or 'DiscoveryAgent',
                host=args.host,
                org_id=args.org_id
            )
    
    else:
        return {
            "success": False,
            "error": f"Unknown stage: {stage}"
        }


def run_queue_command(config: Config, args) -> Dict[str, Any]:
    """Run queue-related commands."""
    queue_manager = QueueManager(config)
    
    if args.task_id:
        return queue_manager.get_task_status(args.task_id)
    
    elif args.cancel_task:
        return queue_manager.cancel_task(args.cancel_task)
    
    elif args.list_tasks:
        return {
            "success": True,
            "message": "Task status listing requires additional task tracking implementation",
            "suggestion": "Use --task-id <id> to check specific task status"
        }
    
    elif args.target:
        if not args.org_id:
            return {
                "success": False,
                "error": "Target scanning requires --org-id argument",
                "suggestion": "Example: pgdn --stage scan --target 139.84.148.36 --org-id myorg --queue"
            }
        result = queue_manager.queue_target_scan(
            args.target, 
            args.debug,
            org_id=args.org_id
        )
        if args.wait_for_completion and result.get('success'):
            task_id = result['task_id']
            wait_result = queue_manager.wait_for_tasks(task_id, timeout=3600)
            result['wait_result'] = wait_result
        return result
    
    elif args.stage:
        # Configure report options if needed
        report_options = None
        if args.stage == 'report':
            report_options = {
                'input_file': getattr(args, 'report_input', None),
                'output_file': getattr(args, 'report_output', None),
                'format': getattr(args, 'report_format', 'json'),
                'auto_save': getattr(args, 'auto_save_report', False),
                'email_report': getattr(args, 'report_email', False),
                'recipient_email': getattr(args, 'recipient_email', None),
                'scan_id': getattr(args, 'scan_id', None),
                'force_report': getattr(args, 'force_report', False)
            }
        
        result = queue_manager.queue_single_stage(
            args.stage,
            getattr(args, 'agent', None),
            getattr(args, 'recon_agents', None),
            getattr(args, 'protocol', None),
            getattr(args, 'debug', False),
            getattr(args, 'force_rescore', False),
            getattr(args, 'host', None),
            report_options=report_options,
            force=getattr(args, 'force', False),
            org_id=args.org_id
        )
        
        if args.wait_for_completion and result.get('success'):
            task_id = result['task_id']
            wait_result = queue_manager.wait_for_tasks(task_id, timeout=3600)
            result['wait_result'] = wait_result
        
        return result
    
    else:
        # Queue full pipeline
        result = queue_manager.queue_full_pipeline(
            getattr(args, 'recon_agents', None),
            org_id=args.org_id
        )
        
        if args.wait_for_completion and result.get('success'):
            task_id = result['task_id']
            wait_result = queue_manager.wait_for_tasks(task_id, timeout=3600)
            result['wait_result'] = wait_result
        
        return result


def run_parallel_command(config: Config, args) -> Dict[str, Any]:
    """Run parallel operations command."""
    # Determine targets
    targets = None
    if args.parallel_targets:
        targets = args.parallel_targets
    elif args.target_file:
        try:
            targets = load_targets_from_file(args.target_file)
        except Exception as e:
            return {
                "success": False,
                "error": f"Error loading targets from file: {str(e)}"
            }
    
    # Use library for parallel operations
    parallel_ops = ParallelOperations(config)
    
    return parallel_ops.coordinate_parallel_operation(
        targets=targets,
        target_file=None,  # Already loaded above if needed
        stages=args.parallel_stages,
        max_parallel=args.max_parallel,
        protocol_filter=args.protocol,
        debug=args.debug,
        agent_name=args.agent,
        recon_agents=args.recon_agents,
        force_rescore=args.force_rescore,
        host=args.host,
        use_queue=args.queue,
        wait_for_completion=args.wait_for_completion,
        org_id=args.org_id
    )


def run_cve_command(args) -> Dict[str, Any]:
    """Run CVE-related commands."""
    cve_manager = CVEManager()
    
    if args.start_cve_scheduler:
        return cve_manager.start_scheduler(args.cve_update_time)
    else:
        return cve_manager.update_database(
            force_update=args.replace_cves,
            initial_populate=args.initial_cves
        )


def run_signature_command(args) -> Dict[str, Any]:
    """Run signature-related commands."""
    signature_manager = SignatureManager()
    
    if args.learn_signatures_from_scans:
        if not args.signature_protocol:
            return {
                "success": False,
                "error": "Signature learning requires --signature-protocol argument",
                "suggestion": "Example: pgdn --learn-signatures-from-scans --signature-protocol sui"
            }
        
        return signature_manager.learn_from_scans(
            protocol=args.signature_protocol,
            min_confidence=args.signature_learning_min_confidence,
            max_examples=args.signature_learning_max_examples,
            org_id=args.org_id
        )
    
    elif args.update_signature_flags:
        return signature_manager.update_signature_flags(
            args.protocol_filter,
            org_id=args.org_id
        )
    
    elif args.mark_signature_created:
        return signature_manager.mark_signature_created(
            args.mark_signature_created,
            org_id=args.org_id
        )
    
    elif args.show_signature_stats:
        return signature_manager.get_signature_statistics(org_id=args.org_id)
    
    else:
        return {
            "success": False,
            "error": "No signature operation specified"
        }


def run_list_agents_command() -> Dict[str, Any]:
    """Run list agents command."""
    agent_manager = AgentManager()
    return agent_manager.list_all_agents()


def main():
    """Main CLI entry point."""
    args = parse_arguments()
    
    # Handle JSON output mode
    json_output = args.json
    
    try:
        # Load configuration
        config = load_config_cli(args, json_output)
        
        # Setup environment (unless in JSON mode or for simple operations)
        if not json_output and not any([
            args.list_agents, args.task_id, args.cancel_task, args.list_tasks,
            args.update_cves and not args.initial_cves
        ]):
            setup_environment_cli(config)
        
        # Route to appropriate command handler
        result = None
        
        if args.list_agents:
            result = run_list_agents_command()
        
        elif args.update_cves:
            result = run_cve_command(args)
        
        elif args.start_cve_scheduler:
            result = run_cve_command(args)
        
        elif any([args.learn_signatures_from_scans, args.update_signature_flags, 
                 args.mark_signature_created, args.show_signature_stats]):
            result = run_signature_command(args)
        
        elif args.task_id or args.cancel_task or args.list_tasks:
            result = run_queue_command(config, args)
        
        elif args.parallel_targets or args.target_file or args.parallel_stages:
            result = run_parallel_command(config, args)
        
        elif args.stage:
            result = run_single_stage_command(config, args)
        
        elif args.queue:
            result = run_queue_command(config, args)
        
        else:
            # Default: run full pipeline
            result = run_full_pipeline_command(config, args)
        
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
        description="PGDN - Agentic DePIN Infrastructure Scanner CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Standard Operations
  pgdn                              # Run full pipeline
  pgdn --stage recon                # Run only reconnaissance
  pgdn --stage scan                 # Run only scanning (scan level 1 by default)
  pgdn --stage scan --scan-level 2  # Run scanning with GeoIP enrichment
  pgdn --stage scan --scan-level 3  # Run comprehensive scanning with advanced analysis
  pgdn --stage scan --protocol filecoin # Scan only Filecoin nodes
  pgdn --stage scan --protocol filecoin --debug # Scan with debug logging
  pgdn --stage scan --protocol sui  # Scan only Sui nodes
  pgdn --stage process              # Run only processing

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
  pgdn --stage score                # Run only scoring
  pgdn --stage signature            # Generate protocol signatures
  pgdn --stage discovery --host 192.168.1.1 # Run network topology discovery for specific host
  pgdn --stage discovery --node-id abc123-def456 --host 192.168.1.1 # Run discovery for specific node (orchestration workflow)
  pgdn --stage publish --scan-id 123   # Publish to blockchain ledger only (default behavior)
  pgdn --stage publish --scan-id 123 --publish-ledger  # Publish only to blockchain ledger (explicit)
  pgdn --stage publish --scan-id 123 --publish-report  # Publish reports to local files and Walrus storage (requires ledger to be published first)
  pgdn --stage report               # Generate AI security analysis report for all unprocessed scans
  pgdn --stage report --scan-id 123 # Generate report for specific scan ID
  pgdn --stage report --force-report # Generate reports for all scans (even if already processed)
  pgdn --stage report --report-input scan_result.json # Generate report from specific scan
  pgdn --stage report --report-email # Generate with email notification
  pgdn --stage report --auto-save-report # Auto-save with timestamp
  pgdn --stage scan --target 139.84.148.36 --org-id myorg # Scan specific IP/hostname (level 1)
  pgdn --stage scan --target 139.84.148.36 --org-id myorg --scan-level 2 # Scan target with GeoIP enrichment
  pgdn --stage scan --target 139.84.148.36 --org-id myorg --scan-level 3 # Comprehensive scan of target
  pgdn --stage scan --target 139.84.148.36 --org-id myorg --protocol sui # Scan target as Sui node
  pgdn --stage scan --target 139.84.148.36 --org-id myorg --protocol sui --scan-level 3 # Comprehensive Sui scan
  pgdn --stage scan --target 139.84.148.36 --org-id myorg --debug # Scan target with debug
  pgdn --list-agents                # List available agents
  pgdn --recon-agents SuiReconAgent # Run specific recon agent
  pgdn --update-cves                # Update CVE database with latest data
  pgdn --update-cves --replace-cves # Force update of CVE database
  pgdn --update-cves --initial-cves # Initial CVE database population
  pgdn --start-cve-scheduler        # Start daily CVE update scheduler
  
  # Organization-specific Operations
  pgdn --org-id myorg               # Run full pipeline for specific organization
  pgdn --stage scan --org-id myorg  # Scan only nodes belonging to organization 'myorg'
  pgdn --stage scan --target 139.84.148.36 --org-id myorg # Scan target and associate with organization
  pgdn --stage report --org-id myorg # Generate reports only for organization's scans
  
  # Orchestration Workflow (when no protocol is known)
  # 1. First scan attempt triggers discovery requirement:
  pgdn --stage scan --target 192.168.1.1 --org-id myorg # Returns: "run-discovery" with node-id
  # 2. Run discovery for the node:
  pgdn --stage discovery --node-id <uuid> --host 192.168.1.1 # Identifies protocol and updates node
  # 3. Re-run scan (now succeeds with discovered protocol):
  pgdn --stage scan --target 192.168.1.1 --org-id myorg # Proceeds with scan using discovered protocol
  
  # Queue Operations (Background Processing)
  pgdn --queue                      # Queue full pipeline for background processing
  pgdn --stage scan --queue         # Queue scan stage for background processing
  pgdn --stage scan --target 139.84.148.36 --org-id myorg --queue # Queue target scan for background processing
  pgdn --queue --wait-for-completion # Queue job and wait for completion
  pgdn --queue --org-id myorg       # Queue pipeline for specific organization
  pgdn --task-id abc123-def456      # Check status of queued task
  pgdn --cancel-task abc123-def456  # Cancel a queued task
  pgdn --list-tasks                 # List all active queued tasks
  
  # Parallel Processing
  pgdn --parallel-targets 192.168.1.100 192.168.1.101 192.168.1.102 # Scan multiple targets in parallel
  pgdn --parallel-targets 10.0.0.1 10.0.0.2 --queue --max-parallel 3 # Queue parallel scans with concurrency limit
  pgdn --target-file targets.txt --queue # Scan targets from file in parallel
  pgdn --parallel-stages recon scan --queue # Run multiple independent stages in parallel
  pgdn --parallel-stages recon scan --queue --wait-for-completion # Run and wait for completion
  pgdn --parallel-targets 10.0.0.1 10.0.0.2 --org-id myorg # Parallel scans for specific organization
  
  # Signature Learning from Existing Scans
  pgdn --learn-signatures-from-scans --signature-protocol sui # Learn Sui signatures from existing scans
  pgdn --learn-signatures-from-scans --signature-protocol filecoin # Learn Filecoin signatures
  pgdn --learn-signatures-from-scans --signature-protocol ethereum --signature-learning-min-confidence 0.8 # Learn with higher confidence threshold
  pgdn --learn-signatures-from-scans --signature-protocol sui --signature-learning-max-examples 500 # Limit examples
  pgdn --learn-signatures-from-scans --signature-protocol sui --org-id myorg # Learn signatures for specific organization
        """
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help='Return results in JSON format instead of human-readable output'
    )
    
    parser.add_argument(
        '--org-id',
        help='Organization ID to filter agentic jobs by organization'
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
        '--node-id',
        help='Node UUID for orchestration workflow (used with discovery stage)'
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
        help='Specific scan ID to generate report for (if not provided, will run for all unprocessed scans). Required for publish stage.'
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
    
    # Publish stage arguments
    parser.add_argument(
        '--publish-ledger',
        action='store_true',
        help='Publish scan results to blockchain ledger (use with --stage publish)'
    )
    
    parser.add_argument(
        '--publish-report',
        action='store_true',
        help='Publish scan reports to local files and Walrus storage (use with --stage publish, requires ledger to be published first)'
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
        '--signature-protocol',
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
