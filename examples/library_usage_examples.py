#!/usr/bin/env python3
"""
PGDN Library Usage Examples

This script demonstrates how to use the PGDN library programmatically
for various scanning and infrastructure management tasks.
"""

import json
import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pgdn import (
    PipelineOrchestrator, Scanner, ReportManager, CVEManager, 
    SignatureManager, QueueManager, AgentManager
)
from pgdn.core.config import Config


def example_basic_scanning():
    """Example: Basic target scanning."""
    print("="*60)
    print("Example 1: Basic Target Scanning")
    print("="*60)
    
    # Initialize configuration and scanner
    config = Config()
    scanner = Scanner(config, debug=True)
    
    # Scan a localhost target
    print("Scanning localhost (127.0.0.1)...")
    result = scanner.scan_target('127.0.0.1')
    
    if result['success']:
        print(f"✅ Scan successful!")
        print(f"   Target: {result['target']}")
        print(f"   Resolved IP: {result.get('resolved_ip', 'N/A')}")
        
        # Save the result
        output_file = scanner.save_scan_result(result['scan_result'], result['target'])
        print(f"   Results saved to: {output_file}")
    else:
        print(f"❌ Scan failed: {result['error']}")
    
    print()


def example_parallel_scanning():
    """Example: Parallel scanning of multiple targets."""
    print("="*60)
    print("Example 2: Parallel Scanning")
    print("="*60)
    
    config = Config()
    scanner = Scanner(config, protocol_filter='sui')
    
    # Define multiple targets to scan
    targets = ['127.0.0.1', '8.8.8.8', 'google.com']
    print(f"Scanning {len(targets)} targets in parallel...")
    
    result = scanner.scan_parallel_targets(targets, max_parallel=3)
    
    if result['success']:
        print(f"✅ Parallel scanning completed!")
        print(f"   Successful: {result['successful']}/{result['total']}")
        
        # Show summary of each result
        for target_result in result['results']:
            target = target_result['target']
            success = "✅" if target_result['success'] else "❌"
            print(f"   {success} {target}")
    else:
        print(f"❌ Parallel scanning failed: {result['error']}")
    
    print()


def example_pipeline_orchestration():
    """Example: Running the full pipeline."""
    print("="*60)
    print("Example 3: Pipeline Orchestration")
    print("="*60)
    
    config = Config()
    orchestrator = PipelineOrchestrator(config)
    
    print("Running reconnaissance stage...")
    recon_result = orchestrator.run_recon_stage(['SuiReconAgent'])
    
    if recon_result['success']:
        print(f"✅ Reconnaissance completed: {recon_result['results_count']} nodes discovered")
    else:
        print(f"❌ Reconnaissance failed: {recon_result['error']}")
        return
    
    # If recon was successful and found nodes, run scanning
    if recon_result['results_count'] > 0:
        print("Running scanning stage...")
        scanner = Scanner(config, protocol_filter='sui')
        scan_result = scanner.scan_nodes_from_database()
        
        if scan_result['success']:
            print(f"✅ Scanning completed: {scan_result['results_count']} nodes scanned")
        else:
            print(f"❌ Scanning failed: {scan_result['error']}")
    else:
        print("⚠️  No nodes found for scanning")
    
    print()


def example_report_generation():
    """Example: Report generation."""
    print("="*60)
    print("Example 4: Report Generation")
    print("="*60)
    
    config = Config()
    report_manager = ReportManager(config)
    
    print("Generating summary report...")
    result = report_manager.generate_summary_report()
    
    if result['success']:
        print(f"✅ Report generated successfully!")
        print(f"   Agent: {result['agent']}")
        print(f"   Scan ID: {result.get('scan_id', 'All unprocessed scans')}")
    else:
        print(f"❌ Report generation failed: {result['error']}")
    
    print()


def example_cve_management():
    """Example: CVE database management."""
    print("="*60)
    print("Example 5: CVE Database Management")
    print("="*60)
    
    cve_manager = CVEManager()
    
    print("Getting CVE database statistics...")
    stats_result = cve_manager.get_statistics()
    
    if stats_result['success']:
        stats = stats_result['statistics']
        print(f"✅ CVE Database Statistics:")
        print(f"   Total CVEs: {stats.get('total_cves', 'Unknown')}")
        print(f"   High Severity: {stats.get('high_severity_count', 'Unknown')}")
        print(f"   Recent (30 days): {stats.get('recent_cves_30_days', 'Unknown')}")
        print(f"   Last Update: {stats.get('last_update', 'Unknown')}")
    else:
        print(f"❌ Failed to get CVE statistics: {stats_result['error']}")
    
    print()


def example_agent_listing():
    """Example: List available agents."""
    print("="*60)
    print("Example 6: Agent Management")
    print("="*60)
    
    agent_manager = AgentManager()
    
    print("Listing available agents...")
    result = agent_manager.list_all_agents()
    
    if result['success']:
        agents = result['agents']
        print(f"✅ Found agents in {len(agents)} categories:")
        
        for category, agent_list in agents.items():
            print(f"\n{category.upper()} AGENTS:")
            if agent_list:
                for agent in agent_list:
                    print(f"  • {agent}")
            else:
                print("  (none available)")
    else:
        print(f"❌ Failed to list agents: {result['error']}")
    
    print()


def example_queue_operations():
    """Example: Background queue operations (requires Celery)."""
    print("="*60)
    print("Example 7: Queue Operations")
    print("="*60)
    
    config = Config()
    queue_manager = QueueManager(config)
    
    print("Attempting to queue a target scan...")
    result = queue_manager.queue_target_scan('127.0.0.1', debug=True)
    
    if result['success']:
        task_id = result['task_id']
        print(f"✅ Task queued successfully!")
        print(f"   Task ID: {task_id}")
        
        # Check task status
        print("Checking task status...")
        status_result = queue_manager.get_task_status(task_id)
        
        if status_result['success']:
            print(f"   Status: {status_result['status']}")
            print(f"   Ready: {'✅' if status_result['ready'] else '⏳'}")
        else:
            print(f"   Failed to get status: {status_result['error']}")
    else:
        print(f"❌ Queue operation failed: {result['error']}")
        if "Celery not available" in result['error']:
            print("   Note: This requires Redis and Celery to be installed and running")
    
    print()


def example_json_output():
    """Example: Working with JSON output for API integration."""
    print("="*60)
    print("Example 8: JSON Output for API Integration")
    print("="*60)
    
    config = Config()
    scanner = Scanner(config)
    
    print("Scanning target and getting JSON result...")
    result = scanner.scan_target('127.0.0.1')
    
    # Convert to JSON for API response
    json_output = json.dumps(result, indent=2)
    
    print("JSON Output (suitable for API responses):")
    print(json_output[:500] + "..." if len(json_output) > 500 else json_output)
    
    print()


def main():
    """Run all examples."""
    print("🐦 PGDN Library Usage Examples")
    print("This script demonstrates various ways to use the PGDN library programmatically.")
    print()
    
    try:
        # Run examples
        example_basic_scanning()
        example_parallel_scanning()
        example_pipeline_orchestration()
        example_report_generation()
        example_cve_management()
        example_agent_listing()
        example_queue_operations()
        example_json_output()
        
        print("="*60)
        print("✅ All examples completed!")
        print("="*60)
        print("For more detailed documentation, see docs/LIBRARY_API.md")
        
    except KeyboardInterrupt:
        print("\n⚠️  Examples interrupted by user")
    except Exception as e:
        print(f"\n❌ Example failed with error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
