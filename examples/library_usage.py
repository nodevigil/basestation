"""
PGDN Library Usage Examples

This file demonstrates how to use the PGDN library programmatically
without the CLI interface. All business logic is accessible as a 
clean Python API.
"""

import sys
sys.path.append('/Users/simon/Documents/Code/depin')

# Import the library
import pgdn
from pgdn import (
    ApplicationCore, PipelineOrchestrator, Scanner, ReportManager,
    CVEManager, SignatureManager, QueueManager, AgentManager, ParallelOperations
)


def example_basic_usage():
    """Basic usage example showing how to initialize and run a pipeline."""
    print("=== Basic Usage Example ===")
    
    # Initialize application
    app = ApplicationCore()
    
    try:
        # Load configuration (pure library call, no CLI dependencies)
        config = app.load_config(config_file='config.json', log_level='INFO')
        
        # Setup environment (logging, database)
        app.setup_environment(config)
        
        # Run full pipeline
        orchestrator = PipelineOrchestrator(config)
        result = orchestrator.run_full_pipeline()
        
        print(f"Pipeline result: {result['success']}")
        if result['success']:
            print(f"Execution ID: {result['execution_id']}")
            print(f"Execution time: {result['execution_time_seconds']:.2f}s")
        else:
            print(f"Error: {result['error']}")
            
    except FileNotFoundError as e:
        print(f"Config file not found: {e}")
    except Exception as e:
        print(f"Error: {e}")


def example_single_operations():
    """Example showing how to run individual operations."""
    print("\\n=== Single Operations Example ===")
    
    app = ApplicationCore()
    
    try:
        # Initialize with convenience function
        config = pgdn.initialize_application(log_level='WARNING')  # Quieter logs
        
        # 1. Target scanning
        print("\\n1. Target Scanning:")
        scanner = Scanner(config, protocol_filter='sui', debug=False)
        scan_result = scanner.scan_target('139.84.148.36')
        print(f"Scan result: {scan_result['success']}")
        
        # 2. Agent listing
        print("\\n2. Agent Listing:")
        agent_manager = AgentManager()
        agents_result = agent_manager.list_all_agents()
        if agents_result['success']:
            for category, agents in agents_result['agents'].items():
                print(f"  {category}: {len(agents)} agents")
        
        # 3. CVE management
        print("\\n3. CVE Management:")
        cve_manager = CVEManager()
        # Just get stats without updating
        stats_result = cve_manager.get_statistics()
        if stats_result['success']:
            stats = stats_result['statistics']
            print(f"  Total CVEs: {stats.get('total_cves', 'Unknown')}")
            print(f"  High severity: {stats.get('high_severity_count', 'Unknown')}")
        
    except Exception as e:
        print(f"Error in operations: {e}")


def example_parallel_operations():
    """Example showing parallel operations."""
    print("\\n=== Parallel Operations Example ===")
    
    try:
        config = pgdn.load_config(log_level='ERROR')  # Minimal logs
        
        # Parallel scanning
        parallel_ops = ParallelOperations(config)
        targets = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
        
        # Direct parallel scans (not queued)
        result = parallel_ops.run_parallel_scans(
            targets=targets,
            max_parallel=2,
            protocol_filter='filecoin',
            use_queue=False
        )
        
        print(f"Parallel scan result: {result['success']}")
        if result['success']:
            print(f"Successful scans: {result['successful']}/{result['total']}")
            
    except Exception as e:
        print(f"Error in parallel operations: {e}")


def example_queue_operations():
    """Example showing background queue operations."""
    print("\\n=== Queue Operations Example ===")
    
    try:
        config = pgdn.load_config()
        
        # Queue manager
        queue_manager = QueueManager(config)
        
        # Queue a single stage
        result = queue_manager.queue_single_stage(
            stage='recon',
            recon_agents=['SuiReconAgent']
        )
        
        if result['success']:
            task_id = result['task_id']
            print(f"Queued task: {task_id}")
            
            # Check status
            status = queue_manager.get_task_status(task_id)
            print(f"Task status: {status}")
        else:
            print(f"Queue error: {result['error']}")
            
    except Exception as e:
        print(f"Error in queue operations: {e}")


def example_report_generation():
    """Example showing report generation."""
    print("\\n=== Report Generation Example ===")
    
    try:
        config = pgdn.load_config()
        
        # Report manager
        report_manager = ReportManager(config)
        
        # Generate report for latest scan
        result = report_manager.generate_report(
            report_format='summary',
            auto_save=True
        )
        
        print(f"Report generation: {result['success']}")
        if result['success']:
            print(f"Report generated with {result.get('reports_generated', 0)} reports")
        else:
            print(f"Report error: {result['error']}")
            
    except Exception as e:
        print(f"Error in report generation: {e}")


def example_signature_learning():
    """Example showing signature learning."""
    print("\\n=== Signature Learning Example ===")
    
    try:
        # Signature manager
        signature_manager = SignatureManager()
        
        # Learn signatures from existing scans
        result = signature_manager.learn_from_scans(
            protocol='sui',
            min_confidence=0.8,
            max_examples=100
        )
        
        print(f"Signature learning: {result['success']}")
        if result['success']:
            print(f"Protocol: {result['protocol']}")
            print(f"Examples used: {result.get('examples_processed', 'Unknown')}")
        else:
            print(f"Learning error: {result['error']}")
            
    except Exception as e:
        print(f"Error in signature learning: {e}")


def example_api_integration():
    """Example showing how the library could be integrated into an API."""
    print("\\n=== API Integration Example ===")
    
    # This shows how you might use the library in a web API
    def api_scan_target(target_ip: str, protocol: str = None):
        """API endpoint simulation for target scanning."""
        try:
            # Load config once (could be cached in real API)
            config = pgdn.load_config()
            
            # Create scanner
            scanner = Scanner(config, protocol_filter=protocol)
            
            # Scan target
            result = scanner.scan_target(target_ip)
            
            # Return API-friendly response
            return {
                "status": "success" if result['success'] else "error",
                "target": target_ip,
                "protocol": protocol,
                "data": result
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "target": target_ip
            }
    
    def api_queue_pipeline(recon_agents: list = None):
        """API endpoint simulation for queueing pipelines."""
        try:
            config = pgdn.load_config()
            queue_manager = QueueManager(config)
            
            result = queue_manager.queue_full_pipeline(recon_agents)
            
            return {
                "status": "success" if result['success'] else "error",
                "task_id": result.get('task_id'),
                "message": "Pipeline queued successfully" if result['success'] else result.get('error')
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
    
    # Simulate API calls
    print("Simulating API calls:")
    scan_response = api_scan_target('192.168.1.100', 'sui')
    print(f"  Scan API: {scan_response['status']}")
    
    queue_response = api_queue_pipeline(['SuiReconAgent'])
    print(f"  Queue API: {queue_response['status']}")


if __name__ == "__main__":
    print("PGDN Library Usage Examples")
    print("=" * 50)
    
    # Run examples (comment out examples that require actual infrastructure)
    try:
        example_basic_usage()
    except Exception as e:
        print(f"Basic usage example failed (expected): {e}")
    
    try:
        example_single_operations()
    except Exception as e:
        print(f"Single operations example failed (expected): {e}")
    
    try:
        example_parallel_operations()
    except Exception as e:
        print(f"Parallel operations example failed (expected): {e}")
    
    try:
        example_queue_operations()
    except Exception as e:
        print(f"Queue operations example failed (expected): {e}")
    
    try:
        example_report_generation()
    except Exception as e:
        print(f"Report generation example failed (expected): {e}")
    
    try:
        example_signature_learning()
    except Exception as e:
        print(f"Signature learning example failed (expected): {e}")
    
    example_api_integration()
    
    print("\\n" + "=" * 50)
    print("Examples complete! See comments for actual usage.")
    print("Most examples fail due to missing config/infrastructure, but show the API structure.")
