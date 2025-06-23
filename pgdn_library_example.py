#!/usr/bin/env python3
"""
PGDN Library Usage Examples

This module demonstrates how to use the PGDN library for various DePIN infrastructure
scanning operations without using the CLI interface.
"""

# Example 1: Basic Configuration and Environment Setup
def example_basic_setup():
    """Example of basic application setup using the library."""
    from pgdn import ApplicationCore
    
    # Initialize application core
    app_core = ApplicationCore()
    
    # Load configuration with custom parameters
    config = app_core.load_config(
        config_file="config.json",
        log_level="INFO",
        use_docker_config=False
    )
    
    # Setup environment (logging, database, etc.)
    app_core.setup_environment(config)
    
    print("✅ Application initialized successfully")
    return config


# Example 2: Running a Full Pipeline Programmatically
def example_full_pipeline():
    """Example of running a full pipeline using the library."""
    from pgdn import initialize_application, PipelineOrchestrator
    
    # Complete initialization in one call
    config = initialize_application(
        config_file="config.json",
        log_level="DEBUG"
    )
    
    # Create pipeline orchestrator
    orchestrator = PipelineOrchestrator(config)
    
    # Run full pipeline with specific recon agents
    result = orchestrator.run_full_pipeline(
        recon_agents=['SuiReconAgent', 'FilecoinReconAgent']
    )
    
    if result['success']:
        print(f"✅ Pipeline completed successfully!")
        print(f"   Execution ID: {result['execution_id']}")
        print(f"   Total time: {result['execution_time_seconds']:.2f} seconds")
        return result
    else:
        print(f"❌ Pipeline failed: {result.get('error', 'Unknown error')}")
        return None


# Example 3: Direct Target Scanning
def example_target_scanning():
    """Example of scanning specific targets directly."""
    from pgdn import load_config, Scanner
    
    # Setup
    config = load_config("config.json")
    
    # Create scanner with protocol filter
    scanner = Scanner(
        config=config,
        protocol_filter='sui',
        debug=True
    )
    
    # Scan a specific target
    target_result = scanner.scan_target("139.84.148.36")
    
    if target_result['success']:
        print(f"✅ Target scan successful")
        print(f"   Target: {target_result['target']}")
        print(f"   Resolved IP: {target_result['resolved_ip']}")
    else:
        print(f"❌ Target scan failed: {target_result.get('error')}")


if __name__ == "__main__":
    """Run a simple example."""
    print("🚀 Running PGDN library example...")
    
    try:
        # Basic setup example
        config = example_basic_setup()
        print(f"Configuration loaded: {type(config)}")
        
    except Exception as e:
        print(f"❌ Example failed: {e}")
        import traceback
        traceback.print_exc()
