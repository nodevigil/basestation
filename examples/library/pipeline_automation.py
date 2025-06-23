#!/usr/bin/env python3
"""
PGDN Pipeline Automation Example

This example demonstrates automated security assessment pipelines.
"""

from pgdn import initialize_application, PipelineOrchestrator, ReportManager

def main():
    # Initialize PGDN
    print("Initializing PGDN pipeline...")
    config = initialize_application("config.json")
    
    # Create orchestrator
    orchestrator = PipelineOrchestrator(config)
    report_manager = ReportManager(config)
    
    # Example 1: Full automated pipeline
    print("\n=== Full Security Pipeline ===")
    result = orchestrator.run_full_pipeline(recon_agents=['SuiReconAgent'])
    
    if result['success']:
        print("✓ Full pipeline completed successfully")
        scan_id = result.get('scan_id')
        
        # Generate and email report
        if scan_id:
            print("Generating security report...")
            report_result = report_manager.generate_report(
                agent_name='ReportAgent',
                scan_id=scan_id,
                report_format='json',
                auto_save=True,
                email_report=True,
                recipient_email='security@company.com'
            )
            
            if report_result['success']:
                print(f"✓ Report generated and emailed")
            else:
                print(f"✗ Report generation failed: {report_result['error']}")
    else:
        print(f"✗ Pipeline failed: {result['error']}")
    
    # Example 2: Stage-by-stage execution with monitoring
    print("\n=== Stage-by-Stage Pipeline ===")
    
    stages = [
        ('recon', 'Reconnaissance'),
        ('scan', 'Security Scanning'),
        ('process', 'Result Processing'),
        ('score', 'Risk Scoring')
    ]
    
    pipeline_results = {}
    
    for stage, description in stages:
        print(f"Executing {description}...")
        
        if stage == 'recon':
            result = orchestrator.run_recon_stage()
        elif stage == 'scan':
            result = orchestrator.run_scan_stage(protocol_filter='sui')
        elif stage == 'process':
            result = orchestrator.run_process_stage()
        elif stage == 'score':
            result = orchestrator.run_scoring_stage(force_rescore=True)
        
        pipeline_results[stage] = result
        
        if result['success']:
            print(f"  ✓ {description} completed")
            if 'execution_time' in result:
                print(f"    Execution time: {result['execution_time']:.2f}s")
        else:
            print(f"  ✗ {description} failed: {result['error']}")
            break
    
    # Example 3: Conditional pipeline execution
    print("\n=== Conditional Pipeline ===")
    
    # Run reconnaissance first
    recon_result = orchestrator.run_recon_stage()
    
    if recon_result['success'] and recon_result.get('targets_found', 0) > 0:
        print(f"Found {recon_result['targets_found']} targets, proceeding with scan...")
        
        scan_result = orchestrator.run_scan_stage()
        
        if scan_result['success']:
            vulnerability_count = scan_result.get('vulnerability_count', 0)
            
            if vulnerability_count > 0:
                print(f"Found {vulnerability_count} vulnerabilities, generating priority report...")
                
                # Generate high-priority report
                report_result = report_manager.generate_report(
                    agent_name='ReportAgent',
                    scan_id=scan_result.get('scan_id'),
                    report_format='json',
                    email_report=True,
                    recipient_email='security-alerts@company.com'
                )
            else:
                print("No vulnerabilities found, skipping alert")
    else:
        print("No targets found during reconnaissance")

if __name__ == "__main__":
    main()