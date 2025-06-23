#!/usr/bin/env python3
"""
Report Generation Example

This example demonstrates various report generation capabilities.
"""

from pgdn import initialize_application, ReportManager, Scanner
import json
import os

def main():
    # Initialize PGDN
    print("Initializing PGDN for report generation...")
    config = initialize_application("config.json")
    
    # Create managers
    report_manager = ReportManager(config)
    scanner = Scanner(config)
    
    # Example 1: Generate scan and create report
    print("\n=== Scan and Report Generation ===")
    target = "127.0.0.1"  # Safe target for demo
    
    # Perform scan
    scan_result = scanner.scan_target(target)
    
    if scan_result['success']:
        scan_id = scan_result.get('scan_id')
        print(f"✓ Scan completed with ID: {scan_id}")
        
        # Generate JSON report
        report_result = report_manager.generate_report(
            agent_name='ReportAgent',
            scan_id=scan_id,
            report_format='json',
            auto_save=True
        )
        
        if report_result['success']:
            print(f"✓ JSON report generated: {report_result.get('output_file')}")
        else:
            print(f"✗ Report generation failed: {report_result['error']}")
    else:
        print(f"✗ Scan failed: {scan_result['error']}")
    
    # Example 2: Multiple report formats
    print("\n=== Multiple Report Formats ===")
    
    # Assuming we have a scan_id from previous operations
    # For demo, we'll create a mock scan_id
    demo_scan_id = 1  # Replace with actual scan_id
    
    formats = ['json', 'csv']
    for format_type in formats:
        print(f"Generating {format_type.upper()} report...")
        
        report_result = report_manager.generate_report(
            agent_name='ReportAgent',
            scan_id=demo_scan_id,
            report_format=format_type,
            auto_save=True,
            output_file=f"demo_report.{format_type}"
        )
        
        if report_result['success']:
            print(f"  ✓ {format_type.upper()} report: {report_result.get('output_file')}")
        else:
            print(f"  ✗ {format_type.upper()} report failed: {report_result['error']}")
    
    # Example 3: Email report
    print("\n=== Email Report ===")
    
    # Note: This requires email configuration in config.json
    email_result = report_manager.generate_report(
        agent_name='ReportAgent',
        scan_id=demo_scan_id,
        report_format='json',
        email_report=True,
        recipient_email='security@example.com'  # Replace with actual email
    )
    
    if email_result['success']:
        print("✓ Email report sent successfully")
    else:
        print(f"✗ Email report failed: {email_result['error']}")
        print("  (This is expected if email is not configured)")
    
    # Example 4: Custom report with filtering
    print("\n=== Custom Filtered Report ===")
    
    # Generate report with custom parameters
    custom_result = report_manager.generate_report(
        agent_name='ReportAgent',
        scan_id=demo_scan_id,
        report_format='json',
        auto_save=True,
        output_file='custom_filtered_report.json',
        force_report=True  # Force regeneration even if exists
    )
    
    if custom_result['success']:
        print(f"✓ Custom report generated: {custom_result.get('output_file')}")
        
        # Load and display report summary
        try:
            with open(custom_result.get('output_file'), 'r') as f:
                report_data = json.load(f)
                print(f"  Report summary:")
                print(f"    Scan ID: {report_data.get('scan_id')}")
                print(f"    Target: {report_data.get('target')}")
                print(f"    Vulnerabilities: {len(report_data.get('vulnerabilities', []))}")
                print(f"    Generated: {report_data.get('generated_at')}")
        except Exception as e:
            print(f"  Could not read report: {e}")
    else:
        print(f"✗ Custom report failed: {custom_result['error']}")
    
    # Example 5: Batch report generation
    print("\n=== Batch Report Generation ===")
    
    # Assuming we have multiple scan IDs
    scan_ids = [1, 2, 3]  # Replace with actual scan IDs
    
    successful_reports = 0
    for scan_id in scan_ids:
        print(f"Generating report for scan {scan_id}...")
        
        result = report_manager.generate_report(
            agent_name='ReportAgent',
            scan_id=scan_id,
            report_format='json',
            auto_save=True,
            output_file=f'batch_report_{scan_id}.json'
        )
        
        if result['success']:
            successful_reports += 1
            print(f"  ✓ Report {scan_id} completed")
        else:
            print(f"  ✗ Report {scan_id} failed: {result['error']}")
    
    print(f"Batch generation complete: {successful_reports}/{len(scan_ids)} successful")
    
    # Example 6: Report analysis
    print("\n=== Report Analysis ===")
    
    # Analyze generated reports
    report_files = [f for f in os.listdir('.') if f.startswith('demo_report') or f.startswith('batch_report')]
    
    if report_files:
        print(f"Found {len(report_files)} report files:")
        
        total_vulnerabilities = 0
        for report_file in report_files:
            try:
                with open(report_file, 'r') as f:
                    data = json.load(f)
                    vuln_count = len(data.get('vulnerabilities', []))
                    total_vulnerabilities += vuln_count
                    print(f"  {report_file}: {vuln_count} vulnerabilities")
            except Exception as e:
                print(f"  {report_file}: Error reading ({e})")
        
        print(f"Total vulnerabilities across all reports: {total_vulnerabilities}")
    else:
        print("No report files found for analysis")
    
    # Cleanup demo files (optional)
    print("\n=== Cleanup ===")
    cleanup_files = [f for f in os.listdir('.') if f.startswith(('demo_report', 'batch_report', 'custom_filtered_report'))]
    
    if cleanup_files:
        for cleanup_file in cleanup_files:
            try:
                os.remove(cleanup_file)
                print(f"Removed {cleanup_file}")
            except Exception as e:
                print(f"Could not remove {cleanup_file}: {e}")

if __name__ == "__main__":
    main()
