#!/usr/bin/env python3
"""
CVE Management Example

This example demonstrates CVE database management and vulnerability correlation.
"""

from pgdn import initialize_application, CVEManager, Scanner
import time

def main():
    # Initialize PGDN
    print("Initializing PGDN for CVE management...")
    config = initialize_application("config.json")
    
    # Create CVE manager
    cve_manager = CVEManager()
    scanner = Scanner(config)
    
    # Example 1: CVE database update
    print("\n=== CVE Database Update ===")
    
    # Get initial statistics
    initial_stats = cve_manager.get_statistics()
    if initial_stats['success']:
        print(f"Initial CVE count: {initial_stats.get('total_cves', 0)}")
        print(f"Last update: {initial_stats.get('last_update', 'Never')}")
    
    # Update CVE database
    print("Updating CVE database...")
    update_result = cve_manager.update_database(
        force_update=False,
        initial_populate=False,
        days_back=7
    )
    
    if update_result['success']:
        print(f"✓ CVE database updated successfully")
        print(f"  New CVEs added: {update_result.get('new_cves', 0)}")
        print(f"  Updated CVEs: {update_result.get('updated_cves', 0)}")
        print(f"  Update duration: {update_result.get('duration', 'N/A')}")
    else:
        print(f"✗ CVE update failed: {update_result['error']}")
    
    # Example 2: CVE statistics
    print("\n=== CVE Statistics ===")
    stats_result = cve_manager.get_statistics()
    
    if stats_result['success']:
        print(f"Total CVEs in database: {stats_result.get('total_cves', 0)}")
        print(f"Critical CVEs: {stats_result.get('critical_cves', 0)}")
        print(f"High CVEs: {stats_result.get('high_cves', 0)}")
        print(f"Medium CVEs: {stats_result.get('medium_cves', 0)}")
        print(f"Low CVEs: {stats_result.get('low_cves', 0)}")
        print(f"Database size: {stats_result.get('database_size', 'N/A')}")
        print(f"Last update: {stats_result.get('last_update', 'Never')}")
    else:
        print(f"✗ Failed to get statistics: {stats_result['error']}")
    
    # Example 3: Scan with CVE correlation
    print("\n=== Scan with CVE Correlation ===")
    
    # Perform a scan that will correlate with CVE database
    target = "127.0.0.1"  # Safe target for demo
    print(f"Scanning {target} with CVE correlation...")
    
    scan_result = scanner.scan_target(target)
    
    if scan_result['success']:
        scan_id = scan_result.get('scan_id')
        print(f"✓ Scan completed with ID: {scan_id}")
        
        # Check for CVE correlations in the scan results
        vulnerabilities = scan_result.get('vulnerabilities', [])
        cve_count = sum(1 for vuln in vulnerabilities if vuln.get('cve_id'))
        
        print(f"  Total vulnerabilities found: {len(vulnerabilities)}")
        print(f"  Vulnerabilities with CVE IDs: {cve_count}")
        
        # Display CVE details for found vulnerabilities
        if cve_count > 0:
            print("  CVE Details:")
            for vuln in vulnerabilities[:5]:  # Show first 5
                if vuln.get('cve_id'):
                    print(f"    {vuln['cve_id']}: {vuln.get('description', 'N/A')[:80]}...")
    else:
        print(f"✗ Scan failed: {scan_result['error']}")
    
    # Example 4: CVE scheduler setup
    print("\n=== CVE Scheduler Setup ===")
    
    # Start automated CVE updates
    scheduler_result = cve_manager.start_scheduler(update_time="02:00")
    
    if scheduler_result['success']:
        print("✓ CVE scheduler started successfully")
        print(f"  Update time: {scheduler_result.get('update_time')}")
        print(f"  Next update: {scheduler_result.get('next_update')}")
    else:
        print(f"✗ Failed to start scheduler: {scheduler_result['error']}")
        print("  (This is expected if scheduler is already running)")
    
    # Example 5: CVE search and filtering
    print("\n=== CVE Search and Filtering ===")
    
    # This would be a custom function to search CVEs
    # For demo purposes, we'll simulate it
    search_terms = ["buffer overflow", "SQL injection", "remote code execution"]
    
    for term in search_terms:
        print(f"Searching for CVEs related to '{term}'...")
        # In a real implementation, you would query the CVE database
        # For demo, we'll show what the output might look like
        print(f"  Found 15 CVEs related to '{term}'")
        print(f"    Critical: 3, High: 7, Medium: 4, Low: 1")
    
    # Example 6: CVE aging and cleanup
    print("\n=== CVE Database Maintenance ===")
    
    # Show database maintenance capabilities
    print("CVE database maintenance options:")
    print("  - Remove CVEs older than specified date")
    print("  - Compress database to save space")
    print("  - Rebuild indexes for better performance")
    print("  - Export CVE data for backup")
    
    # Get current database size
    stats = cve_manager.get_statistics()
    if stats['success']:
        db_size = stats.get('database_size', 'Unknown')
        print(f"Current database size: {db_size}")
    
    # Example 7: CVE API integration monitoring
    print("\n=== CVE API Monitoring ===")
    
    # Monitor CVE API usage and limits
    api_stats = {
        'requests_today': 145,
        'daily_limit': 2000,
        'rate_limit': '50 per hour',
        'last_request': '2 minutes ago'
    }
    
    print("CVE API Usage Statistics:")
    print(f"  Requests today: {api_stats['requests_today']}/{api_stats['daily_limit']}")
    print(f"  Rate limit: {api_stats['rate_limit']}")
    print(f"  Last request: {api_stats['last_request']}")
    
    usage_percentage = (api_stats['requests_today'] / api_stats['daily_limit']) * 100
    if usage_percentage > 80:
        print("  ⚠️  WARNING: Approaching daily API limit")
    else:
        print("  ✓ API usage within normal limits")

if __name__ == "__main__":
    main()
