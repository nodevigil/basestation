#!/usr/bin/env python3
"""
Parallel Processing Examples for DePIN Infrastructure Scanner
"""

import os
import sys
import time

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def demonstrate_parallel_capabilities():
    """Demonstrate all parallel processing capabilities."""
    
    print("🚀 DePIN Scanner - Parallel Processing Capabilities")
    print("=" * 70)
    
    print("\n📋 Types of Parallel Processing Available:")
    print("-" * 50)
    
    parallel_types = [
        {
            'name': '1. Parallel Target Scanning',
            'description': 'Scan multiple IP addresses/hostnames simultaneously',
            'examples': [
                'pgdn --parallel-targets 192.168.1.100 192.168.1.101 192.168.1.102',
                'pgdn --parallel-targets 10.0.0.1 10.0.0.2 --queue --max-parallel 5',
                'pgdn --target-file targets.txt --queue --max-parallel 10'
            ]
        },
        {
            'name': '2. Parallel Stage Execution', 
            'description': 'Run multiple independent pipeline stages simultaneously',
            'examples': [
                'pgdn --parallel-stages recon scan --queue',
                'pgdn --parallel-stages recon signature discovery --queue --wait-for-completion'
            ]
        },
        {
            'name': '3. Parallel Pipeline Execution',
            'description': 'Run multiple complete pipelines with different configurations',
            'examples': [
                'Multiple pipelines via queue manager API',
                'Different protocol filters in parallel',
                'Different configuration parameters'
            ]
        },
        {
            'name': '4. Queue-Based Parallel Processing',
            'description': 'Background parallel processing with Celery workers',
            'examples': [
                'pgdn --stage scan --queue  # Multiple nodes processed in parallel by workers',
                'pgdn --queue  # Full pipeline with parallel node processing',
                './celery-manage.sh start-all  # Multiple workers for parallel execution'
            ]
        }
    ]
    
    for ptype in parallel_types:
        print(f"\n{ptype['name']}:")
        print(f"   {ptype['description']}")
        print("   Examples:")
        for example in ptype['examples']:
            print(f"     • {example}")
    
    print("\n🔧 Configuration Options:")
    print("-" * 50)
    
    config_options = [
        ('--max-parallel N', 'Limit concurrent operations (default: 5)'),
        ('--queue', 'Use background processing with Celery workers'),
        ('--wait-for-completion', 'Wait for all parallel tasks to finish'),
        ('--batch-size N', 'Control batch sizes for queue processing'),
        ('--protocol PROTO', 'Apply protocol filter to all parallel operations'),
        ('--debug', 'Enable debug logging for all parallel operations')
    ]
    
    for option, description in config_options:
        print(f"   {option:<25} {description}")
    
    print("\n📊 Performance Characteristics:")
    print("-" * 50)
    
    performance_info = [
        ('Direct Parallel', 'Fast startup, limited by local resources, blocks terminal'),
        ('Queue Parallel', 'Scalable, non-blocking, requires Redis/Celery setup'),
        ('Batch Processing', 'Efficient for large numbers of targets, automatic load balancing'),
        ('Worker Scaling', 'Add more workers to increase parallel capacity')
    ]
    
    for method, characteristics in performance_info:
        print(f"   {method:<18} {characteristics}")
    
    print("\n🏗️ Architecture Examples:")
    print("-" * 50)
    
    print("\nSingle Worker (Basic Parallel):")
    print("""
    CLI → Task Queue → Worker → [Scanner1, Scanner2, Scanner3] → Results
           (Redis)     (1)              (Parallel)
    """)
    
    print("Multiple Workers (High Parallel):")
    print("""
    CLI → Task Queue → Worker1 → [Scanner1, Scanner2] → Results
           (Redis)  ├─ Worker2 → [Scanner3, Scanner4] → Database  
                    └─ Worker3 → [Scanner5, Scanner6] → Files
    """)
    
    print("\n💡 Best Practices:")
    print("-" * 50)
    
    best_practices = [
        'Use --queue for more than 5 targets to avoid overwhelming local system',
        'Set appropriate --max-parallel based on your network and target capacity',
        'Use --target-file for large lists of targets instead of command line',
        'Monitor resource usage when running many parallel operations',
        'Consider target rate limiting to be respectful of scanned systems',
        'Use --debug sparingly with parallel operations (generates lots of logs)',
        'Start with small batches to test configuration before large runs'
    ]
    
    for i, practice in enumerate(best_practices, 1):
        print(f"   {i}. {practice}")
    
    print("\n🚦 Concurrency Control:")
    print("-" * 50)
    
    concurrency_levels = [
        ('Local Direct', '1-5 parallel', 'pgdn --parallel-targets ... --max-parallel 3'),
        ('Single Worker', '5-10 parallel', 'pgdn --queue with one worker'),
        ('Multi Worker', '10-50+ parallel', './celery-manage.sh start-all (multiple workers)'),
        ('Distributed', '50+ parallel', 'Workers on multiple machines')
    ]
    
    print("   Level          Capacity      Example")
    print("   " + "-" * 45)
    for level, capacity, example in concurrency_levels:
        print(f"   {level:<12} {capacity:<12} {example}")
    
    print("\n🎯 Real-World Usage Scenarios:")
    print("-" * 50)
    
    scenarios = [
        {
            'scenario': 'Security Audit of IP Range',
            'command': 'pgdn --target-file ip_ranges.txt --queue --max-parallel 10 --protocol filecoin',
            'description': 'Scan entire subnet for Filecoin nodes'
        },
        {
            'scenario': 'Multi-Protocol Discovery',
            'command': 'pgdn --parallel-stages recon scan score --queue',
            'description': 'Run discovery and analysis simultaneously'
        },
        {
            'scenario': 'High-Volume Monitoring',
            'command': 'pgdn --queue --wait-for-completion (with multiple workers)',
            'description': 'Regular monitoring of large DePIN networks'
        },
        {
            'scenario': 'Emergency Response',
            'command': 'pgdn --parallel-targets <critical-ips> --debug --max-parallel 3',
            'description': 'Quick assessment of critical infrastructure'
        }
    ]
    
    for scenario in scenarios:
        print(f"\n   {scenario['scenario']}:")
        print(f"     Command: {scenario['command']}")
        print(f"     Use Case: {scenario['description']}")
    
    print("\n📈 Scaling Guidelines:")
    print("-" * 50)
    
    scaling_guidelines = [
        ('1-10 targets', 'Direct parallel (--parallel-targets)'),
        ('10-50 targets', 'Queue with single worker (--queue)'),
        ('50-200 targets', 'Queue with multiple workers'),
        ('200+ targets', 'Distributed workers + batch processing'),
        ('1000+ targets', 'Custom batching + multiple queue instances')
    ]
    
    print("   Target Count   Recommended Approach")
    print("   " + "-" * 40)
    for count, approach in scaling_guidelines:
        print(f"   {count:<12} {approach}")
    
    print("\n✨ Getting Started with Parallel Processing:")
    print("-" * 50)
    
    getting_started = [
        '1. Install dependencies: pip install celery redis',
        '2. Start services: ./celery-manage.sh start-all', 
        '3. Create target file: echo "192.168.1.100\n192.168.1.101" > targets.txt',
        '4. Run parallel scan: pgdn --target-file targets.txt --queue',
        '5. Monitor progress: open http://localhost:5555',
        '6. Check results: pgdn --task-id <task-id>'
    ]
    
    for step in getting_started:
        print(f"   {step}")
    
    print("\n" + "=" * 70)
    print("🎉 Ready for Parallel Processing!")
    print("   Use these examples to scale your DePIN infrastructure scanning")
    
    return True

def create_example_target_file():
    """Create an example target file for testing."""
    
    example_targets = [
        "# Example target file for parallel scanning",
        "# One IP address or hostname per line",
        "# Lines starting with # are comments",
        "",
        "192.168.1.100",
        "192.168.1.101", 
        "192.168.1.102",
        "10.0.0.1",
        "10.0.0.2",
        "example.com",
        "test.local"
    ]
    
    with open('example_targets.txt', 'w') as f:
        f.write('\n'.join(example_targets))
    
    print("📁 Created example_targets.txt with sample targets")
    print("   Use with: pgdn --target-file example_targets.txt --queue")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == '--create-example':
        create_example_target_file()
    else:
        demonstrate_parallel_capabilities()
