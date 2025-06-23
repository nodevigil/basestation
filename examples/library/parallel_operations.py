#!/usr/bin/env python3
"""
Parallel Operations Example

This example demonstrates concurrent scanning and stage execution.
"""

from pgdn import initialize_application, ParallelOperations, Scanner
import time

def main():
    # Initialize PGDN
    print("Initializing PGDN for parallel operations...")
    config = initialize_application("config.json")
    
    # Create parallel operations manager
    parallel_ops = ParallelOperations(config)
    scanner = Scanner(config)
    
    # Example 1: Parallel target scanning
    print("\n=== Parallel Target Scanning ===")
    targets = [
        "192.168.1.100",
        "192.168.1.101", 
        "192.168.1.102",
        "192.168.1.103",
        "192.168.1.104"
    ]
    
    start_time = time.time()
    result = parallel_ops.run_parallel_scans(
        targets=targets,
        max_parallel=3,
        protocol_filter='sui',
        use_queue=True,
        wait_for_completion=True
    )
    end_time = time.time()
    
    if result['success']:
        print(f"✓ Parallel scanning completed in {end_time - start_time:.2f}s")
        print(f"  Total targets: {len(targets)}")
        print(f"  Successful: {result.get('successful_scans', 0)}")
        print(f"  Failed: {result.get('failed_scans', 0)}")
        print(f"  Average time per target: {(end_time - start_time) / len(targets):.2f}s")
    else:
        print(f"✗ Parallel scanning failed: {result['error']}")
    
    # Example 2: Parallel stage execution
    print("\n=== Parallel Stage Execution ===")
    stages = ['recon', 'scan']
    stage_configs = {
        'recon': {'agent_names': ['SuiReconAgent']},
        'scan': {'protocol_filter': 'sui', 'debug': False}
    }
    
    start_time = time.time()
    result = parallel_ops.run_parallel_stages(
        stages=stages,
        stage_configs=stage_configs,
        use_queue=True,
        wait_for_completion=True
    )
    end_time = time.time()
    
    if result['success']:
        print(f"✓ Parallel stages completed in {end_time - start_time:.2f}s")
        for stage in stages:
            stage_result = result.get('stage_results', {}).get(stage, {})
            if stage_result.get('success'):
                print(f"  ✓ {stage.capitalize()} stage completed")
            else:
                print(f"  ✗ {stage.capitalize()} stage failed")
    else:
        print(f"✗ Parallel stages failed: {result['error']}")
    
    # Example 3: Coordinated parallel operation
    print("\n=== Coordinated Parallel Operation ===")
    
    # First, run reconnaissance to discover targets
    from pgdn import PipelineOrchestrator
    orchestrator = PipelineOrchestrator(config)
    
    print("Running reconnaissance...")
    recon_result = orchestrator.run_recon_stage()
    
    if recon_result['success'] and recon_result.get('targets_found', 0) > 0:
        discovered_targets = recon_result.get('targets', [])[:10]  # Limit to 10 targets
        print(f"Found {len(discovered_targets)} targets, scanning in parallel...")
        
        # Scan discovered targets in parallel
        scan_result = parallel_ops.run_parallel_scans(
            targets=discovered_targets,
            max_parallel=5,
            use_queue=True,
            wait_for_completion=True
        )
        
        if scan_result['success']:
            print(f"✓ Coordinated operation completed")
            print(f"  Targets discovered: {len(discovered_targets)}")
            print(f"  Targets scanned: {scan_result.get('successful_scans', 0)}")
        else:
            print(f"✗ Coordinated scanning failed: {scan_result['error']}")
    else:
        print("No targets discovered for coordinated operation")
    
    # Example 4: Performance comparison
    print("\n=== Performance Comparison ===")
    test_targets = targets[:3]  # Use smaller set for comparison
    
    # Sequential scanning
    print("Running sequential scans...")
    start_time = time.time()
    sequential_results = []
    for target in test_targets:
        result = scanner.scan_target(target)
        sequential_results.append(result)
    sequential_time = time.time() - start_time
    
    # Parallel scanning
    print("Running parallel scans...")
    start_time = time.time()
    parallel_result = parallel_ops.run_parallel_scans(
        targets=test_targets,
        max_parallel=3,
        wait_for_completion=True
    )
    parallel_time = time.time() - start_time
    
    # Compare results
    print(f"\nPerformance Comparison:")
    print(f"  Sequential: {sequential_time:.2f}s")
    print(f"  Parallel:   {parallel_time:.2f}s")
    if sequential_time > 0:
        speedup = sequential_time / parallel_time
        print(f"  Speedup:    {speedup:.2f}x")

if __name__ == "__main__":
    main()
