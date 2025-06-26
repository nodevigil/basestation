#!/usr/bin/env python3
"""
Concurrent Scanning Example

This example demonstrates concurrent scanning operations using the simplified Scanner interface.
Note: The PGDN scanner itself handles concurrent operations internally.
"""

from lib import Scanner, Config
import time
import concurrent.futures
import threading

def scan_target_wrapper(scanner, target_config):
    """Wrapper function for concurrent scanning."""
    return scanner.scan(**target_config)

def main():
    # Initialize PGDN
    print("Initializing PGDN scanner...")
    config = Config.from_file("config.json")
    
    # Create scanner
    scanner = Scanner(config)
    
    # Example 1: Concurrent target scanning using ThreadPoolExecutor
    print("\n=== Concurrent Target Scanning ===")
    
    # Define scan jobs
    scan_jobs = [
        {"target": "192.168.1.100", "protocol": "sui", "scan_level": 1},
        {"target": "192.168.1.101", "protocol": "sui", "scan_level": 1},
        {"target": "192.168.1.102", "protocol": "filecoin", "scan_level": 1},
        {"target": "192.168.1.103", "protocol": "filecoin", "scan_level": 1},
        {"target": "192.168.1.104", "protocol": "sui", "scan_level": 1},
    ]
    
    start_time = time.time()
    
    # Use ThreadPoolExecutor for concurrent scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        # Submit all scan jobs
        future_to_job = {
            executor.submit(scan_target_wrapper, scanner, job): job 
            for job in scan_jobs
        }
        
        results = []
        for future in concurrent.futures.as_completed(future_to_job):
            job = future_to_job[future]
            try:
                result = future.result()
                results.append({
                    'job': job,
                    'result': result,
                    'success': result.get('success', False)
                })
                print(f"✓ Completed: {job['target']} ({job['protocol']})")
            except Exception as exc:
                print(f"✗ Failed: {job['target']} - {exc}")
                results.append({
                    'job': job,
                    'result': {'success': False, 'error': str(exc)},
                    'success': False
                })
    
    end_time = time.time()
    successful = sum(1 for r in results if r['success'])
    
    print(f"\nConcurrent scanning completed in {end_time - start_time:.2f}s")
    print(f"  Total jobs: {len(scan_jobs)}")
    print(f"  Successful: {successful}")
    print(f"  Failed: {len(scan_jobs) - successful}")
    print(f"  Average time per job: {(end_time - start_time) / len(scan_jobs):.2f}s")
    
    # Example 2: Performance comparison (sequential vs concurrent)
    print("\n=== Performance Comparison ===")
    test_jobs = scan_jobs[:3]  # Use smaller set for comparison
    
    # Sequential scanning
    print("Running sequential scans...")
    start_time = time.time()
    sequential_results = []
    for job in test_jobs:
        result = scanner.scan(**job)
        sequential_results.append(result)
    sequential_time = time.time() - start_time
    
    # Concurrent scanning
    print("Running concurrent scans...")
    start_time = time.time()
    concurrent_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(scan_target_wrapper, scanner, job) for job in test_jobs]
        for future in concurrent.futures.as_completed(futures):
            concurrent_results.append(future.result())
    concurrent_time = time.time() - start_time
    
    # Compare results
    print(f"\nPerformance Comparison:")
    print(f"  Sequential: {sequential_time:.2f}s")
    print(f"  Concurrent: {concurrent_time:.2f}s")
    if sequential_time > 0 and concurrent_time > 0:
        speedup = sequential_time / concurrent_time
        print(f"  Speedup:    {speedup:.2f}x")


def batch_scan_with_progress():
    """Example of batch scanning with progress reporting."""
    print("\n=== Batch Scan with Progress ===")
    config = Config.from_file("config.json")
    scanner = Scanner(config)
    
    # Large batch of targets
    targets = [f"192.168.1.{i}" for i in range(100, 120)]  # 20 targets
    
    completed = 0
    lock = threading.Lock()
    
    def scan_with_progress(target):
        nonlocal completed
        result = scanner.scan(target=target, protocol="sui", scan_level=1)
        
        with lock:
            completed += 1
            print(f"Progress: {completed}/{len(targets)} ({completed/len(targets)*100:.1f}%)")
        
        return result
    
    print(f"Starting batch scan of {len(targets)} targets...")
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(scan_with_progress, targets))
    
    end_time = time.time()
    successful = sum(1 for r in results if r.get('success', False))
    
    print(f"\nBatch scan completed in {end_time - start_time:.2f}s")
    print(f"  Successful: {successful}/{len(targets)}")
    print(f"  Success rate: {successful/len(targets)*100:.1f}%")


if __name__ == "__main__":
    try:
        main()
        batch_scan_with_progress()
    except Exception as e:
        print(f"Concurrent operations failed: {e}")
        import traceback
        traceback.print_exc()
