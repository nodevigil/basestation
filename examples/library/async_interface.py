#!/usr/bin/env python3
"""
Async library interface for concurrent scanning

This provides async/await interfaces for scanning multiple targets concurrently.
"""

import asyncio
import concurrent.futures
from typing import List, Dict, Optional, Union
import time

from pgdn_scanner.scanners.port_scanner import PortScanner
from pgdn_scanner.scanner import Scanner

class AsyncPGDNScanner:
    """Async interface for concurrent scanning"""
    
    def __init__(self, max_concurrent: int = 5, timeout: int = 15):
        """
        Initialize async scanner
        
        Args:
            max_concurrent: Maximum concurrent scans
            timeout: Timeout per scan
        """
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent)
    
    async def scan_port_async(self, target: str, ports: Union[List[int], str], 
                             nmap_args: Optional[str] = None) -> Dict:
        """
        Async port scanning
        
        Args:
            target: Target to scan
            ports: Ports to scan
            nmap_args: Additional nmap arguments
            
        Returns:
            Scan results
        """
        loop = asyncio.get_event_loop()
        
        # Create scanner in thread
        def run_scan():
            scanner = PortScanner({'timeout': self.timeout})
            
            # Convert ports if needed
            if isinstance(ports, str):
                port_list = [int(p.strip()) for p in ports.split(',')]
            else:
                port_list = ports
            
            # Parse nmap args
            args_list = []
            if nmap_args:
                import shlex
                args_list = shlex.split(nmap_args)
            
            return scanner.scan(
                target=target,
                ports=port_list,
                nmap_args=args_list
            )
        
        # Run in executor
        result = await loop.run_in_executor(self.executor, run_scan)
        return result
    
    async def scan_multiple_targets(self, targets: List[str], ports: Union[List[int], str],
                                   nmap_args: Optional[str] = None) -> Dict[str, Dict]:
        """
        Scan multiple targets concurrently
        
        Args:
            targets: List of targets to scan
            ports: Ports to scan on each target
            nmap_args: nmap arguments to use
            
        Returns:
            Dictionary mapping target -> results
        """
        # Create semaphore to limit concurrent scans
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def scan_with_semaphore(target):
            async with semaphore:
                try:
                    result = await self.scan_port_async(target, ports, nmap_args)
                    return target, result
                except Exception as e:
                    return target, {"error": str(e)}
        
        # Start all scans concurrently
        tasks = [scan_with_semaphore(target) for target in targets]
        results = await asyncio.gather(*tasks)
        
        # Convert to dictionary
        return {target: result for target, result in results}
    
    async def scan_multiple_ports_per_target(self, target_port_map: Dict[str, Union[List[int], str]],
                                           nmap_args: Optional[str] = None) -> Dict[str, Dict]:
        """
        Scan different ports for different targets
        
        Args:
            target_port_map: Dictionary mapping target -> ports to scan
            nmap_args: nmap arguments
            
        Returns:
            Results for each target
        """
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def scan_target_ports(target, ports):
            async with semaphore:
                try:
                    result = await self.scan_port_async(target, ports, nmap_args)
                    return target, result
                except Exception as e:
                    return target, {"error": str(e)}
        
        tasks = [scan_target_ports(target, ports) for target, ports in target_port_map.items()]
        results = await asyncio.gather(*tasks)
        
        return {target: result for target, result in results}
    
    async def progressive_scan(self, target: str, port_groups: List[Union[List[int], str]], 
                              nmap_args: Optional[str] = None) -> List[Dict]:
        """
        Progressive scanning - scan port groups in sequence, but targets in parallel
        
        Args:
            target: Target to scan
            port_groups: Groups of ports to scan sequentially
            nmap_args: nmap arguments
            
        Returns:
            List of results for each port group
        """
        results = []
        
        for i, ports in enumerate(port_groups):
            print(f"Scanning port group {i+1}/{len(port_groups)}: {ports}")
            
            result = await self.scan_port_async(target, ports, nmap_args)
            results.append({
                'group_index': i,
                'ports_scanned': ports,
                'result': result
            })
            
            # Small delay between groups
            await asyncio.sleep(0.5)
        
        return results
    
    def close(self):
        """Clean up executor"""
        self.executor.shutdown(wait=True)

# Convenience async functions
async def async_multi_target_scan(targets: List[str], ports: Union[List[int], str], 
                                 max_concurrent: int = 5, nmap_args: Optional[str] = None) -> Dict[str, Dict]:
    """
    Async scan multiple targets - convenience function
    
    Args:
        targets: List of targets
        ports: Ports to scan
        max_concurrent: Max concurrent scans
        nmap_args: nmap arguments
        
    Returns:
        Results dictionary
    """
    scanner = AsyncPGDNScanner(max_concurrent=max_concurrent)
    try:
        results = await scanner.scan_multiple_targets(targets, ports, nmap_args)
        return results
    finally:
        scanner.close()

async def async_database_audit(targets: List[str], max_concurrent: int = 3) -> Dict[str, Dict]:
    """
    Async database security audit across multiple targets
    """
    db_ports = "3306,5432,27017,6379"
    nmap_args = "-sV -Pn --script=banner,default"
    
    return await async_multi_target_scan(
        targets=targets,
        ports=db_ports,
        max_concurrent=max_concurrent,
        nmap_args=nmap_args
    )

# Example usage functions
async def example_concurrent_scanning():
    """Example of concurrent scanning"""
    print("\\n=== Concurrent Scanning Example ===")
    
    targets = [
        "scanme.nmap.org",
        "google.com",
        "github.com"
    ]
    
    ports = "22,80,443"
    
    print(f"Scanning {len(targets)} targets concurrently...")
    start_time = time.time()
    
    # Scan all targets concurrently
    results = await async_multi_target_scan(
        targets=targets,
        ports=ports,
        max_concurrent=3,
        nmap_args="-sV -Pn"
    )
    
    end_time = time.time()
    
    print(f"Completed in {end_time - start_time:.2f} seconds")
    
    # Display results
    for target, result in results.items():
        if "error" in result:
            print(f"\\n{target}: ERROR - {result['error']}")
        else:
            open_ports = result.get('open_ports', [])
            filtered_ports = result.get('filtered_ports', [])
            print(f"\\n{target}:")
            print(f"  Open: {open_ports}")
            print(f"  Filtered: {filtered_ports}")

async def example_progressive_scanning():
    """Example of progressive port scanning"""
    print("\\n=== Progressive Scanning Example ===")
    
    target = "scanme.nmap.org"
    
    # Define port groups to scan progressively
    port_groups = [
        [80, 443],           # Web ports first
        [22, 23, 3389],      # Remote access ports
        [3306, 5432, 27017], # Database ports
        [25, 587, 993]       # Mail ports
    ]
    
    scanner = AsyncPGDNScanner(max_concurrent=2, timeout=10)
    
    try:
        print(f"Progressive scan of {target}...")
        results = await scanner.progressive_scan(
            target=target,
            port_groups=port_groups,
            nmap_args="-sV"
        )
        
        # Analyze results
        total_open = 0
        total_filtered = 0
        
        for group_result in results:
            group_idx = group_result['group_index']
            ports_scanned = group_result['ports_scanned']
            result = group_result['result']
            
            if "error" not in result:
                open_count = len(result.get('open_ports', []))
                filtered_count = len(result.get('filtered_ports', []))
                
                total_open += open_count
                total_filtered += filtered_count
                
                print(f"  Group {group_idx + 1} ({ports_scanned}): {open_count} open, {filtered_count} filtered")
        
        print(f"\\nTotal: {total_open} open, {total_filtered} filtered ports")
        
    finally:
        scanner.close()

async def example_different_ports_per_target():
    """Example of scanning different ports for different targets"""
    print("\\n=== Different Ports Per Target Example ===")
    
    # Define different scan profiles for different targets
    target_configs = {
        "scanme.nmap.org": [22, 80, 443],           # Basic web server
        "google.com": [80, 443, 25, 587],           # Web + mail
        "github.com": [22, 80, 443, 9418]           # Web + git protocol
    }
    
    scanner = AsyncPGDNScanner(max_concurrent=3)
    
    try:
        print("Scanning targets with custom port profiles...")
        
        results = await scanner.scan_multiple_ports_per_target(
            target_port_map=target_configs,
            nmap_args="-sV -Pn"
        )
        
        # Display results
        for target, result in results.items():
            ports_scanned = target_configs[target]
            
            if "error" in result:
                print(f"\\n{target} (ports {ports_scanned}): ERROR")
            else:
                open_ports = result.get('open_ports', [])
                filtered_ports = result.get('filtered_ports', [])
                
                print(f"\\n{target} (scanned {ports_scanned}):")
                print(f"  Open: {open_ports}")
                if filtered_ports:
                    print(f"  Filtered: {filtered_ports}")
    
    finally:
        scanner.close()

async def example_large_scale_audit():
    """Example of large-scale security audit"""
    print("\\n=== Large Scale Security Audit Example ===")
    
    # Simulate scanning a network range
    targets = [
        "scanme.nmap.org",
        "google.com", 
        "github.com",
        "stackoverflow.com"
    ]
    
    print(f"Performing security audit on {len(targets)} targets...")
    
    # Database audit
    print("\\n1. Database security audit...")
    db_results = await async_database_audit(targets, max_concurrent=2)
    
    # Analyze database results
    high_risk_targets = []
    for target, result in db_results.items():
        if "error" not in result:
            open_db_ports = result.get('open_ports', [])
            if open_db_ports:
                high_risk_targets.append((target, open_db_ports))
    
    if high_risk_targets:
        print("   ⚠️  High risk targets with open database ports:")
        for target, ports in high_risk_targets:
            print(f"     {target}: {ports}")
    else:
        print("   ✅ No exposed database ports found")
    
    # Web services audit
    print("\\n2. Web services audit...")
    web_results = await async_multi_target_scan(
        targets=targets,
        ports="80,443,8080,8443",
        max_concurrent=3,
        nmap_args="-sV --script=http-title,ssl-cert"
    )
    
    # Analyze web results
    ssl_enabled = []
    http_only = []
    
    for target, result in web_results.items():
        if "error" not in result:
            open_ports = result.get('open_ports', [])
            if 443 in open_ports or 8443 in open_ports:
                ssl_enabled.append(target)
            elif 80 in open_ports or 8080 in open_ports:
                if not any(p in [443, 8443] for p in open_ports):
                    http_only.append(target)
    
    print(f"   SSL enabled: {ssl_enabled}")
    print(f"   HTTP only: {http_only}")
    
    # Summary
    print(f"\\n3. Audit Summary:")
    print(f"   Targets scanned: {len(targets)}")
    print(f"   High risk (exposed databases): {len(high_risk_targets)}")
    print(f"   SSL enabled: {len(ssl_enabled)}")
    print(f"   Needs SSL: {len(http_only)}")

# Main async example runner
async def main():
    """Run all async examples"""
    print("Async PGDN Scanner Examples")
    print("=" * 50)
    
    try:
        await example_concurrent_scanning()
        await example_progressive_scanning()  
        await example_different_ports_per_target()
        await example_large_scale_audit()
        
        print(f"\\n" + "=" * 50)
        print("Async examples completed!")
        
    except Exception as e:
        print(f"Error in async examples: {e}")

if __name__ == "__main__":
    # Run the async examples
    asyncio.run(main())