import subprocess
import xml.etree.ElementTree as ET
import logging
import json
import sys
import threading
import time

logger = logging.getLogger("nmap_scan")

def _select_sudo_command(ip, ports, timeout):
    """Select the appropriate sudo command using guard clauses."""
    sudo_cmd = [
        "sudo", "nmap", 
        "-T5",
        "-p", ports, 
        "-sS",
        "--min-rate", "1000",
        "--max-retries", "1",
        "-oX", "-", 
        ip
    ]
    connect_cmd = [
        "nmap", 
        "-T4",  # T5 can be too aggressive for connect scans
        "-p", ports, 
        "-sT",  # Connect scan (no sudo needed)
        "--min-rate", "500",
        "--max-retries", "1",
        "-oX", "-", 
        ip
    ]
    
    # Try sudo first, but handle permission errors gracefully
    try:
        logger.info(f"Trying sudo nmap for faster SYN scan...")
        result = subprocess.run(
            sudo_cmd, 
            capture_output=True, 
            timeout=timeout,
            text=True,
            input='\n'  # Send empty input to avoid hanging on password prompt
        )
        
        if result.returncode == 0:
            logger.info("Using sudo SYN scan")
            return sudo_cmd
            
        logger.info("Sudo failed (no permissions), using connect scan")

        print(12312312, connect_cmd)
        return connect_cmd
        
    except subprocess.TimeoutExpired:
        logger.info("Sudo timed out (password prompt?), using connect scan")
        return connect_cmd
    except Exception as e:
        logger.info(f"Sudo not available ({e}), using connect scan")
        return connect_cmd

def _run_nmap_with_progress(cmd, timeout, logger):
    """Run nmap with periodic progress updates for long scans."""
    import select
    import os
    
    # Start the process
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    start_time = time.time()
    last_update = start_time
    
    def progress_updater():
        nonlocal last_update
        while process.poll() is None:  # While process is running
            current_time = time.time()
            if current_time - last_update >= 30:  # Every 30 seconds
                elapsed = int(current_time - start_time)
                remaining = max(0, timeout - elapsed)
                logger.info(f"Nmap scan progress: {elapsed}s elapsed, {remaining}s remaining...")
                last_update = current_time
            time.sleep(5)  # Check every 5 seconds
    
    # Start progress thread
    progress_thread = threading.Thread(target=progress_updater, daemon=True)
    progress_thread.start()
    
    try:
        # Wait for completion with timeout
        stdout, stderr = process.communicate(timeout=timeout)
        
        # Create a result object similar to subprocess.run
        class Result:
            def __init__(self, returncode, stdout, stderr):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr
        
        return Result(process.returncode, stdout, stderr)
        
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        elapsed = int(time.time() - start_time)
        logger.warning(f"Nmap scan timed out after {elapsed}s")
        raise subprocess.TimeoutExpired(cmd, timeout, stdout, stderr)

def nmap_scan(ip, ports="22,80,443,2375,3306,8080,9000,9184", timeout=30, fast_mode=True, additional_args=None):
    """
    Run nmap scan and return dict results, with logging.
    
    Args:
        ip: Target IP address
        ports: Comma-separated port list
        timeout: Timeout in seconds
        fast_mode: If True, skip version detection for speed
        additional_args: List of additional nmap arguments
    """
    import os
    
    if additional_args is None:
        additional_args = []
    
    # Check if we should use sudo commands (environment variable or actual sudo privileges)
    use_sudo = os.environ.get('USE_SUDO', '').lower() == 'true' or os.geteuid() == 0

    # Build base command
    cmd = ["nmap"]
    
    # Add additional arguments first (they take precedence)
    if additional_args:
        cmd.extend(additional_args)
    
    # Add port specification if not already provided
    if not any('-p' in arg for arg in additional_args):
        cmd.extend(["-p", ports])
    
    # Add scan type if not already specified
    has_scan_type = any(arg in ['-sS', '-sT', '-sU', '-sY', '-sN', '-sF', '-sX'] for arg in additional_args)
    if not has_scan_type:
        if use_sudo:
            cmd.append("-sS")  # SYN scan
        # If no sudo, nmap defaults to -sT (connect scan)
    
    # Add version detection if not already specified and not in fast mode
    has_version = any(arg in ['-sV', '-sC', '-A'] for arg in additional_args)
    if not fast_mode and not has_version:
        cmd.extend(["-sV", "--version-intensity", "2"])
    
    # Add timing if not already specified
    has_timing = any(arg.startswith('-T') for arg in additional_args)
    if not has_timing:
        if fast_mode:
            cmd.append("-T5" if use_sudo else "-T4")
        else:
            cmd.append("-T4")
    
    # Add performance options for fast mode if not already specified
    if fast_mode and use_sudo:
        if not any('--min-rate' in arg for arg in additional_args):
            cmd.extend(["--min-rate", "1000"])
        if not any('--max-retries' in arg for arg in additional_args):
            cmd.extend(["--max-retries", "1"])
    
    # Add verbose output for long scans if not already specified
    if timeout > 60 and not any(arg in ['-v', '-vv', '-d'] for arg in additional_args):
        cmd.append("-v")  # Verbose output to show progress
    
    # Add XML output
    cmd.extend(["-oX", "-"])
    
    # Add target IP
    cmd.append(ip)

    try:
        logger.info(f"Running nmap: {' '.join(cmd)} (timeout={timeout}s)")
        
        # For long scans (>60s), provide progress updates
        if timeout > 60:
            logger.info(f"Starting long nmap scan - will provide progress updates every 30 seconds")
            result = _run_nmap_with_progress(cmd, timeout, logger)
        else:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                timeout=timeout,
                text=True
            )
        
        logger.info(f"Nmap return code: {result.returncode}")
        
        if result.returncode != 0:
            logger.warning(f"Nmap stderr: {result.stderr}")
            
        xml_output = result.stdout
        if not xml_output.strip():
            logger.error("Nmap returned no output")
            return {
                "error": "Nmap returned no output", 
                "stderr": result.stderr,
                "ip": ip
            }
            
        # Parse XML
        root = ET.fromstring(xml_output)
        scan_data = {
            "ip": ip,
            "scan_time": None,
            "ports": [],
            "host_state": "unknown"
        }
        
        # Get scan timing
        runstats = root.find('runstats/finished')
        if runstats is not None:
            scan_data["scan_time"] = runstats.get('elapsed', 'unknown')
            
        # Parse host data
        for host in root.findall('host'):
            # Get host state
            status = host.find('status')
            if status is not None:
                scan_data["host_state"] = status.get('state', 'unknown')
            
            # Parse ports
            ports_elem = host.find('ports')
            if ports_elem is not None:
                for port in ports_elem.findall('port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol', 'tcp')
                    
                    state_elem = port.find('state')
                    state = state_elem.get('state') if state_elem is not None else 'unknown'
                    
                    # Service information (may not be available in fast mode)
                    service_elem = port.find('service')
                    service_info = {
                        "service": "unknown",
                        "product": "",
                        "version": ""
                    }
                    
                    if service_elem is not None:
                        service_info.update({
                            "service": service_elem.get('name', 'unknown'),
                            "product": service_elem.get('product', ''),
                            "version": service_elem.get('version', '')
                        })
                    
                    scan_data["ports"].append({
                        "port": int(port_id),
                        "protocol": protocol,
                        "state": state,
                        **service_info
                    })
        
        # Count open ports for summary
        open_ports = [p for p in scan_data['ports'] if p['state'] == 'open']
        
        if timeout > 60:
            # For long scans, provide detailed completion info
            logger.info(f"Nmap scan completed successfully!")
            logger.info(f"Results: {len(open_ports)} open ports found out of {len(scan_data['ports'])} scanned in {scan_data['scan_time']}s")
            if open_ports:
                open_list = [f"{p['port']}/{p['protocol']}" for p in open_ports]
                logger.info(f"Open ports: {', '.join(open_list)}")
        else:
            logger.info(f"Nmap scan found {len(scan_data['ports'])} ports on {ip} in {scan_data['scan_time']}s")
        
        return scan_data
        
    except subprocess.TimeoutExpired:
        logger.error(f"Nmap timed out after {timeout} seconds for {ip}")
        return {
            "error": f"Command timed out after {timeout} seconds",
            "cmd": ' '.join(cmd),
            "ip": ip
        }
    except ET.ParseError as e:
        logger.error(f"XML parsing failed: {e}")
        return {
            "error": f"XML parsing failed: {e}",
            "cmd": ' '.join(cmd),
            "ip": ip
        }
    except Exception as e:
        logger.error(f"Nmap failed: {e}")
        return {
            "error": str(e), 
            "cmd": ' '.join(cmd),
            "ip": ip
        }

# def bulk_scan(ip_list, ports="22,80,443,2375,3306,8080,9000,9184", timeout=30, fast_mode=True):
#     """Scan multiple IPs efficiently"""
#     results = []
#     for ip in ip_list:
#         logger.info(f"Scanning {ip}...")
#         result = nmap_scan(ip, ports=ports, timeout=timeout, fast_mode=fast_mode)
#         results.append(result)
#     return results

# def analyze_scan_results(scan_data):
#     """Analyze scan results for security issues"""
#     if "error" in scan_data:
#         return {"analysis": "scan_failed", "issues": []}
    
#     issues = []
#     open_ports = [p for p in scan_data["ports"] if p["state"] == "open"]
    
#     # Check for concerning open ports
#     concerning_ports = {
#         2375: "Unencrypted Docker API (should use 2376 with TLS)",
#         3306: "MySQL database exposed",
#         5432: "PostgreSQL database exposed", 
#         6379: "Redis exposed",
#         27017: "MongoDB exposed",
#         9000: "Various services (could be MinIO, SonarQube, etc.)"
#     }
    
#     for port_info in open_ports:
#         port_num = port_info["port"]
#         if port_num in concerning_ports:
#             issues.append({
#                 "type": "exposed_service",
#                 "port": port_num,
#                 "description": concerning_ports[port_num],
#                 "severity": "high" if port_num in [2375, 3306, 5432, 6379, 27017] else "medium"
#             })
    
#     # Check for unusual port combinations (possible honeypot or misconfiguration)
#     if len(open_ports) > 6:
#         issues.append({
#             "type": "many_open_ports",
#             "count": len(open_ports),
#             "description": f"Many ports open ({len(open_ports)}) - possible misconfiguration",
#             "severity": "medium"
#         })
    
#     return {
#         "analysis": "completed",
#         "open_ports": len(open_ports),
#         "total_scanned": len(scan_data["ports"]),
#         "issues": issues,
#         "host_state": scan_data["host_state"]
#     }

if __name__ == "__main__":
    import logging
    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(message)s", 
        level=logging.INFO
    )

    if len(sys.argv) < 2:
        print("Usage: python nmap_scanner.py <ip> [ports] [timeout] [--slow]")
        print("Examples:")
        print("  python nmap_scanner.py 45.250.254.151")
        print("  python nmap_scanner.py 45.250.254.151 22,80,443 15")
        print("  python nmap_scanner.py 45.250.254.151 22,80,443 60 --slow")
        sys.exit(1)

    ip = sys.argv[1]
    ports = sys.argv[2] if len(sys.argv) > 2 else "22,80,443,2375,3306,8080,9000,9184"
    timeout = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] != "--slow" else 30
    fast_mode = "--slow" not in sys.argv

    logger.info(f"Scanning {ip} (fast_mode={fast_mode})")
    result = nmap_scan(ip, ports=ports, timeout=timeout, fast_mode=fast_mode)
    
    print(json.dumps(result))

    # Analyze results
    # analysis = analyze_scan_results(result)
    
    # # Output results
    # output = {
    #     "scan_results": result,
    #     "security_analysis": analysis
    # }
    
    # print(json.dumps(output, indent=2))
