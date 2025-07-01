import subprocess
import xml.etree.ElementTree as ET
import logging
import json
import sys

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
        return connect_cmd
        
    except subprocess.TimeoutExpired:
        logger.info("Sudo timed out (password prompt?), using connect scan")
        return connect_cmd
    except Exception as e:
        logger.info(f"Sudo not available ({e}), using connect scan")
        return connect_cmd

def nmap_scan(ip, ports="22,80,443,2375,3306,8080,9000,9184", timeout=30, fast_mode=True):
    """
    Run nmap scan and return dict results, with logging.
    
    Args:
        ip: Target IP address
        ports: Comma-separated port list
        timeout: Timeout in seconds
        fast_mode: If True, skip version detection for speed
    """
    import os
    
    # Check if we have sudo privileges
    has_sudo = os.geteuid() == 0

    # Build command - optimize for speed using guard clauses
    if not fast_mode:
        cmd = [
            "nmap", 
            "-T4", 
            "-p", ports, 
            "-sV",  # Version detection (slower)
            "--version-intensity", "2",  # Light version detection
            "-oX", "-", 
            ip
        ]
    elif has_sudo:
        cmd = [
            "nmap", 
            "-T5",  # Insane timing (fastest)
            "-p", ports, 
            "-sS",  # SYN scan (requires sudo, faster)
            "--min-rate", "1000",
            "--max-retries", "1",
            "-oX", "-", 
            ip
        ]
    else:
        cmd = _select_sudo_command(ip, ports, timeout)

    try:
        logger.info(f"Running nmap: {' '.join(cmd)} (timeout={timeout}s)")
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

def bulk_scan(ip_list, ports="22,80,443,2375,3306,8080,9000,9184", timeout=30, fast_mode=True):
    """Scan multiple IPs efficiently"""
    results = []
    for ip in ip_list:
        logger.info(f"Scanning {ip}...")
        result = nmap_scan(ip, ports=ports, timeout=timeout, fast_mode=fast_mode)
        results.append(result)
    return results

def analyze_scan_results(scan_data):
    """Analyze scan results for security issues"""
    if "error" in scan_data:
        return {"analysis": "scan_failed", "issues": []}
    
    issues = []
    open_ports = [p for p in scan_data["ports"] if p["state"] == "open"]
    
    # Check for concerning open ports
    concerning_ports = {
        2375: "Unencrypted Docker API (should use 2376 with TLS)",
        3306: "MySQL database exposed",
        5432: "PostgreSQL database exposed", 
        6379: "Redis exposed",
        27017: "MongoDB exposed",
        9000: "Various services (could be MinIO, SonarQube, etc.)"
    }
    
    for port_info in open_ports:
        port_num = port_info["port"]
        if port_num in concerning_ports:
            issues.append({
                "type": "exposed_service",
                "port": port_num,
                "description": concerning_ports[port_num],
                "severity": "high" if port_num in [2375, 3306, 5432, 6379, 27017] else "medium"
            })
    
    # Check for unusual port combinations (possible honeypot or misconfiguration)
    if len(open_ports) > 6:
        issues.append({
            "type": "many_open_ports",
            "count": len(open_ports),
            "description": f"Many ports open ({len(open_ports)}) - possible misconfiguration",
            "severity": "medium"
        })
    
    return {
        "analysis": "completed",
        "open_ports": len(open_ports),
        "total_scanned": len(scan_data["ports"]),
        "issues": issues,
        "host_state": scan_data["host_state"]
    }

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
    
    # Analyze results
    analysis = analyze_scan_results(result)
    
    # Output results
    output = {
        "scan_results": result,
        "security_analysis": analysis
    }
    
    print(json.dumps(output, indent=2))