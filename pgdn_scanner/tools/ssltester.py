import subprocess
import re
from typing import List, Union, Dict, Any

def ssl_test(ip: str, ports: Union[int, List[int], str] = 443) -> Dict[str, Any]:
    """
    Test SSL/TLS on one or more ports.
    
    Args:
        ip: Target IP or hostname
        ports: Single port (int), list of ports, or comma-separated string
        
    Returns:
        Dict containing SSL test results for all ports
    """
    # Parse ports argument
    if isinstance(ports, str):
        port_list = [int(p.strip()) for p in ports.split(',')]
    elif isinstance(ports, int):
        port_list = [ports]
    elif isinstance(ports, list):
        port_list = ports
    else:
        port_list = [443]  # Default fallback
    
    # Test each port
    results = {}
    
    # If only one port, return the old format for backward compatibility
    if len(port_list) == 1:
        return _test_ssl_port(ip, port_list[0])
    
    # Multiple ports - return results per port
    for port in port_list:
        try:
            results[f"port_{port}"] = _test_ssl_port(ip, port)
        except Exception as e:
            results[f"port_{port}"] = {"error": str(e), "vulnerabilities": []}
    
    # Also provide a summary
    all_vulnerabilities = []
    valid_certificates = 0
    total_ports_tested = len(port_list)
    
    for port_result in results.values():
        if "vulnerabilities" in port_result:
            all_vulnerabilities.extend(port_result["vulnerabilities"])
        if "certificate" in port_result and port_result["certificate"] and port_result["certificate"].get("is_valid"):
            valid_certificates += 1
    
    return {
        "ports_tested": port_list,
        "total_ports": total_ports_tested,
        "valid_certificates": valid_certificates,
        "vulnerabilities": list(set(all_vulnerabilities)),  # Remove duplicates
        "port_results": results
    }

def _test_ssl_port(ip: str, port: int) -> Dict[str, Any]:
    """Test SSL on a single port."""
    try:
        # Use openssl s_client with proper SNI and auto-quit
        cmd = [
            "openssl", "s_client", 
            "-connect", f"{ip}:{port}",
            "-servername", ip,  # Enable SNI
            "-verify_return_error",
            "-brief",  # Reduce output noise
            "-quiet"   # Less verbose
        ]
        
        result = subprocess.run(
            cmd,
            input="Q\n",  # Send quit command immediately
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5  # Reduce timeout to 5 seconds
        )
        # SSL info often goes to stderr with openssl s_client
        output = result.stderr + result.stdout
        
        # Parse certificate information
        certificate_info = _parse_certificate(output)
        ssl_version = _parse_ssl_version(output)
        cipher_suites = _parse_cipher_suites(output)
        vulnerabilities = _check_vulnerabilities(output)
        
        return {
            "port": port,
            "certificate": certificate_info,
            "ssl_version": ssl_version,
            "cipher_suites": cipher_suites,
            "vulnerabilities": vulnerabilities,
            "openssl_raw": output[:1000],  # Keep raw output for debugging
        }
    except subprocess.TimeoutExpired:
        # Try simpler approach if timeout
        try:
            simple_result = subprocess.run(
                ["openssl", "s_client", "-connect", f"{ip}:{port}"],
                input="",
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=3
            )
            return {
                "port": port,
                "certificate": None,
                "ssl_version": "connection_established" if simple_result.returncode == 0 else None,
                "cipher_suites": [],
                "vulnerabilities": ["SSL connection timeout on detailed scan"] if simple_result.returncode != 0 else [],
                "openssl_raw": simple_result.stdout[:500],
            }
        except Exception:
            return {"port": port, "error": "SSL connection timeout", "vulnerabilities": ["Connection timeout"]}
    except Exception as e:
        return {"port": port, "error": str(e), "vulnerabilities": []}

def _parse_certificate(output):
    """Parse certificate information from openssl output."""
    cert_info = {}
    
    # Parse -brief format output  
    peer_cert_match = re.search(r'Peer certificate:\s*(.+)', output)
    if peer_cert_match:
        cert_info["subject"] = peer_cert_match.group(1).strip()
    
    # Check verification status
    if "Verification: OK" in output:
        cert_info["is_valid"] = True
        cert_info["verify_message"] = "OK"
    else:
        cert_info["is_valid"] = False
        cert_info["verify_message"] = "Failed"
    
    # For legacy format compatibility, try old parsing too
    if not cert_info.get("subject"):
        subject_match = re.search(r'subject=(.+)', output)
        if subject_match:
            cert_info["subject"] = subject_match.group(1).strip()
    
    # Extract issuer (legacy format)
    issuer_match = re.search(r'issuer=(.+)', output)
    if issuer_match:
        cert_info["issuer"] = issuer_match.group(1).strip()
    
    # Legacy verify code check
    if not cert_info.get("is_valid"):
        verify_match = re.search(r'Verify return code: (\d+) \((.+?)\)', output)
        if verify_match:
            return_code = int(verify_match.group(1))
            cert_info["is_valid"] = return_code == 0
            cert_info["verify_message"] = verify_match.group(2)
    
    # Extract validity dates
    valid_from_match = re.search(r'NotBefore: (.+?) GMT', output)
    valid_to_match = re.search(r'NotAfter: (.+?) GMT', output)
    
    if valid_from_match:
        cert_info["valid_from"] = valid_from_match.group(1).strip()
    if valid_to_match:
        cert_info["valid_to"] = valid_to_match.group(1).strip()
    
    return cert_info if cert_info else None

def _parse_ssl_version(output):
    """Parse SSL/TLS version from openssl output."""
    # Look for -brief format: "Protocol version: TLSv1.3"
    protocol_match = re.search(r'Protocol version:\s*(.+)', output)
    if protocol_match:
        return protocol_match.group(1).strip()
    
    # Legacy format: "Protocol : TLSv1.3"
    legacy_protocol_match = re.search(r'Protocol\s*:\s*(.+)', output)
    if legacy_protocol_match:
        return legacy_protocol_match.group(1).strip()
    
    # Fallback - check for TLS version in other parts
    if "TLSv1.3" in output:
        return "TLSv1.3"
    elif "TLSv1.2" in output:
        return "TLSv1.2"
    elif "TLSv1.1" in output:
        return "TLSv1.1"
    elif "TLSv1" in output:
        return "TLSv1.0"
    
    return None

def _parse_cipher_suites(output):
    """Parse cipher suites from openssl output."""
    cipher_suites = []
    
    # Look for -brief format: "Ciphersuite: TLS_AES_256_GCM_SHA384"
    cipher_match = re.search(r'Ciphersuite:\s*(.+)', output)
    if cipher_match:
        cipher = cipher_match.group(1).strip()
        if cipher != "0000" and cipher != "(NONE)":
            cipher_suites.append(cipher)
    else:
        # Legacy format: "Cipher : ECDHE-RSA-AES256-GCM-SHA384"
        legacy_cipher_match = re.search(r'Cipher\s*:\s*(.+)', output)
        if legacy_cipher_match:
            cipher = legacy_cipher_match.group(1).strip()
            if cipher != "0000" and cipher != "(NONE)":
                cipher_suites.append(cipher)
    
    return cipher_suites

def _check_vulnerabilities(output):
    """Check for SSL/TLS vulnerabilities based on openssl output."""
    vulnerabilities = []
    
    # Check for certificate issues - handle both brief and legacy formats
    is_valid = "Verification: OK" in output or "Verify return code: 0 (ok)" in output
    
    if not is_valid:
        if "certificate has expired" in output.lower():
            vulnerabilities.append("SSL certificate has expired")
        elif "self signed certificate" in output.lower():
            vulnerabilities.append("Self-signed certificate detected")
        elif "unable to verify the first certificate" in output.lower():
            vulnerabilities.append("Unable to verify certificate chain")
        elif "Verify return code:" in output or "Verification:" in output:
            vulnerabilities.append("SSL certificate validation failed")
    
    # Check for weak ciphers
    cipher_match = re.search(r'Cipher\s*:\s*(.+)', output)
    if cipher_match:
        cipher = cipher_match.group(1).strip().upper()
        if "RC4" in cipher:
            vulnerabilities.append("Weak cipher: RC4 detected")
        elif "DES" in cipher:
            vulnerabilities.append("Weak cipher: DES detected")
        elif "MD5" in cipher:
            vulnerabilities.append("Weak hash: MD5 detected")
        elif cipher == "0000" or cipher == "(NONE)":
            vulnerabilities.append("No cipher negotiated")
    
    # Check for deprecated TLS versions
    if "TLSv1.0" in output:
        vulnerabilities.append("Deprecated TLS version: TLSv1.0")
    elif "TLSv1.1" in output:
        vulnerabilities.append("Deprecated TLS version: TLSv1.1")
    elif "SSLv" in output:
        vulnerabilities.append("Deprecated SSL protocol detected")
    
    return vulnerabilities
