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
        # Example using openssl s_client (very basic)
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{ip}:{port}", "-tls1_2"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10
        )
        output = result.stdout.decode(errors="ignore")
        
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
    except Exception as e:
        return {"port": port, "error": str(e), "vulnerabilities": []}

def _parse_certificate(output):
    """Parse certificate information from openssl output."""
    cert_info = {}
    
    # Extract subject
    subject_match = re.search(r'subject=(.+)', output)
    if subject_match:
        cert_info["subject"] = subject_match.group(1).strip()
    
    # Extract issuer
    issuer_match = re.search(r'issuer=(.+)', output)
    if issuer_match:
        cert_info["issuer"] = issuer_match.group(1).strip()
    
    # Check if certificate is valid
    verify_match = re.search(r'Verify return code: (\d+) \((.+?)\)', output)
    if verify_match:
        return_code = int(verify_match.group(1))
        cert_info["is_valid"] = return_code == 0
        cert_info["verify_message"] = verify_match.group(2)
    else:
        cert_info["is_valid"] = False
    
    # Extract validity dates from certificate chain
    valid_from_match = re.search(r'NotBefore: (.+?) GMT', output)
    valid_to_match = re.search(r'NotAfter: (.+?) GMT', output)
    
    if valid_from_match:
        cert_info["valid_from"] = valid_from_match.group(1).strip()
    if valid_to_match:
        cert_info["valid_to"] = valid_to_match.group(1).strip()
    
    return cert_info if cert_info else None

def _parse_ssl_version(output):
    """Parse SSL/TLS version from openssl output."""
    # Look for protocol version
    protocol_match = re.search(r'Protocol\s*:\s*(.+)', output)
    if protocol_match:
        return protocol_match.group(1).strip()
    
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
    
    # Look for Cipher line
    cipher_match = re.search(r'Cipher\s*:\s*(.+)', output)
    if cipher_match:
        cipher = cipher_match.group(1).strip()
        if cipher != "0000" and cipher != "(NONE)":
            cipher_suites.append(cipher)
    
    return cipher_suites

def _check_vulnerabilities(output):
    """Check for SSL/TLS vulnerabilities based on openssl output."""
    vulnerabilities = []
    
    # Check for certificate issues
    if "Verify return code: 0 (ok)" not in output:
        if "certificate has expired" in output.lower():
            vulnerabilities.append("SSL certificate has expired")
        elif "self signed certificate" in output.lower():
            vulnerabilities.append("Self-signed certificate detected")
        elif "unable to verify the first certificate" in output.lower():
            vulnerabilities.append("Unable to verify certificate chain")
        else:
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
