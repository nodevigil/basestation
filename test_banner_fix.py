#!/usr/bin/env python3
"""
Test script to verify banner capture enhancement works.
"""

import socket
import sys

def test_banner_capture(target: str, port: int) -> str:
    """Enhanced banner grabbing with service-specific probes"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10)  # 10 second timeout
            sock.connect((target, port))
            
            # First, try to receive unsolicited banner (SSH, FTP, SMTP, etc.)
            sock.settimeout(2)  # Short timeout for immediate banners
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    return banner
            except socket.timeout:
                # No immediate banner, continue with probes
                pass
            
            # Reset timeout for probes
            sock.settimeout(10)
            
            # Service-specific probes
            if port in [80, 443, 8080, 8443]:
                # HTTP probe
                probe = b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\nConnection: close\r\n\r\n"
                sock.send(probe)
                banner = sock.recv(4096).decode('utf-8', errors='ignore').strip()
                return banner if banner else "No HTTP response"
            elif port == 22:
                # SSH - should have already received banner above, but try again
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner if banner else "No SSH banner"
            else:
                # Generic TCP probe - send nothing, just listen
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner if banner else "No banner response"
                    
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    target = "clayno-sui-mn.prostaking.com"
    
    # Test common ports
    ports_to_test = [22, 80, 443, 9184]
    
    for port in ports_to_test:
        print(f"Testing {target}:{port}")
        banner = test_banner_capture(target, port)
        print(f"Banner: {banner[:200]}{'...' if len(banner) > 200 else ''}")
        print("-" * 50)