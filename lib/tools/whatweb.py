import subprocess
import os
import json
import sys

def whatweb_scan(ip, port=80, scheme="http"):
    url = f"{scheme}://{ip}:{port}"
    env = os.environ.copy()
    env["PATH"] += os.pathsep + "/Users/simon/Documents/Code/WhatWeb"
    try:
        result = subprocess.run(
            ["whatweb", "--log-json=-", "--user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15
        )
        output = result.stdout.decode()
        
        # Parse JSON lines, ignoring non-JSON lines
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if line and line.startswith('{') and line.endswith('}'):
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        
        return findings[0] if findings else None
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tools/whatweb.py <ip_address[:port]>")
        print("Example: python tools/whatweb.py 54.38.136.66")
        print("Example: python tools/whatweb.py 54.38.136.66:8080")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Parse IP and port
    if ':' in target:
        ip, port = target.split(':', 1)
        port = int(port)
    else:
        ip = target
        port = 80
    
    print(f"Running WhatWeb scan on {ip}:{port}...")
    result = whatweb_scan(ip, port)
    print(json.dumps(result, indent=2))
