import subprocess

def ssl_test(ip, port=443):
    try:
        # Example using openssl s_client (very basic)
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{ip}:{port}", "-tls1_2"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10
        )
        output = result.stdout.decode(errors="ignore")
        # Check for known weak ciphers, expired certs, etc (naive example)
        issues = []
        if "Verify return code: 0 (ok)" not in output:
            issues.append("SSL certificate not valid or expired")
        if "Cipher    : 0000" in output:
            issues.append("No strong cipher negotiated")
        return {
            "openssl_raw": output[:1000],  # First 1000 chars for brevity
            "issues": issues
        }
    except Exception as e:
        return {"error": str(e)}
