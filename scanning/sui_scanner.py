import httpx

class SuiSpecificScanner:
    """
    Sui-specific scanner for custom checks (metrics, version, open RPC, debug endpoints).
    """

    def __init__(self, rpc_ports=(9000, 443, 80), metrics_port=9184):
        self.rpc_ports = rpc_ports
        self.metrics_port = metrics_port

    def check_metrics_endpoint(self, ip):
        """
        Checks if the Sui metrics endpoint is exposed on :9184/metrics.
        """
        url_patterns = [
            f"http://{ip}:{self.metrics_port}/metrics",
            f"https://{ip}:{self.metrics_port}/metrics"
        ]
        for url in url_patterns:
            try:
                r = httpx.get(url, timeout=2, verify=False)
                if r.status_code == 200 and "sui_validator" in r.text:
                    return {"metrics_exposed": True, "metrics_url": url}
            except Exception:
                continue
        return {"metrics_exposed": False}

    def check_rpc_endpoint(self, ip):
        """
        Checks if the Sui RPC endpoint is open on default ports.
        """
        for port in self.rpc_ports:
            for scheme in ["http", "https"]:
                url = f"{scheme}://{ip}:{port}"
                try:
                    r = httpx.post(url, timeout=2, verify=False)
                    # If open, should return HTTP status code, not connection refused
                    if r.status_code in (200, 400, 405):
                        return {"rpc_exposed": True, "rpc_url": url}
                except Exception:
                    continue
        return {"rpc_exposed": False}

    def check_version(self, ip):
        """
        Attempts to fetch version endpoint if present (commonly /version, /status).
        """
        for port in self.rpc_ports:
            for scheme in ["http", "https"]:
                for endpoint in ["/version", "/status"]:
                    url = f"{scheme}://{ip}:{port}{endpoint}"
                    try:
                        r = httpx.get(url, timeout=2, verify=False)
                        if r.status_code == 200 and "version" in r.text.lower():
                            return {"version_exposed": True, "version_url": url, "version_info": r.text}
                    except Exception:
                        continue
        return {"version_exposed": False}

    def scan(self, ip):
        """
        Runs all Sui-specific checks on a given IP.
        """
        result = {"ip": ip}
        result.update(self.check_metrics_endpoint(ip))
        result.update(self.check_rpc_endpoint(ip))
        result.update(self.check_version(ip))
        return result
