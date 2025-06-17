import httpx
import logging

class SuiSpecificScanner:
    """
    Sui-specific scanner for custom checks (metrics, version, open RPC, debug endpoints).
    """

    def __init__(self, rpc_ports=(9000, 443, 80), metrics_port=9184):
        self.rpc_ports = rpc_ports
        self.metrics_port = metrics_port
        self.logger = logging.getLogger("sui_scanner")

    def check_metrics_endpoint(self, ip):
        """
        Checks if the Sui metrics endpoint is exposed on :9184/metrics.
        """
        self.logger.info(f"🔍 Checking Sui metrics endpoint for {ip}")
        url_patterns = [
            f"http://{ip}:{self.metrics_port}/metrics",
            f"https://{ip}:{self.metrics_port}/metrics"
        ]
        for url in url_patterns:
            try:
                self.logger.debug(f"🌐 Trying metrics URL: {url}")
                r = httpx.get(url, timeout=5, verify=False)
                if r.status_code == 200:
                    # Check for Sui-related content (more flexible detection)
                    content_lower = r.text.lower()
                    sui_indicators = [
                        "sui_validator",  # Original check
                        "consensus_",     # Sui consensus metrics
                        "authority=\"sui", # Authority names containing sui
                        "sui" in content_lower and "consensus" in content_lower,  # General sui + consensus
                        "sui" in content_lower and "validator" in content_lower   # General sui + validator
                    ]
                    
                    # Count how many Sui-related terms we find
                    sui_count = content_lower.count("sui")
                    consensus_count = content_lower.count("consensus")
                    validator_count = content_lower.count("validator")
                    
                    if any(sui_indicators) or (sui_count > 10 and consensus_count > 10):
                        self.logger.info(f"✅ Sui metrics found at {url} (sui:{sui_count}, consensus:{consensus_count}, validator:{validator_count})")
                        return {
                            "metrics_exposed": True, 
                            "metrics_url": url,
                            "sui_metrics_count": sui_count,
                            "consensus_metrics_count": consensus_count,
                            "validator_metrics_count": validator_count
                        }
                    else:
                        self.logger.debug(f"⚠️  Metrics endpoint responded but no clear Sui content at {url} (sui:{sui_count}, consensus:{consensus_count})")
                else:
                    self.logger.debug(f"⚠️  Metrics endpoint returned {r.status_code} at {url}")
            except Exception as e:
                self.logger.debug(f"❌ Metrics check failed for {url}: {e}")
                continue
        self.logger.debug(f"❌ No Sui metrics found for {ip}")
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
        self.logger.info(f"🚀 Starting Sui-specific scan for {ip}")
        result = {"ip": ip}
        result.update(self.check_metrics_endpoint(ip))
        result.update(self.check_rpc_endpoint(ip))
        result.update(self.check_version(ip))
        self.logger.info(f"✅ Sui scan completed for {ip}: metrics={result.get('metrics_exposed', False)}, rpc={result.get('rpc_exposed', False)}")
        return result
