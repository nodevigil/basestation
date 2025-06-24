import httpx
import logging

class SuiSpecificScanner:
    """
    Sui-specific scanner for custom checks (metrics, version, open RPC, debug endpoints).
    """

    def __init__(self, config=None, rpc_ports=(9000, 443, 80), metrics_port=9184, timeout: int = 10, debug: bool = False):
        """
        Initialize Sui scanner.
        
        Args:
            config: Configuration instance (for orchestrator compatibility)
            rpc_ports: Ports to check for RPC endpoints
            metrics_port: Port to check for metrics
            timeout: Request timeout in seconds
            debug: Enable debug logging
        """
        self.config = config
        self.rpc_ports = rpc_ports
        self.metrics_port = metrics_port
        self.timeout = timeout
        self.debug = debug
        self.logger = self._setup_logging()
        
        # Log debug initialization
        if self.debug:
            self.logger.debug(f"🐛 SuiSpecificScanner debug logging is ACTIVE")
        else:
            self.logger.info(f"ℹ️ SuiSpecificScanner initialized (debug mode: {self.debug})")

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration based on debug mode."""
        logger = logging.getLogger(f"scanning.{self.__class__.__name__}")
        logger.setLevel(logging.DEBUG if self.debug else logging.INFO)
        
        # Remove existing handlers to avoid duplicates
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG if self.debug else logging.INFO)
        
        # Formatter
        if self.debug:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            )
        else:
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File handler for debug mode
        if self.debug:
            from datetime import datetime
            file_handler = logging.FileHandler(f'sui_scanner_debug_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            logger.debug("Debug logging enabled - logs will be saved to file")
        
        return logger

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
                r = httpx.get(url, timeout=self.timeout, verify=False)
                self.logger.debug(f"🌐 Response status: {r.status_code}")
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
                    
                    self.logger.debug(f"🔍 Metrics analysis - sui:{sui_count}, consensus:{consensus_count}, validator:{validator_count}")
                    
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
        self.logger.debug(f"🔍 Checking Sui RPC endpoints for {ip}")
        for port in self.rpc_ports:
            for scheme in ["http", "https"]:
                url = f"{scheme}://{ip}:{port}"
                try:
                    self.logger.debug(f"🌐 Trying RPC URL: {url}")
                    r = httpx.post(url, timeout=self.timeout, verify=False)
                    self.logger.debug(f"🌐 RPC response status: {r.status_code}")
                    # If open, should return HTTP status code, not connection refused
                    if r.status_code in (200, 400, 405):
                        self.logger.debug(f"✅ RPC endpoint found at {url}")
                        return {"rpc_exposed": True, "rpc_url": url}
                except Exception as e:
                    self.logger.debug(f"❌ RPC check failed for {url}: {e}")
                    continue
        self.logger.debug(f"❌ No RPC endpoints found for {ip}")
        return {"rpc_exposed": False}

    def check_version(self, ip):
        """
        Attempts to fetch version endpoint if present (commonly /version, /status).
        """
        self.logger.debug(f"🔍 Checking Sui version endpoints for {ip}")
        for port in self.rpc_ports:
            for scheme in ["http", "https"]:
                for endpoint in ["/version", "/status"]:
                    url = f"{scheme}://{ip}:{port}{endpoint}"
                    try:
                        self.logger.debug(f"🌐 Trying version URL: {url}")
                        r = httpx.get(url, timeout=self.timeout, verify=False)
                        self.logger.debug(f"🌐 Version response status: {r.status_code}")
                        if r.status_code == 200 and "version" in r.text.lower():
                            self.logger.debug(f"✅ Version endpoint found at {url}")
                            return {"version_exposed": True, "version_url": url, "version_info": r.text}
                    except Exception as e:
                        self.logger.debug(f"❌ Version check failed for {url}: {e}")
                        continue
        self.logger.debug(f"❌ No version endpoints found for {ip}")
        return {"version_exposed": False}

    def scan(self, ip, **kwargs):
        """
        Runs all Sui-specific checks on a given IP.
        
        Args:
            ip: Target IP address
            **kwargs: Additional scan parameters (including scan_level)
        """
        scan_level = kwargs.get('scan_level', 1)
        
        self.logger.info(f"🚀 Starting Sui-specific scan for {ip} (level {scan_level})")
        self.logger.debug(f"Scan configuration - timeout: {self.timeout}s, debug: {self.debug}")
        
        result = {"ip": ip, "scan_level": scan_level, "scanner_type": "sui"}
        result.update(self.check_metrics_endpoint(ip))
        result.update(self.check_rpc_endpoint(ip))
        result.update(self.check_version(ip))
        
        self.logger.info(f"✅ Sui scan completed for {ip}: metrics={result.get('metrics_exposed', False)}, rpc={result.get('rpc_exposed', False)}")
        self.logger.debug(f"Final scan results: {result}")
        
        return result
