import httpx
import logging
from .base_scanner import BaseScanner

class SuiSpecificScanner(BaseScanner):
    """
    Sui-specific scanner for custom checks (metrics, version, open RPC, debug endpoints).
    """

    def __init__(self, config=None, rpc_ports=(9000, 443, 80), metrics_port=9184, timeout: int = 10, debug: bool = False):
        """
        Initialize Sui scanner.
        
        Args:
            config: Scanner configuration
            rpc_ports: Ports to check for RPC endpoints
            metrics_port: Port to check for metrics
            timeout: Request timeout in seconds
            debug: Enable debug logging
        """
        super().__init__(config)
        
        # Extract config values if provided
        if config:
            rpc_ports = config.get('rpc_ports', rpc_ports)
            metrics_port = config.get('metrics_port', metrics_port)
            timeout = config.get('timeout', timeout)
            debug = config.get('debug', debug)
        
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

    @property
    def scanner_type(self) -> str:
        """Return the type of scanner."""
        return "sui"

    def scan(self, target: str, **kwargs):
        """
        Runs Sui-specific checks based on scan level.
        
        Args:
            target: Target IP address or hostname
            **kwargs: Additional scan parameters including scan_level
        
        Returns:
            Scan results dictionary
        """
        scan_level = kwargs.get('scan_level', 1)
        self.logger.info(f"🚀 Starting Sui scan for {target} at level {scan_level}")
        
        if scan_level == 1:
            return self._scan_level_1(target)
        elif scan_level == 2:
            return self._scan_level_2(target)
        elif scan_level == 3:
            return self._scan_level_3(target)
        else:
            raise ValueError(f"Invalid scan_level: {scan_level}. Must be 1, 2, or 3.")
    
    def _scan_level_1(self, target):
        """Level 1: Basic node metadata and version check."""
        self.logger.info(f"🔍 Level 1 Sui scan for {target}")
        
        result = {
            "target": target, 
            "scan_level": 1,
            "scanner_type": "sui"
        }
        
        # Basic version and node info
        result.update(self.check_version(target))
        
        # Basic metrics check
        metrics_result = self.check_metrics_endpoint(target)
        result.update(metrics_result)
        
        self.logger.info(f"✅ Level 1 Sui scan completed for {target}")
        return result
    
    def _scan_level_2(self, ip):
        """Level 2: Enhanced checks including RPC and validator health."""
        self.logger.info(f"🔍 Level 2 Sui scan for {ip}")
        
        result = {
            "ip": ip,
            "scan_level": 2, 
            "scanner_type": "sui"
        }
        
        # All level 1 checks
        result.update(self.check_version(ip))
        result.update(self.check_metrics_endpoint(ip))
        
        # Level 2 specific: RPC endpoint checks
        result.update(self.check_rpc_endpoint(ip))
        
        # Enhanced validator health check
        validator_health = self._check_validator_health_basic(ip)
        if validator_health:
            result.update(validator_health)
        
        self.logger.info(f"✅ Level 2 Sui scan completed for {ip}")
        return result
    
    def _scan_level_3(self, ip):
        """Level 3: Deep protocol inspection with transaction testing."""
        self.logger.info(f"🔍 Level 3 Sui scan for {ip}")
        
        result = {
            "ip": ip,
            "scan_level": 3,
            "scanner_type": "sui"
        }
        
        # All level 2 checks
        result.update(self.check_version(ip))
        result.update(self.check_metrics_endpoint(ip))
        result.update(self.check_rpc_endpoint(ip))
        
        # Level 3 specific: deep protocol inspection
        validator_config = self._check_validator_config(ip)
        if validator_config:
            result["validator_config"] = validator_config
        
        chain_stats = self._query_chain_stats(ip)
        if chain_stats:
            result["chain_stats"] = chain_stats
        
        # Test transaction simulation (safe testnet operations)
        tx_test = self._test_dummy_transaction(ip)
        if tx_test:
            result["transaction_test"] = tx_test
        
        self.logger.info(f"✅ Level 3 Sui scan completed for {ip}")
        return result
