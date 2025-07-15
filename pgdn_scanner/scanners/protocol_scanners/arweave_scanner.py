import asyncio
import httpx
import logging
import time
import hashlib
import json
import statistics
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timedelta
from .base_protocol_scanner import ProtocolScanner

class ScanLevel(Enum):
    LITE = 1
    MEDIUM = 2
    FEROCIOUS = 3

class NodeRisk(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ArweaveScanResult:
    """Comprehensive scan result with all trust scoring inputs"""
    ip: str
    port: int
    timestamp: datetime
    scan_level: ScanLevel
    
    # Basic node info
    version: Optional[str] = None
    network: Optional[str] = None
    healthy: bool = False
    node_id: Optional[str] = None
    
    # Network and performance metrics
    peer_count: int = 0
    peer_diversity_score: Optional[float] = None
    sync_gap: Optional[int] = None
    block_height: Optional[int] = None
    network_height: Optional[int] = None
    latency_ms: Optional[float] = None
    latency_variance: Optional[float] = None
    response_time_p95: Optional[float] = None
    
    # Security indicators
    open_ports: List[int] = None
    tls_grade: Optional[str] = None
    tls_cipher_strength: Optional[str] = None
    exposed_services: List[str] = None
    security_headers_score: Optional[float] = None
    admin_interfaces_exposed: bool = False
    
    # Operational metrics
    tx_throughput: Optional[float] = None
    mining_efficiency: Optional[float] = None
    uptime_score: Optional[float] = None
    storage_utilization: Optional[float] = None
    memory_usage: Optional[float] = None
    cpu_usage: Optional[float] = None
    
    # Behavioral analysis
    tx_anchor_freshness: Optional[int] = None  # seconds since last anchor
    peer_connection_stability: Optional[float] = None
    performance_trend: Optional[str] = None  # "improving", "stable", "declining"
    anomaly_score: Optional[float] = None
    
    # Reputation and threat intelligence
    reputation_flags: List[str] = None
    malicious_ip: bool = False
    known_vulnerabilities: List[str] = None
    blacklist_matches: List[str] = None
    
    # Configuration analysis
    misconfigs: List[str] = None
    config_security_score: Optional[float] = None
    compliance_flags: List[str] = None
    
    # Raw data for external trust scoring
    metrics: Dict = None
    headers: Dict = None
    endpoints_status: Dict = None
    peer_list: List = None
    
    # Scan metadata
    scan_duration_ms: Optional[float] = None
    scan_success_rate: Optional[float] = None
    last_seen: Optional[datetime] = None

    def __post_init__(self):
        """Initialize list fields"""
        if self.open_ports is None:
            self.open_ports = []
        if self.exposed_services is None:
            self.exposed_services = []
        if self.reputation_flags is None:
            self.reputation_flags = []
        if self.known_vulnerabilities is None:
            self.known_vulnerabilities = []
        if self.blacklist_matches is None:
            self.blacklist_matches = []
        if self.metrics is None:
            self.metrics = {}
        if self.headers is None:
            self.headers = {}
        if self.endpoints_status is None:
            self.endpoints_status = {}
        if self.misconfigs is None:
            self.misconfigs = []
        if self.compliance_flags is None:
            self.compliance_flags = []
        if self.peer_list is None:
            self.peer_list = []

class EnhancedArweaveScanner(ProtocolScanner):
    """
    Production-grade Arweave scanner focused on comprehensive data collection
    for external trust scoring systems.
    """
    
    @property
    def protocol_name(self) -> str:
        """Return the protocol name."""
        return "arweave"
    
    def get_supported_levels(self) -> List[int]:
        """Return supported scan levels."""
        return [1, 2, 3]
    
    def describe_levels(self) -> Dict[int, str]:
        """Return description of what each scan level does."""
        return {
            1: "Basic Arweave node health check, version, and network status",
            2: "Extended metrics, peer analysis, and sync monitoring", 
            3: "Comprehensive security analysis, behavioral patterns, and threat intelligence"
        }
    
    def __init__(self, config=None, scan_level: ScanLevel = ScanLevel.LITE, 
                 enable_reputation=True, enable_behavioral=True):
        super().__init__(config)
        
        # Configuration
        self.scan_level = scan_level
        self.timeout = config.get('timeout', 15) if config else 15
        self.max_retries = config.get('max_retries', 3) if config else 3
        self.rate_limit_delay = config.get('rate_limit_delay', 1.0) if config else 1.0
        
        # External services (optional - can be None)
        self.reputation_client = ReputationClient() if enable_reputation else None
        self.behavioral_analyzer = BehaviorAnalyzer() if enable_behavioral else None
        
        # Caching and state management
        self.node_cache = {}
        self.scan_history = {}
        self.network_baseline = {}  # For comparative analysis
        
        self.logger = logging.getLogger(__name__)
        
        # Protocol-specific configuration
        self.default_ports = [1984, 1985]
        self.critical_endpoints = ['/info', '/health', '/peers']
        self.metrics_endpoints = ['/metrics', '/price/0']
        self.behavioral_endpoints = ['/tx_anchor', '/current_block', '/block_index/current']
        
        # Vulnerability and configuration databases
        self.known_vulnerabilities = self._load_vulnerability_db()
        self.security_baselines = self._load_security_baselines()

    async def scan_protocol(self, target: str, hostname: Optional[str] = None, scan_level: int = 1, **kwargs) -> Dict[str, Any]:
        """Perform Arweave protocol-specific scan.
        
        Args:
            target: Target IP address or hostname to scan
            hostname: Optional hostname for SNI/virtual host support
            scan_level: Scan intensity level (1-3)
            **kwargs: Additional scan parameters
            
        Returns:
            Dictionary containing scan results
        """
        # Extract ports from kwargs or use defaults
        ports = kwargs.get('ports', self.default_ports)
        
        self.logger.info(f"Starting Arweave protocol scan on {target}" + (f" (hostname: {hostname})" if hostname else ""))
        self.logger.info(f"Scan configuration: level={scan_level}, ports={ports}, timeout={self.timeout}s")
        
        # Convert scan_level to ScanLevel enum
        scan_level_enum = ScanLevel.LITE
        if scan_level == 2:
            scan_level_enum = ScanLevel.MEDIUM
        elif scan_level == 3:
            scan_level_enum = ScanLevel.FEROCIOUS
            
        self.logger.debug(f"Scan level mapped to: {scan_level_enum.name}")
        
        # Temporarily update scan level
        original_scan_level = self.scan_level
        self.scan_level = scan_level_enum
        
        try:
            self.logger.info(f"Executing Arweave enhanced scan")
            # Perform the scan using the existing scan method
            results = await self.scan(target, hostname, ports)
            
            # Log scan results summary
            successful_scans = len(results)
            healthy_nodes = sum(1 for r in results if r.healthy)
            success_rate = successful_scans / len(ports) if ports else 0
            
            if successful_scans > 0:
                self.logger.info(f"Found {successful_scans} Arweave node(s) on {target}")
                self.logger.debug(f"Healthy nodes: {healthy_nodes}/{successful_scans}")
                self.logger.debug(f"Success rate: {success_rate:.1%}")
            else:
                self.logger.warning(f"No Arweave nodes detected on {target}")
            
            # Convert results to dictionary format expected by the framework
            return {
                'target': target,
                'hostname': hostname,
                'scan_level': scan_level,
                'protocol': self.protocol_name,
                'timestamp': datetime.utcnow().isoformat(),
                'results': [asdict(result) for result in results],
                'summary': {
                    'total_ports_scanned': len(ports),
                    'successful_scans': successful_scans,
                    'healthy_nodes': healthy_nodes,
                    'scan_success_rate': success_rate
                }
            }
        finally:
            # Restore original scan level
            self.scan_level = original_scan_level

    async def scan(self, ip: str, hostname: Optional[str] = None, ports: List[int] = None, **kwargs) -> List[ArweaveScanResult]:
        """Enhanced scan with comprehensive data collection"""
        if ports is None:
            ports = self.default_ports
            
        self.logger.debug(f"Starting Arweave port scan on {ip}" + (f" via hostname {hostname}" if hostname else ""))
        self.logger.debug(f"Scan level: {self.scan_level.name}, ports: {ports}")
        
        # Add overall timeout to prevent hanging (5 minutes max)
        try:
            return await asyncio.wait_for(self._perform_scan(ip, hostname, ports), timeout=300)
        except asyncio.TimeoutError:
            self.logger.warning(f"⏰ Arweave scan timeout after 5 minutes for {ip}")
            return []

    async def _perform_scan(self, ip: str, hostname: Optional[str] = None, ports: List[int] = None) -> List[ArweaveScanResult]:
        """Internal scan method with timeout protection"""
        
        # Rate limiting
        if self.rate_limit_delay > 0:
            self.logger.debug(f"Rate limiting: waiting {self.rate_limit_delay}s")
            await asyncio.sleep(self.rate_limit_delay)
        
        scan_start = time.time()
        results = []
        
        self.logger.debug(f"Beginning port scanning on {len(ports)} Arweave ports")
        for i, port in enumerate(ports, 1):
            self.logger.debug(f"Scanning port {port} ({i}/{len(ports)})")
            result = await self._scan_port(ip, port, hostname)
            if result:
                self.logger.debug(f"Port {port}: Arweave node detected (healthy: {result.healthy})")
                results.append(result)
            else:
                self.logger.debug(f"Port {port}: No Arweave node detected")
        
        if results:
            self.logger.debug(f"Updating Arweave network baseline with {len(results)} results")
            # Update network baseline for comparative analysis
            self._update_network_baseline(results)
        else:
            self.logger.debug(f"No baseline update - no results found")
        
        # Calculate scan metadata
        scan_duration = (time.time() - scan_start) * 1000
        for result in results:
            result.scan_duration_ms = scan_duration
        
        return results

    async def _scan_port(self, ip: str, port: int, hostname: Optional[str] = None) -> Optional[ArweaveScanResult]:
        """Comprehensive port scanning with all data collection"""
        # Use hostname for URL if provided (for SNI/virtual host support)
        host_for_url = hostname if hostname else ip
        base_url = f"http://{host_for_url}:{port}"
        
        self.logger.debug(f"Analyzing Arweave port {port} on {ip}" + (f" via hostname {hostname}" if hostname else ""))
        self.logger.debug(f"🌐 Base URL: {base_url}")
        
        # Initialize result with comprehensive structure
        result = ArweaveScanResult(
            ip=ip,
            port=port,
            timestamp=datetime.utcnow(),
            scan_level=self.scan_level
        )
        
        # Check cache first
        cache_key = f"{ip}:{port}"
        if self._should_use_cache(cache_key):
            cached = self.node_cache[cache_key]
            self.logger.debug(f"Using cached result for {cache_key}")
            return cached
        
        successful_requests = 0
        total_requests = 0
        
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                limits=httpx.Limits(max_connections=10)
            ) as client:
                
                # Level 1: Basic health and metadata collection
                success = await self._scan_basic(client, base_url, result)
                total_requests += 4  # Approximate number of requests
                successful_requests += success
                
                if self.scan_level.value >= 2:
                    success = await self._scan_medium(client, base_url, result)
                    total_requests += 6
                    successful_requests += success
                
                if self.scan_level.value >= 3:
                    success = await self._scan_ferocious(client, base_url, result)
                    total_requests += 10
                    successful_requests += success
                
                # Enhanced analysis phases
                await self._analyze_security_posture(result)
                await self._analyze_operational_metrics(result)
                await self._analyze_behavior_patterns(result)
                await self._check_reputation_intelligence(result)
                await self._assess_compliance_indicators(result)
                
        except Exception as e:
            self.logger.warning(f"Scan failed for {ip}:{port} - {e}")
            result.misconfigs.append(f"scan_error: {str(e)}")
        
        # Calculate scan success rate
        result.scan_success_rate = successful_requests / total_requests if total_requests > 0 else 0.0
        
        # Cache result and update history
        self.node_cache[cache_key] = result
        self._update_scan_history(ip, port, result)
        
        return result

    async def _scan_basic(self, client: httpx.AsyncClient, base_url: str, result: ArweaveScanResult) -> int:
        """Level 1: Comprehensive basic node information collection"""
        successful_requests = 0
        
        try:
            # Node info with detailed parsing
            info_response = await self._robust_fetch(client, f"{base_url}/info")
            result.endpoints_status['/info'] = info_response is not None
            
            if info_response:
                successful_requests += 1
                result.version = info_response.get("release") or info_response.get("version")
                result.network = info_response.get("network")
                result.node_id = info_response.get("node_id") or self._extract_node_id(info_response)
                
                # Extract additional metadata
                if "height" in info_response:
                    result.block_height = info_response["height"]
                if "weave_size" in info_response:
                    result.storage_utilization = self._calculate_storage_utilization(info_response)
                
                # Version-based vulnerability assessment
                if result.version:
                    result.known_vulnerabilities = self._check_version_vulnerabilities(result.version)
            
            # Health check with detailed analysis
            health_response = await client.get(f"{base_url}/health")
            result.endpoints_status['/health'] = health_response.status_code == 200
            result.healthy = health_response.status_code == 200
            
            if result.healthy:
                successful_requests += 1
                # Parse health response details if available
                try:
                    health_data = health_response.json()
                    if isinstance(health_data, dict):
                        result.metrics.update(health_data)
                except:
                    pass  # Health endpoint might return simple text
            else:
                result.misconfigs.append("node_unhealthy")
            
            # Price endpoint check (Arweave-specific)
            price_response = await self._robust_fetch(client, f"{base_url}/price/0")
            result.endpoints_status['/price/0'] = price_response is not None
            if price_response:
                successful_requests += 1
            
            # Current block endpoint
            block_response = await self._robust_fetch(client, f"{base_url}/current_block")
            result.endpoints_status['/current_block'] = block_response is not None
            if block_response:
                successful_requests += 1
                if isinstance(block_response, dict) and "height" in block_response:
                    result.network_height = block_response["height"]
                
        except Exception as e:
            self.logger.debug(f"Basic scan error: {e}")
        
        return successful_requests

    async def _scan_medium(self, client: httpx.AsyncClient, base_url: str, result: ArweaveScanResult) -> int:
        """Level 2: Network metrics and peer analysis"""
        successful_requests = 0
        
        try:
            # Comprehensive peer analysis
            peers_response = await self._robust_fetch(client, f"{base_url}/peers")
            result.endpoints_status['/peers'] = peers_response is not None
            
            if peers_response:
                successful_requests += 1
                result.peer_list = peers_response if isinstance(peers_response, list) else []
                result.peer_count = len(result.peer_list)
                
                # Advanced peer analysis
                result.peer_diversity_score = self._analyze_peer_diversity(result.peer_list)
                result.peer_connection_stability = self._analyze_peer_stability(result.peer_list)
                
                # Peer count analysis with context
                if result.peer_count < 5:
                    result.misconfigs.append("insufficient_peers")
                    result.compliance_flags.append("low_connectivity")
                elif result.peer_count > 200:
                    result.misconfigs.append("excessive_peers")
                    result.compliance_flags.append("potential_centralization")
                
                # Geographic and network diversity analysis
                if result.peer_diversity_score and result.peer_diversity_score < 0.3:
                    result.misconfigs.append("low_peer_diversity")
                    result.compliance_flags.append("geographic_centralization")
            
            # Enhanced metrics parsing
            metrics_response = await client.get(f"{base_url}/metrics")
            result.endpoints_status['/metrics'] = metrics_response.status_code == 200
            
            if metrics_response.status_code == 200:
                successful_requests += 1
                result.metrics.update(self._parse_enhanced_metrics(metrics_response.text))
                
                # Calculate derived metrics
                result.sync_gap = self._calculate_sync_gap(result.metrics)
                result.mining_efficiency = self._calculate_mining_efficiency(result.metrics)
                result.tx_throughput = self._calculate_tx_throughput(result.metrics)
                
                # Resource utilization
                result.memory_usage = result.metrics.get('arweave_memory_usage_bytes')
                result.cpu_usage = result.metrics.get('arweave_cpu_usage_percent')
                
                # Sync analysis with context
                if result.sync_gap:
                    if result.sync_gap > 100:
                        result.misconfigs.append("high_sync_lag")
                        result.compliance_flags.append("sync_performance_issue")
                    elif result.sync_gap > 50:
                        result.compliance_flags.append("moderate_sync_lag")
                
                # Mining efficiency analysis
                if result.mining_efficiency and result.mining_efficiency < 0.1:
                    result.misconfigs.append("low_mining_efficiency")
            
            # Block index check
            block_index_response = await self._robust_fetch(client, f"{base_url}/block_index/current")
            result.endpoints_status['/block_index/current'] = block_index_response is not None
            if block_index_response:
                successful_requests += 1
                
        except Exception as e:
            self.logger.debug(f"Medium scan error: {e}")
        
        return successful_requests

    async def _scan_ferocious(self, client: httpx.AsyncClient, base_url: str, result: ArweaveScanResult) -> int:
        """Level 3: Deep behavioral and security analysis"""
        successful_requests = 0
        
        try:
            # Multi-sample latency measurement with statistical analysis
            latencies = []
            for i in range(5):  # More samples for better statistics
                start = time.time()
                try:
                    response = await client.get(f"{base_url}/info")
                    if response.status_code == 200:
                        latencies.append((time.time() - start) * 1000)
                        successful_requests += 0.2  # Fractional success
                except:
                    pass
                await asyncio.sleep(0.1)
            
            if latencies:
                result.latency_ms = statistics.mean(latencies)
                result.latency_variance = statistics.variance(latencies) if len(latencies) > 1 else 0
                result.response_time_p95 = sorted(latencies)[int(0.95 * len(latencies))] if latencies else 0
                
                # Latency analysis
                if result.latency_variance > 100:
                    result.misconfigs.append("unstable_latency")
                    result.compliance_flags.append("performance_instability")
                
                if result.response_time_p95 > 5000:  # 5 second P95
                    result.misconfigs.append("high_p95_latency")
                    result.compliance_flags.append("poor_user_experience")
            
            # Transaction anchor analysis with freshness check
            tx_anchor_response = await client.get(f"{base_url}/tx_anchor")
            result.endpoints_status['/tx_anchor'] = tx_anchor_response.status_code == 200
            
            if tx_anchor_response.status_code == 200:
                successful_requests += 1
                anchor = tx_anchor_response.text.strip()
                
                # Validate anchor format and calculate freshness
                if self._validate_tx_anchor(anchor):
                    result.tx_anchor_freshness = self._calculate_anchor_freshness(anchor)
                    
                    if result.tx_anchor_freshness and result.tx_anchor_freshness > 3600:  # 1 hour
                        result.misconfigs.append("stale_tx_anchor")
                        result.compliance_flags.append("sync_lag_indicator")
                else:
                    result.misconfigs.append("invalid_tx_anchor")
                    result.compliance_flags.append("data_integrity_issue")
            
            # Comprehensive header analysis
            result.headers = dict(tx_anchor_response.headers)
            security_issues = self._analyze_security_headers(result.headers)
            result.misconfigs.extend(security_issues)
            result.security_headers_score = self._calculate_security_headers_score(result.headers)
            
            # Advanced port scanning for security assessment
            result.open_ports = await self._scan_port_range(result.ip, [1984, 1985, 22, 80, 443, 8080, 9090])
            
            # Identify exposed services and admin interfaces
            exposed_services = []
            for port in result.open_ports:
                if port not in self.default_ports:
                    service = await self._identify_service(result.ip, port)
                    if service:
                        exposed_services.append(f"{service}:{port}")
                        
                        # Check for admin interfaces
                        if service in ['ssh', 'rdp', 'vnc', 'telnet']:
                            result.admin_interfaces_exposed = True
                            result.compliance_flags.append("admin_interface_exposed")
            
            result.exposed_services = exposed_services
            
            # TLS analysis for HTTPS endpoints
            if 1985 in result.open_ports or 443 in result.open_ports:
                tls_port = 1985 if 1985 in result.open_ports else 443
                tls_analysis = await self._analyze_tls_config(result.ip, tls_port)
                result.tls_grade = tls_analysis.get('grade')
                result.tls_cipher_strength = tls_analysis.get('cipher_strength')
                
                if result.tls_grade in ['C', 'D', 'F']:
                    result.misconfigs.append(f"weak_tls_{result.tls_grade}")
                    result.compliance_flags.append("encryption_weakness")
                
        except Exception as e:
            self.logger.debug(f"Ferocious scan error: {e}")
        
        return successful_requests

    async def _analyze_security_posture(self, result: ArweaveScanResult):
        """Comprehensive security posture analysis"""
        security_score = 1.0
        
        # Port exposure analysis
        unexpected_ports = [p for p in result.open_ports if p not in self.default_ports]
        if unexpected_ports:
            security_score -= len(unexpected_ports) * 0.1
            for port in unexpected_ports:
                if port in [22, 23, 3389]:  # SSH, Telnet, RDP
                    result.compliance_flags.append("remote_admin_exposed")
        
        # Service exposure analysis
        dangerous_services = ['telnet', 'ftp', 'http-proxy', 'socks']
        for service in result.exposed_services:
            if any(dangerous in service.lower() for dangerous in dangerous_services):
                security_score -= 0.2
                result.compliance_flags.append("insecure_service_exposed")
        
        # Configuration security assessment
        config_issues = self._analyze_node_configuration(result.metrics)
        result.misconfigs.extend(config_issues)
        
        result.config_security_score = max(0.0, security_score)

    async def _analyze_operational_metrics(self, result: ArweaveScanResult):
        """Analyze operational health and performance metrics"""
        
        # Calculate uptime score from scan history
        history = self.scan_history.get(f"{result.ip}:{result.port}", [])
        if len(history) > 1:
            result.uptime_score = self._calculate_uptime_score(history)
            
            # Trend analysis
            if len(history) >= 5:
                result.performance_trend = self._analyze_performance_trend(history)
        
        # Resource utilization analysis
        if result.memory_usage and result.memory_usage > 0.9:  # 90% memory usage
            result.misconfigs.append("high_memory_usage")
            result.compliance_flags.append("resource_constraint")
        
        if result.cpu_usage and result.cpu_usage > 0.8:  # 80% CPU usage
            result.misconfigs.append("high_cpu_usage")
            result.compliance_flags.append("performance_risk")
        
        # Network performance benchmarking
        if hasattr(self, 'network_baseline') and self.network_baseline:
            self._compare_against_baseline(result)

    async def _analyze_behavior_patterns(self, result: ArweaveScanResult):
        """Advanced behavioral pattern analysis"""
        if not self.behavioral_analyzer:
            return
        
        try:
            # Anomaly detection based on historical patterns
            history = self.scan_history.get(f"{result.ip}:{result.port}", [])
            if len(history) > 10:
                result.anomaly_score = self.behavioral_analyzer.detect_anomalies(
                    history, result
                )
                
                if result.anomaly_score and result.anomaly_score > 0.7:
                    result.compliance_flags.append("behavioral_anomaly")
            
            # Transaction pattern analysis
            if result.metrics:
                tx_patterns = self.behavioral_analyzer.analyze_tx_patterns(result.metrics)
                if tx_patterns.get('suspicious', False):
                    result.compliance_flags.append("suspicious_tx_pattern")
                    
        except Exception as e:
            self.logger.debug(f"Behavioral analysis error: {e}")

    async def _check_reputation_intelligence(self, result: ArweaveScanResult):
        """Check against threat intelligence and reputation databases"""
        if not self.reputation_client:
            return
        
        try:
            # IP reputation check
            ip_reputation = await self.reputation_client.check_ip(result.ip)
            result.malicious_ip = ip_reputation.get('malicious', False)
            if result.malicious_ip:
                result.reputation_flags.append("malicious_ip")
                result.compliance_flags.append("security_threat")
            
            # Blacklist checking
            blacklist_results = await self.reputation_client.check_blacklists(result.ip)
            result.blacklist_matches = blacklist_results.get('matches', [])
            
            # Node reputation check
            if result.node_id:
                node_reputation = await self.reputation_client.check_node_reputation(result.node_id)
                result.reputation_flags.extend(node_reputation.get('flags', []))
            
            # Version vulnerability check
            if result.version:
                vuln_check = await self.reputation_client.check_version_vulnerabilities(result.version)
                critical_vulns = vuln_check.get('critical_vulnerabilities', [])
                result.known_vulnerabilities.extend(critical_vulns)
                
                if critical_vulns:
                    result.compliance_flags.append("critical_vulnerabilities")
                    
        except Exception as e:
            self.logger.warning(f"Reputation check failed: {e}")

    async def _assess_compliance_indicators(self, result: ArweaveScanResult):
        """Assess various compliance indicators"""
        
        # Data protection compliance
        if result.admin_interfaces_exposed:
            result.compliance_flags.append("gdpr_access_control_risk")
        
        # Network security compliance
        if result.tls_grade and result.tls_grade in ['D', 'F']:
            result.compliance_flags.append("pci_dss_encryption_fail")
        
        # Operational compliance
        if result.uptime_score and result.uptime_score < 0.99:
            result.compliance_flags.append("sla_availability_risk")
        
        # Security baseline compliance
        insecure_configs = sum(1 for config in result.misconfigs 
                              if any(keyword in config for keyword in 
                                   ['weak', 'exposed', 'insecure', 'vulnerable']))
        if insecure_configs > 3:
            result.compliance_flags.append("security_baseline_fail")

    # Helper methods for data extraction and analysis
    def _parse_enhanced_metrics(self, metrics_text: str) -> Dict[str, Any]:
        """Enhanced metrics parsing with comprehensive data extraction"""
        metrics = {}
        
        for line in metrics_text.splitlines():
            if line.startswith('#') or not line.strip():
                continue
                
            try:
                if ' ' in line:
                    key, value = line.split(' ', 1)
                    
                    # Handle different metric types
                    if key.startswith('arweave_'):
                        try:
                            # Try to parse as number
                            if '.' in value:
                                metrics[key] = float(value)
                            else:
                                metrics[key] = int(value)
                        except ValueError:
                            metrics[key] = value.strip('"')
                    elif any(keyword in key for keyword in 
                           ['block_', 'weave_', 'network_', 'hash_', 'difficulty']):
                        try:
                            metrics[key] = float(value)
                        except ValueError:
                            metrics[key] = value
            except Exception:
                continue
        
        return metrics

    def _calculate_sync_gap(self, metrics: Dict) -> Optional[int]:
        """Calculate synchronization gap with multiple fallbacks"""
        # Try different metric combinations
        current_height = (metrics.get('arweave_block_current_height') or 
                         metrics.get('arweave_height') or
                         metrics.get('block_height'))
        
        network_height = (metrics.get('arweave_block_network_height') or
                         metrics.get('arweave_network_height'))
        
        if current_height is not None and network_height is not None:
            return abs(int(network_height - current_height))
        
        return None

    def _calculate_mining_efficiency(self, metrics: Dict) -> Optional[float]:
        """Calculate mining efficiency with contextual analysis"""
        hash_rate = metrics.get('arweave_hash_rate')
        difficulty = metrics.get('arweave_difficulty')
        
        if hash_rate and difficulty and difficulty > 0:
            # Normalized efficiency calculation
            base_efficiency = hash_rate / difficulty
            # Scale to 0-1 range based on network averages
            return min(1.0, base_efficiency / 1000000)  # Adjust scaling as needed
        
        return None

    def _calculate_tx_throughput(self, metrics: Dict) -> Optional[float]:
        """Calculate transaction throughput from metrics"""
        tx_count = metrics.get('arweave_tx_count')
        tx_rate = metrics.get('arweave_tx_rate')
        
        if tx_rate:
            return float(tx_rate)
        elif tx_count and hasattr(self, '_last_tx_count'):
            # Calculate rate from count difference
            time_diff = 60  # Assume 1 minute between measurements
            rate = (tx_count - self._last_tx_count) / time_diff
            self._last_tx_count = tx_count
            return max(0.0, rate)
        
        return None

    def _analyze_peer_diversity(self, peer_list: List) -> Optional[float]:
        """Analyze geographic and network diversity of peers"""
        if not peer_list or len(peer_list) < 2:
            return 0.0
        
        # Extract IP addresses and analyze diversity
        ips = []
        for peer in peer_list:
            if isinstance(peer, str):
                # Parse IP from peer string (format may vary)
                ip = peer.split(':')[0] if ':' in peer else peer
                ips.append(ip)
            elif isinstance(peer, dict) and 'ip' in peer:
                ips.append(peer['ip'])
        
        if not ips:
            return 0.0
        
        # Calculate subnet diversity (simplified)
        subnets = set()
        for ip in ips:
            try:
                # Get /24 subnet
                parts = ip.split('.')
                if len(parts) >= 3:
                    subnet = '.'.join(parts[:3])
                    subnets.add(subnet)
            except:
                continue
        
        # Diversity score based on unique subnets
        return len(subnets) / len(ips) if ips else 0.0

    def _check_version_vulnerabilities(self, version: str) -> List[str]:
        """Check version against known vulnerability database"""
        vulnerabilities = []
        
        # This would integrate with actual vulnerability databases
        known_vulns = self.known_vulnerabilities.get('arweave', {})
        
        for vuln_version, vuln_list in known_vulns.items():
            if version and vuln_version in version:
                vulnerabilities.extend(vuln_list)
        
        return vulnerabilities

    def _load_vulnerability_db(self) -> Dict:
        """Load vulnerability database (mock implementation)"""
        return {
            'arweave': {
                '2.6.0': ['CVE-2023-1234', 'CVE-2023-5678'],
                '2.5': ['CVE-2022-9999']
            }
        }

    def _load_security_baselines(self) -> Dict:
        """Load security baseline configurations"""
        return {
            'tls_minimum_grade': 'B',
            'max_exposed_ports': 3,
            'required_security_headers': [
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection'
            ]
        }

    def _should_use_cache(self, cache_key: str) -> bool:
        """Determine if cached result should be used"""
        if cache_key not in self.node_cache:
            return False
        
        cached_result = self.node_cache[cache_key]
        age = datetime.utcnow() - cached_result.timestamp
        
        # Cache TTL based on scan level
        ttl_minutes = {
            ScanLevel.LITE: 5,
            ScanLevel.MEDIUM: 15,
            ScanLevel.FEROCIOUS: 30
        }
        
        max_age = timedelta(minutes=ttl_minutes.get(self.scan_level, 10))
        return age < max_age

    def _update_scan_history(self, ip: str, port: int, result: ArweaveScanResult):
        """Update scan history for behavioral analysis"""
        key = f"{ip}:{port}"
        if key not in self.scan_history:
            self.scan_history[key] = []
        
        self.scan_history[key].append(result)
        
        # Keep only last 100 scans for analysis
        self.scan_history[key] = self.scan_history[key][-100:]

    def _update_network_baseline(self, results: List[ArweaveScanResult]):
        """Update network baseline metrics for comparative analysis"""
        if not results:
            return
        
        # Calculate network-wide statistics
        healthy_nodes = [r for r in results if r.healthy]
        if healthy_nodes:
            latencies = [r.latency_ms for r in healthy_nodes if r.latency_ms]
            peer_counts = [r.peer_count for r in healthy_nodes]
            sync_gaps = [r.sync_gap for r in healthy_nodes if r.sync_gap is not None]
            
            self.network_baseline.update({
                'avg_latency': statistics.mean(latencies) if latencies else None,
                'avg_peer_count': statistics.mean(peer_counts) if peer_counts else None,
                'avg_sync_gap': statistics.mean(sync_gaps) if sync_gaps else None,
                'healthy_node_percentage': len(healthy_nodes) / len(results),
                'last_updated': datetime.utcnow()
            })

    def _compare_against_baseline(self, result: ArweaveScanResult):
        """Compare node performance against network baseline"""
        if not self.network_baseline:
            return
        
        # Latency comparison
        if (result.latency_ms and self.network_baseline.get('avg_latency') and 
            result.latency_ms > self.network_baseline['avg_latency'] * 2):
            result.compliance_flags.append("below_network_performance")
        
        # Peer count comparison
        if (result.peer_count and self.network_baseline.get('avg_peer_count') and
            result.peer_count < self.network_baseline['avg_peer_count'] * 0.5):
            result.compliance_flags.append("below_network_connectivity")
        
        # Sync gap comparison
        if (result.sync_gap and self.network_baseline.get('avg_sync_gap') and
            result.sync_gap > self.network_baseline['avg_sync_gap'] * 3):
            result.compliance_flags.append("below_network_sync")

    async def _robust_fetch(self, client: httpx.AsyncClient, url: str, retries: int = None) -> Optional[Dict]:
        """Fetch with comprehensive retry logic and error handling"""
        if retries is None:
            retries = self.max_retries
            
        last_exception = None
        
        for attempt in range(retries):
            try:
                response = await client.get(url)
                if response.status_code == 200:
                    try:
                        return response.json()
                    except json.JSONDecodeError:
                        # Return text response if not JSON
                        return {"text_response": response.text}
                elif response.status_code in [404, 501]:
                    # Endpoint not available, don't retry
                    return None
                    
            except (httpx.TimeoutException, httpx.ConnectError) as e:
                last_exception = e
                if attempt < retries - 1:
                    await asyncio.sleep(0.5 * (2 ** attempt))  # Exponential backoff
            except Exception as e:
                last_exception = e
                break
        
        if last_exception:
            self.logger.debug(f"Failed to fetch {url} after {retries} attempts: {last_exception}")
        
        return None

    async def _scan_port_range(self, ip: str, ports: List[int]) -> List[int]:
        """Scan range of ports to identify open services"""
        open_ports = []
        
        for port in ports:
            try:
                # Quick TCP connect test with short timeout
                future = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(future, timeout=2.0)
                writer.close()
                await writer.wait_closed()
                open_ports.append(port)
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                continue
            except Exception as e:
                self.logger.debug(f"Port scan error {ip}:{port} - {e}")
                continue
        
        return open_ports

    async def _identify_service(self, ip: str, port: int) -> Optional[str]:
        """Identify service running on specific port"""
        try:
            # Quick banner grab
            future = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(future, timeout=3.0)
            
            # Send minimal request and read response
            writer.write(b"GET / HTTP/1.0\r\n\r\n")
            await writer.drain()
            
            try:
                banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                banner_str = banner.decode('utf-8', errors='ignore').lower()
                
                # Service identification patterns
                if 'ssh' in banner_str:
                    return 'ssh'
                elif 'http' in banner_str or 'html' in banner_str:
                    return 'http'
                elif 'ftp' in banner_str:
                    return 'ftp'
                elif 'smtp' in banner_str:
                    return 'smtp'
                elif 'telnet' in banner_str:
                    return 'telnet'
                else:
                    return 'unknown'
                    
            finally:
                writer.close()
                await writer.wait_closed()
                
        except Exception:
            return None

    async def _analyze_tls_config(self, ip: str, port: int) -> Dict[str, Any]:
        """Analyze TLS/SSL configuration"""
        try:
            import ssl
            import socket
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate info
            with socket.create_connection((ip, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Basic TLS grading logic
                    if cipher and cipher[1] == 'TLSv1.3':
                        grade = 'A'
                    elif cipher and cipher[1] == 'TLSv1.2':
                        grade = 'B'
                    elif cipher and cipher[1] == 'TLSv1.1':
                        grade = 'C'
                    else:
                        grade = 'D'
                    
                    return {
                        'grade': grade,
                        'cipher_strength': cipher[2] if cipher else None,
                        'protocol': cipher[1] if cipher else None,
                        'cert_valid': cert is not None
                    }
                    
        except Exception as e:
            self.logger.debug(f"TLS analysis failed for {ip}:{port} - {e}")
            return {'grade': 'F', 'error': str(e)}

    def _analyze_security_headers(self, headers: Dict[str, str]) -> List[str]:
        """Analyze HTTP security headers for misconfigurations"""
        issues = []
        
        # Required security headers
        required_headers = {
            'x-content-type-options': 'nosniff',
            'x-frame-options': ['DENY', 'SAMEORIGIN'],
            'x-xss-protection': '1; mode=block',
            'strict-transport-security': None  # Just check presence
        }
        
        # Convert headers to lowercase for comparison
        lower_headers = {k.lower(): v for k, v in headers.items()}
        
        for header, expected in required_headers.items():
            if header not in lower_headers:
                issues.append(f"missing_security_header_{header.replace('-', '_')}")
            elif expected and isinstance(expected, list):
                if lower_headers[header] not in expected:
                    issues.append(f"weak_security_header_{header.replace('-', '_')}")
            elif expected and expected not in lower_headers[header]:
                issues.append(f"weak_security_header_{header.replace('-', '_')}")
        
        # Check for information disclosure
        disclosure_headers = ['server', 'x-powered-by', 'x-generator']
        for header in disclosure_headers:
            if header in lower_headers:
                issues.append(f"info_disclosure_{header.replace('-', '_')}")
        
        return issues

    def _calculate_security_headers_score(self, headers: Dict[str, str]) -> float:
        """Calculate security headers score (0-1)"""
        score = 1.0
        
        # Penalize missing security headers
        security_headers = [
            'x-content-type-options',
            'x-frame-options', 
            'x-xss-protection',
            'strict-transport-security',
            'content-security-policy'
        ]
        
        lower_headers = {k.lower(): v for k, v in headers.items()}
        missing_count = sum(1 for header in security_headers if header not in lower_headers)
        
        score -= missing_count * 0.15  # 15% penalty per missing header
        
        # Bonus for advanced security headers
        if 'content-security-policy' in lower_headers:
            score += 0.1
        if 'feature-policy' in lower_headers:
            score += 0.05
        
        return max(0.0, min(1.0, score))

    def _analyze_node_configuration(self, metrics: Dict) -> List[str]:
        """Analyze node configuration for security issues"""
        issues = []
        
        # Check for debug mode
        if metrics.get('arweave_debug_mode', False):
            issues.append("debug_mode_enabled")
        
        # Check for excessive logging
        log_level = metrics.get('arweave_log_level', '')
        if log_level.lower() in ['debug', 'trace']:
            issues.append("verbose_logging_enabled")
        
        # Check for test network configuration in production
        if metrics.get('arweave_network') == 'testnet':
            issues.append("testnet_config_in_production")
        
        # Check for insecure API exposure
        if metrics.get('arweave_api_unrestricted', False):
            issues.append("unrestricted_api_access")
        
        return issues

    def _calculate_uptime_score(self, history: List[ArweaveScanResult]) -> float:
        """Calculate uptime score from scan history"""
        if not history:
            return 0.0
        
        healthy_scans = sum(1 for scan in history if scan.healthy)
        return healthy_scans / len(history)

    def _analyze_performance_trend(self, history: List[ArweaveScanResult]) -> str:
        """Analyze performance trend from historical data"""
        if len(history) < 5:
            return "insufficient_data"
        
        # Get recent performance indicators
        recent_5 = history[-5:]
        previous_5 = history[-10:-5] if len(history) >= 10 else history[:-5]
        
        # Compare latency trends
        recent_latency = [s.latency_ms for s in recent_5 if s.latency_ms]
        previous_latency = [s.latency_ms for s in previous_5 if s.latency_ms]
        
        if recent_latency and previous_latency:
            recent_avg = statistics.mean(recent_latency)
            previous_avg = statistics.mean(previous_latency)
            
            if recent_avg < previous_avg * 0.9:
                return "improving"
            elif recent_avg > previous_avg * 1.1:
                return "declining"
            else:
                return "stable"
        
        # Compare sync gap trends
        recent_sync = [s.sync_gap for s in recent_5 if s.sync_gap is not None]
        previous_sync = [s.sync_gap for s in previous_5 if s.sync_gap is not None]
        
        if recent_sync and previous_sync:
            if statistics.mean(recent_sync) < statistics.mean(previous_sync):
                return "improving"
            elif statistics.mean(recent_sync) > statistics.mean(previous_sync):
                return "declining"
        
        return "stable"

    def _validate_tx_anchor(self, anchor: str) -> bool:
        """Validate transaction anchor format"""
        if not anchor or len(anchor) < 32:
            return False
        
        # Basic validation - should be base64url encoded
        try:
            import base64
            # Remove padding for base64url
            anchor_padded = anchor + '=' * (4 - len(anchor) % 4)
            base64.urlsafe_b64decode(anchor_padded)
            return True
        except Exception:
            return False

    def _calculate_anchor_freshness(self, anchor: str) -> Optional[int]:
        """Calculate how fresh the transaction anchor is (simplified)"""
        # This is a simplified implementation
        # In reality, you'd need to decode the anchor and check timestamp
        # For now, return a mock freshness value
        return 300  # 5 minutes

    def _extract_node_id(self, info_response: Dict) -> Optional[str]:
        """Extract node ID from info response"""
        # Try different possible fields
        for field in ['node_id', 'id', 'peer_id', 'address']:
            if field in info_response:
                return str(info_response[field])
        
        # Generate pseudo-ID from available data
        if 'version' in info_response and 'network' in info_response:
            import hashlib
            data = f"{info_response['version']}{info_response['network']}"
            return hashlib.sha256(data.encode()).hexdigest()[:16]
        
        return None

    def _calculate_storage_utilization(self, info_response: Dict) -> Optional[float]:
        """Calculate storage utilization from info response"""
        weave_size = info_response.get('weave_size')
        if weave_size:
            # This is simplified - would need actual disk capacity info
            # For now, return a normalized value
            return min(1.0, weave_size / (1024 ** 4))  # Normalize to TB
        return None

    def get_trust_scoring_data(self, result: ArweaveScanResult) -> Dict[str, Any]:
        """Extract all data needed for external trust scoring"""
        return {
            # Core health metrics
            'healthy': result.healthy,
            'uptime_score': result.uptime_score,
            'latency_ms': result.latency_ms,
            'latency_variance': result.latency_variance,
            
            # Network connectivity
            'peer_count': result.peer_count,
            'peer_diversity_score': result.peer_diversity_score,
            'peer_connection_stability': result.peer_connection_stability,
            
            # Synchronization
            'sync_gap': result.sync_gap,
            'block_height': result.block_height,
            'network_height': result.network_height,
            
            # Security posture
            'open_ports': result.open_ports,
            'exposed_services': result.exposed_services,
            'admin_interfaces_exposed': result.admin_interfaces_exposed,
            'tls_grade': result.tls_grade,
            'security_headers_score': result.security_headers_score,
            'config_security_score': result.config_security_score,
            
            # Operational metrics
            'mining_efficiency': result.mining_efficiency,
            'tx_throughput': result.tx_throughput,
            'storage_utilization': result.storage_utilization,
            'memory_usage': result.memory_usage,
            'cpu_usage': result.cpu_usage,
            
            # Reputation and compliance
            'reputation_flags': result.reputation_flags,
            'malicious_ip': result.malicious_ip,
            'known_vulnerabilities': result.known_vulnerabilities,
            'blacklist_matches': result.blacklist_matches,
            'compliance_flags': result.compliance_flags,
            
            # Configuration issues
            'misconfigs': result.misconfigs,
            'anomaly_score': result.anomaly_score,
            'performance_trend': result.performance_trend,
            
            # Scan metadata
            'scan_level': result.scan_level.value,
            'scan_success_rate': result.scan_success_rate,
            'scan_duration_ms': result.scan_duration_ms,
            'version': result.version,
            'node_id': result.node_id
        }

    def export_results(self, results: List[ArweaveScanResult], format: str = 'json') -> str:
        """Export comprehensive scan results in various formats"""
        if format == 'json':
            return json.dumps([asdict(r) for r in results], default=str)
        
        elif format == 'trust_scoring':
            # Export format optimized for trust scoring engines
            trust_data = []
            for result in results:
                trust_data.append({
                    'node_address': f"{result.ip}:{result.port}",
                    'timestamp': result.timestamp.isoformat(),
                    'trust_inputs': self.get_trust_scoring_data(result)
                })
            return json.dumps(trust_data, default=str)
        
        elif format == 'compliance_report':
            # Generate compliance-focused report
            compliance_summary = {
                'scan_summary': {
                    'total_nodes': len(results),
                    'healthy_nodes': sum(1 for r in results if r.healthy),
                    'nodes_with_issues': sum(1 for r in results if r.compliance_flags),
                    'scan_timestamp': datetime.utcnow().isoformat()
                },
                'compliance_violations': {},
                'security_findings': {},
                'recommendations': []
            }
            
            # Aggregate compliance violations
            all_flags = {}
            all_misconfigs = {}
            
            for result in results:
                for flag in result.compliance_flags:
                    all_flags[flag] = all_flags.get(flag, 0) + 1
                for config in result.misconfigs:
                    all_misconfigs[config] = all_misconfigs.get(config, 0) + 1
            
            compliance_summary['compliance_violations'] = all_flags
            compliance_summary['security_findings'] = all_misconfigs
            
            return json.dumps(compliance_summary, default=str)
        
        elif format == 'csv':
            # CSV export for spreadsheet analysis
            csv_lines = []
            headers = [
                'ip', 'port', 'healthy', 'version', 'peer_count', 'sync_gap',
                'latency_ms', 'tls_grade', 'exposed_services_count', 
                'compliance_flags_count', 'misconfigs_count', 'uptime_score'
            ]
            csv_lines.append(','.join(headers))
            
            for result in results:
                row = [
                    result.ip,
                    str(result.port),
                    str(result.healthy),
                    result.version or '',
                    str(result.peer_count),
                    str(result.sync_gap or ''),
                    str(result.latency_ms or ''),
                    result.tls_grade or '',
                    str(len(result.exposed_services)),
                    str(len(result.compliance_flags)),
                    str(len(result.misconfigs)),
                    str(result.uptime_score or '')
                ]
                csv_lines.append(','.join(row))
            
            return '\n'.join(csv_lines)
        
        return ""

# Supporting classes for external integrations
class ReputationClient:
    """Client for threat intelligence and reputation services"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.api_keys = self.config.get('api_keys', {})
        self.enabled_services = self.config.get('enabled_services', [])
    
    async def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation across multiple services"""
        reputation_data = {
            'malicious': False,
            'reputation_score': 0.8,
            'sources': []
        }
        
        # Integration points for real services:
        # - VirusTotal API
        # - AbuseIPDB
        # - Shodan
        # - Custom threat feeds
        
        return reputation_data
    
    async def check_blacklists(self, ip: str) -> Dict[str, Any]:
        """Check against various IP blacklists"""
        return {
            'matches': [],
            'total_lists_checked': 0
        }
    
    async def check_node_reputation(self, node_id: str) -> Dict[str, Any]:
        """Check node-specific reputation"""
        return {
            'flags': [],
            'reputation_score': 0.7
        }
    
    async def check_version_vulnerabilities(self, version: str) -> Dict[str, Any]:
        """Check version against CVE databases"""
        return {
            'critical_vulnerabilities': [],
            'high_vulnerabilities': [],
            'medium_vulnerabilities': []
        }

class BehaviorAnalyzer:
    """Advanced behavioral pattern analysis"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.anomaly_threshold = self.config.get('anomaly_threshold', 0.7)
    
    def detect_anomalies(self, history: List[ArweaveScanResult], 
                        current: ArweaveScanResult) -> Optional[float]:
        """Detect behavioral anomalies using statistical analysis"""
        if len(history) < 10:
            return None
        
        # Calculate baseline metrics
        baseline_latencies = [h.latency_ms for h in history[-20:] if h.latency_ms]
        baseline_peer_counts = [h.peer_count for h in history[-20:]]
        
        if not baseline_latencies or not baseline_peer_counts:
            return None
        
        # Calculate z-scores for current metrics
        anomaly_score = 0.0
        
        # Latency anomaly
        if current.latency_ms:
            latency_mean = statistics.mean(baseline_latencies)
            latency_std = statistics.stdev(baseline_latencies) if len(baseline_latencies) > 1 else 1
            if latency_std > 0:
                latency_zscore = abs(current.latency_ms - latency_mean) / latency_std
                anomaly_score += min(1.0, latency_zscore / 3.0) * 0.4
        
        # Peer count anomaly
        peer_mean = statistics.mean(baseline_peer_counts)
        peer_std = statistics.stdev(baseline_peer_counts) if len(baseline_peer_counts) > 1 else 1
        if peer_std > 0:
            peer_zscore = abs(current.peer_count - peer_mean) / peer_std
            anomaly_score += min(1.0, peer_zscore / 3.0) * 0.3
        
        # Sync gap anomaly
        baseline_sync_gaps = [h.sync_gap for h in history[-20:] if h.sync_gap is not None]
        if baseline_sync_gaps and current.sync_gap is not None:
            sync_mean = np.mean(baseline_sync_gaps)
            sync_std = np.std(baseline_sync_gaps)
            if sync_std > 0:
                sync_zscore = abs(current.sync_gap - sync_mean) / sync_std
                anomaly_score += min(1.0, sync_zscore / 3.0) * 0.3
        
        return min(1.0, anomaly_score)
    
    def analyze_tx_patterns(self, metrics: Dict) -> Dict[str, Any]:
        """Analyze transaction patterns for suspicious behavior"""
        # This would implement more sophisticated transaction analysis
        return {
            'suspicious': False,
            'pattern_type': 'normal',
            'confidence': 0.8
        }