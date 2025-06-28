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
from datetime import datetime, timedelta

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
class SuiScanResult:
    """Comprehensive Sui scan result with all trust scoring inputs"""
    ip: str
    port: int
    timestamp: datetime
    scan_level: ScanLevel
    
    # Basic node info
    version: Optional[str] = None
    network: Optional[str] = None
    healthy: bool = False
    node_id: Optional[str] = None
    sui_version: Optional[str] = None
    
    # Sui-specific blockchain metrics
    epoch: Optional[int] = None
    checkpoint_height: Optional[int] = None
    network_checkpoint: Optional[int] = None
    checkpoint_lag: Optional[int] = None
    transactions_per_checkpoint: Optional[float] = None
    
    # Validator and consensus metrics  
    validator_count: int = 0
    total_stake: Optional[float] = None
    validator_apy_avg: Optional[float] = None
    validator_apy_variance: Optional[float] = None
    voting_power_distribution: Optional[float] = None  # Gini coefficient
    validator_consistency_score: Optional[float] = None
    
    # Narwhal/Bullshark consensus metrics
    narwhal_round: Optional[int] = None
    bullshark_dag_size: Optional[int] = None
    consensus_latency_ms: Optional[float] = None
    mempool_size: Optional[int] = None
    certificate_throughput: Optional[float] = None
    
    # Network and performance metrics
    peer_count: int = 0
    latency_ms: Optional[float] = None
    latency_variance: Optional[float] = None
    response_time_p95: Optional[float] = None
    rpc_success_rate: Optional[float] = None
    
    # Security indicators
    open_ports: List[int] = None
    tls_grade: Optional[str] = None
    exposed_services: List[str] = None
    admin_interfaces_exposed: bool = False
    metrics_publicly_exposed: bool = False
    rpc_auth_enabled: bool = True
    
    # Operational metrics
    uptime_score: Optional[float] = None
    sync_health_score: Optional[float] = None
    transaction_processing_rate: Optional[float] = None
    gas_price_stability: Optional[float] = None
    storage_utilization: Optional[float] = None
    
    # Behavioral analysis
    validator_behavior_score: Optional[float] = None
    checkpoint_timing_consistency: Optional[float] = None
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
    validator_config_issues: List[str] = None
    
    # Raw data for external trust scoring
    metrics: Dict = None
    headers: Dict = None
    endpoints_status: Dict = None
    validator_list: List = None
    system_state: Dict = None
    
    # Sui-specific anomalies and consistency checks
    consensus_anomalies: List[str] = None
    validator_inconsistencies: List[str] = None
    checkpoint_anomalies: List[str] = None
    
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
        if self.validator_list is None:
            self.validator_list = []
        if self.system_state is None:
            self.system_state = {}
        if self.consensus_anomalies is None:
            self.consensus_anomalies = []
        if self.validator_inconsistencies is None:
            self.validator_inconsistencies = []
        if self.checkpoint_anomalies is None:
            self.checkpoint_anomalies = []
        if self.validator_config_issues is None:
            self.validator_config_issues = []

class BaseScanner:
    """Base scanner class for all protocol scanners"""
    def __init__(self, config=None):
        self.config = config or {}

class EnhancedSuiScanner(ProtocolScanner):
    """
    Production-grade Sui scanner focused on comprehensive data collection
    for external trust scoring systems, with deep Sui protocol understanding.
    """
    
    @property
    def protocol_name(self) -> str:
        """Return the protocol name."""
        return "sui"
    
    def get_supported_levels(self) -> List[int]:
        """Return supported scan levels."""
        return [1, 2, 3]
    
    def describe_levels(self) -> Dict[int, str]:
        """Return description of what each scan level does."""
        return {
            1: "Basic Sui node health check, version, and epoch status",
            2: "Extended metrics, validator analysis, and consensus monitoring",
            3: "Comprehensive security analysis, behavioral patterns, and threat intelligence"
        }
    
    def __init__(self, config=None, scan_level: ScanLevel = ScanLevel.LITE, 
                 enable_reputation=True, enable_behavioral=True):
        super().__init__(config)
        
        # Configuration
        self.scan_level = scan_level
        self.timeout = config.get('timeout', 5) if config else 5  # Reduced from 15 to 5 seconds
        self.max_retries = config.get('max_retries', 2) if config else 2  # Reduced from 3 to 2 retries
        self.rate_limit_delay = config.get('rate_limit_delay', 1.0) if config else 1.0
        
        # External services (optional - can be None)
        self.reputation_client = ReputationClient() if enable_reputation else None
        self.behavioral_analyzer = BehaviorAnalyzer() if enable_behavioral else None
        
        # Caching and state management
        self.node_cache = {}
        self.scan_history = {}
        self.network_baseline = {}
        self.validator_registry = {}  # Track validator consistency across scans
        
        self.logger = logging.getLogger(__name__)
        
        # Sui-specific configuration
        self.default_ports = [9000, 9184, 443, 80]
        self.critical_endpoints = ['/v1/system_state', '/v1/checkpoints', '/v1/validators']
        self.metrics_endpoints = ['/metrics']
        self.rpc_endpoints = ['/v1/transactions', '/v1/objects', '/v1/events']
        
        # Sui protocol knowledge
        self.sui_metrics_patterns = [
            'sui_', 'narwhal_', 'bullshark_', 'checkpoint_', 
            'validator_', 'transactions_', 'consensus_'
        ]
        
        # Vulnerability and configuration databases
        self.known_vulnerabilities = self._load_sui_vulnerability_db()
        self.security_baselines = self._load_sui_security_baselines()

    async def scan_protocol(self, target: str, scan_level: int, **kwargs) -> Dict[str, Any]:
        """Perform Sui protocol-specific scan.
        
        Args:
            target: Target IP address or hostname to scan
            scan_level: Scan intensity level (1-3)
            **kwargs: Additional scan parameters
            
        Returns:
            Dictionary containing scan results
        """
        # Extract ports and hostname from kwargs or use defaults
        ports = kwargs.get('ports', self.default_ports)
        hostname = kwargs.get('hostname', None)
        
        # Convert scan_level to ScanLevel enum
        scan_level_enum = ScanLevel.LITE
        if scan_level == 2:
            scan_level_enum = ScanLevel.MEDIUM
        elif scan_level == 3:
            scan_level_enum = ScanLevel.FEROCIOUS
        
        # Temporarily update scan level
        original_scan_level = self.scan_level
        self.scan_level = scan_level_enum
        
        try:
            # Perform the scan using the existing scan method
            results = await self.scan(target, hostname, ports)
            
            # Convert results to dictionary format expected by the framework
            return {
                'target': target,
                'scan_level': scan_level,
                'protocol': self.protocol_name,
                'timestamp': datetime.utcnow().isoformat(),
                'results': [asdict(result) for result in results],
                'summary': {
                    'total_ports_scanned': len(ports),
                    'successful_scans': len(results),
                    'healthy_nodes': sum(1 for r in results if r.healthy),
                    'scan_success_rate': len(results) / len(ports) if ports else 0
                }
            }
        finally:
            # Restore original scan level
            self.scan_level = original_scan_level

    async def scan(self, ip: str, hostname: Optional[str] = None, ports: List[int] = None, **kwargs) -> List[SuiScanResult]:
        """Enhanced Sui scan with comprehensive protocol analysis
        
        Args:
            ip: Target IP address
            hostname: Optional hostname for SNI/virtual host support
            ports: List of ports to scan (defaults to Sui ports)
            **kwargs: Additional scan parameters
        """
        if ports is None:
            ports = self.default_ports
            
        self.logger.info(f"🔍 Starting Sui enhanced scan on {ip}" + (f" (hostname: {hostname})" if hostname else ""))
        self.logger.info(f"📊 Scan configuration: level={self.scan_level.name}, ports={ports}, timeout={self.timeout}s")
        
        # Add overall timeout to prevent hanging (5 minutes max)
        try:
            return await asyncio.wait_for(self._perform_scan(ip, hostname, ports), timeout=300)
        except asyncio.TimeoutError:
            self.logger.warning(f"⏰ Sui scan timeout after 5 minutes for {ip}")
            return []

    async def _perform_scan(self, ip: str, hostname: Optional[str] = None, ports: List[int] = None) -> List[SuiScanResult]:
        """Internal scan method with timeout protection"""
        
        # Rate limiting
        if self.rate_limit_delay > 0:
            self.logger.debug(f"⏱️  Rate limiting: waiting {self.rate_limit_delay}s before scan")
            await asyncio.sleep(self.rate_limit_delay)
        
        scan_start = time.time()
        results = []
        
        self.logger.info(f"🚀 Beginning port scanning on {len(ports)} Sui ports")
        for i, port in enumerate(ports, 1):
            self.logger.info(f"📡 Scanning port {port} ({i}/{len(ports)})")
            result = await self._scan_port(ip, port, hostname)
            if result:
                self.logger.info(f"✅ Port {port}: Sui node detected (healthy: {result.healthy})")
                results.append(result)
            else:
                self.logger.debug(f"❌ Port {port}: No Sui node detected")
        
        if results:
            self.logger.info(f"🎯 Found {len(results)} active Sui node(s)")
            # Update network baseline for comparative analysis
            self.logger.debug("📈 Updating Sui network baseline with scan results")
            self._update_sui_network_baseline(results)
        else:
            self.logger.warning(f"⚠️  No Sui nodes detected on {ip}")
        
        # Calculate scan metadata
        scan_duration = (time.time() - scan_start) * 1000
        for result in results:
            result.scan_duration_ms = scan_duration
        
        self.logger.info(f"⏱️  Sui scan completed in {scan_duration:.2f}ms")
        
        return results

    async def _scan_port(self, ip: str, port: int, hostname: Optional[str] = None) -> Optional[SuiScanResult]:
        """Comprehensive Sui port scanning with protocol-specific analysis"""
        # Use hostname for URL if provided (for SNI/virtual host support)
        host_for_url = hostname if hostname else ip
        base_url = f"http://{host_for_url}:{port}"
        
        self.logger.debug(f"🔍 Analyzing port {port} on {ip}" + (f" via hostname {hostname}" if hostname else ""))
        self.logger.debug(f"🌐 Base URL: {base_url}")
        
        # Initialize result with comprehensive structure
        result = SuiScanResult(
            ip=ip,
            port=port,
            timestamp=datetime.utcnow(),
            scan_level=self.scan_level
        )
        
        # Check cache first
        cache_key = f"{ip}:{port}"
        if self._should_use_cache(cache_key):
            cached = self.node_cache[cache_key]
            self.logger.debug(f"💾 Using cached result for {cache_key}")
            return cached
        
        successful_requests = 0
        total_requests = 0
        
        try:
            self.logger.debug(f"🚀 Starting multi-level Sui scan on port {port}")
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                limits=httpx.Limits(max_connections=10)
            ) as client:
                
                # Level 1: Basic Sui node health and blockchain state
                self.logger.debug(f"🟢 Level 1: Basic Sui node health check")
                success = await self._scan_sui_basic(client, base_url, result)
                total_requests += 5
                successful_requests += success
                self.logger.debug(f"📊 Level 1 completed: {success}/5 requests successful")
                
                if self.scan_level.value >= 2:
                    self.logger.debug(f"🟡 Level 2: Medium scan - enhanced metrics and consensus data")
                    success = await self._scan_sui_medium(client, base_url, result)
                    total_requests += 8
                    successful_requests += success
                    self.logger.debug(f"📊 Level 2 completed: {success}/8 requests successful")
                
                if self.scan_level.value >= 3:
                    self.logger.debug(f"🔴 Level 3: Ferocious scan - deep security analysis")
                    success = await self._scan_sui_ferocious(client, base_url, result, hostname)
                    total_requests += 12
                    successful_requests += success
                    self.logger.debug(f"📊 Level 3 completed: {success}/12 requests successful")
                
                # Enhanced Sui-specific analysis phases
                self.logger.debug(f"🧠 Starting advanced Sui analysis phases")
                
                self.logger.debug(f"🔄 Analyzing consensus health")
                await self._analyze_sui_consensus_health(result)
                
                self.logger.debug(f"👥 Analyzing validator ecosystem")
                await self._analyze_validator_ecosystem(result)
                
                self.logger.debug(f"📋 Analyzing checkpoint consistency")
                await self._analyze_checkpoint_consistency(result)
                
                self.logger.debug(f"🛡️  Analyzing security posture")
                await self._analyze_security_posture(result)
                
                self.logger.debug(f"🎭 Analyzing behavioral patterns")
                await self._analyze_behavioral_patterns(result)
                
                self.logger.debug(f"🕵️  Checking reputation intelligence")
                await self._check_reputation_intelligence(result)
                
                self.logger.debug(f"📜 Assessing Sui compliance")
                await self._assess_sui_compliance(result)
                
        except Exception as e:
            self.logger.warning(f"❌ Sui scan failed for {ip}:{port} - {e}")
            result.misconfigs.append(f"scan_error: {str(e)}")
        
        # Calculate scan success rate
        result.scan_success_rate = successful_requests / total_requests if total_requests > 0 else 0.0
        success_rate_pct = result.scan_success_rate * 100
        self.logger.debug(f"📈 Scan success rate: {success_rate_pct:.1f}% ({successful_requests}/{total_requests})")
        
        # Determine if node is healthy based on success rate and basic checks
        result.healthy = result.scan_success_rate >= 0.3 and successful_requests > 0
        health_status = "🟢 HEALTHY" if result.healthy else "🔴 UNHEALTHY"
        self.logger.debug(f"💚 Node health assessment: {health_status}")
        
        # Cache result and update history
        self.logger.debug(f"💾 Caching result for {cache_key}")
        self.node_cache[cache_key] = result
        self._update_scan_history(ip, port, result)
        
        return result

    async def _scan_sui_basic(self, client: httpx.AsyncClient, base_url: str, result: SuiScanResult) -> int:
        """Level 1: Core Sui blockchain state and health indicators"""
        successful_requests = 0
        
        try:
            # System state - core Sui blockchain info
            self.logger.debug(f"📊 Fetching Sui system state from {base_url}/v1/system_state")
            system_state = await self._robust_fetch(client, f"{base_url}/v1/system_state")
            result.endpoints_status['/v1/system_state'] = system_state is not None
            
            if system_state:
                successful_requests += 1
                result.system_state = system_state
                result.healthy = True
                
                # Extract core blockchain metrics
                result.epoch = system_state.get("epoch")
                result.sui_version = system_state.get("systemStateVersion")
                result.validator_count = len(system_state.get("activeValidators", []))
                
                self.logger.debug(f"🏗️  System state: epoch={result.epoch}, version={result.sui_version}, validators={result.validator_count}")
                
                # Calculate total stake from system state
                validators = system_state.get("activeValidators", [])
                if validators:
                    stakes = [float(v.get("stakingPoolSuiBalance", 0)) for v in validators]
                    result.total_stake = sum(stakes)
                    
                    # Voting power distribution analysis (Gini coefficient)
                    result.voting_power_distribution = self._calculate_gini_coefficient(stakes)
                    
                    self.logger.debug(f"💰 Total stake: {result.total_stake:.2e} SUI, Gini coefficient: {result.voting_power_distribution:.3f}")
                    
                    if result.voting_power_distribution > 0.8:
                        result.misconfigs.append("high_centralization_gini")
                        result.compliance_flags.append("centralization_risk")
                        self.logger.warning(f"⚠️  High centralization detected (Gini: {result.voting_power_distribution:.3f})")
            else:
                self.logger.warning(f"❌ Failed to fetch system state from {base_url}")
            
            # Checkpoint state - sync and consensus health
            self.logger.debug(f"🔍 Fetching checkpoint data from {base_url}/v1/checkpoints")
            checkpoints = await self._robust_fetch(client, f"{base_url}/v1/checkpoints")
            result.endpoints_status['/v1/checkpoints'] = checkpoints is not None
            
            if checkpoints:
                successful_requests += 1
                
                # Extract checkpoint height and calculate lag
                if "data" in checkpoints and checkpoints["data"]:
                    latest_checkpoint = checkpoints["data"][0]
                    result.checkpoint_height = int(latest_checkpoint.get("sequenceNumber", 0))
                    self.logger.debug(f"📋 Latest checkpoint: {result.checkpoint_height}")
                    
                    # Calculate transaction density per checkpoint
                    tx_count = len(latest_checkpoint.get("transactions", []))
                    result.transactions_per_checkpoint = float(tx_count)
                    
                    if result.transactions_per_checkpoint == 0:
                        result.misconfigs.append("empty_checkpoints")
                        result.compliance_flags.append("low_throughput")
                else:
                    self.logger.warning(f"❌ Checkpoint data format unexpected")
            else:
                self.logger.warning(f"❌ Failed to fetch checkpoint data")
            
            # Basic validator endpoint check
            validators_response = await self._robust_fetch(client, f"{base_url}/v1/validators")
            result.endpoints_status['/v1/validators'] = validators_response is not None
            
            if validators_response:
                successful_requests += 1
                result.validator_list = validators_response.get("result", [])
                
                # Validate minimum validator count
                if len(result.validator_list) < 5:
                    result.misconfigs.append("insufficient_validators")
                    result.compliance_flags.append("network_security_risk")
            
            # RPC endpoint availability check
            rpc_test = await self._robust_fetch(client, f"{base_url}/v1/transactions")
            result.endpoints_status['/v1/transactions'] = rpc_test is not None
            if rpc_test:
                successful_requests += 1
            
            # Version extraction from headers or system state
            if result.sui_version:
                result.version = result.sui_version
                result.known_vulnerabilities = self._check_sui_version_vulnerabilities(result.version)
                
        except Exception as e:
            self.logger.debug(f"Sui basic scan error: {e}")
        
        return successful_requests

    async def _scan_sui_medium(self, client: httpx.AsyncClient, base_url: str, result: SuiScanResult) -> int:
        """Level 2: Metrics analysis, validator deep-dive, and consensus monitoring"""
        successful_requests = 0
        
        try:
            # Comprehensive metrics parsing
            metrics_response = await client.get(f"{base_url}/metrics")
            result.endpoints_status['/metrics'] = metrics_response.status_code == 200
            
            if metrics_response.status_code == 200:
                successful_requests += 1
                result.metrics.update(self._parse_sui_metrics(metrics_response.text))
                
                # Check if metrics are publicly exposed (security concern)
                if not self._requires_authentication(metrics_response):
                    result.metrics_publicly_exposed = True
                    result.misconfigs.append("public_metrics_exposure")
                    result.compliance_flags.append("information_disclosure")
                
                # Extract consensus-specific metrics
                result.narwhal_round = result.metrics.get('narwhal_current_round')
                result.bullshark_dag_size = result.metrics.get('bullshark_dag_vertices')
                result.consensus_latency_ms = result.metrics.get('consensus_commit_latency_ms')
                result.mempool_size = result.metrics.get('narwhal_mempool_size')
                result.certificate_throughput = result.metrics.get('narwhal_certificate_rate')
                
                # Network checkpoint comparison
                metrics_checkpoint = result.metrics.get('sui_checkpoint_height')
                if metrics_checkpoint and result.checkpoint_height:
                    result.checkpoint_lag = abs(int(metrics_checkpoint - result.checkpoint_height))
                    
                    if result.checkpoint_lag > 10:
                        result.misconfigs.append("checkpoint_inconsistency")
                        result.checkpoint_anomalies.append("metrics_api_mismatch")
                
                # Transaction processing analysis
                tx_rate = result.metrics.get('sui_transaction_rate')
                if tx_rate:
                    result.transaction_processing_rate = float(tx_rate)
                    
                    # Flag suspiciously low transaction rates
                    if result.transaction_processing_rate < 0.1:  # Less than 0.1 TPS
                        result.misconfigs.append("low_transaction_rate")
                        result.compliance_flags.append("poor_performance")
            
            # Enhanced validator analysis with consistency checking
            if result.validator_list:
                successful_requests += 1
                validator_analysis = self._analyze_validator_consistency(result.validator_list, result.system_state)
                result.validator_inconsistencies.extend(validator_analysis['inconsistencies'])
                result.validator_consistency_score = validator_analysis['consistency_score']
                
                # APY analysis
                apys = []
                for validator in result.validator_list:
                    apy = validator.get('apy', 0)
                    if apy and apy > 0:
                        apys.append(float(apy))
                    elif validator.get('stakingPoolSuiBalance', 0) > 0:
                        # Flag validators with stake but no APY
                        result.validator_config_issues.append(f"validator_{validator.get('name', 'unknown')}_missing_apy")
                
                if apys:
                    result.validator_apy_avg = statistics.mean(apys)
                    result.validator_apy_variance = statistics.variance(apys) if len(apys) > 1 else 0
                    
                    # Flag suspicious APY patterns
                    if result.validator_apy_variance > 100:  # High variance
                        result.misconfigs.append("high_apy_variance")
                    if result.validator_apy_avg > 50:  # Unrealistically high average
                        result.misconfigs.append("suspicious_high_apy")
                        result.compliance_flags.append("economic_anomaly")
            
            # Gas price stability analysis
            gas_price = result.metrics.get('sui_gas_price')
            if gas_price:
                historical_gas = self._get_historical_gas_prices(result.ip, result.port)
                if historical_gas:
                    result.gas_price_stability = self._calculate_price_stability(historical_gas, gas_price)
                    
                    if result.gas_price_stability < 0.8:  # High volatility
                        result.misconfigs.append("unstable_gas_prices")
            
            # Peer connectivity analysis
            peer_count = result.metrics.get('sui_network_peers')
            if peer_count:
                result.peer_count = int(peer_count)
                
                if result.peer_count < 10:
                    result.misconfigs.append("low_peer_connectivity")
                    result.compliance_flags.append("network_isolation_risk")
                elif result.peer_count > 1000:
                    result.misconfigs.append("excessive_peer_connections")
            
            # Storage utilization monitoring
            storage_used = result.metrics.get('sui_storage_bytes_used')
            storage_total = result.metrics.get('sui_storage_bytes_total')
            if storage_used and storage_total:
                result.storage_utilization = storage_used / storage_total
                
                if result.storage_utilization > 0.9:
                    result.misconfigs.append("high_storage_utilization")
                    result.compliance_flags.append("capacity_risk")
                    
        except Exception as e:
            self.logger.debug(f"Sui medium scan error: {e}")
        
        return successful_requests

    async def _scan_sui_ferocious(self, client: httpx.AsyncClient, base_url: str, result: SuiScanResult, hostname: Optional[str] = None) -> int:
        """Level 3: Deep behavioral analysis, security probing, and anomaly detection"""
        successful_requests = 0
        
        try:
            # Multi-sample latency measurement for RPC performance
            latencies = []
            rpc_successes = 0
            rpc_attempts = 5
            
            for i in range(rpc_attempts):
                start = time.time()
                try:
                    response = await client.get(f"{base_url}/v1/system_state")
                    if response.status_code == 200:
                        latencies.append((time.time() - start) * 1000)
                        rpc_successes += 1
                        successful_requests += 0.2
                except:
                    pass
                await asyncio.sleep(0.1)
            
            if latencies:
                result.latency_ms = statistics.mean(latencies)
                result.latency_variance = statistics.variance(latencies) if len(latencies) > 1 else 0
                result.response_time_p95 = self._calculate_percentile(latencies, 95)
                result.rpc_success_rate = rpc_successes / rpc_attempts
                
                # Performance analysis
                if result.latency_variance > 500:  # High variance
                    result.misconfigs.append("unstable_rpc_latency")
                    result.compliance_flags.append("service_instability")
                
                if result.rpc_success_rate < 0.9:
                    result.misconfigs.append("poor_rpc_reliability")
                    result.compliance_flags.append("availability_issue")
            
            # Comprehensive header analysis
            headers_response = await client.get(f"{base_url}/v1/checkpoints")
            if headers_response.status_code == 200:
                successful_requests += 1
                result.headers = dict(headers_response.headers)
                
                # Sui-specific header analysis
                sui_headers = [k.lower() for k in result.headers.keys() 
                              if any(pattern in k.lower() for pattern in ['sui', 'narwhal', 'mysten'])]
                
                # Security headers analysis
                security_issues = self._analyze_security_headers(result.headers)
                result.misconfigs.extend(security_issues)
            
            # Malformed request testing for error handling
            malformed_tx = await client.post(
                f"{base_url}/v1/transactions", 
                json={"invalid": "transaction", "malformed": True}
            )
            
            if malformed_tx.status_code not in [400, 422, 500]:
                result.consensus_anomalies.append("unexpected_error_handling")
                result.compliance_flags.append("input_validation_weakness")
            else:
                successful_requests += 1
            
            # Advanced port scanning for Sui-specific services
            result.open_ports = await self._scan_sui_port_range(result.ip)
            
            # Identify exposed services
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
            if 443 in result.open_ports or 9184 in result.open_ports:
                tls_port = 443 if 443 in result.open_ports else 9184
                tls_analysis = await self._analyze_tls_config(result.ip, tls_port, hostname)
                result.tls_grade = tls_analysis.get('grade')
                
                if result.tls_grade in ['C', 'D', 'F']:
                    result.misconfigs.append(f"weak_tls_{result.tls_grade}")
                    result.compliance_flags.append("encryption_weakness")
            
            # RPC authentication testing
            auth_test = await self._test_rpc_authentication(client, base_url)
            result.rpc_auth_enabled = auth_test['auth_required']
            if not result.rpc_auth_enabled:
                result.misconfigs.append("rpc_no_authentication")
                result.compliance_flags.append("access_control_weakness")
            
            # Consensus timing analysis
            if result.narwhal_round and len(self.scan_history.get(f"{result.ip}:{result.port}", [])) > 1:
                result.checkpoint_timing_consistency = self._analyze_checkpoint_timing(result)
                
                if result.checkpoint_timing_consistency < 0.8:
                    result.consensus_anomalies.append("irregular_checkpoint_timing")
                    
        except Exception as e:
            self.logger.debug(f"Sui ferocious scan error: {e}")
        
        return successful_requests

    async def _analyze_sui_consensus_health(self, result: SuiScanResult):
        """Analyze Narwhal/Bullshark consensus health"""
        
        # Consensus performance indicators
        if result.consensus_latency_ms:
            if result.consensus_latency_ms > 5000:  # 5 second consensus latency
                result.misconfigs.append("high_consensus_latency")
                result.compliance_flags.append("consensus_performance_issue")
        
        # DAG size analysis (Bullshark)
        if result.bullshark_dag_size:
            if result.bullshark_dag_size > 10000:  # Large DAG might indicate issues
                result.consensus_anomalies.append("large_bullshark_dag")
            elif result.bullshark_dag_size < 10:  # Too small might indicate stalling
                result.consensus_anomalies.append("small_bullshark_dag")
        
        # Mempool health
        if result.mempool_size:
            if result.mempool_size > 1000:  # Large mempool
                result.misconfigs.append("large_mempool_backlog")
                result.compliance_flags.append("transaction_processing_lag")
        
        # Certificate throughput analysis
        if result.certificate_throughput:
            if result.certificate_throughput < 1.0:  # Less than 1 cert/sec
                result.consensus_anomalies.append("low_certificate_throughput")

    async def _analyze_validator_ecosystem(self, result: SuiScanResult):
        """Comprehensive validator ecosystem analysis"""
        
        if not result.validator_list:
            return
        
        # Stake distribution analysis
        stakes = []
        names = []
        active_validators = 0
        
        for validator in result.validator_list:
            stake = float(validator.get('stakingPoolSuiBalance', 0))
            if stake > 0:
                stakes.append(stake)
                names.append(validator.get('name', 'unknown'))
                active_validators += 1
        
        if stakes:
            # Economic centralization metrics
            total_stake = sum(stakes)
            largest_stake = max(stakes)
            
            # Flag if single validator has >33% stake (Byzantine threshold)
            if largest_stake / total_stake > 0.33:
                result.misconfigs.append("byzantine_threshold_exceeded")
                result.compliance_flags.append("critical_centralization")
            
            # Flag if top 3 validators have >67% stake
            top_3_stake = sum(sorted(stakes, reverse=True)[:3])
            if top_3_stake / total_stake > 0.67:
                result.misconfigs.append("high_validator_centralization")
                result.compliance_flags.append("governance_risk")
        
        # Validator behavior scoring
        behavior_scores = []
        for validator in result.validator_list:
            score = self._calculate_validator_behavior_score(validator)
            behavior_scores.append(score)
            
            # Flag problematic validators
            if score < 0.5:
                result.validator_config_issues.append(
                    f"poor_behavior_{validator.get('name', 'unknown')}"
                )
        
        if behavior_scores:
            result.validator_behavior_score = statistics.mean(behavior_scores)

    async def _analyze_checkpoint_consistency(self, result: SuiScanResult):
        """Analyze checkpoint consistency and sequencing"""
        
        if result.checkpoint_height and result.network_checkpoint:
            lag = abs(result.checkpoint_height - result.network_checkpoint)
            result.checkpoint_lag = lag
            
            if lag > 50:
                result.checkpoint_anomalies.append("high_checkpoint_lag")
                result.compliance_flags.append("sync_performance_issue")
        
        # Analyze checkpoint timing from historical data
        history = self.scan_history.get(f"{result.ip}:{result.port}", [])
        if len(history) > 3:
            checkpoint_heights = [h.checkpoint_height for h in history[-5:] if h.checkpoint_height]
            if len(checkpoint_heights) > 2:
                # Calculate checkpoint progression rate
                progression_rates = []
                for i in range(1, len(checkpoint_heights)):
                    rate = checkpoint_heights[i] - checkpoint_heights[i-1]
                    progression_rates.append(rate)
                
                if progression_rates:
                    avg_rate = statistics.mean(progression_rates)
                    if avg_rate < 0.1:  # Very slow checkpoint progression
                        result.checkpoint_anomalies.append("slow_checkpoint_progression")
                    elif any(rate < 0 for rate in progression_rates):  # Backwards progression
                        result.checkpoint_anomalies.append("checkpoint_regression")

    async def _analyze_security_posture(self, result: SuiScanResult):
        """Sui-specific security posture analysis"""
        
        # Check for Sui-specific security misconfigurations
        if result.metrics_publicly_exposed:
            result.config_security_score = 0.7  # Reduced due to info exposure
        else:
            result.config_security_score = 1.0
        
        # RPC security analysis
        if not result.rpc_auth_enabled:
            result.config_security_score *= 0.6  # Major security issue
        
        # Port exposure analysis
        risky_ports = [22, 23, 3389, 5432, 3306]  # SSH, Telnet, RDP, PostgreSQL, MySQL
        exposed_risky = [p for p in result.open_ports if p in risky_ports]
        
        if exposed_risky:
            result.config_security_score *= (1.0 - len(exposed_risky) * 0.1)
            result.compliance_flags.append("risky_ports_exposed")

    async def _analyze_behavioral_patterns(self, result: SuiScanResult):
        """Advanced behavioral pattern analysis for Sui nodes"""
        if not self.behavioral_analyzer:
            return
        
        try:
            # Historical performance analysis
            history = self.scan_history.get(f"{result.ip}:{result.port}", [])
            if len(history) > 5:
                result.uptime_score = self._calculate_uptime_score(history)
                result.performance_trend = self._analyze_performance_trend(history)
                
                # Sui-specific anomaly detection
                result.anomaly_score = self.behavioral_analyzer.detect_sui_anomalies(
                    history, result
                )
                
                if result.anomaly_score and result.anomaly_score > 0.7:
                    result.compliance_flags.append("behavioral_anomaly")
            
            # Sync health scoring
            sync_factors = []
            if result.checkpoint_lag is not None:
                sync_factors.append(1.0 - min(1.0, result.checkpoint_lag / 100))
            if result.rpc_success_rate:
                sync_factors.append(result.rpc_success_rate)
            if result.consensus_latency_ms:
                sync_factors.append(1.0 - min(1.0, result.consensus_latency_ms / 10000))
            
            if sync_factors:
                result.sync_health_score = statistics.mean(sync_factors)
                
        except Exception as e:
            self.logger.debug(f"Behavioral analysis error: {e}")

    async def _check_reputation_intelligence(self, result: SuiScanResult):
        """Check against threat intelligence with Sui-specific considerations"""
        if not self.reputation_client:
            return
        
        try:
            # IP reputation check
            ip_reputation = await self.reputation_client.check_ip(result.ip)
            result.malicious_ip = ip_reputation.get('malicious', False)
            if result.malicious_ip:
                result.reputation_flags.append("malicious_ip")
                result.compliance_flags.append("security_threat")
            
            # Sui-specific node reputation
            if result.node_id:
                node_reputation = await self.reputation_client.check_sui_node(result.node_id)
                result.reputation_flags.extend(node_reputation.get('flags', []))
            
            # Validator reputation check
            for validator in result.validator_list:
                validator_name = validator.get('name', '')
                if validator_name:
                    val_rep = await self.reputation_client.check_validator_reputation(validator_name)
                    if val_rep.get('flagged', False):
                        result.reputation_flags.append(f"flagged_validator_{validator_name}")
            
            # Version vulnerability check
            if result.version:
                vuln_check = await self.reputation_client.check_sui_version_vulnerabilities(result.version)
                critical_vulns = vuln_check.get('critical_vulnerabilities', [])
                result.known_vulnerabilities.extend(critical_vulns)
                
                if critical_vulns:
                    result.compliance_flags.append("critical_vulnerabilities")
                    
        except Exception as e:
            self.logger.warning(f"Reputation check failed: {e}")

    async def _assess_sui_compliance(self, result: SuiScanResult):
        """Assess Sui-specific compliance indicators"""
        
        # Blockchain network compliance
        if result.validator_count < 10:
            result.compliance_flags.append("insufficient_decentralization")
        
        # Economic security compliance
        if result.voting_power_distribution and result.voting_power_distribution > 0.8:
            result.compliance_flags.append("economic_centralization_risk")
        
        # Performance compliance
        if result.transaction_processing_rate and result.transaction_processing_rate < 1.0:
            result.compliance_flags.append("performance_below_threshold")
        
        # Security compliance
        if result.admin_interfaces_exposed:
            result.compliance_flags.append("access_control_violation")
        
        if result.metrics_publicly_exposed:
            result.compliance_flags.append("information_disclosure_risk")
        
        # Operational compliance
        if result.uptime_score and result.uptime_score < 0.95:
            result.compliance_flags.append("availability_sla_risk")

    # Helper methods for Sui-specific analysis
    def _parse_sui_metrics(self, metrics_text: str) -> Dict[str, Any]:
        """Enhanced Sui metrics parsing"""
        metrics = {}
        
        for line in metrics_text.splitlines():
            if line.startswith('#') or not line.strip():
                continue
                
            try:
                if ' ' in line:
                    key, value = line.split(' ', 1)
                    
                    # Parse Sui-specific metrics
                    if any(pattern in key for pattern in self.sui_metrics_patterns):
                        try:
                            if '.' in value:
                                metrics[key] = float(value)
                            else:
                                metrics[key] = int(value)
                        except ValueError:
                            metrics[key] = value.strip('"')
            except Exception:
                continue
        
        return metrics

    def _calculate_gini_coefficient(self, values: List[float]) -> float:
        """Calculate Gini coefficient for stake distribution"""
        if not values or len(values) < 2:
            return 0.0
        
        sorted_values = sorted(values)
        n = len(sorted_values)
        
        # Calculate cumulative sum for Gini coefficient
        cumsum = []
        running_sum = 0
        for val in sorted_values:
            running_sum += val
            cumsum.append(running_sum)
        
        return (n + 1 - 2 * sum(cumsum) / cumsum[-1]) / n

    def _analyze_validator_consistency(self, validator_list: List[Dict], system_state: Dict) -> Dict[str, Any]:
        """Analyze consistency between validator API and system state"""
        inconsistencies = []
        consistency_score = 1.0
        
        # Compare validator counts
        api_count = len(validator_list)
        system_validators = system_state.get("activeValidators", [])
        system_count = len(system_validators)
        
        if api_count != system_count:
            inconsistencies.append(f"validator_count_mismatch_api_{api_count}_system_{system_count}")
            consistency_score *= 0.8
        
        # Compare individual validator data
        for api_validator in validator_list:
            api_name = api_validator.get("name", "")
            api_stake = float(api_validator.get("stakingPoolSuiBalance", 0))
            
            # Find matching validator in system state
            matching_system_validator = None
            for sys_validator in system_validators:
                if sys_validator.get("name", "") == api_name:
                    matching_system_validator = sys_validator
                    break
            
            if not matching_system_validator:
                inconsistencies.append(f"validator_missing_in_system_{api_name}")
                consistency_score *= 0.9
                continue
            
            sys_stake = float(matching_system_validator.get("stakingPoolSuiBalance", 0))
            
            # Check stake consistency (allow 1% variance)
            if abs(api_stake - sys_stake) / max(api_stake, sys_stake, 1) > 0.01:
                inconsistencies.append(f"stake_mismatch_{api_name}")
                consistency_score *= 0.95
        
        return {
            "inconsistencies": inconsistencies,
            "consistency_score": max(0.0, consistency_score)
        }

    def _calculate_validator_behavior_score(self, validator: Dict) -> float:
        """Calculate individual validator behavior score"""
        score = 1.0
        
        # APY reasonableness
        apy = float(validator.get("apy", 0))
        if apy < 0:
            score *= 0.5  # Negative APY is problematic
        elif apy > 100:
            score *= 0.7  # Unrealistically high APY
        
        # Stake amount
        stake = float(validator.get("stakingPoolSuiBalance", 0))
        if stake <= 0:
            score *= 0.3  # No stake is bad
        
        # Commission rate (if available)
        commission = float(validator.get("commissionRate", 0))
        if commission > 0.2:  # More than 20% commission
            score *= 0.8
        
        return score

    def _get_historical_gas_prices(self, ip: str, port: int) -> List[float]:
        """Get historical gas prices for stability analysis"""
        history = self.scan_history.get(f"{ip}:{port}", [])
        gas_prices = []
        
        for scan in history[-10:]:  # Last 10 scans
            if scan.metrics and 'sui_gas_price' in scan.metrics:
                gas_prices.append(float(scan.metrics['sui_gas_price']))
        
        return gas_prices

    def _calculate_price_stability(self, historical_prices: List[float], current_price: float) -> float:
        """Calculate gas price stability score"""
        if not historical_prices:
            return 0.5  # Unknown stability
        
        all_prices = historical_prices + [current_price]
        mean_price = statistics.mean(all_prices)
        std_price = statistics.stdev(all_prices) if len(all_prices) > 1 else 0
        
        if mean_price == 0:
            return 0.0
        
        # Coefficient of variation as stability metric
        cv = std_price / mean_price
        stability = max(0.0, 1.0 - cv)  # Lower CV = higher stability
        
        return stability

    def _analyze_checkpoint_timing(self, result: SuiScanResult) -> float:
        """Analyze checkpoint timing consistency"""
        history = self.scan_history.get(f"{result.ip}:{result.port}", [])
        
        if len(history) < 3:
            return 0.5  # Insufficient data
        
        # Get recent checkpoint data
        recent_scans = history[-5:]
        timestamps = []
        checkpoints = []
        
        for scan in recent_scans:
            if scan.checkpoint_height and scan.timestamp:
                timestamps.append(scan.timestamp)
                checkpoints.append(scan.checkpoint_height)
        
        if len(timestamps) < 3:
            return 0.5
        
        # Calculate checkpoint intervals
        intervals = []
        for i in range(1, len(timestamps)):
            time_diff = (timestamps[i] - timestamps[i-1]).total_seconds()
            checkpoint_diff = checkpoints[i] - checkpoints[i-1]
            
            if checkpoint_diff > 0:
                interval = time_diff / checkpoint_diff  # Seconds per checkpoint
                intervals.append(interval)
        
        if not intervals:
            return 0.0
        
        # Consistency based on variance in intervals
        mean_interval = statistics.mean(intervals)
        stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        
        if mean_interval == 0:
            return 0.0
        
        cv = stdev_interval / mean_interval
        consistency = max(0.0, 1.0 - cv)  # Lower CV = higher consistency
        
        return consistency

    async def _scan_sui_port_range(self, ip: str) -> List[int]:
        """Scan Sui-specific port ranges"""
        # Sui-specific ports and common admin ports
        ports_to_scan = [9000, 9184, 443, 80, 22, 8080, 9090, 3000, 8000, 9001]
        
        open_ports = []
        for port in ports_to_scan:
            try:
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

    async def _test_rpc_authentication(self, client: httpx.AsyncClient, base_url: str) -> Dict[str, Any]:
        """Test if RPC endpoints require authentication"""
        auth_test = {
            'auth_required': True,
            'endpoints_tested': []
        }
        
        # Test sensitive endpoints
        sensitive_endpoints = [
            '/v1/transactions',
            '/v1/objects',
            '/metrics'
        ]
        
        for endpoint in sensitive_endpoints:
            try:
                # Test without authentication
                response = await client.get(f"{base_url}{endpoint}")
                auth_test['endpoints_tested'].append({
                    'endpoint': endpoint,
                    'status_code': response.status_code,
                    'requires_auth': response.status_code in [401, 403]
                })
                
                # If any sensitive endpoint is accessible without auth
                if response.status_code == 200:
                    auth_test['auth_required'] = False
                    
            except Exception:
                continue
        
        return auth_test

    def _check_sui_version_vulnerabilities(self, version: str) -> List[str]:
        """Check Sui version against known vulnerabilities"""
        vulnerabilities = []
        
        # This would integrate with actual Sui vulnerability databases
        known_vulns = self.known_vulnerabilities.get('sui', {})
        
        for vuln_version, vuln_list in known_vulns.items():
            if version and vuln_version in version:
                vulnerabilities.extend(vuln_list)
        
        return vulnerabilities

    def _load_sui_vulnerability_db(self) -> Dict:
        """Load Sui-specific vulnerability database"""
        return {
            'sui': {
                '1.0.0': ['SUI-2023-001', 'SUI-2023-002'],
                '0.35': ['SUI-2023-003']
            }
        }

    def _load_sui_security_baselines(self) -> Dict:
        """Load Sui security baseline configurations"""
        return {
            'min_validators': 10,
            'max_gini_coefficient': 0.7,
            'min_transaction_rate': 1.0,
            'max_consensus_latency_ms': 5000,
            'required_tls_grade': 'B'
        }

    def _requires_authentication(self, response: httpx.Response) -> bool:
        """Check if response indicates authentication was required"""
        # Check for auth headers or status codes
        auth_headers = ['www-authenticate', 'authorization']
        return (response.status_code in [401, 403] or 
                any(header in response.headers for header in auth_headers))

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

    def _update_scan_history(self, ip: str, port: int, result: SuiScanResult):
        """Update scan history for behavioral analysis"""
        key = f"{ip}:{port}"
        if key not in self.scan_history:
            self.scan_history[key] = []
        
        self.scan_history[key].append(result)
        
        # Keep only last 100 scans for analysis
        self.scan_history[key] = self.scan_history[key][-100:]

    def _update_sui_network_baseline(self, results: List[SuiScanResult]):
        """Update Sui network baseline metrics"""
        if not results:
            return
        
        healthy_nodes = [r for r in results if r.healthy]
        if healthy_nodes:
            # Calculate network-wide Sui statistics
            latencies = [r.latency_ms for r in healthy_nodes if r.latency_ms]
            validator_counts = [r.validator_count for r in healthy_nodes]
            checkpoint_lags = [r.checkpoint_lag for r in healthy_nodes if r.checkpoint_lag is not None]
            tx_rates = [r.transaction_processing_rate for r in healthy_nodes if r.transaction_processing_rate]
            
            self.network_baseline.update({
                'avg_latency': statistics.mean(latencies) if latencies else None,
                'avg_validator_count': statistics.mean(validator_counts) if validator_counts else None,
                'avg_checkpoint_lag': statistics.mean(checkpoint_lags) if checkpoint_lags else None,
                'avg_tx_rate': statistics.mean(tx_rates) if tx_rates else None,
                'healthy_node_percentage': len(healthy_nodes) / len(results),
                'network_total_stake': sum(r.total_stake for r in healthy_nodes if r.total_stake),
                'last_updated': datetime.utcnow()
            })

    async def _robust_fetch(self, client: httpx.AsyncClient, url: str, retries: int = None) -> Optional[Dict]:
        """Fetch with comprehensive retry logic"""
        if retries is None:
            retries = self.max_retries
            
        last_exception = None
        first_failure_logged = False
        
        for attempt in range(retries):
            try:
                response = await client.get(url)
                if response.status_code == 200:
                    try:
                        return response.json()
                    except json.JSONDecodeError:
                        return {"text_response": response.text}
                elif response.status_code in [404, 501]:
                    if not first_failure_logged:
                        self.logger.debug(f"❌ Endpoint not found: {url} (HTTP {response.status_code})")
                        first_failure_logged = True
                    return None
                else:
                    if not first_failure_logged:
                        self.logger.debug(f"❌ HTTP {response.status_code} from {url}")
                        first_failure_logged = True
                    
            except (httpx.TimeoutException, httpx.ConnectError) as e:
                if not first_failure_logged:
                    self.logger.debug(f"❌ Connection failed to {url}: {type(e).__name__}")
                    first_failure_logged = True
                last_exception = e
                if attempt < retries - 1:
                    await asyncio.sleep(0.2 * (2 ** attempt))  # Reduced sleep time
            except Exception as e:
                if not first_failure_logged:
                    self.logger.debug(f"❌ Error fetching {url}: {type(e).__name__}")
                    first_failure_logged = True
                last_exception = e
                break
        
        return None

    async def _identify_service(self, ip: str, port: int) -> Optional[str]:
        """Identify service running on specific port"""
        try:
            future = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(future, timeout=3.0)
            
            writer.write(b"GET / HTTP/1.0\r\n\r\n")
            await writer.drain()
            
            try:
                banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                banner_str = banner.decode('utf-8', errors='ignore').lower()
                
                # Service identification patterns
                if 'ssh' in banner_str:
                    return 'ssh'
                elif 'sui' in banner_str or 'mysten' in banner_str:
                    return 'sui-node'
                elif 'http' in banner_str or 'html' in banner_str:
                    return 'http'
                elif 'narwhal' in banner_str:
                    return 'narwhal-consensus'
                else:
                    return 'unknown'
                    
            finally:
                writer.close()
                await writer.wait_closed()
                
        except Exception:
            return None

    async def _analyze_tls_config(self, ip: str, port: int, hostname: Optional[str] = None) -> Dict[str, Any]:
        """Analyze TLS/SSL configuration"""
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, port), timeout=10) as sock:
                # Use hostname for SNI if provided, otherwise use IP
                server_hostname = hostname if hostname else ip
                with context.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # TLS grading logic
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
        """Analyze HTTP security headers"""
        issues = []
        
        required_headers = {
            'x-content-type-options': 'nosniff',
            'x-frame-options': ['DENY', 'SAMEORIGIN'],
            'x-xss-protection': '1; mode=block'
        }
        
        lower_headers = {k.lower(): v for k, v in headers.items()}
        
        for header, expected in required_headers.items():
            if header not in lower_headers:
                issues.append(f"missing_security_header_{header.replace('-', '_')}")
            elif expected and isinstance(expected, list):
                if lower_headers[header] not in expected:
                    issues.append(f"weak_security_header_{header.replace('-', '_')}")
        
        return issues

    def _calculate_uptime_score(self, history: List[SuiScanResult]) -> float:
        """Calculate uptime score from scan history"""
        if not history:
            return 0.0
        
        healthy_scans = sum(1 for scan in history if scan.healthy)
        return healthy_scans / len(history)

    def _analyze_performance_trend(self, history: List[SuiScanResult]) -> str:
        """Analyze performance trend from historical data"""
        if len(history) < 5:
            return "insufficient_data"
        
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
        
        return "stable"

    def get_trust_scoring_data(self, result: SuiScanResult) -> Dict[str, Any]:
        """Extract all data needed for external trust scoring"""
        return {
            # Core health metrics
            'healthy': result.healthy,
            'uptime_score': result.uptime_score,
            'latency_ms': result.latency_ms,
            'latency_variance': result.latency_variance,
            'rpc_success_rate': result.rpc_success_rate,
            
            # Sui blockchain metrics
            'epoch': result.epoch,
            'checkpoint_height': result.checkpoint_height,
            'checkpoint_lag': result.checkpoint_lag,
            'transactions_per_checkpoint': result.transactions_per_checkpoint,
            'transaction_processing_rate': result.transaction_processing_rate,
            
            # Validator ecosystem
            'validator_count': result.validator_count,
            'total_stake': result.total_stake,
            'voting_power_distribution': result.voting_power_distribution,
            'validator_apy_avg': result.validator_apy_avg,
            'validator_apy_variance': result.validator_apy_variance,
            'validator_consistency_score': result.validator_consistency_score,
            'validator_behavior_score': result.validator_behavior_score,
            
            # Consensus health (Narwhal/Bullshark)
            'consensus_latency_ms': result.consensus_latency_ms,
            'narwhal_round': result.narwhal_round,
            'bullshark_dag_size': result.bullshark_dag_size,
            'mempool_size': result.mempool_size,
            'certificate_throughput': result.certificate_throughput,
            
            # Network connectivity
            'peer_count': result.peer_count,
            
            # Security posture
            'open_ports': result.open_ports,
            'exposed_services': result.exposed_services,
            'admin_interfaces_exposed': result.admin_interfaces_exposed,
            'metrics_publicly_exposed': result.metrics_publicly_exposed,
            'rpc_auth_enabled': result.rpc_auth_enabled,
            'tls_grade': result.tls_grade,
            'config_security_score': result.config_security_score,
            
            # Operational metrics
            'sync_health_score': result.sync_health_score,
            'gas_price_stability': result.gas_price_stability,
            'storage_utilization': result.storage_utilization,
            'checkpoint_timing_consistency': result.checkpoint_timing_consistency,
            
            # Reputation and compliance
            'reputation_flags': result.reputation_flags,
            'malicious_ip': result.malicious_ip,
            'known_vulnerabilities': result.known_vulnerabilities,
            'blacklist_matches': result.blacklist_matches,
            'compliance_flags': result.compliance_flags,
            
            # Configuration and anomalies
            'misconfigs': result.misconfigs,
            'validator_config_issues': result.validator_config_issues,
            'consensus_anomalies': result.consensus_anomalies,
            'validator_inconsistencies': result.validator_inconsistencies,
            'checkpoint_anomalies': result.checkpoint_anomalies,
            'anomaly_score': result.anomaly_score,
            'performance_trend': result.performance_trend,
            
            # Scan metadata
            'scan_level': result.scan_level.value,
            'scan_success_rate': result.scan_success_rate,
            'scan_duration_ms': result.scan_duration_ms,
            'version': result.version,
            'node_id': result.node_id
        }

    def export_results(self, results: List[SuiScanResult], format: str = 'json') -> str:
        """Export comprehensive Sui scan results"""
        if format == 'json':
            return json.dumps([asdict(r) for r in results], indent=2, default=str)
        
        elif format == 'trust_scoring':
            trust_data = []
            for result in results:
                trust_data.append({
                    'node_address': f"{result.ip}:{result.port}",
                    'timestamp': result.timestamp.isoformat(),
                    'protocol': 'sui',
                    'trust_inputs': self.get_trust_scoring_data(result)
                })
            return json.dumps(trust_data, indent=2, default=str)
        
        elif format == 'validator_report':
            # Sui-specific validator analysis report
            validator_summary = {
                'network_overview': {
                    'total_nodes_scanned': len(results),
                    'healthy_nodes': sum(1 for r in results if r.healthy),
                    'total_validators': sum(r.validator_count for r in results if r.validator_count),
                    'avg_stake_distribution_gini': statistics.mean([r.voting_power_distribution for r in results if r.voting_power_distribution]),
                    'scan_timestamp': datetime.utcnow().isoformat()
                },
                'consensus_health': {
                    'avg_consensus_latency_ms': statistics.mean([r.consensus_latency_ms for r in results if r.consensus_latency_ms]),
                    'nodes_with_consensus_issues': sum(1 for r in results if r.consensus_anomalies),
                    'avg_checkpoint_lag': statistics.mean([r.checkpoint_lag for r in results if r.checkpoint_lag])
                },
                'security_findings': {
                    'nodes_with_public_metrics': sum(1 for r in results if r.metrics_publicly_exposed),
                    'nodes_without_rpc_auth': sum(1 for r in results if not r.rpc_auth_enabled),
                    'nodes_with_admin_exposure': sum(1 for r in results if r.admin_interfaces_exposed)
                },
                'validator_issues': {},
                'recommendations': []
            }
            
            # Aggregate validator issues
            all_validator_issues = {}
            for result in results:
                for issue in result.validator_config_issues:
                    all_validator_issues[issue] = all_validator_issues.get(issue, 0) + 1
            
            validator_summary['validator_issues'] = all_validator_issues
            
            return json.dumps(validator_summary, indent=2, default=str)
        
        elif format == 'csv':
            csv_lines = []
            headers = [
                'ip', 'port', 'healthy', 'version', 'epoch', 'validator_count',
                'total_stake', 'checkpoint_lag', 'latency_ms', 'consensus_latency_ms',
                'voting_power_gini', 'rpc_auth_enabled', 'metrics_public',
                'compliance_flags_count', 'misconfigs_count', 'uptime_score'
            ]
            csv_lines.append(','.join(headers))
            
            for result in results:
                row = [
                    result.ip,
                    str(result.port),
                    str(result.healthy),
                    result.version or '',
                    str(result.epoch or ''),
                    str(result.validator_count),
                    str(result.total_stake or ''),
                    str(result.checkpoint_lag or ''),
                    str(result.latency_ms or ''),
                    str(result.consensus_latency_ms or ''),
                    str(result.voting_power_distribution or ''),
                    str(result.rpc_auth_enabled),
                    str(result.metrics_publicly_exposed),
                    str(len(result.compliance_flags)),
                    str(len(result.misconfigs)),
                    str(result.uptime_score or '')
                ]
                csv_lines.append(','.join(row))
            
            return '\n'.join(csv_lines)
        
        return ""

# Supporting classes for Sui-specific integrations
class ReputationClient:
    """Enhanced reputation client with Sui-specific capabilities"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.api_keys = self.config.get('api_keys', {})
        self.enabled_services = self.config.get('enabled_services', [])
    
    async def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation across multiple services"""
        return {
            'malicious': False,
            'reputation_score': 0.8,
            'sources': []
        }
    
    async def check_sui_node(self, node_id: str) -> Dict[str, Any]:
        """Check Sui-specific node reputation"""
        return {
            'flags': [],
            'reputation_score': 0.7,
            'validator_history': []
        }
    
    async def check_validator_reputation(self, validator_name: str) -> Dict[str, Any]:
        """Check individual validator reputation"""
        # Integration points for:
        # - Sui validator registry
        # - Community validator ratings
        # - Historical performance data
        return {
            'flagged': False,
            'performance_score': 0.8,
            'community_rating': 0.7
        }
    
    async def check_sui_version_vulnerabilities(self, version: str) -> Dict[str, Any]:
        """Check Sui version against vulnerability databases"""
        return {
            'critical_vulnerabilities': [],
            'high_vulnerabilities': [],
            'medium_vulnerabilities': [],
            'recommended_version': None
        }

class BehaviorAnalyzer:
    """Sui-specific behavioral pattern analysis"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.anomaly_threshold = self.config.get('anomaly_threshold', 0.7)
    
    def detect_sui_anomalies(self, history: List[SuiScanResult], 
                            current: SuiScanResult) -> Optional[float]:
        """Detect Sui-specific behavioral anomalies"""
        if len(history) < 10:
            return None
        
        anomaly_score = 0.0
        
        # Checkpoint progression anomaly
        checkpoint_heights = [h.checkpoint_height for h in history[-10:] if h.checkpoint_height]
        if len(checkpoint_heights) > 5 and current.checkpoint_height:
            diffs = [checkpoint_heights[i] - checkpoint_heights[i-1] for i in range(1, len(checkpoint_heights))]
            expected_progression = statistics.mean(diffs) if diffs else 0
            if expected_progression > 0:
                recent_progression = current.checkpoint_height - checkpoint_heights[-1]
                deviation = abs(recent_progression - expected_progression) / expected_progression
                anomaly_score += min(1.0, deviation) * 0.3
        
        # Validator count anomaly
        validator_counts = [h.validator_count for h in history[-10:]]
        if validator_counts and current.validator_count:
            expected_count = statistics.mean(validator_counts)
            if expected_count > 0:
                deviation = abs(current.validator_count - expected_count) / expected_count
                anomaly_score += min(1.0, deviation) * 0.2
        
        # Consensus latency anomaly
        consensus_latencies = [h.consensus_latency_ms for h in history[-10:] if h.consensus_latency_ms]
        if consensus_latencies and current.consensus_latency_ms:
            latency_mean = statistics.mean(consensus_latencies)
            latency_stdev = statistics.stdev(consensus_latencies) if len(consensus_latencies) > 1 else 0
            if latency_stdev > 0:
                z_score = abs(current.consensus_latency_ms - latency_mean) / latency_stdev
                anomaly_score += min(1.0, z_score / 3.0) * 0.3
        
        # Stake distribution anomaly
        stake_ginis = [h.voting_power_distribution for h in history[-10:] if h.voting_power_distribution]
        if stake_ginis and current.voting_power_distribution:
            gini_mean = statistics.mean(stake_ginis)
            gini_stdev = statistics.stdev(stake_ginis) if len(stake_ginis) > 1 else 0
            if gini_stdev > 0:
                z_score = abs(current.voting_power_distribution - gini_mean) / gini_stdev
                anomaly_score += min(1.0, z_score / 3.0) * 0.2
        
        return min(1.0, anomaly_score)
    
    def analyze_validator_performance(self, validator_data: List[Dict]) -> Dict[str, Any]:
        """Analyze validator performance patterns"""
        performance_analysis = {
            'high_performers': [],
            'underperformers': [],
            'consistency_scores': {},
            'risk_factors': []
        }
        
        for validator in validator_data:
            name = validator.get('name', 'unknown')
            apy = float(validator.get('apy', 0))
            stake = float(validator.get('stakingPoolSuiBalance', 0))
            
            # Performance scoring
            performance_score = 0.0
            
            # APY contribution (normalized)
            if apy > 0:
                performance_score += min(1.0, apy / 10.0) * 0.4
            
            # Stake contribution (normalized)
            if stake > 0:
                performance_score += min(1.0, stake / 1000000) * 0.3  # Normalize to 1M SUI
            
            # Consistency bonus (would need historical data)
            performance_score += 0.3  # Placeholder
            
            performance_analysis['consistency_scores'][name] = performance_score
            
            # Categorize validators
            if performance_score > 0.8:
                performance_analysis['high_performers'].append(name)
            elif performance_score < 0.4:
                performance_analysis['underperformers'].append(name)
                performance_analysis['risk_factors'].append(f"underperforming_validator_{name}")
        
        return performance_analysis

# Usage example and integration patterns
class SuiNetworkAnalyzer:
    """High-level Sui network analysis using the enhanced scanner"""
    
    def __init__(self, scanner: EnhancedSuiScanner):
        self.scanner = scanner
        self.logger = logging.getLogger(__name__)
    
    async def analyze_network_health(self, node_ips: List[str]) -> Dict[str, Any]:
        """Comprehensive Sui network health analysis"""
        all_results = []
        
        # Scan all nodes
        for ip in node_ips:
            try:
                results = await self.scanner.scan(ip)
                all_results.extend(results)
            except Exception as e:
                self.logger.warning(f"Failed to scan {ip}: {e}")
        
        if not all_results:
            return {"error": "No successful scans"}
        
        # Network-wide analysis
        healthy_nodes = [r for r in all_results if r.healthy]
        
        network_analysis = {
            'network_overview': {
                'total_nodes_scanned': len(all_results),
                'healthy_nodes': len(healthy_nodes),
                'network_health_percentage': len(healthy_nodes) / len(all_results) if all_results else 0,
                'scan_timestamp': datetime.utcnow().isoformat()
            },
            
            'consensus_health': self._analyze_consensus_health(healthy_nodes),
            'validator_ecosystem': self._analyze_validator_ecosystem(healthy_nodes),
            'security_posture': self._analyze_network_security(all_results),
            'performance_metrics': self._analyze_network_performance(healthy_nodes),
            'compliance_summary': self._analyze_compliance_status(all_results),
            'recommendations': self._generate_recommendations(all_results)
        }
        
        return network_analysis
    
    def _analyze_consensus_health(self, healthy_nodes: List[SuiScanResult]) -> Dict[str, Any]:
        """Analyze network-wide consensus health"""
        consensus_latencies = [n.consensus_latency_ms for n in healthy_nodes if n.consensus_latency_ms]
        checkpoint_lags = [n.checkpoint_lag for n in healthy_nodes if n.checkpoint_lag is not None]
        
        return {
            'avg_consensus_latency_ms': statistics.mean(consensus_latencies) if consensus_latencies else None,
            'max_consensus_latency_ms': max(consensus_latencies) if consensus_latencies else None,
            'avg_checkpoint_lag': statistics.mean(checkpoint_lags) if checkpoint_lags else None,
            'nodes_with_consensus_issues': sum(1 for n in healthy_nodes if n.consensus_anomalies),
            'consensus_stability_score': self._calculate_consensus_stability(healthy_nodes)
        }
    
    def _analyze_validator_ecosystem(self, healthy_nodes: List[SuiScanResult]) -> Dict[str, Any]:
        """Analyze validator ecosystem health"""
        total_validators = sum(n.validator_count for n in healthy_nodes)
        total_stake = sum(n.total_stake for n in healthy_nodes if n.total_stake)
        
        gini_coefficients = [n.voting_power_distribution for n in healthy_nodes if n.voting_power_distribution]
        avg_gini = statistics.mean(gini_coefficients) if gini_coefficients else None
        
        return {
            'total_validators_observed': total_validators,
            'total_network_stake': total_stake,
            'avg_centralization_gini': avg_gini,
            'decentralization_health': 'healthy' if avg_gini and avg_gini < 0.7 else 'concerning',
            'validator_consistency_issues': sum(len(n.validator_inconsistencies) for n in healthy_nodes)
        }
    
    def _analyze_network_security(self, all_results: List[SuiScanResult]) -> Dict[str, Any]:
        """Analyze network-wide security posture"""
        return {
            'nodes_with_public_metrics': sum(1 for r in all_results if r.metrics_publicly_exposed),
            'nodes_without_rpc_auth': sum(1 for r in all_results if not r.rpc_auth_enabled),
            'nodes_with_admin_exposure': sum(1 for r in all_results if r.admin_interfaces_exposed),
            'nodes_with_weak_tls': sum(1 for r in all_results if r.tls_grade in ['C', 'D', 'F']),
            'avg_security_score': statistics.mean([r.config_security_score for r in all_results if r.config_security_score]) if [r.config_security_score for r in all_results if r.config_security_score] else None
        }
    
    def _analyze_network_performance(self, healthy_nodes: List[SuiScanResult]) -> Dict[str, Any]:
        """Analyze network performance metrics"""
        latencies = [n.latency_ms for n in healthy_nodes if n.latency_ms]
        tx_rates = [n.transaction_processing_rate for n in healthy_nodes if n.transaction_processing_rate]
        
        return {
            'avg_response_latency_ms': statistics.mean(latencies) if latencies else None,
            'p95_response_latency_ms': self._calculate_percentile(latencies, 95) if latencies else None,
            'avg_transaction_rate': statistics.mean(tx_rates) if tx_rates else None,
            'performance_trend': self._calculate_network_trend(healthy_nodes)
        }
    
    def _analyze_compliance_status(self, all_results: List[SuiScanResult]) -> Dict[str, Any]:
        """Analyze compliance across the network"""
        all_compliance_flags = {}
        for result in all_results:
            for flag in result.compliance_flags:
                all_compliance_flags[flag] = all_compliance_flags.get(flag, 0) + 1
        
        return {
            'total_compliance_violations': sum(all_compliance_flags.values()),
            'violation_breakdown': all_compliance_flags,
            'compliance_score': self._calculate_network_compliance_score(all_results)
        }
    
    def _generate_recommendations(self, all_results: List[SuiScanResult]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Security recommendations
        public_metrics_count = sum(1 for r in all_results if r.metrics_publicly_exposed)
        if public_metrics_count > 0:
            recommendations.append(f"Secure metrics endpoints on {public_metrics_count} nodes")
        
        # Performance recommendations
        high_latency_nodes = sum(1 for r in all_results if r.latency_ms and r.latency_ms > 2000)
        if high_latency_nodes > 0:
            recommendations.append(f"Investigate high latency on {high_latency_nodes} nodes")
        
        # Consensus recommendations
        consensus_issues = sum(1 for r in all_results if r.consensus_anomalies)
        if consensus_issues > 0:
            recommendations.append(f"Address consensus anomalies on {consensus_issues} nodes")
        
        # Validator recommendations
        validator_issues = sum(len(r.validator_config_issues) for r in all_results)
        if validator_issues > 0:
            recommendations.append(f"Resolve {validator_issues} validator configuration issues")
        
        return recommendations
    
    def _calculate_consensus_stability(self, healthy_nodes: List[SuiScanResult]) -> float:
        """Calculate overall consensus stability score"""
        if not healthy_nodes:
            return 0.0
        
        stability_factors = []
        
        # Consensus latency stability
        latencies = [n.consensus_latency_ms for n in healthy_nodes if n.consensus_latency_ms]
        if latencies:
            mean_latency = statistics.mean(latencies)
            stdev_latency = statistics.stdev(latencies) if len(latencies) > 1 else 0
            cv_latency = stdev_latency / mean_latency if mean_latency > 0 else 1
            stability_factors.append(max(0.0, 1.0 - cv_latency))
        
        # Checkpoint consistency
        nodes_with_consistent_checkpoints = sum(1 for n in healthy_nodes if not n.checkpoint_anomalies)
        if healthy_nodes:
            stability_factors.append(nodes_with_consistent_checkpoints / len(healthy_nodes))
        
        return statistics.mean(stability_factors) if stability_factors else 0.0
    
    def _calculate_network_trend(self, healthy_nodes: List[SuiScanResult]) -> str:
        """Calculate overall network performance trend"""
        improving_nodes = sum(1 for n in healthy_nodes if n.performance_trend == "improving")
        declining_nodes = sum(1 for n in healthy_nodes if n.performance_trend == "declining")
        
        if improving_nodes > declining_nodes:
            return "improving"
        elif declining_nodes > improving_nodes:
            return "declining"
        else:
            return "stable"
    
    def _calculate_network_compliance_score(self, all_results: List[SuiScanResult]) -> float:
        """Calculate overall network compliance score"""
        if not all_results:
            return 0.0
        
        total_flags = sum(len(r.compliance_flags) for r in all_results)
        max_possible_flags = len(all_results) * 10  # Assume max 10 flags per node
        
        return max(0.0, 1.0 - (total_flags / max_possible_flags))

    def _calculate_percentile(self, data: List[float], percentile: float) -> float:
        """Calculate percentile"""
        if not data:
            return 0.0
        
        sorted_data = sorted(data)
        n = len(sorted_data)
        index = (percentile / 100.0) * (n - 1)
        
        if index == int(index):
            return sorted_data[int(index)]
        else:
            lower = sorted_data[int(index)]
            upper = sorted_data[int(index) + 1]
            return lower + (upper - lower) * (index - int(index))

# # Example usage
# async def example_sui_network_scan():
#     """Example of how to use the enhanced Sui scanner"""
    
#     # Initialize scanner with ferocious level scanning
#     config = {
#         'timeout': 20,
#         'max_retries': 3,
#         'rate_limit_delay': 2.0,
#         'scan_level': 3  # Ferocious
#     }
    
#     scanner = EnhancedSuiScanner(
#         config=config,
#         scan_level=ScanLevel.FEROCIOUS,
#         enable_reputation=True,
#         enable_behavioral=True
#     )
    
#     # Scan a Sui node
#     sui_node_ips = ["192.168.1.100", "10.0.0.50"]
    
#     all_results = []
#     for ip in sui_node_ips:
#         results = await scanner.scan(ip)
#         all_results.extend(results)
    
#     # Export results for trust scoring
#     trust_scoring_data = scanner.export_results(all_results, format='trust_scoring')
#     print("Trust scoring data:", trust_scoring_data)
    
#     # Generate validator-specific report
#     validator_report = scanner.export_results(all_results, format='validator_report')
#     print("Validator report:", validator_report)
    
#     # High-level network analysis
#     analyzer = SuiNetworkAnalyzer(scanner)
#     network_health = await analyzer.analyze_network_health(sui_node_ips)
#     print("Network health analysis:", json.dumps(network_health, indent=2, default=str))

# if __name__ == "__main__":
#     asyncio.run(example_sui_network_scan())