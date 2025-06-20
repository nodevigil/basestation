"""
DePIN Protocol Discovery Agent

This agent specializes in DePIN protocol detection using high-performance binary signature
matching and comprehensive database persistence. It extends the base DiscoveryAgent to
provide protocol-specific discovery functionality for DePIN networks.
"""

import json
import subprocess
import requests
import logging
import base64
import hashlib
import struct
import uuid
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass
from enum import Enum

from agents.base import ProcessAgent
from core.config import Config
from core.database import get_db_session, Protocol, ProtocolSignature
from sqlalchemy import text


class ConfidenceLevel(Enum):
    HIGH = "high"
    MEDIUM = "medium" 
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class DePINDiscoveryResult:
    """Result structure for DePIN protocol discovery"""
    protocol: Optional[str]
    confidence: ConfidenceLevel
    confidence_score: float
    evidence: Dict[str, Any]
    scan_data: Dict[str, Any]
    signature_match: Optional[Dict[str, Any]] = None
    performance_metrics: Optional[Dict[str, Any]] = None
    discovery_id: Optional[int] = None


class DatabaseResultPersister:
    """Handles persisting discovery results to database"""
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config
        
    def create_scan_session(self, session_id: Optional[str] = None, created_by: Optional[str] = None) -> str:
        """Create a new scan session and return session ID"""
        if session_id is None:
            session_id = str(uuid.uuid4())
            
        try:
            with get_db_session() as session:
                session.execute(
                    text("INSERT OR REPLACE INTO scan_sessions (session_id, started_at, status, created_by, scanner_version) VALUES (:session_id, :started_at, :status, :created_by, :scanner_version)"),
                    {
                        'session_id': session_id,
                        'started_at': datetime.utcnow(),
                        'status': 'running',
                        'created_by': created_by or 'discovery_agent',
                        'scanner_version': '2.0'
                    }
                )
                session.commit()
                
        except Exception as e:
            logging.error(f"Failed to create scan session: {e}")
            
        return session_id
    
    def start_host_discovery(self, session_id: str, hostname: str, ip_address: Optional[str] = None) -> int:
        """Start a host discovery and return discovery_id"""
        discovery_id = None
        
        try:
            with get_db_session() as session:
                result = session.execute(
                    text("""INSERT INTO host_discoveries 
                       (session_id, hostname, ip_address, confidence_level, confidence_score, 
                        scan_started_at, scan_status) 
                       VALUES (:session_id, :hostname, :ip_address, 'unknown', 0.0, :started_at, 'scanning')"""),
                    {
                        'session_id': session_id,
                        'hostname': hostname,
                        'ip_address': ip_address,
                        'started_at': datetime.utcnow()
                    }
                )
                discovery_id = result.lastrowid
                session.commit()
                
        except Exception as e:
            logging.error(f"Failed to start host discovery: {e}")
            discovery_id = hash(f"{session_id}_{hostname}") % 1000000
            
        return discovery_id
    
    def save_network_scan_data(self, discovery_id: int, nmap_data: Dict, nmap_command: str = "", nmap_duration: float = 0.0):
        """Save network scan results"""
        try:
            with get_db_session() as session:
                session.execute(
                    text("""INSERT INTO network_scan_data 
                       (discovery_id, open_ports, services_detected, nmap_command, 
                        nmap_output, nmap_duration_seconds) 
                       VALUES (:discovery_id, :open_ports, :services_detected, :nmap_command, :nmap_output, :nmap_duration_seconds)"""),
                    {
                        'discovery_id': discovery_id,
                        'open_ports': json.dumps(nmap_data.get('ports', [])),
                        'services_detected': json.dumps(nmap_data.get('services', {})),
                        'nmap_command': nmap_command,
                        'nmap_output': json.dumps(nmap_data)[:10000],  # Truncate large output
                        'nmap_duration_seconds': nmap_duration
                    }
                )
                session.commit()
        except Exception as e:
            logging.error(f"Failed to save network scan data: {e}")
    
    def save_probe_result(self, discovery_id: int, probe_type: str, target_port: int, 
                         endpoint_path: str, protocol_hint: str, request_data: Dict, 
                         response_data: Dict, error_info: Dict = None):
        """Save individual probe result"""
        try:
            with get_db_session() as session:
                session.execute(
                    text("""INSERT INTO protocol_probe_results 
                       (discovery_id, probe_type, target_port, endpoint_path, protocol_hint,
                        request_method, request_headers, request_body, request_timestamp,
                        response_status_code, response_headers, response_body, response_size_bytes,
                        response_time_ms, error_occurred, error_message, timeout_occurred)
                       VALUES (:discovery_id, :probe_type, :target_port, :endpoint_path, :protocol_hint,
                               :request_method, :request_headers, :request_body, :request_timestamp,
                               :response_status_code, :response_headers, :response_body, :response_size_bytes,
                               :response_time_ms, :error_occurred, :error_message, :timeout_occurred)"""),
                    {
                        'discovery_id': discovery_id,
                        'probe_type': probe_type,
                        'target_port': target_port,
                        'endpoint_path': endpoint_path or '',
                        'protocol_hint': protocol_hint or '',
                        'request_method': request_data.get('method', ''),
                        'request_headers': json.dumps(request_data.get('headers', {})),
                        'request_body': str(request_data.get('body', ''))[:5000],
                        'request_timestamp': datetime.utcnow(),
                        'response_status_code': response_data.get('status'),
                        'response_headers': json.dumps(response_data.get('headers', {})),
                        'response_body': str(response_data.get('body', ''))[:10000],
                        'response_size_bytes': len(str(response_data.get('body', ''))),
                        'response_time_ms': response_data.get('response_time_ms', 0),
                        'error_occurred': error_info is not None,
                        'error_message': error_info.get('message', '') if error_info else '',
                        'timeout_occurred': error_info.get('timeout', False) if error_info else False
                    }
                )
                session.commit()
        except Exception as e:
            logging.error(f"Failed to save probe result: {e}")
    
    def complete_host_discovery(self, discovery_id: int, result: DePINDiscoveryResult, total_duration: float):
        """Complete host discovery with final results"""
        try:
            with get_db_session() as session:
                session.execute(
                    text("""UPDATE host_discoveries 
                       SET detected_protocol = ?, confidence_level = ?, confidence_score = ?,
                           detection_method = ?, scan_completed_at = ?, scan_duration_seconds = ?,
                           scan_status = 'completed', performance_metrics = ?
                       WHERE id = ?"""),
                    [
                        result.protocol,
                        result.confidence.value,
                        result.confidence_score,
                        result.signature_match.get('analysis_method', 'unknown') if result.signature_match else 'unknown',
                        datetime.utcnow(),
                        total_duration,
                        json.dumps(result.performance_metrics or {}),
                        discovery_id
                    ]
                )
                session.commit()
        except Exception as e:
            logging.error(f"Failed to complete host discovery: {e}")
    
    def mark_discovery_failed(self, discovery_id: int, error_message: str):
        """Mark discovery as failed"""
        try:
            with get_db_session() as session:
                session.execute(
                    text("""UPDATE host_discoveries 
                       SET scan_status = 'failed', error_message = :error_message, scan_completed_at = :completed_at
                       WHERE id = :discovery_id"""),
                    {
                        'error_message': error_message,
                        'completed_at': datetime.utcnow(),
                        'discovery_id': discovery_id
                    }
                )
                session.commit()
        except Exception as e:
            logging.error(f"Failed to mark discovery as failed: {e}")


class NmapScanner:
    """Handles nmap scanning and result parsing"""
    
    @staticmethod
    def scan_host(hostname: str) -> Dict:
        """Perform comprehensive nmap scan"""
        # Use a more conservative nmap approach for better reliability
        cmd = [
            'nmap', '-sS', '-sV', 
            '--script=http-enum,ssl-cert,banner',
            '-p1-1000',  # Scan first 1000 ports instead of all 65535 for speed
            '--max-retries=1',
            '--host-timeout=120s',
            '--max-rtt-timeout=1000ms',
            '-oX', '-',
            hostname
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Check if we got XML output
            if result.stdout.strip() and '<?xml' in result.stdout:
                return NmapScanner._parse_nmap_output(result.stdout)
            else:
                # If no XML, try a simpler scan
                return NmapScanner._fallback_scan(hostname)
                
        except subprocess.TimeoutExpired:
            logging.error(f"Nmap scan timed out for {hostname}")
            return NmapScanner._fallback_scan(hostname)
        except Exception as e:
            logging.error(f"Nmap scan failed: {e}")
            return NmapScanner._fallback_scan(hostname)
    
    @staticmethod
    def _fallback_scan(hostname: str) -> Dict:
        """Fallback simple port scan when full nmap fails"""
        try:
            # Simple ping-style port check on common ports
            import socket
            common_ports = [22, 80, 443, 8080, 8443, 9000, 9100, 3000, 5000]
            open_ports = []
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((hostname, port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                except:
                    continue
            
            return {
                'ports': open_ports,
                'services': {},
                'os': None,
                'scripts': {},
                'fallback_scan': True
            }
            
        except Exception as e:
            logging.error(f"Fallback scan failed for {hostname}: {e}")
            return {
                'ports': [],
                'services': {},
                'os': None,
                'scripts': {},
                'scan_error': str(e)
            }
    
    @staticmethod
    def _parse_nmap_output(xml_output: str) -> Dict:
        """Parse nmap XML output into structured data"""
        import xml.etree.ElementTree as ET
        
        try:
            # Clean up the XML string
            xml_output = xml_output.strip()
            
            # Ensure we have valid XML
            if not xml_output.startswith('<?xml'):
                logging.error("Invalid XML format in nmap output")
                return {}
            
            root = ET.fromstring(xml_output)
            result = {
                'ports': [],
                'services': {},
                'os': None,
                'scripts': {}
            }
            
            # Find all hosts
            for host in root.findall('.//host'):
                # Find all ports for this host
                for port in host.findall('.//port'):
                    port_num = port.get('portid')
                    protocol = port.get('protocol', 'tcp')
                    state = port.find('state')
                    service = port.find('service')
                    
                    if state is not None and state.get('state') == 'open' and port_num:
                        try:
                            port_int = int(port_num)
                            result['ports'].append(port_int)
                            
                            if service is not None:
                                result['services'][port_int] = {
                                    'name': service.get('name', ''),
                                    'product': service.get('product', ''),
                                    'version': service.get('version', ''),
                                    'banner': service.get('banner', ''),
                                    'protocol': protocol
                                }
                        except ValueError:
                            continue
            
            # Remove duplicates and sort
            result['ports'] = sorted(list(set(result['ports'])))
            
            return result
            
        except ET.ParseError as e:
            logging.error(f"Failed to parse nmap XML output: {e}")
            return {}
        except Exception as e:
            logging.error(f"Unexpected error parsing nmap output: {e}")
            return {}


class HighPerformanceBinaryMatcher:
    """High-performance binary signature matching"""
    
    @staticmethod
    def generate_scan_signatures(nmap_data: Dict, probe_data: Dict, signature_length: int = 256) -> Dict[str, str]:
        """Generate binary signatures from scan data"""
        
        # Extract features
        scan_ports = [str(port) for port in nmap_data.get('ports', [])]
        scan_banners = []
        scan_endpoints = []
        scan_keywords = []
        
        # Service banner extraction
        for port, service in nmap_data.get('services', {}).items():
            banners = [service.get('name', ''), service.get('product', ''), service.get('banner', '')]
            scan_banners.extend([b for b in banners if b])
        
        # HTTP data extraction
        for endpoint_key, response in probe_data.items():
            if isinstance(response, dict):
                if 'url' in response:
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(response['url'])
                        scan_endpoints.append(parsed.path)
                    except:
                        pass
                
                if 'body' in response:
                    keywords = HighPerformanceBinaryMatcher._extract_protocol_keywords(response['body'])
                    scan_keywords.extend(keywords[:20])
        
        # Generate binary signatures
        return {
            'port': HighPerformanceBinaryMatcher._create_binary_signature(scan_ports, signature_length),
            'banner': HighPerformanceBinaryMatcher._create_binary_signature(scan_banners, signature_length),
            'endpoint': HighPerformanceBinaryMatcher._create_binary_signature(scan_endpoints, signature_length),
            'keyword': HighPerformanceBinaryMatcher._create_binary_signature(scan_keywords, signature_length)
        }
    
    @staticmethod
    def _create_binary_signature(items: List[str], signature_length: int = 256) -> str:
        """Create binary signature from items"""
        if not items:
            return base64.b64encode(b'\x00' * (signature_length // 8)).decode('utf-8')
        
        signature_bytes = bytearray(signature_length // 8)
        
        for item in items:
            if item.isdigit():
                try:
                    port_num = int(item)
                    item_hash = hashlib.sha256(struct.pack('!H', port_num)).digest()
                except (ValueError, OverflowError):
                    item_hash = hashlib.sha256(str(item).lower().encode('utf-8')).digest()
            else:
                item_hash = hashlib.sha256(str(item).lower().encode('utf-8')).digest()
            
            for i in range(min(6, len(item_hash))):
                byte_val = item_hash[i]
                bit_pos = byte_val % signature_length
                byte_pos = bit_pos // 8
                bit_offset = bit_pos % 8
                signature_bytes[byte_pos] |= (1 << bit_offset)
        
        return base64.b64encode(bytes(signature_bytes)).decode('utf-8')
    
    @staticmethod
    def _extract_protocol_keywords(text: str, max_keywords: int = 30) -> List[str]:
        """Extract DePIN-specific keywords from text"""
        if not text or len(text) > 10000:
            return []
        
        import re
        keywords = set()
        text_lower = text.lower()
        
        # DePIN-specific patterns
        patterns = [
            r'\b\w*rpc\w*\b', r'\b\w*json\w*\b', r'\b\w*consensus\w*\b',
            r'\b\w*validator\w*\b', r'\b\w*transaction\w*\b', r'\b\w*block\w*\b',
            r'\b\w*chain\w*\b', r'\b\w*node\w*\b', r'\b\w*storage\w*\b'
        ]
        
        for pattern in patterns:
            try:
                matches = re.findall(pattern, text_lower)
                keywords.update(matches[:3])
            except:
                continue
        
        # Protocol identifiers
        protocol_ids = ['sui', 'filecoin', 'ethereum', 'celestia', 'bittensor', 'theta', 'akash', 'helium']
        for identifier in protocol_ids:
            if identifier in text_lower:
                keywords.add(identifier)
        
        return list(keywords)[:max_keywords]
    
    @staticmethod
    def calculate_binary_similarity(sig1: str, sig2: str) -> float:
        """Calculate similarity between binary signatures"""
        try:
            bytes1 = base64.b64decode(sig1)
            bytes2 = base64.b64decode(sig2)
            
            if len(bytes1) != len(bytes2):
                return 0.0
            
            matching_bits = 0
            total_bits = len(bytes1) * 8
            
            for i in range(len(bytes1)):
                xor_result = bytes1[i] ^ bytes2[i]
                matching_bits += 8 - bin(xor_result).count('1')
            
            return matching_bits / total_bits if total_bits > 0 else 0.0
            
        except Exception:
            return 0.0


class DiscoveryAgent(ProcessAgent):
    """
    DePIN Protocol Discovery Agent
    
    Specializes in discovering and identifying DePIN protocols using high-performance
    binary signature matching, comprehensive probing, and database persistence.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the DePIN discovery agent.
        
        Args:
            config: Configuration instance
        """
        super().__init__(config, "DePINDiscoveryAgent")
        self.persister = DatabaseResultPersister(config)
        self.session_id = self.persister.create_scan_session(created_by="depin_discovery_agent")
        
        # Performance thresholds
        self.binary_threshold = 0.25
        self.detailed_threshold = 0.4
        
        self.logger.info("🔍 DePIN Discovery Agent initialized")
    
    def run(self, host: Optional[str] = None, *args, **kwargs) -> List[Dict[str, Any]]:
        """
        Execute DePIN protocol discovery for the specified host.
        
        Args:
            host: Target host for discovery (IP address or hostname)
            
        Returns:
            List of discovery results in standard format
        """
        if not host:
            self.logger.warning("No host specified for DePIN discovery")
            return []
            
        self.logger.info(f"🔍 Starting DePIN protocol discovery for host: {host}")
        
        # Perform DePIN-specific discovery
        discovery_result = self.discover_depin_protocol(host)
        
        # Convert to standard format expected by the framework
        return [self._convert_to_standard_format(discovery_result)]
    
    def discover_depin_protocol(self, hostname: str, ip_address: Optional[str] = None) -> DePINDiscoveryResult:
        """
        Core DePIN protocol discovery logic.
        
        Args:
            hostname: Target hostname to analyze
            ip_address: Optional IP address
            
        Returns:
            DePINDiscoveryResult with detailed protocol analysis
        """
        import time
        start_time = time.time()
        
        # Start host discovery in database
        discovery_id = self.persister.start_host_discovery(self.session_id, hostname, ip_address)
        
        self.logger.info(f"🔍 Starting DePIN discovery for {hostname} (discovery_id: {discovery_id})")
        
        try:
            # Step 1: Network reconnaissance
            self.logger.info("Phase 1: Network reconnaissance")
            nmap_start = time.time()
            nmap_data = NmapScanner.scan_host(hostname)
            nmap_duration = time.time() - nmap_start
            
            # Save network scan data
            nmap_command = f"nmap -sS -sV -O --script=http-enum,ssl-cert,banner -p1-65535 {hostname}"
            self.persister.save_network_scan_data(discovery_id, nmap_data, nmap_command, nmap_duration)
            
            if not nmap_data.get('ports'):
                error_msg = "No open ports detected"
                self.logger.warning(f"{error_msg} on {hostname}")
                self.persister.mark_discovery_failed(discovery_id, error_msg)
                
                return DePINDiscoveryResult(
                    protocol=None,
                    confidence=ConfidenceLevel.UNKNOWN,
                    confidence_score=0.0,
                    evidence={"error": error_msg},
                    scan_data={"nmap": nmap_data},
                    performance_metrics={"total_time": time.time() - start_time},
                    discovery_id=discovery_id
                )
            
            self.logger.info(f"Discovered {len(nmap_data['ports'])} open ports: {nmap_data['ports']}")
            
            # Step 2: Load protocols and signatures
            self.logger.info("Phase 2: Loading protocol signatures")
            protocols = self._load_protocols_with_signatures()
            
            if not protocols:
                error_msg = "No protocol signatures available"
                self.logger.error(error_msg)
                self.persister.mark_discovery_failed(discovery_id, error_msg)
                
                return DePINDiscoveryResult(
                    protocol=None,
                    confidence=ConfidenceLevel.UNKNOWN,
                    confidence_score=0.0,
                    evidence={"error": error_msg},
                    scan_data={"nmap": nmap_data},
                    performance_metrics={"total_time": time.time() - start_time},
                    discovery_id=discovery_id
                )
            
            # Step 3: Intelligent protocol probing
            self.logger.info("Phase 3: Protocol-specific probing")
            probe_data = self._perform_intelligent_probing(hostname, nmap_data, protocols, discovery_id)
            
            # Step 4: Signature-based matching
            self.logger.info("Phase 4: Signature-based protocol matching")
            protocol_name, confidence_score, evidence, perf_metrics = self._match_protocol_signatures(
                nmap_data, probe_data, protocols
            )
            
            # Determine confidence level
            if confidence_score >= 0.8:
                confidence_level = ConfidenceLevel.HIGH
            elif confidence_score >= 0.6:
                confidence_level = ConfidenceLevel.MEDIUM
            elif confidence_score >= 0.4:
                confidence_level = ConfidenceLevel.LOW
            else:
                confidence_level = ConfidenceLevel.UNKNOWN
            
            # Compile results
            total_time = time.time() - start_time
            perf_metrics['total_time'] = total_time
            
            result = DePINDiscoveryResult(
                protocol=protocol_name,
                confidence=confidence_level,
                confidence_score=confidence_score,
                evidence=evidence,
                scan_data={
                    "nmap": nmap_data,
                    "probes": probe_data,
                    "hostname": hostname
                },
                signature_match={
                    "analysis_method": "hybrid_binary_detailed",
                    "protocols_checked": len(protocols),
                    "confidence_score": confidence_score
                },
                performance_metrics=perf_metrics,
                discovery_id=discovery_id
            )
            
            # Complete discovery in database
            self.persister.complete_host_discovery(discovery_id, result, total_time)
            
            # Log results
            if protocol_name:
                self.logger.info(f"✅ Detected {protocol_name} with {confidence_level.value} confidence ({confidence_score:.3f})")
            else:
                self.logger.warning(f"❓ Could not identify protocol (max confidence: {confidence_score:.3f})")
            
            self.logger.info(f"🔧 Discovery completed in {total_time:.3f}s")
            
            return result
            
        except Exception as e:
            error_msg = f"DePIN discovery failed: {str(e)}"
            self.logger.error(error_msg)
            self.persister.mark_discovery_failed(discovery_id, error_msg)
            
            return DePINDiscoveryResult(
                protocol=None,
                confidence=ConfidenceLevel.UNKNOWN,
                confidence_score=0.0,
                evidence={"error": error_msg},
                scan_data={"hostname": hostname},
                performance_metrics={"total_time": time.time() - start_time},
                discovery_id=discovery_id
            )
    
    def _load_protocols_with_signatures(self) -> List[Dict]:
        """Load protocols with signatures from database"""
        protocols = []
        
        try:
            with get_db_session() as session:
                results = session.query(Protocol, ProtocolSignature).join(
                    ProtocolSignature
                ).order_by(ProtocolSignature.uniqueness_score.desc()).all()
                
                for protocol, signature in results:
                    protocol_data = {
                        'id': protocol.id,
                        'name': protocol.name,
                        'display_name': protocol.display_name,
                        'category': protocol.category,
                        'ports': protocol.ports,
                        'endpoints': protocol.endpoints,
                        'banners': protocol.banners,
                        'rpc_methods': protocol.rpc_methods,
                        'metrics_keywords': protocol.metrics_keywords,
                        'http_paths': protocol.http_paths,
                        'identification_hints': protocol.identification_hints,
                        'signatures': {
                            'port_signature': signature.port_signature,
                            'banner_signature': signature.banner_signature,
                            'endpoint_signature': signature.endpoint_signature,
                            'keyword_signature': signature.keyword_signature,
                            'uniqueness_score': signature.uniqueness_score,
                            'signature_version': signature.signature_version
                        }
                    }
                    protocols.append(protocol_data)
                    
        except Exception as e:
            self.logger.error(f"Failed to load protocols: {e}")
            
        self.logger.info(f"Loaded {len(protocols)} protocols with signatures")
        return protocols
    
    def _perform_intelligent_probing(self, hostname: str, nmap_data: Dict, 
                                   protocols: List[Dict], discovery_id: int) -> Dict:
        """Perform intelligent protocol-specific probing"""
        probe_data = {}
        open_ports = set(nmap_data.get('ports', []))
        
        # Map ports to potential protocols
        port_to_protocols = {}
        for protocol in protocols:
            for port in protocol.get('ports', []):
                if port in open_ports:
                    if port not in port_to_protocols:
                        port_to_protocols[port] = []
                    port_to_protocols[port].append(protocol)
        
        # Probe each relevant port
        for port, potential_protocols in port_to_protocols.items():
            paths_to_probe = set()
            
            for protocol in potential_protocols:
                paths_to_probe.update(protocol.get('http_paths', []))
            
            # HTTP probing
            if paths_to_probe:
                for path in paths_to_probe:
                    try:
                        import time
                        request_start = time.time()
                        
                        protocol_hint = ','.join([p['name'] for p in potential_protocols])
                        
                        response = requests.get(f"http://{hostname}:{port}{path}", timeout=10, verify=False)
                        response_time = (time.time() - request_start) * 1000
                        
                        probe_key = f"{port}{path}"
                        probe_result = {
                            'status': response.status_code,
                            'headers': dict(response.headers),
                            'body': response.text[:1000],
                            'url': f"http://{hostname}:{port}{path}",
                            'response_time_ms': response_time
                        }
                        probe_data[probe_key] = probe_result
                        
                        # Save to database
                        self.persister.save_probe_result(
                            discovery_id=discovery_id,
                            probe_type='http',
                            target_port=port,
                            endpoint_path=path,
                            protocol_hint=protocol_hint,
                            request_data={
                                'method': 'GET',
                                'headers': {'User-Agent': 'DePIN-Discovery-Agent/2.0'},
                                'body': ''
                            },
                            response_data=probe_result,
                            error_info=None
                        )
                        
                    except Exception as e:
                        self.logger.debug(f"HTTP probe failed for {hostname}:{port}{path}: {e}")
        
        return probe_data
    
    def _match_protocol_signatures(self, nmap_data: Dict, probe_data: Dict, 
                                 protocols: List[Dict]) -> Tuple[Optional[str], float, Dict, Dict]:
        """Match protocols using binary signatures and detailed analysis"""
        import time
        
        performance_metrics = {
            'total_protocols_available': len(protocols),
            'binary_filter_time': 0,
            'detailed_analysis_time': 0,
            'candidates_after_binary_filter': 0
        }
        
        # Phase 1: Binary pre-filtering
        binary_start = time.time()
        scan_signatures = HighPerformanceBinaryMatcher.generate_scan_signatures(nmap_data, probe_data)
        candidates = self._binary_filter_protocols(scan_signatures, protocols)
        performance_metrics['binary_filter_time'] = time.time() - binary_start
        performance_metrics['candidates_after_binary_filter'] = len(candidates)
        
        if not candidates:
            return None, 0.0, {"binary_filter": "no_candidates"}, performance_metrics
        
        # Phase 2: Detailed analysis
        detailed_start = time.time()
        best_match = None
        best_score = 0.0
        best_evidence = {}
        
        for protocol_data, binary_score in candidates:
            detailed_score, evidence = self._calculate_detailed_match_score(protocol_data, nmap_data, probe_data)
            final_score = (binary_score * 0.3) + (detailed_score * 0.7)
            
            if final_score > best_score:
                best_score = final_score
                best_match = protocol_data['name']
                best_evidence = {
                    **evidence,
                    'binary_score': binary_score,
                    'detailed_score': detailed_score,
                    'combined_score': final_score
                }
        
        performance_metrics['detailed_analysis_time'] = time.time() - detailed_start
        
        if best_score >= self.detailed_threshold:
            return best_match, best_score, best_evidence, performance_metrics
        else:
            return None, best_score, {"insufficient_confidence": best_score}, performance_metrics
    
    def _binary_filter_protocols(self, scan_signatures: Dict[str, str], protocols: List[Dict]) -> List[Tuple[Dict, float]]:
        """Fast binary signature pre-filtering"""
        candidates = []
        
        for protocol in protocols:
            try:
                sigs = protocol['signatures']
                
                port_sim = HighPerformanceBinaryMatcher.calculate_binary_similarity(
                    scan_signatures['port'], sigs['port_signature']
                )
                banner_sim = HighPerformanceBinaryMatcher.calculate_binary_similarity(
                    scan_signatures['banner'], sigs['banner_signature']
                )
                endpoint_sim = HighPerformanceBinaryMatcher.calculate_binary_similarity(
                    scan_signatures['endpoint'], sigs['endpoint_signature']
                )
                keyword_sim = HighPerformanceBinaryMatcher.calculate_binary_similarity(
                    scan_signatures['keyword'], sigs['keyword_signature']
                )
                
                binary_score = (
                    port_sim * 0.1 +
                    banner_sim * 0.4 +
                    endpoint_sim * 0.2 +
                    keyword_sim * 0.3
                )
                
                uniqueness_boost = 1.0 + (sigs['uniqueness_score'] * 0.2)
                final_score = binary_score * uniqueness_boost
                
                if final_score >= self.binary_threshold:
                    candidates.append((protocol, final_score))
                    
            except Exception as e:
                self.logger.debug(f"Binary matching failed for {protocol.get('name', 'unknown')}: {e}")
        
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[:10]
    
    def _calculate_detailed_match_score(self, protocol: Dict, nmap_data: Dict, probe_data: Dict) -> Tuple[float, Dict]:
        """Calculate detailed traditional matching score"""
        score = 0.0
        evidence = {}
        
        # Port matching (15% weight)
        open_ports = set(nmap_data.get('ports', []))
        expected_ports = set(protocol.get('ports', []))
        port_matches = list(open_ports.intersection(expected_ports))
        
        if port_matches:
            port_score = len(port_matches) / len(expected_ports) if expected_ports else 0
            score += port_score * 0.15
            evidence['port_matches'] = port_matches
        
        # Service banner matching (35% weight)
        banner_matches = []
        for port, service in nmap_data.get('services', {}).items():
            service_text = ' '.join([
                service.get('name', ''),
                service.get('product', ''),
                service.get('version', ''),
                service.get('banner', '')
            ]).lower()
            
            for banner_pattern in protocol.get('banners', []):
                if banner_pattern.lower() in service_text:
                    banner_matches.append({
                        'port': port,
                        'pattern': banner_pattern,
                        'matched_text': service_text[:100]
                    })
        
        if banner_matches:
            score += 0.35
            evidence['banner_matches'] = banner_matches
        
        # HTTP content matching (30% weight)
        content_matches = []
        for endpoint_key, response in probe_data.items():
            if not isinstance(response, dict) or response.get('status') != 200:
                continue
            
            body = response.get('body', '').lower()
            for keyword in protocol.get('metrics_keywords', []):
                if keyword.lower() in body:
                    content_matches.append({
                        'keyword': keyword,
                        'endpoint': endpoint_key
                    })
            
            for hint in protocol.get('identification_hints', []):
                if hint.lower() in body:
                    content_matches.append({
                        'hint': hint,
                        'endpoint': endpoint_key,
                        'type': 'identification_hint'
                    })
        
        if content_matches:
            content_score = min(len(content_matches) * 0.05, 0.30)
            score += content_score
            evidence['content_matches'] = content_matches
        
        # RPC method matching (20% weight)
        rpc_matches = []
        for endpoint_key, response in probe_data.items():
            if 'rpc' in str(endpoint_key).lower():
                for rpc_method in protocol.get('rpc_methods', []):
                    if (rpc_method.lower() in str(endpoint_key).lower() or
                        (response.get('status') == 200 and 
                         rpc_method.lower() in str(response.get('body', '')).lower())):
                        rpc_matches.append({
                            'method': rpc_method,
                            'endpoint': endpoint_key
                        })
        
        if rpc_matches:
            rpc_score = min(len(rpc_matches) * 0.1, 0.20)
            score += rpc_score
            evidence['rpc_matches'] = rpc_matches
        
        return score, evidence
    
    def _convert_to_standard_format(self, discovery_result: DePINDiscoveryResult) -> Dict[str, Any]:
        """Convert DePINDiscoveryResult to standard discovery agent format"""
        return {
            'host': discovery_result.scan_data.get('hostname', 'unknown'),
            'discovery_type': 'depin_protocol',
            'protocol': discovery_result.protocol,
            'confidence': discovery_result.confidence.value,
            'confidence_score': discovery_result.confidence_score,
            'evidence': discovery_result.evidence,
            'scan_data': discovery_result.scan_data,
            'signature_match': discovery_result.signature_match,
            'performance_metrics': discovery_result.performance_metrics,
            'discovery_id': discovery_result.discovery_id,
            'timestamp': datetime.utcnow().isoformat(),
            'agent': 'DePINDiscoveryAgent'
        }
    
    def discover_host(self, host: str) -> List[Dict[str, Any]]:
        """
        Discover DePIN protocol for a single host (legacy interface support).
        
        Args:
            host: Target hostname or IP address
            
        Returns:
            List containing single discovery result
        """
        self.logger.info(f"🔍 Legacy discover_host called for: {host}")
        return self.run(host=host)
    
    def batch_discover(self, hosts: List[str]) -> List[Dict[str, Any]]:
        """
        Perform batch DePIN discovery across multiple hosts.
        
        Args:
            hosts: List of hostnames/IP addresses to discover
            
        Returns:
            List of discovery results for all hosts
        """
        self.logger.info(f"🔍 Starting batch DePIN discovery for {len(hosts)} hosts")
        
        results = []
        for i, host in enumerate(hosts, 1):
            self.logger.info(f"📡 [{i}/{len(hosts)}] Discovering {host}")
            
            try:
                host_results = self.run(host=host)
                results.extend(host_results)
            except Exception as e:
                self.logger.error(f"Failed to discover {host}: {e}")
                # Add error result
                results.append({
                    'host': host,
                    'discovery_type': 'depin_protocol',
                    'protocol': None,
                    'confidence': 'unknown',
                    'confidence_score': 0.0,
                    'evidence': {'error': str(e)},
                    'timestamp': datetime.utcnow().isoformat(),
                    'agent': 'DePINDiscoveryAgent'
                })
        
        self.logger.info(f"✅ Batch discovery completed: {len(results)} results")
        return results
    
    def get_discovery_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about recent discoveries performed by this agent.
        
        Returns:
            Dictionary with discovery statistics
        """
        try:
            with get_db_session() as session:
                # Get statistics for discoveries in current session
                stats = session.execute(
                    text("""SELECT 
                           COUNT(*) as total_discoveries,
                           SUM(CASE WHEN detected_protocol IS NOT NULL THEN 1 ELSE 0 END) as successful,
                           SUM(CASE WHEN scan_status = 'failed' THEN 1 ELSE 0 END) as failed,
                           AVG(scan_duration_seconds) as avg_duration,
                           AVG(confidence_score) as avg_confidence
                       FROM host_discoveries 
                       WHERE session_id = ?"""),
                    [self.session_id]
                ).fetchone()
                
                # Get protocol breakdown
                protocol_stats = session.execute(
                    text("""SELECT detected_protocol, COUNT(*) as count
                       FROM host_discoveries 
                       WHERE session_id = ? AND detected_protocol IS NOT NULL
                       GROUP BY detected_protocol
                       ORDER BY count DESC"""),
                    [self.session_id]
                ).fetchall()
                
                return {
                    'session_id': self.session_id,
                    'total_discoveries': stats[0] or 0,
                    'successful_discoveries': stats[1] or 0,
                    'failed_discoveries': stats[2] or 0,
                    'success_rate': (stats[1] / stats[0] * 100) if stats[0] > 0 else 0,
                    'average_duration_seconds': stats[3] or 0,
                    'average_confidence_score': stats[4] or 0,
                    'protocol_breakdown': {row[0]: row[1] for row in protocol_stats},
                    'timestamp': datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get discovery statistics: {e}")
            return {
                'session_id': self.session_id,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def validate_discovery_result(self, discovery_id: int, actual_protocol: str, 
                                validation_confidence: str = "certain", 
                                validation_source: str = "manual", 
                                notes: str = "") -> bool:
        """
        Add validation data for a discovery result to track accuracy.
        
        Args:
            discovery_id: Database ID of the discovery to validate
            actual_protocol: What the host actually runs
            validation_confidence: 'certain', 'likely', 'unsure'
            validation_source: Source of validation info
            notes: Additional notes
            
        Returns:
            True if validation was saved successfully
        """
        try:
            with get_db_session() as session:
                # Get the original discovery result
                discovery = session.execute(
                    text("SELECT detected_protocol, confidence_level FROM host_discoveries WHERE id = ?"),
                    [discovery_id]
                ).fetchone()
                
                if not discovery:
                    self.logger.error(f"Discovery {discovery_id} not found")
                    return False
                
                detected_protocol, confidence_level = discovery
                
                # Determine accuracy
                detection_correct = (detected_protocol == actual_protocol)
                detection_close = (detected_protocol != actual_protocol and 
                                 detected_protocol is not None and 
                                 actual_protocol is not None)
                
                # Save validation result
                session.execute(
                    text("""INSERT INTO validation_results 
                       (discovery_id, validation_type, validated_by, validation_timestamp,
                        actual_protocol, validation_confidence, validation_source,
                        detection_was_correct, detection_was_close, validation_notes)
                       VALUES (?, 'manual', 'agent', ?, ?, ?, ?, ?, ?, ?)"""),
                    [
                        discovery_id,
                        datetime.utcnow(),
                        actual_protocol,
                        validation_confidence,
                        validation_source,
                        detection_correct,
                        detection_close,
                        notes
                    ]
                )
                session.commit()
                
                self.logger.info(f"Validation saved for discovery {discovery_id}: {actual_protocol} ({'correct' if detection_correct else 'incorrect'})")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to save validation: {e}")
            return False
    
    def cleanup_session(self):
        """Clean up the current scan session"""
        try:
            # Mark session as completed
            with get_db_session() as session:
                session.execute(
                    text("""UPDATE scan_sessions 
                       SET status = 'completed', completed_at = ?
                       WHERE session_id = ?"""),
                    [datetime.utcnow(), self.session_id]
                )
                session.commit()
                
            self.logger.info(f"Scan session {self.session_id} marked as completed")
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup session: {e}")
    
    def process_results(self, scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process scan results for discovery (required by ProcessAgent).
        
        For discovery agents, this method extracts hosts from scan results
        and performs discovery on each host.
        
        Args:
            scan_results: List of scan results containing host information
            
        Returns:
            List of discovery results
        """
        if not scan_results:
            self.logger.warning("No scan results provided for discovery processing")
            return []
        
        discovery_results = []
        
        # Extract unique hosts from scan results
        hosts = set()
        for result in scan_results:
            host = result.get('host') or result.get('hostname') or result.get('ip_address')
            if host:
                hosts.add(host)
        
        # Perform discovery on each host
        for host in hosts:
            try:
                host_results = self.run(host=host)
                discovery_results.extend(host_results)
            except Exception as e:
                self.logger.error(f"Discovery failed for host {host}: {e}")
                # Add error result
                discovery_results.append({
                    'host': host,
                    'discovery_type': 'depin_protocol',
                    'protocol': None,
                    'confidence': 'unknown',
                    'confidence_score': 0.0,
                    'evidence': {'error': str(e)},
                    'timestamp': datetime.utcnow().isoformat(),
                    'agent': 'DePINDiscoveryAgent'
                })
        
        return discovery_results


# Example usage and testing functions
def test_depin_discovery():
    """Test function for the DePIN Discovery Agent"""
    
    # Initialize agent
    agent = DiscoveryAgent()
    
    # Test single host discovery
    test_hosts = [
        "sui-validator.example.com",
        "filecoin-node.example.com", 
        "unknown-host.example.com"
    ]
    
    print("🧪 Testing DePIN Discovery Agent")
    print("=" * 50)
    
    for host in test_hosts:
        print(f"\n🔍 Testing discovery for: {host}")
        
        try:
            results = agent.run(host=host)
            
            if results:
                result = results[0]
                print(f"✅ Protocol: {result.get('protocol', 'Unknown')}")
                print(f"🎯 Confidence: {result.get('confidence', 'unknown')} ({result.get('confidence_score', 0):.3f})")
                print(f"⏱️  Duration: {result.get('performance_metrics', {}).get('total_time', 0):.2f}s")
            else:
                print("❌ No results returned")
                
        except Exception as e:
            print(f"❌ Discovery failed: {e}")
    
    # Show statistics
    print(f"\n📊 Discovery Statistics:")
    stats = agent.get_discovery_statistics()
    print(f"   Total Discoveries: {stats.get('total_discoveries', 0)}")
    print(f"   Success Rate: {stats.get('success_rate', 0):.1f}%")
    print(f"   Average Duration: {stats.get('average_duration_seconds', 0):.2f}s")
    
    # Cleanup
    agent.cleanup_session()
    print(f"\n✅ Test completed")


if __name__ == "__main__":
    test_depin_discovery()