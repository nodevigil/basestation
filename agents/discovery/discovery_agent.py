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
import time
import socket
import re
import traceback
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from enum import Enum

from agents.base import ProcessAgent
from pgdn.core.config import Config
from pgdn.core.database import get_db_session, Protocol, ProtocolSignature
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
    
    @staticmethod
    def _sanitize_string(s: str) -> str:
        """Remove NUL characters and other problematic characters from strings"""
        if not isinstance(s, str):
            s = str(s)
        return s.replace('\x00', '').replace('\r', '').replace('\n', ' ')
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config
        
    def create_scan_session(self, session_id: Optional[str] = None, created_by: Optional[str] = None) -> str:
        """Create a new scan session and return session ID"""
        if session_id is None:
            session_id = str(uuid.uuid4())
            
        try:
            with get_db_session() as session:
                session.execute(
                    text("""INSERT INTO scan_sessions 
                           (session_id, started_at, status, created_by, scanner_version, 
                            total_hosts, successful_detections, failed_scans) 
                           VALUES (:session_id, :started_at, :status, :created_by, :scanner_version, 
                                   :total_hosts, :successful_detections, :failed_scans)
                           ON CONFLICT (session_id) DO UPDATE SET
                           started_at = EXCLUDED.started_at,
                           status = EXCLUDED.status"""),
                    {
                        'session_id': session_id,
                        'started_at': datetime.utcnow(),
                        'status': 'running',
                        'created_by': created_by or 'discovery_agent',
                        'scanner_version': '2.0',
                        'total_hosts': 0,  # Will be updated as hosts are processed
                        'successful_detections': 0,  # Will be updated on completion
                        'failed_scans': 0  # Will be updated on completion
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
                            scan_started_at, scan_status, created_at, updated_at) 
                           VALUES (:session_id, :hostname, :ip_address, 'unknown', 0.0, :started_at, 'scanning', :created_at, :updated_at)
                           RETURNING id"""),
                    {
                        'session_id': session_id,
                        'hostname': hostname,
                        'ip_address': ip_address,
                        'started_at': datetime.utcnow(),
                        'created_at': datetime.utcnow(),
                        'updated_at': datetime.utcnow()
                    }
                )
                discovery_id = result.fetchone()[0]
                session.commit()
                
        except Exception as e:
            logging.error(f"Failed to start host discovery: {e}")
            discovery_id = hash(f"{session_id}_{hostname}") % 1000000
            
        return discovery_id
    
    def save_network_scan_data(self, discovery_id: int, nmap_data: Dict, nmap_command: str = "", nmap_duration: float = 0.0):
        """Save network scan results"""
        try:
            with get_db_session() as session:
                # Calculate total ports scanned - try to extract from command or use default
                total_ports_scanned = 1000  # Default fallback
                if "p1-" in nmap_command:
                    try:
                        port_range = nmap_command.split("p1-")[1].split()[0]
                        total_ports_scanned = int(port_range)
                    except:
                        pass
                
                # Determine scan technique
                scan_technique = 'fallback_socket' if nmap_data.get('fallback_scan') else 'nmap'
                
                session.execute(
                    text("""INSERT INTO network_scan_data 
                           (discovery_id, open_ports, total_ports_scanned, scan_technique, 
                            services_detected, nmap_command, nmap_output, nmap_duration_seconds, created_at) 
                           VALUES (:discovery_id, :open_ports, :total_ports_scanned, :scan_technique,
                                   :services_detected, :nmap_command, :nmap_output, :nmap_duration_seconds, :created_at)"""),
                    {
                        'discovery_id': discovery_id,
                        'open_ports': json.dumps(nmap_data.get('ports', [])),
                        'total_ports_scanned': total_ports_scanned,
                        'scan_technique': scan_technique,
                        'services_detected': json.dumps(nmap_data.get('services', {})),
                        'nmap_command': nmap_command,
                        'nmap_output': json.dumps(nmap_data)[:10000],  # Truncate large output
                        'nmap_duration_seconds': nmap_duration,
                        'created_at': datetime.utcnow()
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
                # Calculate confidence contribution based on response characteristics
                confidence_contribution = 0.0
                if response_data.get('status') == 200:
                    confidence_contribution += 0.3
                if response_data.get('body') and len(str(response_data.get('body', ''))) > 0:
                    confidence_contribution += 0.2
                if response_data.get('headers') and len(response_data.get('headers', {})) > 0:
                    confidence_contribution += 0.1
                if response_data.get('response_time_ms', 0) < 5000:  # Fast response
                    confidence_contribution += 0.1
                
                session.execute(
                    text("""INSERT INTO protocol_probe_results 
                       (discovery_id, probe_type, target_port, endpoint_path, protocol_hint,
                        request_method, request_headers, request_body, request_timestamp,
                        response_status_code, response_headers, response_body, response_size_bytes,
                        response_time_ms, error_occurred, error_message, timeout_occurred,
                        confidence_contribution, created_at, updated_at)
                       VALUES (:discovery_id, :probe_type, :target_port, :endpoint_path, :protocol_hint,
                               :request_method, :request_headers, :request_body, :request_timestamp,
                               :response_status_code, :response_headers, :response_body, :response_size_bytes,
                               :response_time_ms, :error_occurred, :error_message, :timeout_occurred,
                               :confidence_contribution, :created_at, :updated_at)"""),
                    {
                        'discovery_id': discovery_id,
                        'probe_type': probe_type,
                        'target_port': target_port,
                        'endpoint_path': endpoint_path or '',
                        'protocol_hint': protocol_hint or '',
                        'request_method': self._sanitize_string(request_data.get('method', '')),
                        'request_headers': json.dumps(request_data.get('headers', {})),
                        'request_body': self._sanitize_string(str(request_data.get('body', '')))[:5000],
                        'request_timestamp': datetime.utcnow(),
                        'response_status_code': response_data.get('status'),
                        'response_headers': json.dumps(response_data.get('headers', {})),
                        'response_body': self._sanitize_string(str(response_data.get('body', '')))[:10000],
                        'response_size_bytes': len(str(response_data.get('body', ''))),
                        'response_time_ms': response_data.get('response_time_ms', 0),
                        'error_occurred': error_info is not None,
                        'error_message': self._sanitize_string(error_info.get('message', '')) if error_info else '',
                        'timeout_occurred': error_info.get('timeout', False) if error_info else False,
                        'confidence_contribution': confidence_contribution,
                        'created_at': datetime.utcnow(),
                        'updated_at': datetime.utcnow()
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
                       SET detected_protocol = :detected_protocol, confidence_level = :confidence_level, 
                           confidence_score = :confidence_score, detection_method = :detection_method, 
                           scan_completed_at = :scan_completed_at, scan_duration_seconds = :scan_duration_seconds,
                           scan_status = 'completed', performance_metrics = :performance_metrics
                       WHERE id = :discovery_id"""),
                    {
                        'detected_protocol': result.protocol,
                        'confidence_level': result.confidence.value,
                        'confidence_score': result.confidence_score,
                        'detection_method': result.signature_match.get('analysis_method', 'unknown') if result.signature_match else 'unknown',
                        'scan_completed_at': datetime.utcnow(),
                        'scan_duration_seconds': total_duration,
                        'performance_metrics': json.dumps(result.performance_metrics or {}),
                        'discovery_id': discovery_id
                    }
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
    
    def run(self, host: Optional[str] = None, force: bool = False, *args, **kwargs) -> List[Dict[str, Any]]:
        """
        Execute DePIN protocol discovery for the specified host.
        
        Args:
            host: Target host for discovery (IP address or hostname)
            force: Force discovery even if host was recently scanned
            
        Returns:
            List of discovery results in standard format
        """
        if not host:
            self.logger.warning("No host specified for DePIN discovery")
            return []
            
        # Check for recent scans unless force is used
        if not force:
            recent_scan = self._check_recent_scan(host)
            if recent_scan:
                self.logger.info(f"🔍 Using cached results for {host} (scanned {recent_scan['days_ago']:.1f} days ago)")
                self.logger.info(f"   Use --force to bypass cache and rescan")
                return [self._convert_cached_result_to_standard_format(recent_scan)]
        
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
    
    def _check_recent_scan(self, hostname: str) -> Optional[Dict[str, Any]]:
        """
        Check if the host has been scanned recently (within the last week).
        
        Args:
            hostname: Target hostname to check
            
        Returns:
            Dictionary with recent scan data if found, None otherwise
        """
        try:
            with get_db_session() as session:
                # Look for successful scans within the last 7 days
                from sqlalchemy import text
                from datetime import datetime, timedelta
                
                # Calculate cutoff date (7 days ago)
                cutoff_date = datetime.utcnow() - timedelta(days=7)
                
                result = session.execute(
                    text("""SELECT 
                           hd.id, hd.hostname, hd.ip_address, hd.detected_protocol,
                           hd.confidence_level, hd.confidence_score, hd.scan_completed_at,
                           hd.scan_duration_seconds, hd.performance_metrics
                       FROM host_discoveries hd
                       WHERE (hd.hostname = :hostname OR hd.ip_address = :hostname)
                         AND hd.scan_status = 'completed'
                         AND hd.scan_completed_at > :cutoff_date
                       ORDER BY hd.scan_completed_at DESC
                       LIMIT 1"""),
                    {'hostname': hostname, 'cutoff_date': cutoff_date}
                ).fetchone()
                
                if result:
                    # Calculate days ago manually
                    scan_date = result[6]  # scan_completed_at
                    if scan_date:
                        days_ago = (datetime.utcnow() - scan_date).total_seconds() / 86400
                    else:
                        days_ago = 0
                    
                    return {
                        'discovery_id': result[0],
                        'hostname': result[1],
                        'ip_address': result[2],
                        'detected_protocol': result[3],
                        'confidence_level': result[4],
                        'confidence_score': result[5],
                        'scan_completed_at': result[6],
                        'scan_duration_seconds': result[7],
                        'performance_metrics': result[8],
                        'days_ago': days_ago
                    }
                
                return None
                
        except Exception as e:
            self.logger.debug(f"Error checking recent scan for {hostname}: {e}")
            return None
    
    def _convert_cached_result_to_standard_format(self, cached_result: Dict[str, Any]) -> Dict[str, Any]:
        """Convert cached scan result to standard discovery agent format"""
        return {
            'host': cached_result.get('hostname', 'unknown'),
            'discovery_type': 'depin_protocol',
            'protocol': cached_result.get('detected_protocol'),
            'confidence': cached_result.get('confidence_level', 'unknown'),
            'confidence_score': cached_result.get('confidence_score', 0.0),
            'evidence': {'cached_result': True, 'original_scan_date': cached_result.get('scan_completed_at')},
            'scan_data': {
                'hostname': cached_result.get('hostname'),
                'ip_address': cached_result.get('ip_address'),
                'cached': True,
                'days_ago': cached_result.get('days_ago')
            },
            'signature_match': None,
            'performance_metrics': cached_result.get('performance_metrics', {}),
            'discovery_id': cached_result.get('discovery_id'),
            'timestamp': datetime.utcnow().isoformat(),
            'agent': 'DePINDiscoveryAgent',
            'cached': True,
            'cache_age_days': cached_result.get('days_ago')
        }
    
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
    
    def discover_host(self, host: str, force: bool = False) -> List[Dict[str, Any]]:
        """
        Discover DePIN protocol for a single host (legacy interface support).
        
        Args:
            host: Target hostname or IP address
            force: Force discovery even if host was recently scanned
            
        Returns:
            List containing single discovery result
        """
        self.logger.info(f"🔍 Legacy discover_host called for: {host}")
        return self.run(host=host, force=force)
    
    def batch_discover(self, hosts: List[str], force: bool = False) -> List[Dict[str, Any]]:
        """
        Perform batch DePIN discovery across multiple hosts.
        
        Args:
            hosts: List of hostnames/IP addresses to discover
            force: Force discovery even if hosts were recently scanned
            
        Returns:
            List of discovery results for all hosts
        """
        self.logger.info(f"🔍 Starting batch DePIN discovery for {len(hosts)} hosts")
        
        results = []
        for i, host in enumerate(hosts, 1):
            self.logger.info(f"📡 [{i}/{len(hosts)}] Discovering {host}")
            
            try:
                host_results = self.run(host=host, force=force)
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
                       WHERE session_id = :session_id"""),
                    {'session_id': self.session_id}
                ).fetchone()
                
                # Get protocol breakdown
                protocol_stats = session.execute(
                    text("""SELECT detected_protocol, COUNT(*) as count
                       FROM host_discoveries 
                       WHERE session_id = :session_id AND detected_protocol IS NOT NULL
                       GROUP BY detected_protocol
                       ORDER BY count DESC"""),
                    {'session_id': self.session_id}
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
                    text("SELECT detected_protocol, confidence_level FROM host_discoveries WHERE id = :discovery_id"),
                    {'discovery_id': discovery_id}
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
                       VALUES (:discovery_id, 'manual', 'agent', :validation_timestamp, 
                               :actual_protocol, :validation_confidence, :validation_source,
                               :detection_was_correct, :detection_was_close, :validation_notes)"""),
                    {
                        'discovery_id': discovery_id,
                        'validation_timestamp': datetime.utcnow(),
                        'actual_protocol': actual_protocol,
                        'validation_confidence': validation_confidence,
                        'validation_source': validation_source,
                        'detection_was_correct': detection_correct,
                        'detection_was_close': detection_close,
                        'validation_notes': notes
                    }
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
                       SET status = 'completed', completed_at = :completed_at
                       WHERE session_id = :session_id"""),
                    {
                        'completed_at': datetime.utcnow(),
                        'session_id': self.session_id
                    }
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

    def _load_protocols_with_signatures(self) -> List[Dict[str, Any]]:
        """
        Load all protocols with their signatures from the database.
        
        Returns:
            List of protocol dictionaries with signature data
        """
        try:
            self.logger.info("🔍 Starting to load protocols with signatures...")
            
            with get_db_session() as session:
                self.logger.info("🔗 Database session established")
                
                # First check individual counts
                protocol_count = session.query(Protocol).count()
                signature_count = session.query(ProtocolSignature).count()
                self.logger.info(f"📊 Found {protocol_count} protocols and {signature_count} signatures in database")
                
                # Query protocols with their signatures
                self.logger.info("🔄 Starting database join query...")
                protocols_query = session.query(Protocol, ProtocolSignature).join(
                    ProtocolSignature, Protocol.id == ProtocolSignature.protocol_id
                ).all()
                self.logger.info(f"✅ Join query completed, processing {len(protocols_query)} results...")
                
                if not protocols_query:
                    self.logger.warning("No protocols with signatures found in database")
                    return []
                
                self.logger.info(f"Found {len(protocols_query)} protocols with signatures after join")
                
                protocols = []
                self.logger.info("🔄 Processing protocol results...")
                
                for i, (protocol_obj, signature_obj) in enumerate(protocols_query):
                    if i % 5 == 0:  # Log every 5th protocol
                        self.logger.info(f"   Processing protocol {i+1}/{len(protocols_query)}: {protocol_obj.name}")
                    
                    protocol_dict = {
                        'id': protocol_obj.id,
                        'name': protocol_obj.name,
                        'display_name': protocol_obj.display_name,
                        'category': protocol_obj.category,
                        'ports': protocol_obj.ports or [],
                        'endpoints': protocol_obj.endpoints or [],
                        'banners': protocol_obj.banners or [],
                        'rpc_methods': protocol_obj.rpc_methods or [],
                        'metrics_keywords': protocol_obj.metrics_keywords or [],
                        'http_paths': protocol_obj.http_paths or [],
                        'identification_hints': protocol_obj.identification_hints or [],
                        'signature': {
                            'port_signature': signature_obj.port_signature,
                            'banner_signature': signature_obj.banner_signature,
                            'endpoint_signature': signature_obj.endpoint_signature,
                            'keyword_signature': signature_obj.keyword_signature,
                            'uniqueness_score': signature_obj.uniqueness_score,
                            'signature_version': signature_obj.signature_version
                        }
                    }
                    protocols.append(protocol_dict)
                
                self.logger.info(f"✅ Successfully processed all {len(protocols)} protocols with signatures")
                return protocols
                
        except Exception as e:
            self.logger.error(f"❌ Failed to load protocols with signatures: {e}")
            import traceback
            self.logger.error(f"Stack trace: {traceback.format_exc()}")
            return []
    
    def _perform_intelligent_probing(self, hostname: str, nmap_data: Dict, protocols: List[Dict], discovery_id: int) -> Dict[str, Any]:
        """
        Perform intelligent protocol-specific probing based on discovered ports and protocol definitions.
        
        Args:
            hostname: Target hostname
            nmap_data: Network scan data
            protocols: List of protocol definitions
            discovery_id: Database discovery ID for persistence
            
        Returns:
            Dictionary of probe results
        """
        probe_data = {}
        open_ports = nmap_data.get('ports', [])
        
        if not open_ports:
            self.logger.warning("No open ports available for probing")
            return probe_data
        
        self.logger.info(f"Starting probing on {len(open_ports)} open ports: {open_ports}")
        
        # Create port-to-protocol mapping based on protocol definitions
        port_to_protocols = {}
        for protocol in protocols:
            for port in protocol.get('ports', []):
                if port in open_ports:
                    if port not in port_to_protocols:
                        port_to_protocols[port] = []
                    port_to_protocols[port].append(protocol)
        
        self.logger.info(f"Mapped {len(port_to_protocols)} ports to protocols")
        
        successful_probes = 0
        
        # Probe each port with protocol-specific requests
        self.logger.info(f"🔄 Starting to probe {len(open_ports)} open ports...")
        for i, port in enumerate(open_ports):
            self.logger.debug(f"   Probing port {i+1}/{len(open_ports)}: {port}")
            relevant_protocols = port_to_protocols.get(port, [])
            
            # HTTP/HTTPS probing for web ports
            if port in [80, 8080, 3000, 5000, 9000]:
                self.logger.debug(f"   Starting HTTP probing for port {port}...")
                try:
                    probe_data.update(self._probe_http_endpoints(hostname, port, relevant_protocols, discovery_id))
                    successful_probes += 1
                    self.logger.debug(f"   ✅ HTTP probing completed for port {port}")
                except Exception as e:
                    self.logger.debug(f"   ❌ HTTP probing failed for port {port}: {e}")
                    
            elif port in [443, 8443, 9100]:
                self.logger.debug(f"   Starting HTTPS probing for port {port}...")
                try:
                    probe_data.update(self._probe_https_endpoints(hostname, port, relevant_protocols, discovery_id))
                    successful_probes += 1
                    self.logger.debug(f"   ✅ HTTPS probing completed for port {port}")
                except Exception as e:
                    self.logger.debug(f"   ❌ HTTPS probing failed for port {port}: {e}")
            
            # RPC probing for potential RPC ports
            if port in [9000, 9100, 8545, 8546] or any(p.get('name') == 'sui' for p in relevant_protocols):
                self.logger.debug(f"   Starting RPC probing for port {port}...")
                try:
                    probe_data.update(self._probe_rpc_endpoints(hostname, port, relevant_protocols, discovery_id))
                    successful_probes += 1
                    self.logger.debug(f"   ✅ RPC probing completed for port {port}")
                except Exception as e:
                    self.logger.debug(f"   ❌ RPC probing failed for port {port}: {e}")
        
        self.logger.info(f"✅ Completed probing with {successful_probes} successful responses")
        return probe_data
    
    def _probe_http_endpoints(self, hostname: str, port: int, protocols: List[Dict], discovery_id: int) -> Dict[str, Any]:
        """Probe HTTP endpoints for protocol identification"""
        probe_results = {}
        
        # Common endpoints to probe
        endpoints = ['/health', '/status', '/metrics', '/info', '/api/v1/status', '/']
        
        # Add protocol-specific endpoints
        for protocol in protocols:
            endpoints.extend(protocol.get('http_paths', []))
            endpoints.extend(protocol.get('endpoints', []))
        
        # Remove duplicates and limit
        endpoints = list(set(endpoints))[:10]
        
        self.logger.info(f"   Probing {len(endpoints)} HTTP endpoints on port {port}")
        
        for i, endpoint in enumerate(endpoints):
            try:
                self.logger.debug(f"     Endpoint {i+1}/{len(endpoints)}: {endpoint}")
                url = f"http://{hostname}:{port}{endpoint}"
                
                import requests
                import signal
                
                def timeout_handler(signum, frame):
                    raise requests.exceptions.Timeout(f"Request to {url} timed out after 5 seconds")
                
                # Set aggressive timeout for individual requests
                old_handler = signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(5)  # 5 second timeout per request
                
                try:
                    response = requests.get(url, timeout=3, verify=False)  # 3 second requests timeout
                    signal.alarm(0)  # Cancel alarm
                    signal.signal(signal.SIGALRM, old_handler)  # Restore previous handler
                    
                    response_data = {
                        'status': response.status_code,
                        'headers': dict(response.headers),
                        'body': response.text[:5000],  # Limit body size
                        'url': url,
                        'response_time_ms': response.elapsed.total_seconds() * 1000
                    }
                    
                    request_data = {
                        'method': 'GET',
                        'headers': {},
                        'body': ''
                    }
                    
                    # Save probe result to database
                    protocol_hint = protocols[0].get('name', '') if protocols else ''
                    self.persister.save_probe_result(
                        discovery_id, 'http', port, endpoint, protocol_hint, 
                        request_data, response_data
                    )
                    
                    probe_results[f"http_{port}_{endpoint}"] = response_data
                    self.logger.debug(f"     ✅ HTTP {endpoint} responded: {response.status_code}")
                    
                except (requests.exceptions.Timeout, requests.exceptions.RequestException) as e:
                    signal.alarm(0)  # Cancel alarm
                    signal.signal(signal.SIGALRM, old_handler)  # Restore previous handler
                    self.logger.debug(f"     ⏰ HTTP {endpoint} timeout/error: {str(e)[:100]}")
                    
                    error_info = {'message': str(e), 'timeout': True}
                    self.persister.save_probe_result(
                        discovery_id, 'http', port, endpoint, 
                        protocols[0].get('name', '') if protocols else '',
                        {'method': 'GET'}, {}, error_info
                    )
                    continue
                    
            except Exception as e:
                self.logger.debug(f"     ❌ HTTP {endpoint} failed: {str(e)[:100]}")
                error_info = {'message': str(e), 'timeout': 'timeout' in str(e).lower()}
                self.persister.save_probe_result(
                    discovery_id, 'http', port, endpoint, 
                    protocols[0].get('name', '') if protocols else '',
                    {'method': 'GET'}, {}, error_info
                )
        
        return probe_results
    
    def _probe_https_endpoints(self, hostname: str, port: int, protocols: List[Dict], discovery_id: int) -> Dict[str, Any]:
        """Probe HTTPS endpoints for protocol identification"""
        probe_results = {}
        
        # Common HTTPS endpoints
        endpoints = ['/health', '/status', '/metrics', '/info', '/api/v1/status', '/']
        
        # Add protocol-specific endpoints
        for protocol in protocols:
            endpoints.extend(protocol.get('http_paths', []))
            endpoints.extend(protocol.get('endpoints', []))
        
        endpoints = list(set(endpoints))[:10]
        
        self.logger.info(f"   Probing {len(endpoints)} HTTPS endpoints on port {port}")
        
        for i, endpoint in enumerate(endpoints):
            try:
                self.logger.debug(f"     Endpoint {i+1}/{len(endpoints)}: {endpoint}")
                url = f"https://{hostname}:{port}{endpoint}"
                
                import requests
                import signal
                
                def timeout_handler(signum, frame):
                    raise requests.exceptions.Timeout(f"Request to {url} timed out after 5 seconds")
                
                # Set aggressive timeout for individual requests
                old_handler = signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(5)  # 5 second timeout per request
                
                try:
                    response = requests.get(url, timeout=3, verify=False)  # 3 second requests timeout
                    signal.alarm(0)  # Cancel alarm
                    signal.signal(signal.SIGALRM, old_handler)  # Restore previous handler
                    
                    response_data = {
                        'status': response.status_code,
                        'headers': dict(response.headers),
                        'body': response.text[:5000],
                        'url': url,
                        'response_time_ms': response.elapsed.total_seconds() * 1000
                    }
                    
                    request_data = {
                        'method': 'GET',
                        'headers': {},
                        'body': ''
                    }
                    
                    protocol_hint = protocols[0].get('name', '') if protocols else ''
                    self.persister.save_probe_result(
                        discovery_id, 'https', port, endpoint, protocol_hint,
                        request_data, response_data
                    )
                    
                    probe_results[f"https_{port}_{endpoint}"] = response_data
                    self.logger.debug(f"     ✅ HTTPS {endpoint} responded: {response.status_code}")
                    
                except (requests.exceptions.Timeout, requests.exceptions.RequestException) as e:
                    signal.alarm(0)  # Cancel alarm
                    signal.signal(signal.SIGALRM, old_handler)  # Restore previous handler
                    self.logger.debug(f"     ⏰ HTTPS {endpoint} timeout/error: {str(e)[:100]}")
                    
                    error_info = {'message': str(e), 'timeout': True}
                    self.persister.save_probe_result(
                        discovery_id, 'https', port, endpoint,
                        protocols[0].get('name', '') if protocols else '',
                        {'method': 'GET'}, {}, error_info
                    )
                    continue
                    
            except Exception as e:
                self.logger.debug(f"     ❌ HTTPS {endpoint} failed: {str(e)[:100]}")
                error_info = {'message': str(e), 'timeout': 'timeout' in str(e).lower()}
                self.persister.save_probe_result(
                    discovery_id, 'https', port, endpoint,
                    protocols[0].get('name', '') if protocols else '',
                    {'method': 'GET'}, {}, error_info
                )
        
        return probe_results
    
    def _probe_rpc_endpoints(self, hostname: str, port: int, protocols: List[Dict], discovery_id: int) -> Dict[str, Any]:
        """Probe RPC endpoints for protocol identification"""
        probe_results = {}
        
        # Protocol-specific RPC methods
        rpc_methods = []
        for protocol in protocols:
            rpc_methods.extend(protocol.get('rpc_methods', []))
        
        # Default RPC methods if none specified
        if not rpc_methods:
            rpc_methods = ['sui_getChainId', 'eth_chainId', 'system.listMethods', 'getinfo']
        
        self.logger.info(f"   Probing {len(rpc_methods)} RPC methods on port {port}")
        
        for i, method in enumerate(rpc_methods[:5]):  # Limit to 5 methods
            try:
                self.logger.debug(f"     RPC Method {i+1}/{min(5, len(rpc_methods))}: {method}")
                url = f"http://{hostname}:{port}/"
                
                payload = {
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": [],
                    "id": 1
                }
                
                import requests
                import signal
                
                def timeout_handler(signum, frame):
                    raise requests.exceptions.Timeout(f"RPC request to {url} timed out after 5 seconds")
                
                # Set aggressive timeout for individual requests
                old_handler = signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(5)  # 5 second timeout per request
                
                try:
                    response = requests.post(url, json=payload, timeout=3, verify=False)  # 3 second requests timeout
                    signal.alarm(0)  # Cancel alarm
                    signal.signal(signal.SIGALRM, old_handler)  # Restore previous handler
                    
                    response_data = {
                        'status': response.status_code,
                        'headers': dict(response.headers),
                        'body': response.text[:5000],
                        'url': url,
                        'response_time_ms': response.elapsed.total_seconds() * 1000
                    }
                    
                    request_data = {
                        'method': 'POST',
                        'headers': {'Content-Type': 'application/json'},
                        'body': str(payload)
                    }
                    
                    protocol_hint = protocols[0].get('name', '') if protocols else ''
                    self.persister.save_probe_result(
                        discovery_id, 'rpc', port, '/', protocol_hint,
                        request_data, response_data
                    )
                    
                    probe_results[f"rpc_{port}_{method}"] = response_data
                    self.logger.debug(f"     ✅ RPC {method} responded: {response.status_code}")
                    
                except (requests.exceptions.Timeout, requests.exceptions.RequestException) as e:
                    signal.alarm(0)  # Cancel alarm
                    signal.signal(signal.SIGALRM, old_handler)  # Restore previous handler
                    self.logger.debug(f"     ⏰ RPC {method} timeout/error: {str(e)[:100]}")
                    
                    error_info = {'message': str(e), 'timeout': True}
                    self.persister.save_probe_result(
                        discovery_id, 'rpc', port, '/',
                        protocols[0].get('name', '') if protocols else '',
                        {'method': 'POST', 'body': str(payload)},
                        {}, error_info
                    )
                    continue
                    
            except Exception as e:
                self.logger.debug(f"     ❌ RPC {method} failed: {str(e)[:100]}")
                error_info = {'message': str(e), 'timeout': 'timeout' in str(e).lower()}
                self.persister.save_probe_result(
                    discovery_id, 'rpc', port, '/',
                    protocols[0].get('name', '') if protocols else '',
                    {'method': 'POST', 'body': str(payload) if 'payload' in locals() else ''},
                    {}, error_info
                )
        
        return probe_results

    def _match_protocol_signatures(self, nmap_data: Dict, probe_data: Dict, protocols: List[Dict]) -> Tuple[Optional[str], float, Dict[str, Any], Dict[str, Any]]:
        """
        Match protocol signatures against scan and probe data.
        
        Args:
            nmap_data: Network scan data
            probe_data: Protocol probe data
            protocols: List of protocol definitions with signatures
            
        Returns:
            Tuple of (protocol_name, confidence_score, evidence, performance_metrics)
        """
        import time
        start_time = time.time()
        
        self.logger.info(f"🔍 Starting signature matching for {len(protocols)} protocols...")
        
        best_protocol = None
        best_confidence = 0.0
        best_evidence = {}
        
        # Generate signatures from scan data
        self.logger.info("🔄 Generating scan signatures...")
        scan_signatures = HighPerformanceBinaryMatcher.generate_scan_signatures(
            nmap_data, probe_data, signature_length=256
        )
        self.logger.info("✅ Scan signatures generated")
        
        # Debug log the protocols being checked
        self.logger.info(f"Checking signatures for {len(protocols)} protocols")
        for protocol in protocols:
            if protocol.get('name') == 'sui':
                self.logger.info(f"Found Sui protocol in database: {protocol.get('display_name', 'Unknown')}")
        
        # Check each protocol
        self.logger.info("🔄 Starting protocol matching loop...")
        for i, protocol in enumerate(protocols):
            if i % 5 == 0:  # Log every 5th protocol
                self.logger.info(f"   Checking protocol {i+1}/{len(protocols)}: {protocol.get('name', 'unknown')}")
            
            protocol_name = protocol.get('name', 'unknown')
            signature_data = protocol.get('signature', {})
            
            # Calculate similarity scores for each signature type
            port_similarity = 0.0
            banner_similarity = 0.0
            endpoint_similarity = 0.0
            keyword_similarity = 0.0
            
            if signature_data.get('port_signature'):
                port_similarity = HighPerformanceBinaryMatcher.calculate_binary_similarity(
                    scan_signatures['port'], signature_data['port_signature']
                )
            
            if signature_data.get('banner_signature'):
                banner_similarity = HighPerformanceBinaryMatcher.calculate_binary_similarity(
                    scan_signatures['banner'], signature_data['banner_signature']
                )
            
            if signature_data.get('endpoint_signature'):
                endpoint_similarity = HighPerformanceBinaryMatcher.calculate_binary_similarity(
                    scan_signatures['endpoint'], signature_data['endpoint_signature']
                )
            
            if signature_data.get('keyword_signature'):
                keyword_similarity = HighPerformanceBinaryMatcher.calculate_binary_similarity(
                    scan_signatures['keyword'], signature_data['keyword_signature']
                )
            
            # Additional manual checks for Sui protocol
            manual_score = 0.0
            manual_evidence = {}
            
            if protocol_name == 'sui':
                # Check for Sui-specific indicators
                open_ports = nmap_data.get('ports', [])
                
                # Sui commonly uses ports 9000, 9100
                if 9000 in open_ports or 9100 in open_ports:
                    manual_score += 0.3
                    manual_evidence['sui_ports'] = 'Found Sui common ports'
                
                # Check probe responses for Sui indicators
                for probe_key, probe_response in probe_data.items():
                    if isinstance(probe_response, dict):
                        body = probe_response.get('body', '').lower()
                        headers = str(probe_response.get('headers', {})).lower()
                        
                        # Look for Sui-specific keywords
                        sui_keywords = ['sui', 'move', 'epoch', 'validator', 'checkpoint', 'object', 'digest']
                        found_keywords = [kw for kw in sui_keywords if kw in body or kw in headers]
                        
                        if found_keywords:
                            manual_score += min(0.4, len(found_keywords) * 0.1)
                            manual_evidence['sui_keywords'] = found_keywords
                        
                        # Check for JSON-RPC structure typical of Sui
                        if '"jsonrpc"' in body or '"result"' in body:
                            manual_score += 0.2
                            manual_evidence['jsonrpc'] = 'Found JSON-RPC structure'
                        
                        # Check for Sui-specific error messages or responses
                        if 'sui_' in body or 'move' in body:
                            manual_score += 0.3
                            manual_evidence['sui_specific'] = 'Found Sui-specific content'
            
            # Weighted combination of signature similarities and manual checks
            uniqueness_score = signature_data.get('uniqueness_score', 0.5)
            combined_similarity = (
                port_similarity * 0.25 +
                banner_similarity * 0.25 +
                endpoint_similarity * 0.25 +
                keyword_similarity * 0.25
            )
            
            # Final confidence calculation
            confidence = (combined_similarity * 0.6 + manual_score * 0.4) * uniqueness_score
            
            # Debug logging for Sui
            if protocol_name == 'sui':
                self.logger.info(f"Sui signature analysis:")
                self.logger.info(f"  Port similarity: {port_similarity:.3f}")
                self.logger.info(f"  Banner similarity: {banner_similarity:.3f}")
                self.logger.info(f"  Endpoint similarity: {endpoint_similarity:.3f}")
                self.logger.info(f"  Keyword similarity: {keyword_similarity:.3f}")
                self.logger.info(f"  Manual score: {manual_score:.3f}")
                self.logger.info(f"  Combined similarity: {combined_similarity:.3f}")
                self.logger.info(f"  Uniqueness score: {uniqueness_score:.3f}")
                self.logger.info(f"  Final confidence: {confidence:.3f}")
                self.logger.info(f"  Manual evidence: {manual_evidence}")
            
            # Update best match
            if confidence > best_confidence:
                best_confidence = confidence
                best_protocol = protocol_name
                best_evidence = {
                    'signature_similarities': {
                        'port': port_similarity,
                        'banner': banner_similarity,
                        'endpoint': endpoint_similarity,
                        'keyword': keyword_similarity
                    },
                    'manual_checks': manual_evidence,
                    'combined_similarity': combined_similarity,
                    'manual_score': manual_score,
                    'uniqueness_score': uniqueness_score,
                    'protocol_details': {
                        'name': protocol.get('name'),
                        'display_name': protocol.get('display_name'),
                        'category': protocol.get('category')
                    }
                }
        
        self.logger.info(f"✅ Protocol matching completed. Best match: {best_protocol} ({best_confidence:.3f})")
        
        performance_metrics = {
            'signature_matching_time': time.time() - start_time,
            'protocols_checked': len(protocols),
            'best_protocol': best_protocol,
            'best_confidence': best_confidence
        }
        
        return best_protocol, best_confidence, best_evidence, performance_metrics
