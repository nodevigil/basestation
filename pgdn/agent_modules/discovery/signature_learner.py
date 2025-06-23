"""
Training and Improvement System for DePIN Discovery

This system uses labeled scan data from known hosts to improve protocol detection
through multiple approaches: signature learning, AI fine-tuning preparation, and
pattern analysis.
"""

import json
import logging
import hashlib
import base64
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime
from collections import defaultdict, Counter
from dataclasses import dataclass
import sqlite3
import os


@dataclass
class LabeledScanData:
    """Structure for labeled training data"""
    hostname: str
    true_protocol: str
    scan_data: Dict[str, Any]
    confidence: float = 1.0  # How confident we are in this label
    source: str = "manual"  # manual, verified, automated
    timestamp: datetime = None


class SignatureLearner:
    """Learn and improve binary signatures from labeled data"""
    
    def __init__(self, existing_signatures: Dict[str, Any] = None):
        self.existing_signatures = existing_signatures or {}
        self.learned_patterns = defaultdict(list)
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def learn_from_labeled_data(self, labeled_data: List[LabeledScanData]) -> Dict[str, Any]:
        """
        Learn new signatures from labeled scan data
        
        Args:
            labeled_data: List of labeled scan examples
            
        Returns:
            Dictionary of learned signatures and improvements
        """
        self.logger.info(f"🎓 Learning from {len(labeled_data)} labeled examples")
        
        # Group by protocol
        protocol_examples = defaultdict(list)
        for example in labeled_data:
            protocol_examples[example.true_protocol].append(example)
        
        learned_signatures = {}
        improvements = {}
        
        for protocol, examples in protocol_examples.items():
            self.logger.info(f"📊 Learning {protocol} from {len(examples)} examples")
            
            # Extract features from all examples
            port_patterns = []
            banner_patterns = []
            endpoint_patterns = []
            keyword_patterns = []
            
            for example in examples:
                scan_data = example.scan_data
                nmap_data = scan_data.get('nmap', {})
                probe_data = scan_data.get('probes', {})
                
                # Extract ports
                ports = nmap_data.get('ports', [])
                port_patterns.extend([str(p) for p in ports])
                
                # Extract service banners
                services = nmap_data.get('services', {})
                for port, service in services.items():
                    banners = [service.get('name', ''), service.get('product', ''), service.get('banner', '')]
                    banner_patterns.extend([b for b in banners if b])
                
                # Extract endpoints and keywords from probes
                for probe_key, probe_response in probe_data.items():
                    if isinstance(probe_response, dict):
                        # Extract endpoint from URL
                        url = probe_response.get('url', '')
                        if url:
                            try:
                                from urllib.parse import urlparse
                                parsed = urlparse(url)
                                endpoint_patterns.append(parsed.path)
                            except:
                                pass
                        
                        # Extract keywords from response body
                        body = probe_response.get('body', '')
                        if body:
                            keywords = self._extract_keywords(body, protocol)
                            keyword_patterns.extend(keywords)
            
            # Generate signatures
            signature_data = {
                'port_signature': self._create_optimized_signature(port_patterns),
                'banner_signature': self._create_optimized_signature(banner_patterns),
                'endpoint_signature': self._create_optimized_signature(endpoint_patterns),
                'keyword_signature': self._create_optimized_signature(keyword_patterns),
                'uniqueness_score': self._calculate_uniqueness_score(protocol, protocol_examples),
                'examples_count': len(examples),
                'confidence_score': sum(ex.confidence for ex in examples) / len(examples)
            }
            
            learned_signatures[protocol] = signature_data
            
            # Compare with existing signatures
            if protocol in self.existing_signatures:
                improvements[protocol] = self._compare_signatures(
                    self.existing_signatures[protocol], signature_data
                )
        
        return {
            'learned_signatures': learned_signatures,
            'improvements': improvements,
            'protocol_stats': {p: len(examples) for p, examples in protocol_examples.items()}
        }
    
    def _extract_keywords(self, text: str, protocol: str) -> List[str]:
        """Extract protocol-specific keywords from text"""
        if not text:
            return []
        
        text_lower = text.lower()
        keywords = set()
        
        # Protocol-specific keyword patterns
        protocol_patterns = {
            'sui': ['sui', 'move', 'epoch', 'validator', 'checkpoint', 'object', 'digest', 'transaction'],
            'ethereum': ['eth', 'geth', 'web3', 'blockchain', 'transaction', 'block', 'gas'],
            'filecoin': ['filecoin', 'lotus', 'miner', 'storage', 'retrieval', 'deal', 'sector'],
            'celestia': ['celestia', 'blob', 'namespace', 'height', 'rollup', 'da'],
            'bittensor': ['bittensor', 'tao', 'subnet', 'neuron', 'synapse', 'axon'],
        }
        
        # General DePIN patterns
        general_patterns = [
            'jsonrpc', 'rpc', 'api', 'node', 'peer', 'consensus', 'validator',
            'chain', 'network', 'protocol', 'version', 'status', 'health'
        ]
        
        # Check protocol-specific patterns
        if protocol in protocol_patterns:
            for keyword in protocol_patterns[protocol]:
                if keyword in text_lower:
                    keywords.add(keyword)
        
        # Check general patterns
        for keyword in general_patterns:
            if keyword in text_lower:
                keywords.add(keyword)
        
        return list(keywords)
    
    def _create_optimized_signature(self, patterns: List[str], signature_length: int = 256) -> str:
        """Create optimized binary signature from patterns"""
        if not patterns:
            return base64.b64encode(b'\x00' * (signature_length // 8)).decode('utf-8')
        
        # Count pattern frequency
        pattern_counts = Counter(patterns)
        
        # Use most common patterns for signature
        signature_bytes = bytearray(signature_length // 8)
        
        for pattern, count in pattern_counts.most_common(20):  # Top 20 patterns
            # Weight by frequency
            weight = min(count, 5)  # Cap at 5 for balance
            
            pattern_hash = hashlib.sha256(str(pattern).lower().encode('utf-8')).digest()
            
            for i in range(min(6, len(pattern_hash))):
                byte_val = pattern_hash[i]
                bit_pos = byte_val % signature_length
                byte_pos = bit_pos // 8
                bit_offset = bit_pos % 8
                
                # Apply weight
                for _ in range(weight):
                    signature_bytes[byte_pos] |= (1 << bit_offset)
        
        return base64.b64encode(bytes(signature_bytes)).decode('utf-8')
    
    def _calculate_uniqueness_score(self, protocol: str, all_protocols: Dict[str, List]) -> float:
        """Calculate how unique this protocol's patterns are"""
        if len(all_protocols) < 2:
            return 1.0
        
        # Simple uniqueness based on number of examples vs total
        protocol_examples = len(all_protocols[protocol])
        total_examples = sum(len(examples) for examples in all_protocols.values())
        
        # Protocols with fewer examples get higher uniqueness (rarer = more unique)
        uniqueness = 1.0 - (protocol_examples / total_examples)
        return max(0.3, min(1.0, uniqueness + 0.5))  # Clamp between 0.3 and 1.0
    
    def _compare_signatures(self, old_sig: Dict, new_sig: Dict) -> Dict:
        """Compare old vs new signatures to measure improvement"""
        improvements = {}
        
        for sig_type in ['port_signature', 'banner_signature', 'endpoint_signature', 'keyword_signature']:
            if old_sig.get(sig_type) and new_sig.get(sig_type):
                # Calculate similarity (lower = more different = potentially better)
                similarity = self._calculate_similarity(old_sig[sig_type], new_sig[sig_type])
                improvements[f'{sig_type}_change'] = 1.0 - similarity
        
        improvements['examples_added'] = new_sig.get('examples_count', 0)
        improvements['confidence_improvement'] = new_sig.get('confidence_score', 0) - old_sig.get('confidence_score', 0)
        
        return improvements
    
    def _calculate_similarity(self, sig1: str, sig2: str) -> float:
        """Calculate similarity between two binary signatures"""
        try:
            bytes1 = base64.b64decode(sig1)
            bytes2 = base64.b64decode(sig2)
            
            if len(bytes1) != len(bytes2):
                return 0.0
            
            matching_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(bytes1, bytes2))
            total_bits = len(bytes1) * 8
            
            return 1.0 - (matching_bits / total_bits)
        except:
            return 0.0


class AITrainingDataPreparer:
    """Prepare training data for AI fine-tuning"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def prepare_fine_tuning_data(self, labeled_data: List[LabeledScanData]) -> Dict[str, Any]:
        """
        Prepare data for AI model fine-tuning
        
        Returns:
            Dictionary with training examples in various formats
        """
        self.logger.info(f"🤖 Preparing fine-tuning data from {len(labeled_data)} examples")
        
        # OpenAI fine-tuning format
        openai_examples = []
        
        # Anthropic training format
        anthropic_examples = []
        
        # General training format
        general_examples = []
        
        for example in labeled_data:
            # Create structured prompt
            context = self._prepare_context(example.hostname, example.scan_data)
            
            # OpenAI format
            openai_example = {
                "messages": [
                    {
                        "role": "system",
                        "content": "You are an expert in DePIN protocol identification. Analyze network scan data and identify the protocol."
                    },
                    {
                        "role": "user",
                        "content": self._build_analysis_prompt(context)
                    },
                    {
                        "role": "assistant",
                        "content": json.dumps({
                            "protocol": example.true_protocol,
                            "confidence": example.confidence,
                            "reasoning": f"Identified as {example.true_protocol} based on scan patterns",
                            "key_indicators": self._extract_key_indicators(example.scan_data, example.true_protocol)
                        })
                    }
                ]
            }
            openai_examples.append(openai_example)
            
            # General format for analysis
            general_example = {
                "input": context,
                "output": {
                    "protocol": example.true_protocol,
                    "confidence": example.confidence,
                    "source": example.source
                },
                "metadata": {
                    "hostname": example.hostname,
                    "timestamp": example.timestamp.isoformat() if example.timestamp else None
                }
            }
            general_examples.append(general_example)
        
        return {
            "openai_format": openai_examples,
            "anthropic_format": anthropic_examples,
            "general_format": general_examples,
            "statistics": {
                "total_examples": len(labeled_data),
                "protocols": list(set(ex.true_protocol for ex in labeled_data)),
                "confidence_avg": sum(ex.confidence for ex in labeled_data) / len(labeled_data)
            }
        }
    
    def _prepare_context(self, hostname: str, scan_data: Dict) -> Dict:
        """Prepare context for AI training"""
        nmap_data = scan_data.get('nmap', {})
        probe_data = scan_data.get('probes', {})
        
        return {
            'hostname': hostname,
            'network_scan': {
                'open_ports': nmap_data.get('ports', []),
                'services': nmap_data.get('services', {})
            },
            'protocol_probes': {
                key: {
                    'status_code': resp.get('status'),
                    'headers': dict(list(resp.get('headers', {}).items())[:3]),
                    'body_preview': str(resp.get('body', ''))[:500]
                }
                for key, resp in probe_data.items()
                if isinstance(resp, dict)
            }
        }
    
    def _build_analysis_prompt(self, context: Dict) -> str:
        """Build training prompt"""
        return f"""Analyze this network scan data to identify the DePIN protocol:

Hostname: {context['hostname']}
Open Ports: {context['network_scan']['open_ports']}
Services: {json.dumps(context['network_scan']['services'], indent=2)}
Probe Results: {json.dumps(context['protocol_probes'], indent=2)}

Identify the protocol and provide reasoning."""
    
    def _extract_key_indicators(self, scan_data: Dict, protocol: str) -> List[str]:
        """Extract key indicators that led to protocol identification"""
        indicators = []
        
        nmap_data = scan_data.get('nmap', {})
        probe_data = scan_data.get('probes', {})
        
        # Port indicators
        ports = nmap_data.get('ports', [])
        protocol_ports = {
            'sui': [9000, 9100],
            'ethereum': [8545, 8546],
            'filecoin': [1234, 3453],
            'celestia': [26657, 26658]
        }
        
        if protocol in protocol_ports:
            matching_ports = set(ports) & set(protocol_ports[protocol])
            if matching_ports:
                indicators.append(f"Common {protocol} ports: {list(matching_ports)}")
        
        # Service indicators
        services = nmap_data.get('services', {})
        for port, service in services.items():
            if service.get('product'):
                indicators.append(f"Service on port {port}: {service['product']}")
        
        # Probe indicators
        for probe_key, probe_response in probe_data.items():
            if isinstance(probe_response, dict):
                body = probe_response.get('body', '')
                if protocol.lower() in body.lower():
                    indicators.append(f"Protocol name in response body")
                if 'jsonrpc' in body.lower():
                    indicators.append(f"JSON-RPC endpoint detected")
        
        return indicators[:5]  # Limit to top 5 indicators


class TrainingDataManager:
    """Manage training data storage and retrieval"""
    
    def __init__(self, db_path: str = "training_data.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(self.__class__.__name__)
        self._init_database()
    
    def _init_database(self):
        """Initialize training data database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS labeled_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT NOT NULL,
                    true_protocol TEXT NOT NULL,
                    scan_data TEXT NOT NULL,
                    confidence REAL DEFAULT 1.0,
                    source TEXT DEFAULT 'manual',
                    timestamp TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS training_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_name TEXT NOT NULL,
                    examples_count INTEGER,
                    protocols TEXT,
                    improvements TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
    
    def add_labeled_example(self, hostname: str, true_protocol: str, scan_data: Dict, 
                          confidence: float = 1.0, source: str = "manual") -> int:
        """Add a labeled training example"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                INSERT INTO labeled_scans (hostname, true_protocol, scan_data, confidence, source, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                hostname,
                true_protocol,
                json.dumps(scan_data),
                confidence,
                source,
                datetime.utcnow().isoformat()
            ))
            return cursor.lastrowid
    
    def get_labeled_examples(self, protocol: str = None, min_confidence: float = 0.0) -> List[LabeledScanData]:
        """Retrieve labeled examples"""
        query = """
            SELECT hostname, true_protocol, scan_data, confidence, source, timestamp
            FROM labeled_scans
            WHERE confidence >= ?
        """
        params = [min_confidence]
        
        if protocol:
            query += " AND true_protocol = ?"
            params.append(protocol)
        
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(query, params).fetchall()
        
        examples = []
        for row in rows:
            examples.append(LabeledScanData(
                hostname=row[0],
                true_protocol=row[1],
                scan_data=json.loads(row[2]),
                confidence=row[3],
                source=row[4],
                timestamp=datetime.fromisoformat(row[5]) if row[5] else None
            ))
        
        return examples
    
    def save_training_session(self, session_name: str, results: Dict):
        """Save training session results"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO training_sessions (session_name, examples_count, protocols, improvements)
                VALUES (?, ?, ?, ?)
            """, (
                session_name,
                results.get('total_examples', 0),
                json.dumps(results.get('protocols', [])),
                json.dumps(results.get('improvements', {}))
            ))


def quick_training_example():
    """Quick example of how to use the training system"""
    
    # Example: You know prod.sui.infstones.io runs Sui
    known_sui_data = {
        'nmap': {
            'ports': [9000, 9100],
            'services': {
                9000: {'name': 'http', 'product': 'unknown'},
                9100: {'name': 'http', 'product': 'unknown'}
            }
        },
        'probes': {
            'http_9000_root': {
                'status': 200,
                'headers': {'content-type': 'application/json'},
                'body': '{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request"}}',
                'response_time_ms': 45
            }
        }
    }
    
    # Create labeled example
    labeled_example = LabeledScanData(
        hostname="prod.sui.infstones.io",
        true_protocol="sui",
        scan_data=known_sui_data,
        confidence=1.0,
        source="verified",
        timestamp=datetime.utcnow()
    )
    
    # Train signature learner
    learner = SignatureLearner()
    results = learner.learn_from_labeled_data([labeled_example])
    
    print("🎓 Training Results:")
    print(f"Learned signatures for: {list(results['learned_signatures'].keys())}")
    
    # Prepare AI training data
    ai_preparer = AITrainingDataPreparer()
    ai_data = ai_preparer.prepare_fine_tuning_data([labeled_example])
    
    print(f"🤖 Prepared {len(ai_data['openai_format'])} examples for AI training")
    
    return results, ai_data


if __name__ == "__main__":
    print("🚀 DePIN Discovery Training System")
    print("Run quick_training_example() to see how it works!")
    
    # Run example
    results, ai_data = quick_training_example()
    
    print("\n📊 Example training data prepared successfully!")
    print("Use this system to:")
    print("1. Add your known protocol scan data")
    print("2. Learn improved signatures")
    print("3. Prepare AI fine-tuning data")
    print("4. Track training improvements")

class ScanDataSignatureLearner(SignatureLearner):
    """Learn signatures from existing scan data in the database"""
    
    def __init__(self, existing_signatures: Dict[str, Any] = None, db_path: str = None):
        super().__init__(existing_signatures)
        self.db_path = db_path or "training_data.db"
        self.training_manager = TrainingDataManager(self.db_path)
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def learn_from_scans(self, protocol: str = None, 
                        min_confidence: float = 0.7, max_examples: int = 1000) -> Dict[str, Any]:
        """
        Learn signatures from existing scan data in the database
        
        Args:
            protocol: Specific protocol to learn (required)
            min_confidence: Minimum confidence threshold for scans to include
            max_examples: Maximum examples to process per protocol
            
        Returns:
            Dictionary with learning results and statistics
        """
        if not protocol:
            raise ValueError("Protocol name is required for signature learning")
        
        self.logger.info(f"🎓 Learning signatures from existing scans")
        self.logger.info(f"   Protocol: {protocol}")
        self.logger.info(f"   Min confidence: {min_confidence}")
        self.logger.info(f"   Max examples: {max_examples}")
        
        # Start learning session for tracking
        session_id = self._start_learning_session(protocol, protocol, min_confidence, max_examples)
        
        try:
            # Extract scan data from database
            scan_data = self._extract_scan_data_from_database(protocol, min_confidence, max_examples)
            
            if not scan_data:
                self.logger.warning("No suitable scan data found for learning")
                return {'success': False, 'error': 'No scan data found'}
            
            # Convert to labeled training data
            labeled_examples = []
            for scan in scan_data:
                try:
                    labeled_data = self._convert_discovery_to_labeled_data(scan, protocol)
                    if labeled_data:
                        labeled_examples.append(labeled_data)
                except Exception as e:
                    self.logger.warning(f"Failed to convert scan {scan.get('hostname', 'unknown')}: {e}")
            
            if not labeled_examples:
                self.logger.warning("No valid labeled examples created from scan data")
                return {'success': False, 'error': 'No valid examples created'}
            
            # Learn signatures using the parent class method
            learning_results = self.learn_from_labeled_data(labeled_examples)
            
            # Ensure uniqueness and update database
            unique_signatures = self._ensure_signature_uniqueness(learning_results['learned_signatures'])
            update_results = self._update_protocol_signatures_database(unique_signatures, protocol)
            
            # Complete learning session
            session_results = {
                'signatures_learned': len(unique_signatures),
                'examples_processed': len(labeled_examples),
                'protocols_affected': list(unique_signatures.keys()),
                'database_updates': update_results,
                'improvements': learning_results.get('improvements', {})
            }
            
            self._complete_learning_session(session_id, session_results)
            
            return {
                'success': True,
                'session_id': session_id,
                'signatures_learned': unique_signatures,
                'statistics': session_results,
                'protocol': protocol
            }
            
        except Exception as e:
            self.logger.error(f"Learning failed: {e}")
            self._fail_learning_session(session_id, str(e))
            raise
    
    def _extract_scan_data_from_database(self, protocol: str = None, min_confidence: float = 0.7, 
                                       limit: int = 1000) -> List[Dict[str, Any]]:
        """Extract scan data from validator_scans table by protocol relationship"""
        from pgdn.core.database import get_db_session, ValidatorScan, ValidatorAddress, Protocol
        
        try:
            with get_db_session() as session:
                # Query validator_scans table with protocol relationship
                query = session.query(ValidatorScan, ValidatorAddress, Protocol).join(
                    ValidatorAddress, ValidatorScan.validator_address_id == ValidatorAddress.id
                ).join(
                    Protocol, ValidatorAddress.protocol_id == Protocol.id
                ).filter(
                    ValidatorScan.failed == False,
                    ValidatorScan.scan_results.isnot(None)
                )
                
                if protocol:
                    # Filter by protocol name
                    query = query.filter(Protocol.name == protocol)
                
                # Order by creation date and limit results
                scans = query.order_by(ValidatorScan.created_at.desc()).limit(limit).all()
                
                scan_data = []
                for scan, validator_address, protocol_obj in scans:
                    scan_results = scan.scan_results
                    
                    # Extract protocol information from the relationship
                    protocol_name = protocol_obj.name
                    
                    # Calculate a simple confidence score based on scan completeness
                    confidence = self._calculate_scan_confidence(scan_results)
                    
                    if confidence >= min_confidence:
                        scan_record = {
                            'hostname': scan.ip_address,
                            'detected_protocol': protocol_name,
                            'confidence_score': confidence,
                            'scan_completed_at': scan.created_at,
                            'discovery_id': scan.id,
                            'protocol_name': protocol_name,
                            'scan_type': f'{protocol_name}_scan',
                            'network_scan_data': self._extract_network_data(scan_results),
                            'probe_results': self._extract_probe_data(scan_results)
                        }
                        
                        scan_data.append(scan_record)
                
                self.logger.info(f"Extracted {len(scan_data)} scan records from validator_scans table for protocol: {protocol or 'all'}")
                return scan_data
                
        except Exception as e:
            self.logger.error(f"Failed to extract scan data: {e}")
            return []
    
    def _convert_discovery_to_labeled_data(self, scan_record: Dict[str, Any], protocol: str) -> LabeledScanData:
        """Convert a host discovery record to labeled training data"""
        # Build scan_data structure expected by the parent class
        nmap_data = scan_record['network_scan_data']
        
        # Convert probe results to the expected format
        probes = {}
        for probe in scan_record['probe_results']:
            key = f"{probe['probe_type']}_{probe['target_port']}_{probe['endpoint_path'] or ''}"
            probes[key] = probe['response_data']
        
        scan_data = {
            'nmap': {
                'ports': nmap_data.get('open_ports', []),
                'services': nmap_data.get('services_detected', {})
            },
            'probes': probes
        }
        
        return LabeledScanData(
            hostname=scan_record['hostname'],
            true_protocol=scan_record['detected_protocol'],
            scan_data=scan_data,
            confidence=scan_record['confidence_score'],
            source=protocol,  # Use protocol name as source
            timestamp=scan_record['scan_completed_at']
        )
    
    def _ensure_signature_uniqueness(self, learned_signatures: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure learned signatures are unique across the database"""
        from pgdn.core.database import get_db_session, ProtocolSignature, Protocol
        from sqlalchemy import text
        
        unique_signatures = {}
        
        try:
            with get_db_session() as session:
                # Get existing signatures for comparison
                existing_sigs = session.execute(
                    text("""SELECT p.name, ps.port_signature, ps.banner_signature, 
                               ps.endpoint_signature, ps.keyword_signature
                           FROM protocol_signatures ps
                           JOIN protocols p ON ps.protocol_id = p.id""")
                ).fetchall()
                
                existing_by_protocol = {}
                for sig in existing_sigs:
                    existing_by_protocol[sig.name] = {
                        'port_signature': sig.port_signature,
                        'banner_signature': sig.banner_signature,
                        'endpoint_signature': sig.endpoint_signature,
                        'keyword_signature': sig.keyword_signature
                    }
                
                # Check each learned signature for uniqueness
                for protocol, signature_data in learned_signatures.items():
                    if self._check_signature_uniqueness(signature_data, existing_by_protocol, protocol):
                        unique_signatures[protocol] = signature_data
                        self.logger.info(f"✅ Signature for {protocol} is unique")
                    else:
                        self.logger.warning(f"⚠️  Signature for {protocol} is not unique, skipping")
                
                return unique_signatures
                
        except Exception as e:
            self.logger.error(f"Failed to check signature uniqueness: {e}")
            # Return original signatures if uniqueness check fails
            return learned_signatures
    
    def _check_signature_uniqueness(self, new_signature: Dict[str, Any], 
                                  existing_signatures: Dict[str, Dict], 
                                  protocol: str) -> bool:
        """Check if a signature is unique enough to warrant updating"""
        if protocol not in existing_signatures:
            return True  # No existing signature for this protocol
        
        existing = existing_signatures[protocol]
        
        # Check if any component is exactly the same (indicating no improvement)
        for sig_type in ['port_signature', 'banner_signature', 'endpoint_signature', 'keyword_signature']:
            if (new_signature.get(sig_type) == existing.get(sig_type) and 
                new_signature.get(sig_type) is not None):
                # If any signature component is identical, check if we have enough new examples
                new_examples = new_signature.get('examples_count', 0)
                if new_examples < 5:  # Need at least 5 new examples to justify update
                    return False
        
        # Check for duplicate across other protocols (cross-protocol uniqueness)
        new_port_sig = new_signature.get('port_signature')
        if new_port_sig:
            for other_protocol, other_sig in existing_signatures.items():
                if other_protocol != protocol and other_sig.get('port_signature') == new_port_sig:
                    self.logger.warning(f"Port signature for {protocol} matches {other_protocol}")
                    return False
        
        return True
    
    def _update_protocol_signatures_database(self, signatures: Dict[str, Any], protocol: str) -> Dict[str, Any]:
        """Update protocol signatures in the database"""
        from pgdn.core.database import get_db_session, Protocol, ProtocolSignature
        from sqlalchemy import text
        
        update_results = {'updated': [], 'created': [], 'errors': []}
        
        try:
            with get_db_session() as session:
                for protocol_name, signature_data in signatures.items():
                    try:
                        # Get protocol ID
                        protocol = session.execute(
                            text("SELECT id FROM protocols WHERE name = :name"),
                            {'name': protocol_name}
                        ).fetchone()
                        
                        if not protocol:
                            self.logger.warning(f"Protocol {protocol_name} not found in database")
                            update_results['errors'].append(f"Protocol {protocol_name} not found")
                            continue
                        
                        protocol_id = protocol.id
                        
                        # Check if signature exists
                        existing = session.execute(
                            text("SELECT signature_version FROM protocol_signatures WHERE protocol_id = :id"),
                            {'id': protocol_id}
                        ).fetchone()
                        
                        if existing:
                            # Update existing signature
                            session.execute(
                                text("""UPDATE protocol_signatures 
                                       SET port_signature = :port_sig,
                                           banner_signature = :banner_sig,
                                           endpoint_signature = :endpoint_sig,
                                           keyword_signature = :keyword_sig,
                                           uniqueness_score = :uniqueness_score,
                                           signature_version = signature_version + 1
                                       WHERE protocol_id = :protocol_id"""),
                                {
                                    'port_sig': signature_data['port_signature'],
                                    'banner_sig': signature_data['banner_signature'],
                                    'endpoint_sig': signature_data['endpoint_signature'],
                                    'keyword_sig': signature_data['keyword_signature'],
                                    'uniqueness_score': signature_data.get('uniqueness_score', 0.5),
                                    'protocol_id': protocol_id
                                }
                            )
                            update_results['updated'].append(protocol_name)
                            self.logger.info(f"✅ Updated signature for {protocol_name}")
                        else:
                            # Create new signature
                            session.execute(
                                text("""INSERT INTO protocol_signatures 
                                       (protocol_id, port_signature, banner_signature, endpoint_signature, 
                                        keyword_signature, uniqueness_score, signature_version)
                                       VALUES (:protocol_id, :port_sig, :banner_sig, :endpoint_sig, 
                                               :keyword_sig, :uniqueness_score, 1)"""),
                                {
                                    'protocol_id': protocol_id,
                                    'port_sig': signature_data['port_signature'],
                                    'banner_sig': signature_data['banner_signature'],
                                    'endpoint_sig': signature_data['endpoint_signature'],
                                    'keyword_sig': signature_data['keyword_signature'],
                                    'uniqueness_score': signature_data.get('uniqueness_score', 0.5)
                                }
                            )
                            update_results['created'].append(protocol_name)
                            self.logger.info(f"✅ Created new signature for {protocol_name}")
                        
                        # Save to training data manager for tracking (simplified to avoid serialization issues)
                        try:
                            self.training_manager.add_labeled_example(
                                hostname=f"learned_from_scans_{protocol_name}",
                                true_protocol=protocol_name,
                                scan_data={
                                    'learning_metadata': {
                                        'examples_count': int(signature_data.get('examples_count', 0)),
                                        'confidence_score': float(signature_data.get('confidence_score', 0.0)),
                                        'protocol': str(protocol)
                                    }
                                },
                                confidence=float(signature_data.get('confidence_score', 0.0)),
                                source=str(protocol)
                            )
                        except Exception as training_error:
                            self.logger.warning(f"Failed to save training data for {protocol_name}: {training_error}")
                            # Continue processing even if training data save fails
                        
                    except Exception as e:
                        error_msg = f"Failed to update {protocol_name}: {e}"
                        self.logger.error(error_msg)
                        update_results['errors'].append(error_msg)
                
                session.commit()
                return update_results
                
        except Exception as e:
            self.logger.error(f"Database update failed: {e}")
            return {'updated': [], 'created': [], 'errors': [str(e)]}
    
    def _start_learning_session(self, protocol: str, filter_protocol: str = None, 
                              min_confidence: float = 0.7, max_examples: int = 1000) -> str:
        """Start a learning session for tracking"""
        session_id = f"scan_learning_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{protocol}"
        
        self.training_manager.save_training_session(session_id, {
            'session_type': 'scan_data_learning',
            'protocol': protocol,
            'protocol_filter': filter_protocol,
            'min_confidence': min_confidence,
            'max_examples': max_examples,
            'status': 'started',
            'started_at': datetime.utcnow().isoformat()
        })
        
        return session_id
    
    def _complete_learning_session(self, session_id: str, results: Dict) -> None:
        """Complete a learning session with results"""
        results.update({
            'status': 'completed',
            'completed_at': datetime.utcnow().isoformat()
        })
        
        self.training_manager.save_training_session(f"{session_id}_completed", results)
    
    def _fail_learning_session(self, session_id: str, error: str) -> None:
        """Mark a learning session as failed"""
        self.training_manager.save_training_session(f"{session_id}_failed", {
            'status': 'failed',
            'error': error,
            'failed_at': datetime.utcnow().isoformat()
        })
    
    def _infer_protocol_from_scan(self, scan_results: Dict[str, Any]) -> str:
        """Infer the protocol type from scan results"""
        # Check for explicit source first
        source = scan_results.get('source', '')
        if 'filecoin' in source.lower():
            return 'filecoin'
        elif 'sui' in source.lower():
            return 'sui'
        elif 'lotus' in source.lower():
            return 'filecoin'
        
        # Check protocol_scan section
        protocol_scan = scan_results.get('protocol_scan', {})
        scan_type = protocol_scan.get('scan_type', '')
        if 'filecoin' in scan_type.lower():
            return 'filecoin'
        elif 'sui' in scan_type.lower():
            return 'sui'
        
        # Check for specific API endpoints that indicate protocols
        if protocol_scan.get('lotus_api_exposed'):
            return 'filecoin'
        
        # Default based on source
        if source:
            return source.split('_')[0] if '_' in source else source
        
        return 'unknown'
    
    def _calculate_scan_confidence(self, scan_results: Dict[str, Any]) -> float:
        """Calculate confidence score based on scan completeness"""
        confidence = 0.0
        
        # Base confidence for having scan results
        confidence += 0.3
        
        # Check if scan completed successfully
        if not scan_results.get('failed', True):
            confidence += 0.2
        
        # Check for network scan data
        generic_scan = scan_results.get('generic_scan', {})
        if generic_scan.get('open_ports'):
            confidence += 0.1
        if generic_scan.get('banners'):
            confidence += 0.1
        
        # Check for protocol-specific scan
        protocol_scan = scan_results.get('protocol_scan', {})
        if protocol_scan:
            confidence += 0.2
            
            # Bonus for specific protocol indicators
            if protocol_scan.get('lotus_api_exposed') or protocol_scan.get('storage_api_exposed'):
                confidence += 0.1
        
        return min(1.0, confidence)
    
    def _extract_network_data(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract network scan data from scan results"""
        generic_scan = scan_results.get('generic_scan', {})
        nmap_data = generic_scan.get('nmap', {})
        
        open_ports = generic_scan.get('open_ports', [])
        
        # Convert nmap ports to services dict with proper structure
        services_detected = {}
        for port_info in nmap_data.get('ports', []):
            port = port_info.get('port')
            if port:
                # Create service dict with expected structure
                services_detected[str(port)] = {
                    'name': port_info.get('service', 'unknown'),
                    'product': port_info.get('product', ''),
                    'version': port_info.get('version', ''),
                    'banner': ''  # Will be filled from banners if available
                }
        
        # Add banner information to services
        banners = generic_scan.get('banners', {})
        for port_str, banner_data in banners.items():
            if port_str in services_detected:
                # Extract actual banner text
                if isinstance(banner_data, str):
                    services_detected[port_str]['banner'] = banner_data
                elif isinstance(banner_data, dict):
                    # If banner_data is a dict, try to extract meaningful text
                    services_detected[port_str]['banner'] = str(banner_data)
        
        return {
            'open_ports': open_ports,
            'services_detected': services_detected,
            'banners': banners,
            'nmap_data': nmap_data
        }
    
    def _extract_probe_data(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract probe results from scan results"""
        probe_results = []
        
        # Extract protocol-specific probe data
        protocol_scan = scan_results.get('protocol_scan', {})
        if protocol_scan:
            # Add API endpoint probes
            for api_type in ['lotus_api', 'storage_api', 'market_api']:
                url_key = f'{api_type}_url'
                exposed_key = f'{api_type}_exposed'
                
                if protocol_scan.get(url_key) and protocol_scan.get(exposed_key):
                    probe_results.append({
                        'probe_type': api_type,
                        'target_port': self._extract_port_from_url(protocol_scan[url_key]),
                        'endpoint_path': self._extract_path_from_url(protocol_scan[url_key]),
                        'response_data': protocol_scan.get(f'{api_type[:-4]}_info', {})
                    })
        
        # Extract web probe data
        web_probes = scan_results.get('web_probes', {})
        for target, probe_data in web_probes.items():
            if ':' in target:
                host, port = target.split(':', 1)
                for probe_type, result in probe_data.items():
                    if result.get('detected'):
                        probe_results.append({
                            'probe_type': f'web_{probe_type}',
                            'target_port': int(port),
                            'endpoint_path': '/',
                            'response_data': result
                        })
        
        return probe_results
    
    def _extract_port_from_url(self, url: str) -> int:
        """Extract port number from URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.port or (443 if parsed.scheme == 'https' else 80)
        except:
            return 80
    
    def _extract_path_from_url(self, url: str) -> str:
        """Extract path from URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.path or '/'
        except:
            return '/'

# Add new methods to the existing SignatureLearner class
def learn_from_existing_scans(self, protocol: str = None, 
                            min_confidence: float = 0.7, max_examples: int = 1000) -> Dict[str, Any]:
    """
    Learn signatures from existing scan data (convenience method)
    
    This method creates a ScanDataSignatureLearner and uses it to learn from existing scans.
    """
    scan_learner = ScanDataSignatureLearner(self.existing_signatures)
    return scan_learner.learn_from_scans(protocol, min_confidence, max_examples)

# Monkey patch the method onto SignatureLearner
SignatureLearner.learn_from_existing_scans = learn_from_existing_scans