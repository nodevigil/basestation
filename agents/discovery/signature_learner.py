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