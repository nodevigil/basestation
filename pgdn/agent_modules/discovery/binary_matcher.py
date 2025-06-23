"""
Binary Signature Matcher - High-performance signature matching
"""

import base64
import hashlib
import struct
import re
from typing import Dict, List


class HighPerformanceBinaryMatcher:
    """High-performance binary signature matching"""
    
    @staticmethod
    def generate_scan_signatures(nmap_data: Dict, probe_data: Dict, signature_length: int = 256) -> Dict[str, str]:
        """Generate binary signatures from scan data"""
        scan_ports = [str(port) for port in nmap_data.get('ports', [])]
        scan_banners = []
        scan_endpoints = []
        scan_keywords = []
        
        # Extract service banners
        for port, service in nmap_data.get('services', {}).items():
            banners = [service.get('name', ''), service.get('product', ''), service.get('banner', '')]
            scan_banners.extend([b for b in banners if b])
        
        # Extract probe data
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
        """Extract DePIN-specific keywords"""
        if not text or len(text) > 10000:
            return []
        
        keywords = set()
        text_lower = text.lower()
        
        # DePIN patterns
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
        except:
            return 0.0