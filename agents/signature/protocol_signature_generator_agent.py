"""
Enhanced Protocol Signature Generator Agent

This agent combines the best features from both signature generation approaches:
- Maintains your existing ProcessAgent structure and database integration
- Adds high-performance binary signature generation for fast matching
- Includes comprehensive DePIN protocol definitions
- Provides hybrid matching with binary pre-filtering + detailed analysis
"""

import json
import hashlib
import re
import base64
import struct
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime, timezone
from collections import Counter

from agents.base import ProcessAgent
from core.config import Config
from core.database import get_db_session, ValidatorScan
from core.database import Protocol, ProtocolSignature


class ProtocolSignatureGeneratorAgent(ProcessAgent):
    """
    Agent for generating high-performance binary protocol signatures from database protocols.
    
    This agent processes protocol definitions from the database to create optimized binary 
    signatures that can be used by other agents for fast protocol identification and matching.
    It does NOT match scan results - it only generates signatures from protocol definitions.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the Enhanced Protocol Signature Generator Agent.
        
        Args:
            config: Configuration instance
        """
        super().__init__(config, "ProtocolSignatureGeneratorAgent")
        
        # Signature generation parameters
        self.min_uniqueness_score = 0.6
        self.signature_length = 256  # bits for each signature component
        
        self.logger.info("🔏 Protocol Signature Generator Agent initialized")
    
    def process_results(self, scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate binary signatures from protocol definitions in the database.
        
        Args:
            scan_results: List of scan result dictionaries (not used, just passed through)
            
        Returns:
            List of scan results (unchanged, as this agent only generates signatures)
        """
        # Generate/update signatures from database protocols
        updated_signatures = self._generate_signatures_from_protocols()
        
        self.logger.info(f"✅ Generated/updated {len(updated_signatures)} protocol signatures")
        
        # Return scan results unchanged - this agent only generates signatures
        return scan_results

    def _generate_signatures_from_protocols(self) -> List[str]:
        """
        Generate binary signatures from protocol definitions in the database.
        
        Returns:
            List of protocol names that had signatures generated/updated
        """
        updated_protocols = []
        
        try:
            with get_db_session() as session:
                # Get all protocols from database
                protocols = session.query(Protocol).all()
                
                if not protocols:
                    self.logger.warning("No protocols found in database for signature generation")
                    return []
                
                self.logger.info(f"🔏 Generating signatures for {len(protocols)} protocols from database")
                
                for protocol in protocols:
                    try:
                        # Generate binary signatures from protocol data
                        port_sig = self._create_optimized_binary_signature(
                            [str(p) for p in protocol.ports], 'port'
                        )
                        banner_sig = self._create_optimized_binary_signature(
                            protocol.banners, 'banner'
                        )
                        endpoint_sig = self._create_optimized_binary_signature(
                            protocol.endpoints + protocol.http_paths, 'endpoint'
                        )
                        keyword_sig = self._create_optimized_binary_signature(
                            protocol.metrics_keywords + protocol.identification_hints, 'keyword'
                        )
                        
                        # Calculate uniqueness score based on protocol data overlap
                        uniqueness_score = self._calculate_protocol_uniqueness_score(
                            protocol, protocols
                        )
                        
                        # Update or create signature
                        existing_sig = session.query(ProtocolSignature).filter_by(
                            protocol_id=protocol.id
                        ).first()
                        
                        if existing_sig:
                            # Update existing signature
                            existing_sig.port_signature = port_sig
                            existing_sig.banner_signature = banner_sig
                            existing_sig.endpoint_signature = endpoint_sig
                            existing_sig.keyword_signature = keyword_sig
                            existing_sig.uniqueness_score = uniqueness_score
                            existing_sig.signature_version += 1
                            
                            self.logger.debug(f"Updated signature for {protocol.name} "
                                            f"(uniqueness: {uniqueness_score:.3f}, v{existing_sig.signature_version})")
                        else:
                            # Create new signature
                            signature = ProtocolSignature(
                                protocol_id=protocol.id,
                                port_signature=port_sig,
                                banner_signature=banner_sig,
                                endpoint_signature=endpoint_sig,
                                keyword_signature=keyword_sig,
                                uniqueness_score=uniqueness_score,
                                signature_version=1
                            )
                            session.add(signature)
                            
                            self.logger.debug(f"Created signature for {protocol.name} "
                                            f"(uniqueness: {uniqueness_score:.3f})")
                        
                        updated_protocols.append(protocol.name)
                        
                    except Exception as e:
                        self.logger.error(f"Failed to generate signature for {protocol.name}: {e}")
                        continue
                
                # Commit all changes
                session.commit()
                self.logger.info(f"💾 Successfully saved signatures for {len(updated_protocols)} protocols")
                
        except Exception as e:
            self.logger.error(f"Failed to generate signatures from protocols: {e}")
        
        return updated_protocols
    
    def _calculate_protocol_uniqueness_score(self, protocol: Protocol, all_protocols: List[Protocol]) -> float:
        """
        Calculate uniqueness score for a protocol based on overlap with other protocols.
        
        Args:
            protocol: The protocol to calculate uniqueness for
            all_protocols: List of all protocols for comparison
            
        Returns:
            Uniqueness score between 0.0 and 1.0
        """
        if len(all_protocols) <= 1:
            return 1.0  # Only protocol or no comparison possible
        
        # Component weights (more distinctive components get higher weights)
        component_weights = {
            'banners': 0.4,      # Most distinctive
            'keywords': 0.3,     # Very distinctive (metrics_keywords + identification_hints)
            'endpoints': 0.2,    # Moderately distinctive (endpoints + http_paths)
            'ports': 0.1         # Least distinctive (often shared)
        }
        
        # Combine related fields for comparison
        our_data = {
            'banners': set(protocol.banners),
            'keywords': set(protocol.metrics_keywords + protocol.identification_hints),
            'endpoints': set(protocol.endpoints + protocol.http_paths),
            'ports': set(str(p) for p in protocol.ports)
        }
        
        total_weighted_uniqueness = 0.0
        total_weights = 0.0
        
        for component, weight in component_weights.items():
            our_items = our_data[component]
            if not our_items:
                continue
            
            overlap_scores = []
            
            for other_protocol in all_protocols:
                if other_protocol.id == protocol.id:
                    continue
                
                # Get other protocol's data for this component
                if component == 'banners':
                    other_items = set(other_protocol.banners)
                elif component == 'keywords':
                    other_items = set(other_protocol.metrics_keywords + other_protocol.identification_hints)
                elif component == 'endpoints':
                    other_items = set(other_protocol.endpoints + other_protocol.http_paths)
                elif component == 'ports':
                    other_items = set(str(p) for p in other_protocol.ports)
                else:
                    continue
                
                if not other_items:
                    continue
                
                # Calculate Jaccard similarity
                intersection = len(our_items & other_items)
                union = len(our_items | other_items)
                
                if union > 0:
                    similarity = intersection / union
                    overlap_scores.append(similarity)
            
            if overlap_scores:
                # Use average overlap as the similarity measure
                avg_overlap = sum(overlap_scores) / len(overlap_scores)
                component_uniqueness = 1.0 - avg_overlap
            else:
                component_uniqueness = 1.0  # No other protocols to compare against
            
            total_weighted_uniqueness += component_uniqueness * weight
            total_weights += weight
        
        if total_weights == 0:
            return 0.5  # Default score when no data available
        
        base_score = total_weighted_uniqueness / total_weights
        
        # Boost score for protocols with more comprehensive data
        data_completeness = sum(1 for items in our_data.values() if items) / len(our_data)
        completeness_boost = data_completeness * 0.1  # Max 10% boost
        
        final_score = min(base_score + completeness_boost, 1.0)        
        return final_score
    
    def _create_optimized_binary_signature(self, items: List[str], item_type: str) -> str:
        """
        Create optimized binary signature with type-specific handling.
        
        Args:
            items: List of items to include in signature
            item_type: Type of items ('port', 'banner', 'endpoint', 'keyword')
            
        Returns:
            Base64 encoded binary signature
        """
        if not items:
            return base64.b64encode(b'\x00' * (self.signature_length // 8)).decode('utf-8')
        
        signature_bytes = bytearray(self.signature_length // 8)
        
        for item in items:
            # Type-specific preprocessing
            if item_type == 'port':
                # For ports, use the port number directly
                try:
                    port_num = int(item)
                    item_hash = hashlib.sha256(struct.pack('!H', port_num)).digest()
                except (ValueError, TypeError):
                    item_hash = hashlib.sha256(str(item).encode('utf-8')).digest()
            else:
                # For other types, use string hash
                item_hash = hashlib.sha256(str(item).lower().encode('utf-8')).digest()
            
            # Set multiple bits per item for better collision resistance
            for i in range(min(6, len(item_hash))):  # Use more bytes
                byte_val = item_hash[i]
                bit_pos = byte_val % self.signature_length
                byte_pos = bit_pos // 8
                bit_offset = bit_pos % 8
                signature_bytes[byte_pos] |= (1 << bit_offset)
        
        return base64.b64encode(bytes(signature_bytes)).decode('utf-8')