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
from pgdn.core.config import Config
from pgdn.core.database import get_db_session, ValidatorScan
from pgdn.core.database import Protocol, ProtocolSignature


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
    
    def process_pending_scan_signatures(self) -> Dict[str, Any]:
        """
        Process scans that need protocol signature creation and mark them as completed.
        
        Returns:
            Dictionary with processing results and statistics
        """
        processed_scans = []
        skipped_scans = []
        errors = []
        
        try:
            with get_db_session() as session:
                # Get scans that need signature creation (not already processed)
                pending_scans = session.query(ValidatorScan).filter(
                    ValidatorScan.failed == False,
                    ValidatorScan.signature_created == False,
                    ValidatorScan.scan_results.isnot(None)
                ).all()
                
                self.logger.info(f"🔍 Found {len(pending_scans)} scans pending signature creation")
                
                for scan in pending_scans:
                    try:
                        # Check if we can determine the protocol from scan results
                        scan_results = scan.scan_results
                        detected_protocol = self._extract_protocol_from_scan(scan_results)
                        
                        if not detected_protocol or detected_protocol == 'unknown':
                            skipped_scans.append({
                                'scan_id': scan.id,
                                'reason': 'No definitive protocol detected',
                                'detected_protocol': detected_protocol
                            })
                            continue
                        
                        # Check if this protocol exists in our database
                        protocol = session.query(Protocol).filter_by(name=detected_protocol).first()
                        if not protocol:
                            skipped_scans.append({
                                'scan_id': scan.id,
                                'reason': f'Protocol {detected_protocol} not found in database',
                                'detected_protocol': detected_protocol
                            })
                            continue
                        
                        # Process the scan for signature creation
                        success = self._process_scan_for_signature(scan, protocol, session)
                        
                        if success:
                            # Mark as signature created
                            scan.signature_created = True
                            processed_scans.append({
                                'scan_id': scan.id,
                                'protocol': detected_protocol,
                                'ip_address': scan.ip_address
                            })
                            self.logger.debug(f"✅ Processed scan {scan.id} for {detected_protocol}")
                        else:
                            errors.append({
                                'scan_id': scan.id,
                                'error': 'Failed to process scan for signature creation'
                            })
                    
                    except Exception as e:
                        errors.append({
                            'scan_id': scan.id,
                            'error': str(e)
                        })
                        self.logger.error(f"Error processing scan {scan.id}: {e}")
                
                # Commit all changes
                session.commit()
                
                result = {
                    'processed_count': len(processed_scans),
                    'skipped_count': len(skipped_scans),
                    'error_count': len(errors),
                    'processed_scans': processed_scans,
                    'skipped_scans': skipped_scans,
                    'errors': errors
                }
                
                self.logger.info(f"📊 Signature processing complete: "
                               f"{len(processed_scans)} processed, "
                               f"{len(skipped_scans)} skipped, "
                               f"{len(errors)} errors")
                
                return result
                
        except Exception as e:
            self.logger.error(f"Failed to process pending scan signatures: {e}")
            return {
                'processed_count': 0,
                'skipped_count': 0,
                'error_count': 1,
                'processed_scans': [],
                'skipped_scans': [],
                'errors': [{'error': str(e)}]
            }
    
    def _extract_protocol_from_scan(self, scan_results: Dict[str, Any]) -> Optional[str]:
        """
        Extract the detected protocol from scan results.
        
        Args:
            scan_results: The scan results dictionary
            
        Returns:
            Protocol name if detected, None if uncertain
        """
        if not scan_results:
            return None
        
        # Check for explicitly detected protocol
        detected_protocol = scan_results.get('detected_protocol')
        if detected_protocol and detected_protocol != 'unknown':
            return detected_protocol
        
        # Check source for protocol hints
        source = scan_results.get('source', '').lower()
        if 'sui' in source:
            return 'sui'
        elif 'filecoin' in source or 'lotus' in source:
            return 'filecoin'
        elif 'ethereum' in source or 'geth' in source:
            return 'ethereum'
        
        # Check protocol_scan section
        protocol_scan = scan_results.get('protocol_scan', {})
        if protocol_scan:
            scan_type = protocol_scan.get('scan_type', '').lower()
            if 'sui' in scan_type:
                return 'sui'
            elif 'filecoin' in scan_type:
                return 'filecoin'
            elif 'ethereum' in scan_type:
                return 'ethereum'
        
        return None
    
    def _process_scan_for_signature(self, scan: ValidatorScan, protocol: Protocol, session) -> bool:
        """
        Process a scan to potentially improve the protocol signature.
        
        Args:
            scan: The ValidatorScan object
            protocol: The Protocol object
            session: Database session
            
        Returns:
            True if processing was successful, False otherwise
        """
        try:
            # This could be enhanced to actually learn from the scan data
            # For now, we just mark it as processed since the signature generation
            # from protocol definitions is handled separately
            
            # Future enhancement: Extract scan features and update signatures
            # scan_features = self._extract_scan_features(scan.scan_results)
            # updated_signature = self._update_protocol_signature(protocol, scan_features)
            
            self.logger.debug(f"Processed scan {scan.id} for protocol {protocol.name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to process scan {scan.id} for signature: {e}")
            return False
    
    def get_signature_processing_stats(self) -> Dict[str, Any]:
        """
        Get statistics about signature processing status.
        
        Returns:
            Dictionary with processing statistics
        """
        try:
            with get_db_session() as session:
                from sqlalchemy import func
                
                total_scans = session.query(ValidatorScan).filter(
                    ValidatorScan.failed == False,
                    ValidatorScan.scan_results.isnot(None)
                ).count()
                
                processed_scans = session.query(ValidatorScan).filter(
                    ValidatorScan.failed == False,
                    ValidatorScan.signature_created == True
                ).count()
                
                pending_scans = session.query(ValidatorScan).filter(
                    ValidatorScan.failed == False,
                    ValidatorScan.signature_created == False,
                    ValidatorScan.scan_results.isnot(None)
                ).count()
                
                # Get breakdown by detected protocol
                protocol_stats = session.query(
                    ValidatorScan.scan_results.op('->>')('detected_protocol').label('protocol'),
                    func.count().label('total'),
                    func.sum(func.cast(ValidatorScan.signature_created, type_=int)).label('processed')
                ).filter(
                    ValidatorScan.failed == False,
                    ValidatorScan.scan_results.isnot(None)
                ).group_by(
                    ValidatorScan.scan_results.op('->>')('detected_protocol')
                ).all()
                
                return {
                    'total_scans': total_scans,
                    'processed_scans': processed_scans,
                    'pending_scans': pending_scans,
                    'processing_rate': processed_scans / total_scans if total_scans > 0 else 0,
                    'protocol_breakdown': [
                        {
                            'protocol': stat.protocol or 'unknown',
                            'total_scans': stat.total,
                            'processed': stat.processed or 0,
                            'pending': stat.total - (stat.processed or 0)
                        }
                        for stat in protocol_stats
                    ]
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get signature processing stats: {e}")
            return {
                'total_scans': 0,
                'processed_scans': 0,
                'pending_scans': 0,
                'processing_rate': 0,
                'protocol_breakdown': []
            }