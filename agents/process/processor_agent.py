"""
Processor agent for analyzing and enriching scan results.
"""

import hashlib
import json
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timedelta
from collections import defaultdict

from agents.base import ProcessAgent
from core.database import get_db_session, ValidatorScan
from core.config import Config
from agents.score.scoring_agent import ScoringAgent


class ProcessorAgent(ProcessAgent):
    """
    Processing agent for analyzing and enriching scan results.
    
    This agent takes raw scan results, deduplicates them, computes trust scores,
    enriches with additional metadata, and prepares structured outputs for publishing.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize processor agent.
        
        Args:
            config: Configuration instance
        """
        super().__init__(config, "ProcessorAgent")
        self.scoring_agent = ScoringAgent(config)
    
    def process_results(self, scan_results: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """
        Process and enrich scan results.
        
        Args:
            scan_results: Optional list of scan results to process. If None, loads unprocessed results.
            
        Returns:
            List of processed and enriched results
        """
        if scan_results is None:
            scan_results = self._get_unprocessed_results()
        
        if not scan_results:
            self.logger.info("🎯 No scan results to process")
            return []
        
        self.logger.info(f"📊 Processing {len(scan_results)} scan results")
        
        # Step 1: Deduplicate results
        deduplicated_results = self._deduplicate_results(scan_results)
        self.logger.info(f"📋 After deduplication: {len(deduplicated_results)} unique results")
        
        # Step 2: Compute trust scores using scoring agent
        scored_results = self.scoring_agent.process_results(deduplicated_results)
        
        # Step 3: Enrich with metadata
        enriched_results = self._enrich_results(scored_results)
        
        # Step 4: Update database with processed results
        self._update_processed_results(enriched_results)
        
        # Step 5: Generate summary statistics
        summary_stats = self._generate_summary_stats(enriched_results)
        self.logger.info(f"📈 Processing summary: {summary_stats}")
        
        self.logger.info(f"✅ Successfully processed {len(enriched_results)} results")
        return enriched_results
    
    def _get_unprocessed_results(self) -> List[Dict[str, Any]]:
        """
        Get unprocessed scan results from database.
        
        Returns:
            List of unprocessed scan results
        """
        try:
            with get_db_session() as session:
                # Get scans that don't have trust scores yet
                unprocessed_scans = session.query(ValidatorScan).filter(
                    ValidatorScan.score.is_(None),
                    ValidatorScan.failed == False
                ).order_by(ValidatorScan.scan_date.desc()).all()
                
                results = []
                for scan in unprocessed_scans:
                    if scan.scan_results:
                        results.append({
                            'scan_id': scan.id,
                            'validator_id': scan.validator_address_id,
                            'scan_date': scan.scan_date.isoformat(),
                            'ip_address': scan.ip_address,
                            'scan_version': scan.version,
                            'raw_results': scan.scan_results
                        })
                
                return results
                
        except Exception as e:
            self.logger.error(f"Failed to get unprocessed results: {e}")
            return []
    
    def _deduplicate_results(self, scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicate scan results based on content hash.
        
        Args:
            scan_results: List of scan results
            
        Returns:
            List of deduplicated results
        """
        seen_hashes: Set[str] = set()
        deduplicated = []
        
        for result in scan_results:
            # Create content hash
            content_hash = self._compute_content_hash(result)
            
            if content_hash not in seen_hashes:
                seen_hashes.add(content_hash)
                result['content_hash'] = content_hash
                deduplicated.append(result)
            else:
                self.logger.debug(f"Skipping duplicate result for {result.get('ip_address', 'unknown')}")
        
        return deduplicated
    
    def _compute_content_hash(self, result: Dict[str, Any]) -> str:
        """
        Compute content hash for scan result.
        
        Args:
            result: Scan result
            
        Returns:
            SHA-256 hash of scan content
        """
        # Create normalized content for hashing
        if 'raw_results' in result:
            scan_data = result['raw_results']
        else:
            scan_data = result
        
        # Extract relevant scan data for hashing
        hash_data = {
            'ip_address': result.get('ip_address'),
            'generic_scan': scan_data.get('generic_scan', {}),
            'protocol_scan': scan_data.get('protocol_scan', {})
        }
        
        # Create hash
        content_json = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha256(content_json.encode()).hexdigest()
    
    def _enrich_results(self, scored_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enrich results with additional metadata and analysis.
        
        Args:
            scored_results: List of scored results
            
        Returns:
            List of enriched results
        """
        enriched_results = []
        
        for result in scored_results:
            try:
                # Add processing metadata
                result['processed_at'] = datetime.utcnow().isoformat()
                result['processor_version'] = '1.0.0'
                
                # Add security analysis
                security_analysis = self._analyze_security_posture(result)
                result['security_analysis'] = security_analysis
                
                # Add risk classification
                risk_level = self._classify_risk_level(result)
                result['risk_level'] = risk_level
                
                # Add compliance information
                compliance_info = self._check_compliance(result)
                result['compliance'] = compliance_info
                
                # Add geolocation information (if available)
                geo_info = self._get_geolocation_info(result)
                if geo_info:
                    result['geolocation'] = geo_info
                
                enriched_results.append(result)
                
            except Exception as e:
                self.logger.error(f"Failed to enrich result for {result.get('ip_address', 'unknown')}: {e}")
                # Include result even if enrichment fails
                enriched_results.append(result)
        
        return enriched_results
    
    def _analyze_security_posture(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze security posture of scanned node.
        
        Args:
            result: Scan result
            
        Returns:
            Security analysis information
        """
        raw_results = result.get('raw_results', result)
        generic_scan = raw_results.get('generic_scan', {})
        
        analysis = {
            'open_ports_count': len(generic_scan.get('open_ports', [])),
            'critical_ports_exposed': [],
            'ssl_configured': False,
            'known_vulnerabilities': len(generic_scan.get('vulns', {})),
            'security_headers_present': False
        }
        
        # Check for critical ports
        critical_ports = [22, 23, 135, 139, 445, 2375, 3389, 5432, 3306]
        open_ports = generic_scan.get('open_ports', [])
        
        for port in critical_ports:
            if port in open_ports:
                analysis['critical_ports_exposed'].append(port)
        
        # Check SSL configuration
        tls_info = generic_scan.get('tls', {})
        if tls_info and tls_info.get('issuer'):
            analysis['ssl_configured'] = True
        
        # Check for security headers
        http_headers = generic_scan.get('http_headers', {})
        security_headers = ['X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options', 'Strict-Transport-Security']
        
        for header in security_headers:
            if header in http_headers:
                analysis['security_headers_present'] = True
                break
        
        return analysis
    
    def _check_compliance(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check compliance with common security standards.
        
        Args:
            result: Scan result
            
        Returns:
            Compliance information
        """
        compliance = {
            'cis_compliant': False,
            'pci_dss_compliant': False,
            'iso27001_compliant': False,
            'recommendations': []
        }
        
        security_analysis = result.get('security_analysis', {})
        trust_flags = result.get('trust_flags', [])
        
        # Basic compliance checks
        if not security_analysis.get('critical_ports_exposed'):
            compliance['cis_compliant'] = True
        else:
            compliance['recommendations'].append('Close unnecessary ports')
        
        if security_analysis.get('ssl_configured'):
            compliance['pci_dss_compliant'] = True
        else:
            compliance['recommendations'].append('Configure SSL/TLS')
        
        if 'Docker socket exposed' in trust_flags:
            compliance['recommendations'].append('Secure Docker daemon')
        
        return compliance
    
    def _get_geolocation_info(self, result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Get geolocation information for IP address.
        
        Args:
            result: Scan result
            
        Returns:
            Geolocation information or None
        """
        # Placeholder for geolocation lookup
        # In a real implementation, you might use a service like MaxMind GeoIP
        # or ipapi.co to get location information
        return None
    
    def _update_processed_results(self, enriched_results: List[Dict[str, Any]]) -> None:
        """
        Update database with processed results.
        
        Args:
            enriched_results: List of enriched results
        """
        try:
            with get_db_session() as session:
                for result in enriched_results:
                    scan_id = result.get('scan_id')
                    if not scan_id:
                        continue
                    
                    # Update scan record with processed data
                    scan = session.query(ValidatorScan).filter_by(id=scan_id).first()
                    if scan:
                        scan.score = result.get('trust_score')
                        scan.scan_hash = result.get('content_hash')
                        scan.scan_results = result  # Update with enriched data
                
                session.commit()
                self.logger.debug(f"Updated {len(enriched_results)} processed results in database")
                
        except Exception as e:
            self.logger.error(f"Failed to update processed results: {e}")
    
    def _generate_summary_stats(self, enriched_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate summary statistics for processed results.
        
        Args:
            enriched_results: List of enriched results
            
        Returns:
            Summary statistics
        """
        if not enriched_results:
            return {}
        
        # Calculate statistics
        trust_scores = [r.get('trust_score', 0) for r in enriched_results]
        risk_levels = [r.get('risk_level', 'UNKNOWN') for r in enriched_results]
        
        risk_counts = defaultdict(int)
        for level in risk_levels:
            risk_counts[level] += 1
        
        stats = {
            'total_processed': len(enriched_results),
            'average_trust_score': sum(trust_scores) / len(trust_scores) if trust_scores else 0,
            'min_trust_score': min(trust_scores) if trust_scores else 0,
            'max_trust_score': max(trust_scores) if trust_scores else 0,
            'risk_distribution': dict(risk_counts),
            'processing_date': datetime.utcnow().isoformat()
        }
        
        return stats
    
    def get_processed_results(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Get processed results from database.
        
        Args:
            days: Number of days to look back
            
        Returns:
            List of processed results
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            with get_db_session() as session:
                processed_scans = session.query(ValidatorScan).filter(
                    ValidatorScan.scan_date >= cutoff_date,
                    ValidatorScan.score.isnot(None)
                ).all()
                
                results = []
                for scan in processed_scans:
                    if scan.scan_results:
                        # Ensure the version is included in the results
                        result = scan.scan_results.copy() if isinstance(scan.scan_results, dict) else scan.scan_results
                        if isinstance(result, dict):
                            result['scan_version'] = scan.version
                        results.append(result)
                
                return results
                
        except Exception as e:
            self.logger.error(f"Failed to get processed results: {e}")
            return []
    
    def run(self, scan_results: Optional[List[Dict[str, Any]]] = None, *args, **kwargs) -> List[Dict[str, Any]]:
        """
        Execute result processing.
        
        Args:
            scan_results: Optional list of scan results to process
            
        Returns:
            List of processed results
        """
        return self.process_results(scan_results)
