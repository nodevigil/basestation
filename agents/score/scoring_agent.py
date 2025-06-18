"""
Scoring agent for computing trust scores and risk classifications.
Supports both built-in scoring and external private scoring libraries.
"""

import importlib
import hashlib
import json
from typing import List, Dict, Any, Optional
from datetime import datetime

from agents.base import ProcessAgent
from core.config import Config

class DefaultTrustScorer:
    """
    Default built-in trust scorer that combines the original trust scoring logic.
    This serves as fallback when external scorer is not available.
    """
    
    def score(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Score scan data based on security analysis.
        
        Args:
            scan_data: Generic scan data
            
        Returns:
            Trust scoring results with score, flags, and summary
        """
        score = 100
        flags = []

        # Check for Docker socket exposure (critical security issue)
        if 2375 in scan_data.get('open_ports', []):
            score -= 30
            flags.append("Docker socket exposed")
            
        # Check for SSH port open
        if 22 in scan_data.get('open_ports', []):
            score -= 10
            flags.append("SSH port open")
            
        # Check TLS configuration
        tls = scan_data.get("tls", {})
        if tls.get("issuer") in (None, "Self-signed") or not tls.get("expiry"):
            score -= 25
            flags.append("TLS misconfigured")
            
        # Check for known vulnerabilities
        for vuln in scan_data.get("vulns", {}).values():
            score -= 15
            flags.append(f"Known vuln: {vuln}")

        summary = f"Trust Score: {score}. Flags: {', '.join(flags)}."

        return {
            "ip": scan_data.get("ip", "unknown"),
            "score": score,
            "flags": flags,
            "summary": summary,
            "timestamp": datetime.utcnow().isoformat(),
            "hash": hashlib.sha256(json.dumps(scan_data, sort_keys=True).encode()).hexdigest(),
            "docker_exposure": scan_data.get("docker_exposure", {"exposed": False})
        }


class ScoringAgent(ProcessAgent):
    """
    Scoring agent responsible for computing trust scores and risk classifications.
    
    This agent takes scan results and computes trust scores based on security analysis,
    vulnerability detection, and other risk factors.
    """
    
    def __init__(self, config: Optional[Config] = None, force_rescore: bool = False):
        """
        Initialize scoring agent with dynamic scorer loading.
        
        Args:
            config: Configuration instance
            force_rescore: Whether to re-score results that already have scores
        """
        super().__init__(config, "ScoringAgent")
        self.force_rescore = force_rescore
        
        # Dynamic scorer loading with fallback
        self.trust_scorer = self._load_scorer()
    
    def _get_scorer(self, scorer_path: str):
        """
        Dynamically load a scorer class from an external library.
        
        Args:
            scorer_path: Dot-separated path to scorer class (module.ClassName)
            
        Returns:
            Scorer instance
        """
        try:
            mod_name, class_name = scorer_path.rsplit('.', 1)
            mod = importlib.import_module(mod_name)
            ScorerClass = getattr(mod, class_name)
            return ScorerClass()
        except Exception as e:
            self.logger.debug(f"Failed to load external scorer '{scorer_path}': {e}")
            raise
    
    def _load_scorer(self):
        """
        Load scorer with fallback to built-in DefaultTrustScorer.
        
        Returns:
            Scorer instance (external or default)
        """
        # Try to load external scorer first from config
        scorer_path = getattr(self.config.scoring, 'scorer_path', None) if hasattr(self.config, 'scoring') else None
        
        if scorer_path:
            try:
                scorer = self._get_scorer(scorer_path)
                self.logger.info(f"✅ Loaded external scorer: {scorer_path}")
                return scorer
            except Exception as e:
                self.logger.warning(f"External scorer '{scorer_path}' not available: {e}")
        
        # When no external scorer is configured, use built-in scorer directly
        self.logger.info("📊 Using built-in DefaultTrustScorer")
        return DefaultTrustScorer()
    
    def process_results(self, scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process scan results and compute trust scores.
        
        Args:
            scan_results: List of scan results to score
            
        Returns:
            List of results with trust scores and risk classifications
        """
        if not scan_results:
            self.logger.info("🎯 No scan results to score")
            return []
        
        self.logger.info(f"📊 Computing trust scores for {len(scan_results)} results")
        
        # Count new vs re-scored results
        new_scores = len([r for r in scan_results if not r.get('is_rescore', False)])
        rescores = len([r for r in scan_results if r.get('is_rescore', False)])
        
        if rescores > 0:
            self.logger.info(f"   • New scores: {new_scores}, Re-scores: {rescores}")
        
        scored_results = self._compute_trust_scores(scan_results)
        
        # Update database with scored results
        self._update_scored_results(scored_results)
        
        # Generate scoring summary
        summary_stats = self._generate_scoring_summary(scored_results)
        self.logger.info(f"📈 Scoring summary: {summary_stats}")
        
        self.logger.info(f"✅ Successfully scored {len(scored_results)} results")
        return scored_results
    
    def _compute_trust_scores(self, scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Compute trust scores for scan results.
        
        Args:
            scan_results: List of scan results
            
        Returns:
            List of results with trust scores
        """
        scored_results = []
        
        for result in scan_results:
            try:
                # Get generic scan data
                raw_results = result.get('raw_results', result)
                generic_scan = raw_results.get('generic_scan', {})
                
                if not generic_scan:
                    self.logger.warning(f"No generic scan data for {result.get('ip_address', 'unknown')}")
                    continue
                
                # Compute trust score using either external or built-in scorer
                if self.trust_scorer:
                    trust_result = self.trust_scorer.score(generic_scan)
                else:
                    # This should never happen due to fallback, but just in case
                    self.logger.warning("No scorer available, using minimal fallback")
                    trust_result = {
                        "score": 50,  # Neutral score
                        "flags": ["No scorer available"],
                        "summary": "No scorer available for evaluation",
                        "docker_exposure": {"exposed": False}
                    }
                
                # Classify risk level
                risk_level = self._classify_risk_level(trust_result['score'])
                
                # Merge trust score and risk classification with result
                result.update({
                    'trust_score': trust_result['score'],
                    'trust_flags': trust_result['flags'],
                    'trust_summary': trust_result['summary'],
                    'risk_level': risk_level,
                    'scoring_timestamp': datetime.utcnow().isoformat(),
                    'docker_exposure': trust_result.get('docker_exposure', {'exposed': False})
                })
                
                scored_results.append(result)
                
            except Exception as e:
                self.logger.error(f"Failed to compute trust score for {result.get('ip_address', 'unknown')}: {e}")
                continue
        
        return scored_results
    
    def _classify_risk_level(self, trust_score: float) -> str:
        """
        Classify risk level based on trust score.
        
        Args:
            trust_score: Trust score value
            
        Returns:
            Risk level classification
        """
        if trust_score >= 90:
            return 'LOW'
        elif trust_score >= 70:
            return 'MEDIUM'
        elif trust_score >= 50:
            return 'HIGH'
        else:
            return 'CRITICAL'
    
    def _generate_scoring_summary(self, scored_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate summary statistics for scoring results.
        
        Args:
            scored_results: List of scored results
            
        Returns:
            Summary statistics
        """
        if not scored_results:
            return {'total': 0}
        
        scores = [result.get('trust_score', 0) for result in scored_results]
        risk_levels = [result.get('risk_level', 'UNKNOWN') for result in scored_results]
        
        # Count by risk level
        risk_counts = {}
        for level in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
            risk_counts[level] = risk_levels.count(level)
        
        return {
            'total': len(scored_results),
            'avg_score': sum(scores) / len(scores) if scores else 0,
            'min_score': min(scores) if scores else 0,
            'max_score': max(scores) if scores else 0,
            'risk_distribution': risk_counts,
            'flagged_nodes': len([r for r in scored_results if r.get('trust_flags', [])])
        }
    
    def score_single_result(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Score a single scan result.
        
        Args:
            scan_result: Single scan result to score
            
        Returns:
            Scored result
        """
        results = self.process_results([scan_result])
        return results[0] if results else scan_result
    
    def execute(self, force_rescore: bool = False) -> List[Dict[str, Any]]:
        """
        Execute the scoring agent by loading results and processing them.
        Only unscored results are processed unless force_rescore is True.
        
        Args:
            force_rescore: Whether to force re-score all results
            
        Returns:
            List of scored results
        """
        self.logger.info(f"🚀 Starting ScoringAgent execution (force_rescore={force_rescore})")
        
        # Load results from database
        results_to_score = self._get_results_to_score(force_rescore=force_rescore)
        
        if not results_to_score:
            self.logger.info("📊 No results to score from database")
            return []
        
        # Process the results to add scoring
        return self.process_results(results_to_score)
    
    def _get_results_to_score(self, force_rescore: bool = False) -> List[Dict[str, Any]]:
        """
        Get scan results to score from the database.
        Only unscored results unless force_rescore is True.
        
        Args:
            force_rescore: Whether to force re-score all results
            
        Returns:
            List of scan results to score
        """
        try:
            from core.database import get_db_session, ValidatorScan
            
            with get_db_session() as session:
                query = session.query(ValidatorScan).filter(ValidatorScan.failed == False)
                
                if not force_rescore:
                    query = query.filter(ValidatorScan.score.is_(None))
                
                scans = query.order_by(ValidatorScan.scan_date.desc()).all()
                
                results = []
                for scan in scans:
                    if scan.scan_results:
                        results.append({
                            'scan_id': scan.id,
                            'validator_id': scan.validator_address_id,
                            'scan_date': scan.scan_date.isoformat(),
                            'ip_address': scan.ip_address,
                            'scan_version': scan.version,
                            'raw_results': scan.scan_results
                        })
                
                self.logger.info(f"📊 Found {len(results)} results to score (force_rescore={force_rescore})")
                return results
                
        except Exception as e:
            self.logger.error(f"❌ Error loading results to score: {e}")
            return []
    
    def _update_scored_results(self, scored_results: List[Dict[str, Any]]) -> None:
        """
        Update the database with scored results.
        
        Args:
            scored_results: List of results with trust scores
        """
        try:
            from core.database import get_db_session, ValidatorScan
            
            with get_db_session() as session:
                updated_count = 0
                
                for result in scored_results:
                    scan_id = result.get('scan_id')
                    trust_score = result.get('trust_score')
                    
                    if scan_id and trust_score is not None:
                        # Update the scan record with the trust score
                        scan = session.query(ValidatorScan).filter(
                            ValidatorScan.id == scan_id
                        ).first()
                        
                        if scan:
                            scan.score = trust_score
                            updated_count += 1
                
                session.commit()
                self.logger.info(f"📊 Updated {updated_count} scan records with trust scores")
                
        except Exception as e:
            self.logger.error(f"❌ Error updating scored results in database: {e}")
