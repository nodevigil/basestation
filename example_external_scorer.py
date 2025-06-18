"""
Example external scorer implementation.
This demonstrates how to create a compatible external scorer for the DePIN scanner.
"""

from datetime import datetime
import hashlib
import json


class ExampleAdvancedScorer:
    """
    Example advanced scorer that demonstrates the external scorer interface.
    This would typically be in your private repo like pgdn.scoring.advanced_scorer.
    """
    
    def __init__(self):
        """Initialize the advanced scorer with custom weights."""
        self.weights = {
            'docker_exposure': 40,      # Even higher penalty for Docker
            'ssh_open': 15,            # Higher penalty for SSH
            'tls_issues': 30,          # Higher penalty for TLS
            'vulnerabilities': 20,      # Higher penalty per vuln
            'port_count': 5            # Penalty for many open ports
        }
    
    def score(self, scan_data):
        """
        Advanced scoring algorithm with enhanced security analysis.
        
        Args:
            scan_data (dict): Generic scan data
            
        Returns:
            dict: Enhanced trust result
        """
        score = 100
        flags = []
        advanced_metrics = {}
        
        # Enhanced Docker socket analysis
        open_ports = scan_data.get('open_ports', [])
        if 2375 in open_ports:
            score -= self.weights['docker_exposure']
            flags.append("Critical: Docker socket exposed (unencrypted)")
            advanced_metrics['docker_risk_level'] = 'CRITICAL'
        elif 2376 in open_ports:
            score -= 20  # Less penalty for encrypted Docker
            flags.append("Warning: Docker TLS socket exposed")
            advanced_metrics['docker_risk_level'] = 'MEDIUM'
        else:
            advanced_metrics['docker_risk_level'] = 'LOW'
            
        # Enhanced SSH analysis
        if 22 in open_ports:
            score -= self.weights['ssh_open']
            flags.append("SSH port exposed")
            # Check for non-standard SSH ports
            ssh_ports = [p for p in open_ports if p in [22, 2222, 2200]]
            if len(ssh_ports) > 1:
                score -= 10
                flags.append("Multiple SSH ports detected")
                
        # Enhanced TLS analysis
        tls = scan_data.get("tls", {})
        if not tls or tls.get("issuer") in (None, "Self-signed") or not tls.get("expiry"):
            score -= self.weights['tls_issues']
            flags.append("TLS configuration issues")
            advanced_metrics['tls_grade'] = 'F'
        else:
            # Grade TLS configuration
            if "Let's Encrypt" in str(tls.get("issuer", "")):
                advanced_metrics['tls_grade'] = 'B'
            else:
                advanced_metrics['tls_grade'] = 'A'
                
        # Enhanced vulnerability analysis
        vulns = scan_data.get("vulns", {})
        for vuln_id, vuln_desc in vulns.items():
            score -= self.weights['vulnerabilities']
            severity = self._assess_vulnerability_severity(vuln_id, vuln_desc)
            flags.append(f"Vulnerability: {vuln_id} ({severity})")
            
        # Port exposure analysis
        port_count = len(open_ports)
        if port_count > 10:
            penalty = (port_count - 10) * self.weights['port_count']
            score -= penalty
            flags.append(f"Excessive port exposure: {port_count} ports")
            advanced_metrics['port_exposure_level'] = 'HIGH'
        elif port_count > 5:
            advanced_metrics['port_exposure_level'] = 'MEDIUM'
        else:
            advanced_metrics['port_exposure_level'] = 'LOW'
            
        # Database exposure check
        db_ports = [p for p in open_ports if p in [3306, 5432, 27017, 6379]]
        if db_ports:
            score -= 25
            flags.append(f"Database ports exposed: {db_ports}")
            advanced_metrics['database_exposure'] = True
        else:
            advanced_metrics['database_exposure'] = False
            
        # Ensure score doesn't go below 0
        score = max(0, score)
        
        # Generate risk category
        risk_category = self._calculate_risk_category(score, advanced_metrics)
        
        summary = f"Advanced Trust Score: {score}/100. Risk: {risk_category}. Issues: {len(flags)}"

        return {
            "ip": scan_data.get("ip", "unknown"),
            "score": score,
            "flags": flags,
            "summary": summary,
            "timestamp": datetime.utcnow().isoformat(),
            "hash": hashlib.sha256(json.dumps(scan_data, sort_keys=True).encode()).hexdigest(),
            "docker_exposure": scan_data.get("docker_exposure", {"exposed": False}),
            # Advanced metrics specific to this scorer
            "advanced_metrics": advanced_metrics,
            "risk_category": risk_category,
            "scorer_version": "advanced-1.0.0"
        }
    
    def _assess_vulnerability_severity(self, vuln_id, vuln_desc):
        """Assess vulnerability severity based on ID and description."""
        vuln_text = f"{vuln_id} {vuln_desc}".lower()
        
        if any(keyword in vuln_text for keyword in ['critical', 'rce', 'remote code']):
            return 'CRITICAL'
        elif any(keyword in vuln_text for keyword in ['high', 'privilege escalation']):
            return 'HIGH'
        elif any(keyword in vuln_text for keyword in ['medium', 'dos', 'denial of service']):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _calculate_risk_category(self, score, metrics):
        """Calculate risk category based on score and advanced metrics."""
        if score >= 90 and not metrics.get('database_exposure', False):
            return 'MINIMAL'
        elif score >= 80:
            return 'LOW'
        elif score >= 60:
            return 'MODERATE'
        elif score >= 40:
            return 'HIGH'
        else:
            return 'CRITICAL'


# For backward compatibility, provide DefaultScorer alias
DefaultScorer = ExampleAdvancedScorer
