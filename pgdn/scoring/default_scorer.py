"""
Default external scorer for PGDN (Private Grid Detection Network).
This is a more advanced external scorer implementation.
"""

from datetime import datetime
import hashlib
import json
import logging


class DefaultScorer:
    """
    Default external scorer with enhanced security analysis.
    This demonstrates the external scorer interface expected by the DePIN scanner.
    """
    
    def __init__(self):
        """Initialize the external scorer with custom weights and logging."""
        self.logger = logging.getLogger(__name__)
        self.logger.info("🔧 External DefaultScorer initialized")
        
        # Enhanced scoring weights
        self.weights = {
            'docker_exposure': 40,      # High penalty for Docker exposure
            'ssh_open': 15,            # Penalty for SSH
            'tls_issues': 25,          # Penalty for TLS issues
            'vulnerabilities': 30,      # High penalty per vulnerability
            'port_count': 3,           # Penalty for many open ports
            'web_services': 5          # Minor penalty for web services
        }
    
    def score(self, scan_data):
        """
        Enhanced scoring algorithm with detailed security analysis.
        
        Args:
            scan_data (dict): Scan data containing security information
            
        Returns:
            dict: Trust scoring result with enhanced metrics
        """
        self.logger.info(f"🔧 ZYX scorer processing IP: {scan_data.get('ip', 'unknown')}")
        
        score = 100
        flags = []
        advanced_metrics = {}
        
        # Enhanced Docker socket analysis
        open_ports = scan_data.get('open_ports', [])
        if 2375 in open_ports:
            score -= self.weights['docker_exposure']
            flags.append("CRITICAL: Docker socket exposed (unencrypted)")
            advanced_metrics['docker_risk_level'] = 'CRITICAL'
        elif 2376 in open_ports:
            score -= 25  # Less penalty for encrypted Docker
            flags.append("WARNING: Docker TLS socket exposed")
            advanced_metrics['docker_risk_level'] = 'MEDIUM'
        else:
            advanced_metrics['docker_risk_level'] = 'LOW'
            
        # SSH analysis
        if 22 in open_ports:
            score -= self.weights['ssh_open']
            flags.append("SSH service exposed")
            advanced_metrics['ssh_exposed'] = True
        else:
            advanced_metrics['ssh_exposed'] = False
            
        # Web services analysis
        web_ports = [80, 443, 8080, 8443]
        exposed_web_ports = [port for port in open_ports if port in web_ports]
        if exposed_web_ports:
            score -= self.weights['web_services'] * len(exposed_web_ports)
            flags.append(f"Web services on ports: {exposed_web_ports}")
            advanced_metrics['web_ports'] = exposed_web_ports
            
        # TLS certificate analysis
        tls_data = scan_data.get('tls', {})
        if tls_data:
            if tls_data.get('expired', False):
                score -= self.weights['tls_issues']
                flags.append("TLS certificate expired")
                advanced_metrics['tls_status'] = 'EXPIRED'
            elif tls_data.get('self_signed', False):
                score -= 10
                flags.append("Self-signed TLS certificate")
                advanced_metrics['tls_status'] = 'SELF_SIGNED'
            else:
                advanced_metrics['tls_status'] = 'VALID'
        
        # Vulnerability analysis
        vulns = scan_data.get('vulns', {})
        if vulns:
            vuln_count = len(vulns)
            score -= self.weights['vulnerabilities'] * vuln_count
            flags.append(f"{vuln_count} vulnerabilities detected")
            advanced_metrics['vulnerability_count'] = vuln_count
        else:
            advanced_metrics['vulnerability_count'] = 0
            
        # Port count penalty
        port_count = len(open_ports)
        if port_count > 5:
            penalty = (port_count - 5) * self.weights['port_count']
            score -= penalty
            flags.append(f"Many open ports ({port_count})")
            
        advanced_metrics['total_open_ports'] = port_count
        
        # Ensure score doesn't go below 0
        score = max(0, score)
        
        # Generate summary
        if score >= 80:
            risk_level = "LOW"
        elif score >= 60:
            risk_level = "MEDIUM"
        elif score >= 40:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"
            
        summary = f"External Trust Score: {score} ({risk_level})"
        if flags:
            summary += f". Issues: {', '.join(flags)}"
            
        # Create result hash for tracking
        result_data = {
            'ip': scan_data.get('ip'),
            'score': score,
            'flags': flags,
            'timestamp': datetime.now().isoformat()
        }
        result_hash = hashlib.sha256(json.dumps(result_data, sort_keys=True).encode()).hexdigest()
        
        return {
            'ip': scan_data.get('ip'),
            'score': score,
            'risk_level': risk_level,
            'flags': flags,
            'summary': summary,
            'timestamp': datetime.now().isoformat(),
            'hash': result_hash,
            'advanced_metrics': advanced_metrics,
            'external_scorer': 'pgdn.scoring.default_scorer.DefaultScorer',
            'docker_exposure': scan_data.get('docker_exposure', {'exposed': False})
        }
