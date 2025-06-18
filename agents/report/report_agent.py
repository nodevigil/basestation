"""
Report agent for generating security analysis reports.
Supports both built-in reporting and external private reporting libraries.
"""

import importlib
import hashlib
import json
import os
from typing import List, Dict, Any, Optional
from datetime import datetime

from agents.base import ProcessAgent
from core.config import Config


class DefaultReportGenerator:
    """
    Default built-in report generator that creates basic security reports.
    This serves as fallback when external report generator is not available.
    """
    
    def __init__(self, report_config=None):
        """
        Initialize the default report generator.
        
        Args:
            report_config: Dict of report configuration options
        """
        self.report_config = report_config or {
            'format': 'json',
            'include_summary': True,
            'include_recommendations': True,
            'severity_threshold': 'medium'
        }
    
    def generate_report(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a security analysis report from scan data.
        
        Args:
            scan_data: Scan data to analyze
            
        Returns:
            Report data with analysis, findings, and recommendations
        """
        report = {
            "report_metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "report_version": "1.0",
                "generator": "DefaultReportGenerator",
                "scan_hash": hashlib.sha256(json.dumps(scan_data, sort_keys=True).encode()).hexdigest()
            },
            "target_info": {
                "ip_address": scan_data.get("ip", "unknown"),
                "hostname": scan_data.get("hostname", "unknown"),
                "scan_timestamp": scan_data.get("timestamp", "unknown")
            },
            "executive_summary": self._generate_executive_summary(scan_data),
            "security_findings": self._analyze_security_findings(scan_data),
            "recommendations": self._generate_recommendations(scan_data),
            "technical_details": self._extract_technical_details(scan_data)
        }
        
        return report
    
    def _generate_executive_summary(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of security findings."""
        open_ports = scan_data.get('open_ports', [])
        vulns = scan_data.get('vulns', {})
        
        # Count severity levels
        critical_count = len([v for v in vulns.values() if v.get('severity') == 'CRITICAL'])
        high_count = len([v for v in vulns.values() if v.get('severity') == 'HIGH'])
        medium_count = len([v for v in vulns.values() if v.get('severity') == 'MEDIUM'])
        
        risk_level = "LOW"
        if critical_count > 0:
            risk_level = "CRITICAL"
        elif high_count > 0:
            risk_level = "HIGH"
        elif medium_count > 0 or len(open_ports) > 5:
            risk_level = "MEDIUM"
        
        return {
            "overall_risk_level": risk_level,
            "total_vulnerabilities": len(vulns),
            "critical_vulnerabilities": critical_count,
            "high_vulnerabilities": high_count,
            "medium_vulnerabilities": medium_count,
            "open_ports_count": len(open_ports),
            "summary_text": f"Security scan identified {len(vulns)} vulnerabilities with {risk_level} overall risk level."
        }
    
    def _analyze_security_findings(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze and categorize security findings."""
        findings = []
        
        # Check for critical exposures
        open_ports = scan_data.get('open_ports', [])
        if 2375 in open_ports:
            findings.append({
                "finding_id": "DOCKER_SOCKET_EXPOSED",
                "severity": "CRITICAL",
                "title": "Docker Socket Exposed",
                "description": "Docker daemon socket is exposed without authentication",
                "impact": "Full container host compromise possible",
                "confidence": "HIGH"
            })
        
        # Check for common risky ports
        risky_ports = {
            23: "Telnet - Unencrypted remote access",
            135: "RPC Endpoint Mapper - Windows RPC",
            445: "SMB - File sharing protocol",
            3389: "RDP - Remote Desktop Protocol"
        }
        
        for port in open_ports:
            if port in risky_ports:
                findings.append({
                    "finding_id": f"RISKY_PORT_{port}",
                    "severity": "MEDIUM",
                    "title": f"Risky Port {port} Open",
                    "description": risky_ports[port],
                    "impact": "Potential unauthorized access vector",
                    "confidence": "HIGH"
                })
        
        # Add vulnerability findings
        vulns = scan_data.get('vulns', {})
        for vuln_id, vuln_data in vulns.items():
            findings.append({
                "finding_id": vuln_id,
                "severity": vuln_data.get('severity', 'UNKNOWN'),
                "title": vuln_data.get('title', f'Vulnerability {vuln_id}'),
                "description": vuln_data.get('description', 'No description available'),
                "impact": vuln_data.get('impact', 'Impact assessment needed'),
                "confidence": vuln_data.get('confidence', 'MEDIUM')
            })
        
        return findings
    
    def _generate_recommendations(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        open_ports = scan_data.get('open_ports', [])
        vulns = scan_data.get('vulns', {})
        
        # Docker socket recommendations
        if 2375 in open_ports:
            recommendations.append({
                "priority": "CRITICAL",
                "category": "Access Control",
                "title": "Secure Docker Socket",
                "description": "Configure Docker daemon with TLS authentication or restrict access to Docker socket",
                "effort": "Medium"
            })
        
        # General port security
        if len(open_ports) > 10:
            recommendations.append({
                "priority": "MEDIUM",
                "category": "Network Security",
                "title": "Review Open Ports",
                "description": "Review all open ports and close unnecessary services to reduce attack surface",
                "effort": "Low"
            })
        
        # Vulnerability patching
        if vulns:
            critical_vulns = [v for v in vulns.values() if v.get('severity') == 'CRITICAL']
            if critical_vulns:
                recommendations.append({
                    "priority": "CRITICAL",
                    "category": "Vulnerability Management",
                    "title": "Patch Critical Vulnerabilities",
                    "description": f"Immediately patch {len(critical_vulns)} critical vulnerabilities",
                    "effort": "High"
                })
        
        # TLS configuration
        tls = scan_data.get("tls", {})
        if tls.get("issuer") in (None, "Self-signed"):
            recommendations.append({
                "priority": "MEDIUM",
                "category": "Encryption",
                "title": "Configure Valid TLS Certificate",
                "description": "Replace self-signed certificate with valid CA-issued certificate",
                "effort": "Medium"
            })
        
        return recommendations
    
    def _extract_technical_details(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract technical details for the report."""
        return {
            "network_information": {
                "open_ports": scan_data.get('open_ports', []),
                "services": scan_data.get('services', {}),
                "protocols": scan_data.get('protocols', [])
            },
            "security_configuration": {
                "tls_configuration": scan_data.get('tls', {}),
                "authentication_methods": scan_data.get('auth', {}),
                "encryption_status": scan_data.get('encryption', {})
            },
            "system_information": {
                "operating_system": scan_data.get('os', {}),
                "software_versions": scan_data.get('versions', {}),
                "running_services": scan_data.get('processes', [])
            }
        }


class ReportAgent(ProcessAgent):
    """
    Report agent responsible for generating security analysis reports.
    
    This agent takes scan results and generates comprehensive security reports
    with findings, risk assessments, and recommendations.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize report agent with dynamic report generator loading.
        
        Args:
            config: Configuration instance
        """
        super().__init__(config, "ReportAgent")
        
        # Dynamic report generator loading with fallback
        self.report_generator = self._load_report_generator()
    
    def _get_report_generator(self, generator_path: str):
        """
        Dynamically load a report generator class from an external library.
        
        Args:
            generator_path: Dot-separated path to generator class (module.ClassName)
            
        Returns:
            Report generator instance
        """
        try:
            mod_name, class_name = generator_path.rsplit('.', 1)
            mod = importlib.import_module(mod_name)
            GeneratorClass = getattr(mod, class_name)
            
            # Pass configuration to external report generator
            report_config = getattr(self.config.reporting, 'config', {}) if hasattr(self.config, 'reporting') else {}
            
            # Try to initialize with configuration parameters
            try:
                return GeneratorClass(report_config=report_config)
            except TypeError:
                # Fallback if external generator doesn't accept these parameters
                self.logger.warning(f"External report generator '{generator_path}' doesn't accept configuration parameters")
                return GeneratorClass()
                
        except Exception as e:
            self.logger.debug(f"Failed to load external report generator '{generator_path}': {e}")
            raise
    
    def _load_report_generator(self):
        """
        Load report generator with fallback to built-in DefaultReportGenerator.
        
        Returns:
            Report generator instance (external or default)
        """
        # Check if external report generator is configured
        if hasattr(self.config, 'reporting') and hasattr(self.config.reporting, 'external_generator'):
            external_generator = self.config.reporting.external_generator
            
            if external_generator and external_generator.get('enabled', False):
                generator_path = external_generator.get('class_path')
                if generator_path:
                    try:
                        self.logger.info(f"Loading external report generator: {generator_path}")
                        generator = self._get_report_generator(generator_path)
                        self.logger.info("External report generator loaded successfully")
                        return generator
                    except Exception as e:
                        self.logger.warning(f"Failed to load external report generator, falling back to default: {e}")
        
        # Fallback to built-in generator
        self.logger.info("Using built-in DefaultReportGenerator")
        report_config = getattr(self.config.reporting, 'config', {}) if hasattr(self.config, 'reporting') else {}
        return DefaultReportGenerator(report_config=report_config)
    
    def process_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a single scan result to generate a security report.
        
        Args:
            item: Scan result data
            
        Returns:
            Report data with security analysis
        """
        try:
            self.logger.info(f"Generating report for {item.get('ip', 'unknown')}")
            
            # Generate the report using the configured generator
            report_data = self.report_generator.generate_report(item)
            
            # Add processing metadata
            report_data['processing_info'] = {
                'agent': self.agent_name,
                'processed_at': datetime.utcnow().isoformat(),
                'generator_type': type(self.report_generator).__name__
            }
            
            self.logger.info(f"Report generated successfully for {item.get('ip', 'unknown')}")
            return report_data
            
        except Exception as e:
            self.logger.error(f"Error generating report for {item.get('ip', 'unknown')}: {e}")
            # Return minimal error report
            return {
                'error': True,
                'message': str(e),
                'target_ip': item.get('ip', 'unknown'),
                'processed_at': datetime.utcnow().isoformat()
            }
    
    def process_results(self, scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process scan results to generate reports for each item.
        
        Args:
            scan_results: List of scan results to process
            
        Returns:
            List of report data for each scan result
        """
        reports = []
        
        for scan_result in scan_results:
            try:
                report_data = self.process_item(scan_result)
                reports.append(report_data)
            except Exception as e:
                self.logger.error(f"Failed to generate report for {scan_result.get('ip', 'unknown')}: {e}")
                # Add error report
                reports.append({
                    'error': True,
                    'message': str(e),
                    'target_ip': scan_result.get('ip', 'unknown'),
                    'processed_at': datetime.utcnow().isoformat()
                })
        
        return reports
    
    def save_report(self, report_data: Dict[str, Any], output_file: Optional[str] = None) -> str:
        """
        Save report to file.
        
        Args:
            report_data: Report data to save
            output_file: Optional output file path
            
        Returns:
            Path to saved report file
        """
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_ip = report_data.get('target_info', {}).get('ip_address', 'unknown')
            output_file = f"security_report_{target_ip}_{timestamp}.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            self.logger.info(f"Report saved to: {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(f"Error saving report: {e}")
            raise
