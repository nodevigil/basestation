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
from pgdn.core.config import Config

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
        # Extract the actual scan data from the nested structure
        processed_data = self._normalize_scan_data(scan_data)
        
        # Calculate risk score based on vulnerabilities
        risk_score = self._calculate_risk_score(processed_data)
        
        report = {
            "report_metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "report_version": "2.0",
                "custom_analysis": True,
                "risk_score": risk_score
            },
            "executive_summary": self._generate_executive_summary(processed_data),
            "detailed_analysis": {
                "vulnerability_breakdown": self._get_vulnerability_breakdown(processed_data),
                "port_analysis": self._get_port_analysis(processed_data),
                "compliance_check": self._get_compliance_status(processed_data)
            },
            "raw_data": scan_data
        }
        
        return report

    def generate_human_report(self, scan_data: Dict[str, Any], use_openai: bool = False, openai_api_key: str = None) -> str:
        """
        Generate a human-readable security analysis report from scan data.

        Args:
            scan_data: Scan data to analyze
            use_openai: Whether to use OpenAI to enhance the report prose
            openai_api_key: API key for OpenAI (optional)

        Returns:
            Plain text human-readable report
        """
        # Normalize the data first
        normalized_data = self._normalize_scan_data(scan_data)
        
        summary = self._generate_executive_summary(normalized_data)
        findings = self._analyze_security_findings(normalized_data)
        recommendations = self._generate_recommendations(normalized_data)

        lines = []
        lines.append(f"Security Analysis Report")
        lines.append(f"Generated: {datetime.utcnow().isoformat()}")
        lines.append(f"Target IP: {normalized_data.get('ip', 'unknown')}")
        lines.append("")

        # Executive Summary
        lines.append("Executive Summary:")
        lines.append(f"  - Overall Risk Level: {summary.get('overall_risk_level')}")
        lines.append(f"  - Vulnerabilities found: {summary.get('total_vulnerabilities')}")
        lines.append(f"  - Critical: {summary.get('critical_vulnerabilities')}")
        lines.append(f"  - Open Ports: {summary.get('open_ports_count')}")
        
        custom_recs = summary.get('custom_recommendations', [])
        if custom_recs:
            lines.append(f"  - Key Issues: {'; '.join(custom_recs[:2])}")
        lines.append("")

        # Findings
        lines.append("Key Findings:")
        if findings:
            for f in findings[:10]:  # limit to 10 for human readability
                lines.append(f"  - [{f.get('severity')}] {f.get('title')}: {f.get('description')}")
                if f.get("impact"):
                    lines.append(f"      Impact: {f.get('impact')}")
        else:
            lines.append("  No findings identified.")
        lines.append("")

        # Recommendations
        lines.append("Recommendations:")
        if recommendations:
            for r in recommendations:
                lines.append(f"  - [{r.get('priority')}] {r.get('title')}: {r.get('description')} (Effort: {r.get('effort')})")
        else:
            lines.append("  No recommendations at this time.")
        lines.append("")

        # Technical Appendix
        lines.append("Technical Details:")
        lines.append(f"  Open Ports: {normalized_data.get('open_ports', [])}")
        lines.append(f"  Services: {normalized_data.get('services', {})}")
        lines.append(f"  Total Vulnerabilities: {len(normalized_data.get('vulnerabilities', []))}")

        report_text = "\n".join(lines)

        print("\nReport generated successfully.")
        print(report_text)
        print("\nReport generated successfully.")

        # Optional: Run through OpenAI for better prose
        if use_openai and openai_api_key:
            try:
                import openai
                openai.api_key = openai_api_key
                prompt = (
                    "Rewrite the following technical security report as a clear, readable summary for a non-technical audience. "
                    "Keep all findings and recommendations, but make it less formal and more understandable:\n\n"
                    + report_text
                )
                response = openai.ChatCompletion.create(
                    model="gpt-4o",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=1200,
                )
                return response.choices[0].message['content'].strip()
            except Exception as e:
                report_text += f"\n\n[Note: OpenAI enhancement failed: {e}]"
        return report_text
    
    def _generate_executive_summary(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of security findings."""
        vulnerabilities = scan_data.get('vulnerabilities', [])
        open_ports = scan_data.get('open_ports', [])
        
        # Count vulnerabilities by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW').upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Determine overall risk level
        total_vulns = len(vulnerabilities)
        critical_count = severity_counts['CRITICAL']
        high_count = severity_counts['HIGH']
        medium_count = severity_counts['MEDIUM']
        
        if critical_count > 0:
            risk_level = "CRITICAL"
        elif high_count > 0:
            risk_level = "HIGH"
        elif medium_count > 0 or len(open_ports) > 5:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        # Generate recommendations
        recommendations = []
        if critical_count > 0:
            recommendations.append(f"Immediately patch {critical_count} critical vulnerabilities")
        if high_count > 0:
            recommendations.append(f"Address {high_count} high-severity vulnerabilities")
        
        # Check for risky ports
        high_risk_ports = {2375, 3306, 1433, 5432, 23, 135, 445, 3389}
        risky_open_ports = [p for p in open_ports if p in high_risk_ports]
        if risky_open_ports:
            recommendations.append(f"Secure or close high-risk ports: {', '.join(map(str, risky_open_ports))}")
        
        if len(open_ports) > 10:
            recommendations.append("Review and minimize open ports to reduce attack surface")
        
        return {
            "overall_risk_level": risk_level,
            "total_vulnerabilities": total_vulns,
            "critical_vulnerabilities": critical_count,
            "open_ports_count": len(open_ports),
            "custom_recommendations": recommendations
        }
    
    def _analyze_security_findings(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze and categorize security findings."""
        findings = []
        
        vulnerabilities = scan_data.get('vulnerabilities', [])
        open_ports = scan_data.get('open_ports', [])
        
        # Add vulnerability findings
        for vuln in vulnerabilities:
            findings.append({
                "finding_id": vuln.get('cve_id', f"VULN_{vuln.get('id', 'UNKNOWN')}"),
                "severity": vuln.get('severity', 'UNKNOWN'),
                "title": vuln.get('cve_id', f'Vulnerability {vuln.get("id", "Unknown")}'),
                "description": vuln.get('description', 'No description available')[:200] + "..." if len(vuln.get('description', '')) > 200 else vuln.get('description', 'No description available'),
                "impact": self._assess_vulnerability_impact(vuln),
                "confidence": "HIGH"
            })
        
        # Check for critical exposures
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
            3389: "RDP - Remote Desktop Protocol",
            3306: "MySQL - Database server",
            1433: "SQL Server - Database server",
            5432: "PostgreSQL - Database server"
        }
        
        for port in open_ports:
            if port in risky_ports:
                findings.append({
                    "finding_id": f"RISKY_PORT_{port}",
                    "severity": "MEDIUM" if port not in [2375, 3306, 1433, 5432] else "HIGH",
                    "title": f"Risky Port {port} Open",
                    "description": risky_ports[port],
                    "impact": "Potential unauthorized access vector",
                    "confidence": "HIGH"
                })
        
        return findings
    
    def _assess_vulnerability_impact(self, vuln: Dict[str, Any]) -> str:
        """Assess the impact of a vulnerability."""
        severity = vuln.get('severity', 'LOW').upper()
        cvss_score = vuln.get('cvss_score')
        
        if severity == 'CRITICAL':
            return "Critical system compromise possible"
        elif severity == 'HIGH':
            return "High risk of system compromise"
        elif severity == 'MEDIUM':
            return "Moderate security risk"
        else:
            return "Low security risk"
    
    def _generate_recommendations(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        vulnerabilities = scan_data.get('vulnerabilities', [])
        open_ports = scan_data.get('open_ports', [])
        
        # Count vulnerabilities by severity
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'CRITICAL']
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'HIGH']
        medium_vulns = [v for v in vulnerabilities if v.get('severity') == 'MEDIUM']
        
        # Critical vulnerability recommendations
        if critical_vulns:
            recommendations.append({
                "priority": "CRITICAL",
                "category": "Vulnerability Management",
                "title": "Patch Critical Vulnerabilities",
                "description": f"Immediately patch {len(critical_vulns)} critical vulnerabilities including: {', '.join([v.get('cve_id', 'Unknown') for v in critical_vulns[:3]])}",
                "effort": "High"
            })
        
        # High vulnerability recommendations
        if high_vulns:
            recommendations.append({
                "priority": "HIGH",
                "category": "Vulnerability Management", 
                "title": "Address High-Severity Vulnerabilities",
                "description": f"Patch {len(high_vulns)} high-severity vulnerabilities",
                "effort": "Medium"
            })
        
        # SSH-specific recommendations
        ssh_vulns = [v for v in vulnerabilities if 'SSH' in v.get('description', '')]
        if ssh_vulns:
            recommendations.append({
                "priority": "HIGH",
                "category": "Service Security",
                "title": "Update OpenSSH",
                "description": f"Update OpenSSH to version 9.6+ to address {len(ssh_vulns)} known vulnerabilities",
                "effort": "Medium"
            })
        
        # Docker socket recommendations
        if 2375 in open_ports:
            recommendations.append({
                "priority": "CRITICAL",
                "category": "Access Control",
                "title": "Secure Docker Socket",
                "description": "Configure Docker daemon with TLS authentication or restrict access to Docker socket",
                "effort": "Medium"
            })
        
        # Database security recommendations
        db_ports = [p for p in open_ports if p in [3306, 1433, 5432]]
        if db_ports:
            recommendations.append({
                "priority": "HIGH",
                "category": "Database Security",
                "title": "Secure Database Access",
                "description": f"Restrict database access and ensure authentication for ports: {', '.join(map(str, db_ports))}",
                "effort": "Medium"
            })
        
        # General port security
        if len(open_ports) > 10:
            recommendations.append({
                "priority": "MEDIUM",
                "category": "Network Security",
                "title": "Review Open Ports",
                "description": f"Review all {len(open_ports)} open ports and close unnecessary services to reduce attack surface",
                "effort": "Low"
            })
        
        # Medium vulnerability recommendations
        if medium_vulns and len(medium_vulns) > 5:
            recommendations.append({
                "priority": "MEDIUM",
                "category": "Vulnerability Management",
                "title": "Address Medium-Severity Vulnerabilities",
                "description": f"Plan to address {len(medium_vulns)} medium-severity vulnerabilities",
                "effort": "Medium"
            })
        
        return recommendations
    
    def _extract_technical_details(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract technical details for the report."""
        open_ports = scan_data.get('open_ports', [])
        services = scan_data.get('services', {})
        vulnerabilities = scan_data.get('vulnerabilities', [])
        nmap_data = scan_data.get('nmap_data', {})
        
        return {
            "network_information": {
                "open_ports": open_ports,
                "services": services,
                "total_ports_scanned": len(nmap_data.get('ports', [])),
                "scan_duration": nmap_data.get('scan_time', 'unknown')
            },
            "vulnerability_summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "cve_count": len([v for v in vulnerabilities if v.get('cve_id')]),
                "severity_distribution": self._get_severity_distribution(vulnerabilities)
            },
            "service_analysis": {
                "identified_services": list(set(services.values())),
                "high_risk_services": self._identify_high_risk_services(open_ports, services),
                "version_information": "Limited version detection performed"
            }
        }
    
    def _get_severity_distribution(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of vulnerabilities by severity."""
        distribution = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW').upper()
            if severity in distribution:
                distribution[severity] += 1
        return distribution
    
    def _identify_high_risk_services(self, open_ports: List[int], services: Dict[int, str]) -> List[str]:
        """Identify high-risk services from open ports."""
        high_risk_ports = {2375, 3306, 1433, 5432, 23, 135, 445, 3389}
        risky_services = []
        
        for port in open_ports:
            if port in high_risk_ports:
                service = services.get(port, 'unknown')
                risky_services.append(f"{service} (port {port})")
        
        return risky_services

    def _normalize_scan_data(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize scan data from various input formats to a consistent structure.
        
        Args:
            scan_data: Raw scan data in various possible formats
            
        Returns:
            Normalized scan data with consistent structure
        """
        normalized = {
            'ip': 'unknown',
            'open_ports': [],
            'vulnerabilities': [],
            'services': {},
            'nmap_data': {},
            'scan_timestamp': None
        }
        
        # Handle different scan data structures
        if 'raw_data' in scan_data:
            # This is an already processed report - extract the raw scan data
            raw_data = scan_data['raw_data']
            
            # Get IP from multiple possible locations
            normalized['ip'] = raw_data.get('ip_address', raw_data.get('address', 'unknown'))
            
            # Extract data from generic_scan section
            if 'generic_scan' in raw_data:
                generic_scan = raw_data['generic_scan']
                normalized['open_ports'] = generic_scan.get('open_ports', [])
                
                # Extract vulnerabilities from the vulns structure
                vulns_data = generic_scan.get('vulns', {})
                for port, port_vulns in vulns_data.items():
                    if isinstance(port_vulns, list):
                        normalized['vulnerabilities'].extend(port_vulns)
                
                # Extract service information from nmap data
                nmap_data = generic_scan.get('nmap', {})
                normalized['nmap_data'] = nmap_data
                if 'ports' in nmap_data:
                    for port_info in nmap_data['ports']:
                        port = port_info.get('port')
                        service = port_info.get('service', 'unknown')
                        if port:
                            normalized['services'][port] = service
                
                normalized['scan_timestamp'] = raw_data.get('scan_date')
            
        elif 'generic_scan' in scan_data:
            # This is the current structure from the security report
            generic_scan = scan_data['generic_scan']
            
            normalized['ip'] = generic_scan.get('ip', scan_data.get('ip_address', 'unknown'))
            normalized['open_ports'] = generic_scan.get('open_ports', [])
            
            # Extract vulnerabilities from the vulns structure
            vulns_data = generic_scan.get('vulns', {})
            for port, port_vulns in vulns_data.items():
                if isinstance(port_vulns, list):
                    normalized['vulnerabilities'].extend(port_vulns)
            
            # Extract service information from nmap data
            nmap_data = generic_scan.get('nmap', {})
            normalized['nmap_data'] = nmap_data
            if 'ports' in nmap_data:
                for port_info in nmap_data['ports']:
                    port = port_info.get('port')
                    service = port_info.get('service', 'unknown')
                    if port:
                        normalized['services'][port] = service
            
            normalized['scan_timestamp'] = scan_data.get('scan_date')
            
        elif 'ip' in scan_data or 'ip_address' in scan_data:
            # Direct format with ip, open_ports, etc.
            normalized['ip'] = scan_data.get('ip', scan_data.get('ip_address', 'unknown'))
            normalized['open_ports'] = scan_data.get('open_ports', [])
            normalized['vulnerabilities'] = scan_data.get('vulnerabilities', [])
            normalized['services'] = scan_data.get('services', {})
            normalized['scan_timestamp'] = scan_data.get('scan_date', scan_data.get('timestamp'))
            
        return normalized
    
    def _calculate_risk_score(self, scan_data: Dict[str, Any]) -> float:
        """
        Calculate overall risk score based on vulnerabilities and exposed services.
        
        Args:
            scan_data: Normalized scan data
            
        Returns:
            Risk score between 0.0 and 10.0
        """
        vulnerabilities = scan_data.get('vulnerabilities', [])
        open_ports = scan_data.get('open_ports', [])
        
        # Severity weights for vulnerabilities
        severity_weights = {
            'CRITICAL': 10.0,
            'HIGH': 7.0,
            'MEDIUM': 4.0,
            'LOW': 1.0
        }
        
        # Calculate vulnerability score
        vuln_score = 0.0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW').upper()
            vuln_score += severity_weights.get(severity, 1.0)
        
        # Add bonus risk for high-risk ports
        high_risk_ports = {2375, 3306, 1433, 5432, 23, 135, 445, 3389}
        risk_port_count = len([p for p in open_ports if p in high_risk_ports])
        port_risk_score = risk_port_count * 2.0
        
        # Combine scores and normalize to 0-10 scale
        total_score = min(vuln_score + port_risk_score, 100.0)
        return round(total_score / 10.0, 1)
    
    def _get_vulnerability_breakdown(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get breakdown of vulnerabilities by severity and type."""
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        # Count by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        type_counts = {}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW').upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Categorize by type (simplified)
            if 'SSH' in vuln.get('description', ''):
                type_counts['SSH'] = type_counts.get('SSH', 0) + 1
            elif 'TLS' in vuln.get('description', '') or 'SSL' in vuln.get('description', ''):
                type_counts['TLS/SSL'] = type_counts.get('TLS/SSL', 0) + 1
            else:
                type_counts['Other'] = type_counts.get('Other', 0) + 1
        
        return {
            'by_severity': severity_counts,
            'by_type': type_counts,
            'trends': []
        }
    
    def _get_port_analysis(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get analysis of open ports and services."""
        open_ports = scan_data.get('open_ports', [])
        services = scan_data.get('services', {})
        
        # Identify common services
        common_services = []
        for port in open_ports:
            service = services.get(port, 'unknown')
            if service != 'unknown':
                common_services.append(f"{service} ({port})")
        
        # Identify high-risk ports
        high_risk_ports = {
            2375: "Docker API (unencrypted)",
            3306: "MySQL Database", 
            1433: "SQL Server",
            5432: "PostgreSQL",
            23: "Telnet (unencrypted)",
            135: "RPC Endpoint Mapper",
            445: "SMB File Sharing",
            3389: "Remote Desktop Protocol"
        }
        
        risky_ports = []
        for port in open_ports:
            if port in high_risk_ports:
                risky_ports.append(f"{port}: {high_risk_ports[port]}")
        
        return {
            'total_open': len(open_ports),
            'common_services': common_services,
            'high_risk_ports': risky_ports
        }
    
    def _get_compliance_status(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get compliance status assessment."""
        vulnerabilities = scan_data.get('vulnerabilities', [])
        open_ports = scan_data.get('open_ports', [])
        
        # Simple compliance assessment
        has_critical_vulns = any(v.get('severity') == 'CRITICAL' for v in vulnerabilities)
        has_risky_ports = bool(set(open_ports) & {2375, 3306, 1433, 5432, 23})
        
        compliance_level = "PARTIAL"
        issues = []
        
        if has_critical_vulns:
            compliance_level = "NON_COMPLIANT"
            issues.append("Critical vulnerabilities present")
        
        if has_risky_ports:
            if compliance_level != "NON_COMPLIANT":
                compliance_level = "PARTIAL"
            issues.append("High-risk ports exposed")
        
        if not vulnerabilities and len(open_ports) <= 3:
            compliance_level = "COMPLIANT"
        
        return {
            'pci_dss': compliance_level,
            'iso_27001': compliance_level,
            'nist': compliance_level,
            'issues': issues
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
        
        # Initialize external reporter
        self.external_reporter = None
        
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
        if hasattr(self.config, 'reporting') and hasattr(self.config.reporting, 'external_library'):
            external_library = self.config.reporting.external_library
            
            if external_library and external_library.get('enabled', False):
                module_path = external_library.get('module_path')
                
                if module_path:
                    try:
                        self.logger.info(f"Loading external report library: {module_path}")
                        
                        # Import the module and get the class (same pattern as scoring)
                        import importlib
                        mod_name, class_name = module_path.rsplit('.', 1)
                        module = importlib.import_module(mod_name)
                        reporter_class = getattr(module, class_name)
                        
                        # Initialize with configuration
                        config_data = external_library.get('config', {})
                        self.external_reporter = reporter_class(config_data)
                        
                        self.logger.info("External report library loaded successfully")
                        return self.external_reporter
                        
                    except Exception as e:
                        self.logger.warning(f"Failed to load external report library, falling back to default: {e}")
        
        # Also check legacy external_generator for backward compatibility
        elif hasattr(self.config, 'reporting') and hasattr(self.config.reporting, 'external_generator'):
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
            
            # Check if external reporter has custom report generation
            if self.external_reporter and hasattr(self.external_reporter, 'generate_custom_report'):
                try:
                    self.logger.info("Using external reporter for custom report generation")
                    report_data = self.external_reporter.generate_custom_report(item)
                except Exception as e:
                    self.logger.warning(f"External reporter failed, falling back to default: {e}")
                    report_data = self.report_generator.generate_report(item)
            else:
                # Generate the report using the configured generator
                report_data = self.report_generator.generate_report(item)
            
            # Add processing metadata
            report_data['processing_info'] = {
                'agent': self.agent_name,
                'processed_at': datetime.utcnow().isoformat(),
                'generator_type': type(self.report_generator).__name__,
                'external_reporter': self.external_reporter is not None
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

    def generate_report_from_file(self, input_file: str, output_file: Optional[str] = None, 
                                format_type: str = 'json', auto_save: bool = True) -> Dict[str, Any]:
        """
        Generate a report from a scan result file.
        
        Args:
            input_file: Path to scan result JSON file
            output_file: Optional output file path
            format_type: Output format ('json' or 'summary')
            auto_save: Whether to automatically save the report
            
        Returns:
            Generated report data
        """
        import os
        
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        # Load scan data
        try:
            with open(input_file, 'r') as f:
                scan_data = json.load(f)
        except Exception as e:
            raise ValueError(f"Failed to load scan data from {input_file}: {e}")
        
        # Generate report
        report_data = self.process_item(scan_data)
        
        if report_data.get('error'):
            raise Exception(f"Failed to generate report: {report_data.get('message', 'Unknown error')}")
        
        # Save report if requested
        if auto_save or output_file:
            if not output_file:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                target_ip = report_data.get('target_info', {}).get('ip_address', 'unknown').replace('.', '_')
                output_file = f"security_report_{target_ip}_{timestamp}.json"
            
            saved_file = self.save_report(report_data, output_file)
            report_data['saved_to'] = saved_file
        
        return report_data

    def find_latest_scan_result(self, directory: str = ".") -> Optional[str]:
        """
        Find the latest scan result file in the given directory.
        
        Args:
            directory: Directory to search in
            
        Returns:
            Path to latest scan result file or None if not found
        """
        import glob
        import os
        
        scan_files = glob.glob(os.path.join(directory, "scan_result_*.json"))
        if scan_files:
            return max(scan_files, key=os.path.getctime)
        return None

    def print_report_summary(self, report_data: Dict[str, Any]) -> None:
        """
        Print a formatted summary of the report to console.
        
        Args:
            report_data: Report data to summarize
        """
        print(f"\n📊 Security Report Summary:")
        
        summary = report_data.get('executive_summary', {})
        print(f"   Overall Risk Level: {summary.get('overall_risk_level', 'Unknown')}")
        print(f"   Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        print(f"   Critical Issues: {summary.get('critical_vulnerabilities', 0)}")
        print(f"   Open Ports: {summary.get('open_ports_count', 0)}")
        
        findings = report_data.get('security_findings', [])
        critical_findings = [f for f in findings if f.get('severity') == 'CRITICAL']
        if critical_findings:
            print(f"   Critical Findings:")
            for finding in critical_findings[:3]:  # Show top 3
                print(f"     • {finding.get('title', 'Unknown')}")

    def send_email_report(self, report_data: Dict[str, Any], recipients: Optional[List[str]] = None) -> bool:
        """
        Send report via email (placeholder for future implementation).
        
        Args:
            report_data: Report data to email
            recipients: List of recipient email addresses
            
        Returns:
            True if email sent successfully, False otherwise
        """
        # This would integrate with the email configuration
        email_config = getattr(self.config.reporting, 'email', {})
        
        if not email_config.get('enabled', False):
            self.logger.warning("Email reporting is not enabled in configuration")
            return False
        
        # TODO: Implement actual email sending logic
        self.logger.info("Email notification generation not yet implemented")
        self.logger.info("This feature will use the external report library or built-in email functionality")
        
        return False

    def generate_and_output_report(self, options):
        print("Generating security analysis report with options:", options)
        print("Generating security analysis report with options:", options)
        """Generate report and handle output based on options"""
        try:
            # Load scan data from input
            scan_data = self._load_scan_data(options.get('input_file'))
            
            # Generate the report
            self.logger.info("Generating security analysis report...")
            report_data = self.process_item(scan_data)
            
            if report_data.get('error'):
                raise Exception(report_data.get('message', 'Unknown error in report generation'))
            
            # Handle output
            self._handle_output(report_data, options)
            
            self.logger.info("Report generation completed successfully")
            return report_data
            
        except Exception as e:
            self.logger.error(f"Error in report generation: {e}")
            raise
    
    def _load_scan_data(self, input_file):
        """Load scan data from file or find latest scan result"""
        import glob
        import os
        
        if not input_file:
            # Look for recent scan results in current directory
            scan_files = glob.glob("scan_result_*.json")
            if scan_files:
                # Get the most recent file
                input_file = max(scan_files, key=os.path.getctime)
                self.logger.info(f"Using latest scan result: {input_file}")
            else:
                raise Exception("No scan result files found. Specify input file.")
        
        if not os.path.exists(input_file):
            raise Exception(f"Input file not found: {input_file}")
        
        self.logger.info(f"Loading scan results from: {input_file}")
        
        with open(input_file, 'r') as f:
            return json.load(f)
    
    def _handle_output(self, report_data, options):
        """Handle different output formats and destinations"""
        import json
        from datetime import datetime
        
        # Determine output file
        output_file = options.get('output_file')
        if options.get('auto_save') or not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_ip = report_data.get('target_info', {}).get('ip_address', 'unknown').replace('.', '_')
            output_file = f"security_report_{target_ip}_{timestamp}.json"
        
        # Save report if output file specified
        if output_file:
            saved_file = self.save_report(report_data, output_file)
            self.logger.info(f"Report saved to: {saved_file}")
        
        # Handle different output formats
        report_format = options.get('format', 'json')
        if report_format == 'human':
            use_openai = options.get('use_openai', False)
            openai_key = options.get('openai_api_key')
            print(self.report_generator.generate_human_report(
                report_data,
                use_openai=use_openai,
                openai_api_key=openai_key
            ))
        elif report_format == 'summary':
            self._print_summary(report_data)
        elif report_format == 'json' and not output_file:
            # Print JSON to stdout if no output file
            print(json.dumps(report_data, indent=2, default=str))
        
        # Handle email if requested
        if options.get('email_report'):
            self._send_email_report(report_data, options.get('recipient_email'))
    
    def _print_summary(self, report_data):
        """Print a summary of the report to stdout"""
        print(f"\n📊 Security Report Summary:")
        summary = report_data.get('executive_summary', {})
        print(f"   Overall Risk Level: {summary.get('overall_risk_level', 'Unknown')}")
        print(f"   Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        print(f"   Critical Issues: {summary.get('critical_vulnerabilities', 0)}")
        print(f"   Open Ports: {summary.get('open_ports_count', 0)}")
        
        findings = report_data.get('security_findings', [])
        critical_findings = [f for f in findings if f.get('severity') == 'CRITICAL']
        if critical_findings:
            print(f"   Critical Findings:")
            for finding in critical_findings[:3]:  # Show top 3
                print(f"     • {finding.get('title', 'Unknown')}")
    
    def _send_email_report(self, report_data, recipient_email):
        """Send report via email (placeholder for external library)"""
        if self.external_reporter:
            try:
                self.external_reporter.send_email_report(report_data, recipient_email)
                self.logger.info(f"Email report sent to {recipient_email}")
            except Exception as e:
                self.logger.error(f"Failed to send email report: {e}")
        else:
            self.logger.warning("Email notification not available - no external report library configured")
    
    def execute(self, scan_id: Optional[int] = None, force_report: bool = False) -> List[Dict[str, Any]]:
        """
        Execute the report agent by loading scan results and generating reports.
        
        Args:
            scan_id: Optional specific scan ID to generate report for
            force_report: Whether to force report generation even if already processed
            
        Returns:
            List of generated reports
        """
        self.logger.info(f"🚀 Starting ReportAgent execution (scan_id={scan_id}, force_report={force_report})")
        
        # Check if external reporter has its own execute method (like external scorers)
        if self.external_reporter and hasattr(self.external_reporter, 'execute'):
            try:
                self.logger.info(f"✅ Using external reporter execute method")
                return self.external_reporter.execute(scan_id=scan_id, force_report=force_report)
            except Exception as e:
                self.logger.warning(f"External reporter execute failed, falling back to built-in: {e}")
        
        # Load scan results from database
        scan_results = self._get_scans_for_reporting(scan_id=scan_id, force_report=force_report)
        
        if not scan_results:
            self.logger.info("📊 No scans to generate reports for")
            return []
        
        # Generate reports for each scan
        reports = []
        for scan_result in scan_results:
            try:
                # Generate the report
                report_data = self.process_item(scan_result)
                
                if not report_data.get('error'):
                    # Save the report to database
                    saved_report = self._save_report_to_database(report_data, scan_result['scan_id'])
                    if saved_report:
                        reports.append(saved_report)
                        self.logger.info(f"✅ Report generated and saved for scan {scan_result['scan_id']}")
                    else:
                        self.logger.warning(f"⚠️ Report generated but not saved for scan {scan_result['scan_id']}")
                        reports.append(report_data)
                else:
                    self.logger.error(f"❌ Report generation failed for scan {scan_result['scan_id']}: {report_data.get('message')}")
                    
            except Exception as e:
                self.logger.error(f"❌ Error generating report for scan {scan_result['scan_id']}: {e}")
        
        self.logger.info(f"✅ Report generation completed: {len(reports)} reports generated")
        return reports
    
    def _get_scans_for_reporting(self, scan_id: Optional[int] = None, force_report: bool = False) -> List[Dict[str, Any]]:
        """
        Get scan results for report generation from the database.
        
        Args:
            scan_id: Optional specific scan ID to generate report for  
            force_report: Whether to force report generation even if already processed
            
        Returns:
            List of scan results to generate reports for
        """
        try:
            from pgdn.core.database import get_db_session, ValidatorScan, ValidatorScanReport
            
            with get_db_session() as session:
                # Base query for successful scans
                query = session.query(ValidatorScan).filter(ValidatorScan.failed == False)
                
                if scan_id:
                    # Generate report for specific scan
                    query = query.filter(ValidatorScan.id == scan_id)
                    
                    # Check if report already exists for this scan (unless force_report)
                    if not force_report:
                        existing_report = session.query(ValidatorScanReport).filter(
                            ValidatorScanReport.scan_id == scan_id
                        ).first()
                        if existing_report:
                            self.logger.info(f"📊 Report already exists for scan {scan_id} (use --force-report to regenerate)")
                            return []
                else:
                    # Generate reports for scans without reports (unless force_report)
                    if not force_report:
                        # Get scans that don't have reports yet
                        scan_ids_with_reports = session.query(ValidatorScanReport.scan_id).distinct()
                        query = query.filter(~ValidatorScan.id.in_(scan_ids_with_reports))
                
                scans = query.order_by(ValidatorScan.scan_date.desc()).all()
                
                results = []
                for scan in scans:
                    if scan.scan_results:
                        # Prepare scan data in the format expected by the report generator
                        results.append({
                            'scan_id': scan.id,
                            'validator_id': scan.validator_address_id,
                            'scan_date': scan.scan_date.isoformat(),
                            'ip_address': scan.ip_address,
                            'scan_version': scan.version,
                            'scan_hash': scan.scan_hash,
                            'raw_results': scan.scan_results,
                            # Include the raw scan data for report generation
                            **scan.scan_results
                        })
                
                self.logger.info(f"📊 Found {len(results)} scans for report generation (scan_id={scan_id}, force_report={force_report})")
                return results
                
        except Exception as e:
            self.logger.error(f"❌ Error loading scans for reporting: {e}")
            return []
    
    def _save_report_to_database(self, report_data: Dict[str, Any], scan_id: int) -> Optional[Dict[str, Any]]:
        """
        Save generated report to the database.
        
        Args:
            report_data: Generated report data
            scan_id: ID of the scan this report is for
            
        Returns:
            Saved report data with database info, or None if failed
        """
        try:
            from pgdn.core.database import get_db_session, ValidatorScanReport
            import uuid as uuid_lib
            
            # Extract key metrics from the report
            summary = report_data.get('executive_summary', {})
            overall_risk_level = summary.get('overall_risk_level', 'UNKNOWN')
            total_vulnerabilities = summary.get('total_vulnerabilities', 0)
            critical_vulnerabilities = summary.get('critical_vulnerabilities', 0)
            
            # Generate a brief summary
            findings = report_data.get('security_findings', [])
            critical_findings = [f for f in findings if f.get('severity') == 'CRITICAL']
            summary_text = f"Risk: {overall_risk_level}, Vulns: {total_vulnerabilities}"
            if critical_findings:
                summary_text += f", Critical: {len(critical_findings)}"
            
            with get_db_session() as session:
                # Create the report record
                report_record = ValidatorScanReport(
                    uuid=uuid_lib.uuid4(),
                    scan_id=scan_id,
                    report_date=datetime.utcnow(),
                    report_type='security_analysis',
                    report_format='json',
                    overall_risk_level=overall_risk_level,
                    total_vulnerabilities=total_vulnerabilities,
                    critical_vulnerabilities=critical_vulnerabilities,
                    report_data=report_data,
                    report_summary=summary_text[:1000],  # Truncate to fit field
                    processed=True,
                    created_at=datetime.utcnow()
                )
                
                session.add(report_record)
                session.commit()
                session.refresh(report_record)
                
                self.logger.info(f"💾 Report saved to database with ID {report_record.id}")
                
                # Return the saved report data
                return report_record.to_dict()
                
        except Exception as e:
            self.logger.error(f"❌ Error saving report to database: {e}")
            return None
