"""
Example External Report Library for PGDN

This is an example implementation of an external report library that can be loaded
dynamically by the PGDN report agent. This demonstrates how to extend the reporting
capabilities with custom formats, delivery methods, and analysis.

To use this library:
1. Install any required dependencies
2. Update your config.json to point to this module:
   {
     "reporting": {
       "external_library": {
         "enabled": true,
         "module_path": "docs.examples.example_external_reporter",
         "class_name": "ExampleReporter"
       }
     }
   }
3. Run: pgdn --stage report
"""

import json
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, Optional


class ExampleReporter:
    """
    Example external reporter implementation.
    
    This class demonstrates the interface that external report libraries should implement.
    You can extend this with your own custom reporting logic, formats, and delivery methods.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the external reporter with configuration.
        
        Args:
            config: Configuration dictionary from the report agent
        """
        self.config = config
        self.smtp_config = config.get('smtp', {})
        
    def generate_custom_report(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a custom report format.
        
        Args:
            scan_data: Raw scan data from the security scan
            
        Returns:
            Custom formatted report data
        """
        # Example custom analysis
        vulnerabilities = scan_data.get('vulnerabilities', [])
        open_ports = scan_data.get('open_ports', [])
        
        # Custom risk scoring
        risk_score = self._calculate_custom_risk_score(vulnerabilities, open_ports)
        
        # Generate custom report structure
        custom_report = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'report_version': '2.0',
                'custom_analysis': True,
                'risk_score': risk_score
            },
            'executive_summary': {
                'overall_risk_level': self._get_risk_level(risk_score),
                'total_vulnerabilities': len(vulnerabilities),
                'critical_vulnerabilities': len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL']),
                'open_ports_count': len(open_ports),
                'custom_recommendations': self._get_custom_recommendations(scan_data)
            },
            'detailed_analysis': {
                'vulnerability_breakdown': self._analyze_vulnerabilities(vulnerabilities),
                'port_analysis': self._analyze_ports(open_ports),
                'compliance_check': self._check_compliance(scan_data)
            },
            'raw_data': scan_data
        }
        
        return custom_report
    
    def generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """
        Generate an HTML formatted report.
        
        Args:
            report_data: Report data dictionary
            
        Returns:
            HTML formatted report as string
        """
        summary = report_data.get('executive_summary', {})
        findings = report_data.get('security_findings', [])
        
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; margin-bottom: 20px; }}
                .summary {{ background-color: #e6f3ff; padding: 15px; margin-bottom: 20px; }}
                .critical {{ color: #dc3545; }}
                .high {{ color: #fd7e14; }}
                .medium {{ color: #ffc107; }}
                .low {{ color: #28a745; }}
                .finding {{ border: 1px solid #dee2e6; padding: 10px; margin: 10px 0; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Analysis Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Overall Risk Level:</strong> <span class="{summary.get('overall_risk_level', '').lower()}">{summary.get('overall_risk_level', 'Unknown')}</span></p>
                <p><strong>Total Vulnerabilities:</strong> {summary.get('total_vulnerabilities', 0)}</p>
                <p><strong>Critical Issues:</strong> {summary.get('critical_vulnerabilities', 0)}</p>
                <p><strong>Open Ports:</strong> {summary.get('open_ports_count', 0)}</p>
            </div>
            
            <div class="findings">
                <h2>Security Findings</h2>
        """
        
        for finding in findings:
            severity_class = finding.get('severity', '').lower()
            html_template += f"""
                <div class="finding">
                    <h3 class="{severity_class}">{finding.get('title', 'Unknown')}</h3>
                    <p><strong>Severity:</strong> {finding.get('severity', 'Unknown')}</p>
                    <p><strong>Description:</strong> {finding.get('description', 'No description available')}</p>
                    <p><strong>Recommendation:</strong> {finding.get('recommendation', 'No recommendation available')}</p>
                </div>
            """
        
        html_template += """
            </div>
        </body>
        </html>
        """
        
        return html_template
    
    def send_email_report(self, report_data: Dict[str, Any], recipient_email: str) -> bool:
        """
        Send report via email.
        
        Args:
            report_data: Report data dictionary
            recipient_email: Email address to send report to
            
        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            # Create email message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"Security Report - {datetime.now().strftime('%Y-%m-%d')}"
            msg['From'] = self.smtp_config.get('from_email', 'security@example.com')
            msg['To'] = recipient_email
            
            # Create text version
            text_content = self._generate_text_summary(report_data)
            text_part = MIMEText(text_content, 'plain')
            msg.attach(text_part)
            
            # Create HTML version
            html_content = self.generate_html_report(report_data)
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            # Send email
            smtp_server = self.smtp_config.get('server', 'localhost')
            smtp_port = self.smtp_config.get('port', 587)
            username = self.smtp_config.get('username')
            password = self.smtp_config.get('password')
            
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if username and password:
                    server.starttls()
                    server.login(username, password)
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            print(f"Failed to send email: {e}")
            return False
    
    def export_to_csv(self, report_data: Dict[str, Any], filename: str) -> str:
        """
        Export vulnerabilities to CSV format.
        
        Args:
            report_data: Report data dictionary
            filename: Output filename
            
        Returns:
            Path to saved CSV file
        """
        import csv
        
        findings = report_data.get('security_findings', [])
        
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['title', 'severity', 'cvss_score', 'description', 'recommendation', 'affected_service']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for finding in findings:
                writer.writerow({
                    'title': finding.get('title', ''),
                    'severity': finding.get('severity', ''),
                    'cvss_score': finding.get('cvss_score', ''),
                    'description': finding.get('description', ''),
                    'recommendation': finding.get('recommendation', ''),
                    'affected_service': finding.get('affected_service', '')
                })
        
        return filename
    
    def _calculate_custom_risk_score(self, vulnerabilities: list, open_ports: list) -> float:
        """Calculate a custom risk score based on findings."""
        score = 0.0
        
        # Score based on vulnerabilities
        for vuln in vulnerabilities:
            severity = vuln.get('severity', '').upper()
            if severity == 'CRITICAL':
                score += 10.0
            elif severity == 'HIGH':
                score += 7.0
            elif severity == 'MEDIUM':
                score += 4.0
            elif severity == 'LOW':
                score += 1.0
        
        # Score based on open ports
        dangerous_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        for port in open_ports:
            port_num = port.get('port', 0)
            if port_num in dangerous_ports:
                score += 2.0
            else:
                score += 0.5
        
        return min(score, 100.0)  # Cap at 100
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level."""
        if risk_score >= 80:
            return 'CRITICAL'
        elif risk_score >= 60:
            return 'HIGH'
        elif risk_score >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_custom_recommendations(self, scan_data: Dict[str, Any]) -> list:
        """Generate custom recommendations based on scan data."""
        recommendations = []
        
        vulnerabilities = scan_data.get('vulnerabilities', [])
        open_ports = scan_data.get('open_ports', [])
        
        # Check for common issues
        if any(v.get('severity') == 'CRITICAL' for v in vulnerabilities):
            recommendations.append("Immediately patch critical vulnerabilities")
        
        if len(open_ports) > 10:
            recommendations.append("Review and close unnecessary open ports")
        
        if any(p.get('port') == 22 for p in open_ports):
            recommendations.append("Secure SSH access with key-based authentication")
        
        if any(p.get('port') == 21 for p in open_ports):
            recommendations.append("Replace FTP with secure alternatives like SFTP")
        
        return recommendations
    
    def _analyze_vulnerabilities(self, vulnerabilities: list) -> Dict[str, Any]:
        """Analyze vulnerability patterns."""
        analysis = {
            'by_severity': {},
            'by_type': {},
            'trends': []
        }
        
        # Count by severity
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            analysis['by_severity'][severity] = analysis['by_severity'].get(severity, 0) + 1
        
        return analysis
    
    def _analyze_ports(self, open_ports: list) -> Dict[str, Any]:
        """Analyze open port patterns."""
        analysis = {
            'total_open': len(open_ports),
            'common_services': [],
            'high_risk_ports': []
        }
        
        dangerous_ports = [21, 23, 25, 53, 135, 139, 445]
        for port in open_ports:
            port_num = port.get('port', 0)
            if port_num in dangerous_ports:
                analysis['high_risk_ports'].append(port)
        
        return analysis
    
    def _check_compliance(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check compliance against common standards."""
        compliance = {
            'pci_dss': 'PARTIAL',
            'iso_27001': 'PARTIAL',
            'nist': 'PARTIAL',
            'issues': []
        }
        
        # Example compliance checks
        open_ports = scan_data.get('open_ports', [])
        if any(p.get('port') == 21 for p in open_ports):
            compliance['issues'].append("Unencrypted FTP detected (PCI-DSS violation)")
        
        return compliance
    
    def _generate_text_summary(self, report_data: Dict[str, Any]) -> str:
        """Generate a text summary of the report."""
        summary = report_data.get('executive_summary', {})
        
        text = f"""
Security Analysis Report Summary
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

EXECUTIVE SUMMARY
=================
Overall Risk Level: {summary.get('overall_risk_level', 'Unknown')}
Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}
Critical Issues: {summary.get('critical_vulnerabilities', 0)}
Open Ports: {summary.get('open_ports_count', 0)}

TOP FINDINGS
============
"""
        
        findings = report_data.get('security_findings', [])[:5]  # Top 5
        for i, finding in enumerate(findings, 1):
            text += f"{i}. {finding.get('title', 'Unknown')} [{finding.get('severity', 'Unknown')}]\n"
            text += f"   {finding.get('description', 'No description')}\n\n"
        
        return text


# Example usage and testing
if __name__ == "__main__":
    # Example configuration
    config = {
        'smtp': {
            'server': 'smtp.example.com',
            'port': 587,
            'username': 'security@example.com',
            'password': 'your-password',
            'from_email': 'security@example.com'
        }
    }
    
    # Example scan data
    scan_data = {
        'vulnerabilities': [
            {
                'title': 'SQL Injection',
                'severity': 'CRITICAL',
                'cvss_score': 9.8,
                'description': 'SQL injection vulnerability detected',
                'recommendation': 'Use parameterized queries'
            }
        ],
        'open_ports': [
            {'port': 80, 'service': 'http'},
            {'port': 443, 'service': 'https'},
            {'port': 22, 'service': 'ssh'}
        ]
    }
    
    # Test the reporter
    reporter = ExampleReporter(config)
    report = reporter.generate_custom_report(scan_data)
    
    print("Generated custom report:")
    print(json.dumps(report, indent=2))
