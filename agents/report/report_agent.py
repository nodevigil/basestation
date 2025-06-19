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
        summary = self._generate_executive_summary(scan_data)
        findings = self._analyze_security_findings(scan_data)
        recommendations = self._generate_recommendations(scan_data)

        lines = []
        lines.append(f"Security Analysis Report")
        lines.append(f"Generated: {datetime.utcnow().isoformat()}")
        lines.append(f"Target IP: {scan_data.get('ip', 'unknown')}")
        lines.append("")

        # Executive Summary
        lines.append("Executive Summary:")
        lines.append(f"  - Overall Risk Level: {summary.get('overall_risk_level')}")
        lines.append(f"  - Vulnerabilities found: {summary.get('total_vulnerabilities')}")
        lines.append(f"  - Critical: {summary.get('critical_vulnerabilities')}, High: {summary.get('high_vulnerabilities')}, Medium: {summary.get('medium_vulnerabilities')}")
        lines.append(f"  - Open Ports: {summary.get('open_ports_count')}")
        lines.append(f"  - {summary.get('summary_text')}")
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
        lines.append(f"  Open Ports: {scan_data.get('open_ports', [])}")
        lines.append(f"  Services: {scan_data.get('services', {})}")
        tls = scan_data.get('tls', {})
        if tls:
            lines.append(f"  TLS: {tls}")
        osinfo = scan_data.get('os', {})
        if osinfo:
            lines.append(f"  OS: {osinfo}")

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
                class_name = external_library.get('class_name')
                
                if module_path and class_name:
                    try:
                        self.logger.info(f"Loading external report library: {module_path}.{class_name}")
                        
                        # Import the module and get the class
                        import importlib
                        module = importlib.import_module(module_path)
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
