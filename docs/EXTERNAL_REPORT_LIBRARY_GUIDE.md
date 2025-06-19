# External Report Library Guide

The PGDN reporting system supports external report libraries that can extend the built-in reporting capabilities with custom formats, analysis methods, and delivery mechanisms.

## Overview

External report libraries allow you to:
- Generate custom report formats (HTML, PDF, CSV, etc.)
- Implement custom risk scoring algorithms
- Add compliance checking against specific standards
- Integrate with external systems (SIEM, ticketing, etc.)
- Send reports via email, Slack, or other channels
- Perform advanced analysis and correlation

## Configuration

To enable an external report library, update your `config.json`:

```json
{
  "reporting": {
    "external_library": {
      "enabled": true,
      "module_path": "path.to.your.reporter",
      "class_name": "YourReporterClass",
      "config": {
        "smtp": {
          "server": "smtp.example.com",
          "port": 587,
          "username": "security@example.com",
          "password": "your-password",
          "from_email": "security@example.com"
        },
        "custom_settings": {
          "risk_threshold": 7.0,
          "compliance_standards": ["PCI-DSS", "ISO-27001"]
        }
      }
    }
  }
}
```

## Implementation Interface

Your external reporter class should implement the following interface:

```python
class YourReporter:
    def __init__(self, config: Dict[str, Any]):
        """Initialize with configuration from config.json"""
        pass
    
    def generate_custom_report(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a custom report format (optional)"""
        pass
    
    def send_email_report(self, report_data: Dict[str, Any], recipient_email: str) -> bool:
        """Send report via email (optional)"""
        pass
    
    def generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML formatted report (optional)"""
        pass
    
    def export_to_csv(self, report_data: Dict[str, Any], filename: str) -> str:
        """Export to CSV format (optional)"""
        pass
```

## Available Methods

The report agent will attempt to call these methods on your external library if they exist:

### Core Methods

- `generate_custom_report(scan_data)` - Override the default report generation
- `send_email_report(report_data, recipient_email)` - Handle email delivery
- `generate_html_report(report_data)` - Generate HTML format
- `export_to_csv(report_data, filename)` - Export to CSV
- `export_to_pdf(report_data, filename)` - Export to PDF

### Analysis Methods

- `calculate_risk_score(vulnerabilities, ports)` - Custom risk scoring
- `check_compliance(scan_data, standards)` - Compliance checking
- `correlate_findings(findings)` - Find patterns in vulnerabilities
- `generate_recommendations(scan_data)` - Custom recommendations

### Integration Methods

- `send_to_siem(report_data)` - Send to SIEM system
- `create_ticket(finding)` - Create tickets for findings
- `send_slack_notification(summary)` - Send Slack notifications
- `update_dashboard(metrics)` - Update security dashboard

## Data Structures

### Input Scan Data Structure

```python
{
    "target_info": {
        "ip_address": "192.168.1.100",
        "hostname": "server.example.com",
        "scan_time": "2024-01-15T10:30:00Z"
    },
    "open_ports": [
        {
            "port": 80,
            "service": "http",
            "version": "Apache 2.4.41",
            "state": "open"
        }
    ],
    "vulnerabilities": [
        {
            "title": "SQL Injection",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "description": "SQL injection vulnerability detected",
            "recommendation": "Use parameterized queries",
            "affected_service": "web application",
            "cve_id": "CVE-2024-1234"
        }
    ],
    "web_technologies": [
        {
            "name": "Apache",
            "version": "2.4.41",
            "confidence": 100
        }
    ]
}
```

### Output Report Data Structure

```python
{
    "report_metadata": {
        "generated_at": "2024-01-15T10:35:00Z",
        "report_version": "1.0",
        "external_library": "YourReporter v1.0"
    },
    "target_info": {
        "ip_address": "192.168.1.100",
        "hostname": "server.example.com"
    },
    "executive_summary": {
        "overall_risk_level": "HIGH",
        "total_vulnerabilities": 5,
        "critical_vulnerabilities": 2,
        "open_ports_count": 8,
        "compliance_status": "NON_COMPLIANT"
    },
    "security_findings": [
        {
            "title": "SQL Injection",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "description": "Detailed description",
            "recommendation": "Specific remediation steps",
            "affected_service": "web application"
        }
    ],
    "compliance_results": {
        "pci_dss": "FAIL",
        "iso_27001": "PARTIAL",
        "custom_policy": "PASS"
    },
    "recommendations": [
        "Patch critical vulnerabilities immediately",
        "Implement WAF protection",
        "Enable security headers"
    ]
}
```

## Example Implementation

See `docs/examples/example_external_reporter.py` for a complete implementation example that demonstrates:

- Custom risk scoring
- HTML report generation
- Email delivery
- CSV export
- Compliance checking
- Custom recommendations

## Testing Your Library

1. Create your reporter class following the interface
2. Update your `config.json` to point to your module
3. Test with: `pgdn --stage report --report-format summary`
4. Check logs for any loading or execution errors

## Best Practices

1. **Error Handling**: Always include proper error handling and logging
2. **Configuration**: Use the config parameter for all settings
3. **Dependencies**: Document any external dependencies required
4. **Performance**: Keep report generation efficient for large datasets
5. **Security**: Sanitize any user input, especially for HTML/PDF generation
6. **Backward Compatibility**: Handle missing fields gracefully

## Common Use Cases

### Enterprise Integration

```python
def send_to_siem(self, report_data):
    """Send findings to SIEM system"""
    for finding in report_data.get('security_findings', []):
        siem_event = {
            'timestamp': datetime.now().isoformat(),
            'severity': finding.get('severity'),
            'source_ip': report_data.get('target_info', {}).get('ip_address'),
            'event_type': 'vulnerability_detected',
            'description': finding.get('title')
        }
        # Send to SIEM API
        self.siem_client.send_event(siem_event)
```

### Compliance Reporting

```python
def check_pci_compliance(self, scan_data):
    """Check PCI-DSS compliance"""
    issues = []
    
    # Check for unencrypted protocols
    for port in scan_data.get('open_ports', []):
        if port.get('port') in [21, 23, 80]:
            issues.append(f"Unencrypted service on port {port['port']}")
    
    return {
        'status': 'FAIL' if issues else 'PASS',
        'issues': issues
    }
```

### Custom Risk Scoring

```python
def calculate_business_risk(self, vulnerabilities, asset_value):
    """Calculate risk based on business impact"""
    risk_score = 0
    
    for vuln in vulnerabilities:
        base_score = vuln.get('cvss_score', 0)
        business_impact = asset_value * 0.1  # 10% of asset value
        risk_score += base_score * business_impact
    
    return min(risk_score, 100)
```

## Troubleshooting

### Common Issues

1. **Module Not Found**: Check the `module_path` in config.json
2. **Class Not Found**: Verify the `class_name` matches your class
3. **Import Errors**: Ensure all dependencies are installed
4. **Method Errors**: Check method signatures match the interface

### Debug Mode

Enable debug logging to see detailed information about external library loading:

```bash
pgdn --stage report --debug --log-level DEBUG
```

This will show:
- External library loading attempts
- Method availability checks
- Configuration passed to the library
- Any exceptions during execution
