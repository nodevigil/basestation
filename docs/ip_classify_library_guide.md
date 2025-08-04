# IP Classification Scanner - Library Guide

The IP Classification Scanner provides comprehensive analysis of IP addresses to identify cloud providers, CDNs, hosting services, and infrastructure characteristics. This guide covers both direct library usage and integration examples.

## Table of Contents

- [Quick Start](#quick-start)
- [Library API](#library-api)
- [Configuration](#configuration)
- [Advanced Usage](#advanced-usage)
- [Integration Examples](#integration-examples)
- [Output Format](#output-format)
- [Error Handling](#error-handling)
- [Performance Tips](#performance-tips)

## Quick Start

### CLI Usage

```bash
# Basic IP classification
pgdn-scanner --target 1.1.1.1 --run ip_classify

# Multiple IPs
pgdn-scanner --target "8.8.8.8,1.1.1.1" --run ip_classify --json

# Output with pretty formatting
pgdn-scanner --target cloudfront.amazonaws.com --run ip_classify --json --pretty
```

### Python Library Usage

```python
from pgdn_scanner.scanner import Scanner

# Create scanner instance
scanner = Scanner()

# Classify single IP
result = scanner.scan(target="1.1.1.1", run="ip_classify")
print(result.data)

# Classify multiple IPs
result = scanner.scan(target="8.8.8.8,1.1.1.1,192.168.1.1", run="ip_classify")
for classification in result.data:
    print(f"IP: {classification['result']['ip']}")
    print(f"Provider: {classification['result']['ipinfo_org']}")
    print(f"Role: {classification['result']['likely_role']}")
```

## Library API

### Scanner Class

The main entry point for IP classification is through the `Scanner` class:

```python
from pgdn_scanner.scanner import Scanner

scanner = Scanner(config=None)  # Optional configuration
```

### scan() Method

```python
result = scanner.scan(
    target="1.1.1.1",        # IP address or comma-separated list
    run="ip_classify",       # Scanner type
    debug=False              # Optional debug mode
)
```

**Parameters:**
- `target` (str): IP address or comma-separated list of IPs
- `run` (str): Must be "ip_classify" for IP classification
- `debug` (bool): Enable debug logging (optional)

**Returns:**
- `DictResult`: Object containing classification data and metadata

### Direct Scanner Usage

For advanced use cases, you can use the scanner directly:

```python
from pgdn_scanner.scanners.ip_classify_scanner import IpClassifyScanner

# Create scanner with custom config
config = {
    'timeout': 10,
    'default_port': 443,
    'ipinfo_url': 'https://ipinfo.io/{ip}/json'
}

scanner = IpClassifyScanner(config)

# Single IP scan
result = scanner.scan("1.1.1.1", scan_level=1)

# Multiple IP scan
result = scanner.scan("8.8.8.8,1.1.1.1", scan_level=2)
```

## Configuration

### Default Configuration

The scanner uses these default settings:

```python
default_config = {
    'timeout': 5,                                      # Request timeout in seconds
    'default_port': 443,                              # Default port for TLS inspection
    'ipinfo_url': 'https://ipinfo.io/{ip}/json',      # IPInfo API URL
    'aws_ranges_url': 'https://ip-ranges.amazonaws.com/ip-ranges.json'  # AWS ranges URL
}
```

### Custom Configuration

```python
from pgdn_scanner.core.config import Config
from pgdn_scanner.scanner import Scanner

# Create custom config
config = Config()
config.scanners = {
    'ip_classify': {
        'timeout': 10,
        'default_port': 80,
        'fallback_to_api': True
    }
}

scanner = Scanner(config)
```

### Environment Variables

You can also configure via environment variables:

```bash
export PGDN_IP_CLASSIFY_TIMEOUT=10
export PGDN_IP_CLASSIFY_PORT=80
```

## Advanced Usage

### Scan Levels

The scanner supports different scan levels for varying detail:

```python
scanner = IpClassifyScanner()

# Level 1: Basic classification (default)
# - Reverse DNS lookup
# - IPInfo organization lookup
# - AWS service matching
# - Basic classification
result = scanner.scan("1.1.1.1", scan_level=1)

# Level 2: Detailed analysis
# - All Level 1 features
# - TLS certificate inspection
# - HTTP header analysis
# - Advanced role determination
result = scanner.scan("1.1.1.1", scan_level=2)
```

### Bulk IP Analysis

Efficiently analyze multiple IPs:

```python
from pgdn_scanner.scanners.ip_classify_scanner import IpClassifyScanner

scanner = IpClassifyScanner()

# Analyze IP list from file
with open('ip_list.txt', 'r') as f:
    ips = [line.strip() for line in f.readlines()]
    
ip_string = ','.join(ips)
result = scanner.scan(ip_string, scan_level=2)

# Process results
for ip_result in result['results']:
    print(f"{ip_result['ip']}: {ip_result['likely_role']}")
```

### Custom Provider Detection

Extend the scanner with custom provider patterns:

```python
class CustomIpClassifyScanner(IpClassifyScanner):
    def _classify_hostname(self, hostname: str) -> str:
        """Override with custom classification logic."""
        result = super()._classify_hostname(hostname)
        
        # Add custom patterns
        if 'mycdn.com' in hostname.lower():
            return 'My Custom CDN'
        elif 'mycloud.net' in hostname.lower():
            return 'My Cloud Provider'
            
        return result

# Use custom scanner
scanner = CustomIpClassifyScanner()
result = scanner.scan("custom.mycdn.com")
```

## Integration Examples

### Threat Intelligence Integration

```python
import json
from pgdn_scanner.scanner import Scanner

def analyze_suspicious_ips(ip_list):
    """Analyze list of IPs for threat intelligence."""
    scanner = Scanner()
    
    results = []
    for ip in ip_list:
        result = scanner.scan(target=ip, run="ip_classify")
        
        if result.success:
            classification = result.data[0]['result']
            
            # Flag suspicious characteristics
            if classification['likely_role'] == 'unclassified':
                classification['suspicious'] = True
                classification['reason'] = 'Unknown provider'
            elif 'cloudflare' in classification.get('ipinfo_org', '').lower():
                classification['suspicious'] = False
                classification['reason'] = 'Known CDN provider'
            
            results.append(classification)
    
    return results

# Example usage
suspicious_ips = ['185.220.101.182', '198.96.155.3']
analysis = analyze_suspicious_ips(suspicious_ips)
print(json.dumps(analysis, indent=2))
```

### Infrastructure Mapping

```python
from pgdn_scanner.scanner import Scanner
from collections import defaultdict

def map_infrastructure(target_ips):
    """Map infrastructure providers for a list of IPs."""
    scanner = Scanner()
    provider_map = defaultdict(list)
    
    # Analyze all IPs
    ip_string = ','.join(target_ips)
    result = scanner.scan(target=ip_string, run="ip_classify")
    
    if result.success:
        for classification in result.data[0]['result']['results']:
            provider = classification.get('ipinfo_org', 'Unknown')
            provider_map[provider].append({
                'ip': classification['ip'],
                'role': classification['likely_role'],
                'aws_service': classification.get('aws_service'),
                'reverse_dns': classification.get('reverse_dns')
            })
    
    return dict(provider_map)

# Example usage
infrastructure_ips = ['8.8.8.8', '1.1.1.1', '13.107.42.14']
mapping = map_infrastructure(infrastructure_ips)

for provider, ips in mapping.items():
    print(f"\n{provider}:")
    for ip_info in ips:
        print(f"  {ip_info['ip']} - {ip_info['role']}")
```

### Security Monitoring

```python
import logging
from pgdn_scanner.scanner import Scanner

def monitor_ip_changes(ip_address, previous_classification=None):
    """Monitor IP for classification changes."""
    scanner = Scanner()
    
    result = scanner.scan(target=ip_address, run="ip_classify")
    
    if not result.success:
        logging.error(f"Failed to classify {ip_address}: {result.error}")
        return None
    
    current = result.data[0]['result']
    
    if previous_classification:
        changes = {}
        
        # Check for provider changes
        if current['ipinfo_org'] != previous_classification.get('ipinfo_org'):
            changes['provider'] = {
                'old': previous_classification.get('ipinfo_org'),
                'new': current['ipinfo_org']
            }
        
        # Check for role changes
        if current['likely_role'] != previous_classification.get('likely_role'):
            changes['role'] = {
                'old': previous_classification.get('likely_role'),
                'new': current['likely_role']
            }
        
        if changes:
            logging.warning(f"IP {ip_address} classification changed: {changes}")
    
    return current
```

### Automated Reporting

```python
from pgdn_scanner.scanner import Scanner
import csv
from datetime import datetime

def generate_ip_report(ip_list, output_file='ip_classification_report.csv'):
    """Generate CSV report of IP classifications."""
    scanner = Scanner()
    
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = [
            'timestamp', 'ip', 'reverse_dns', 'organization', 
            'aws_service', 'aws_region', 'classification', 
            'likely_role', 'tls_common_name'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for ip in ip_list:
            result = scanner.scan(target=ip, run="ip_classify")
            
            if result.success:
                data = result.data[0]['result']
                writer.writerow({
                    'timestamp': datetime.now().isoformat(),
                    'ip': data['ip'],
                    'reverse_dns': data.get('reverse_dns', ''),
                    'organization': data.get('ipinfo_org', ''),
                    'aws_service': data.get('aws_service', ''),
                    'aws_region': data.get('aws_region', ''),
                    'classification': data.get('classification', ''),
                    'likely_role': data.get('likely_role', ''),
                    'tls_common_name': data.get('tls_common_name', '')
                })
            else:
                writer.writerow({
                    'timestamp': datetime.now().isoformat(),
                    'ip': ip,
                    'error': result.error
                })

# Example usage
ip_addresses = ['8.8.8.8', '1.1.1.1', '13.107.42.14']
generate_ip_report(ip_addresses)
```

## Output Format

### Single IP Result

```json
{
  "data": [
    {
      "scan_type": "discovery",
      "target": "1.1.1.1",
      "result": {
        "ip": "1.1.1.1",
        "port": 443,
        "reverse_dns": "one.one.one.one",
        "ipinfo_org": "AS13335 Cloudflare, Inc.",
        "aws_service": null,
        "aws_region": null,
        "aws_prefix": null,
        "tls_common_name": "cloudflare-dns.com",
        "http_headers": {
          "Server": "cloudflare",
          "CF-Ray": "969f8b8de8c89541-LHR"
        },
        "classification": "Unknown or custom",
        "likely_role": "Cloudflare WAF/CDN",
        "target": "1.1.1.1",
        "scan_level": 1,
        "scanner_type": "ip_classify"
      },
      "metadata": {
        "scan_duration": 0.745,
        "timestamp": "2025-08-04T16:48:08.707295Z",
        "status": "success"
      }
    }
  ],
  "meta": {
    "operation": "scan",
    "scan_level": "basic",
    "total_scans": 1,
    "successful_scans": 1,
    "failed_scans": 0,
    "scan_duration": 0.746,
    "target": "1.1.1.1",
    "tools_used": ["ip_classify"]
  }
}
```

### Multiple IP Result

```json
{
  "scanner_type": "ip_classify",
  "scan_level": 1,
  "targets": ["8.8.8.8", "1.1.1.1"],
  "results": [
    {
      "ip": "8.8.8.8",
      "reverse_dns": "dns.google",
      "ipinfo_org": "AS15169 Google LLC",
      "classification": "Unknown or custom",
      "likely_role": "unclassified"
    },
    {
      "ip": "1.1.1.1",
      "reverse_dns": "one.one.one.one", 
      "ipinfo_org": "AS13335 Cloudflare, Inc.",
      "classification": "Unknown or custom",
      "likely_role": "Cloudflare WAF/CDN"
    }
  ]
}
```

### Field Descriptions

- `ip`: The IP address being analyzed
- `port`: Port used for TLS/HTTP analysis (default: 443)
- `reverse_dns`: Hostname from reverse DNS lookup
- `ipinfo_org`: Organization from IPInfo API (format: "AS{number} {name}")
- `aws_service`: AWS service if IP matches AWS ranges
- `aws_region`: AWS region if IP matches AWS ranges
- `aws_prefix`: AWS IP prefix that matched
- `tls_common_name`: Common Name from TLS certificate
- `http_headers`: HTTP response headers (Level 2+ scans)
- `classification`: Service type based on hostname patterns
- `likely_role`: Best guess of actual service role based on all data
- `scanner_type`: Always "ip_classify"
- `scan_level`: Detail level of the scan (1 or 2)

## Error Handling

### Common Errors

```python
from pgdn_scanner.scanner import Scanner

scanner = Scanner()

# Handle DNS resolution failures
result = scanner.scan(target="invalid.domain.test", run="ip_classify")
if not result.success:
    print(f"Error: {result.error}")
    # Output: "DNS resolution failed"

# Handle network timeouts
try:
    result = scanner.scan(target="1.1.1.1", run="ip_classify", debug=True)
except Exception as e:
    print(f"Network error: {e}")
```

### Graceful Degradation

The scanner gracefully handles various failure scenarios:

- **DNS Resolution Failure**: Returns error for invalid domains
- **API Timeouts**: Falls back to basic classification without external data
- **TLS Inspection Failure**: Continues without TLS certificate data
- **HTTP Request Failure**: Continues without HTTP headers
- **AWS Ranges Unavailable**: Continues without AWS service matching

### Validation

```python
import ipaddress

def validate_and_classify(target):
    """Validate IP address before classification."""
    try:
        # Validate IP format
        ipaddress.ip_address(target)
        
        scanner = Scanner()
        result = scanner.scan(target=target, run="ip_classify")
        
        if result.success:
            return result.data[0]['result']
        else:
            return {'error': result.error}
            
    except ipaddress.AddressValueError:
        return {'error': 'Invalid IP address format'}
    except Exception as e:
        return {'error': str(e)}
```

## Performance Tips

### Bulk Processing

For large IP lists, use the built-in bulk processing:

```python
# Efficient - single request with internal batching
ip_list = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
result = scanner.scan(target=",".join(ip_list), run="ip_classify")

# Less efficient - multiple requests
for ip in ip_list:
    result = scanner.scan(target=ip, run="ip_classify")
```

### Caching

The scanner includes built-in caching for AWS ranges and repeat lookups:

```python
scanner = IpClassifyScanner()

# First scan fetches AWS ranges
result1 = scanner.scan("1.1.1.1")

# Second scan reuses cached AWS ranges
result2 = scanner.scan("8.8.8.8")  # Faster
```

### Timeout Configuration

Adjust timeouts based on your network conditions:

```python
config = {
    'timeout': 2,  # Faster scans, may miss some data
    'timeout': 10  # Slower but more comprehensive
}

scanner = IpClassifyScanner(config)
```

### Scan Level Selection

Choose appropriate scan levels:

```python
# Level 1: Fast, basic classification
scanner.scan("1.1.1.1", scan_level=1)  # ~0.5-1s per IP

# Level 2: Slower, detailed analysis with TLS/HTTP
scanner.scan("1.1.1.1", scan_level=2)  # ~1-3s per IP
```

## Troubleshooting

### Debug Mode

Enable debug logging for troubleshooting:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

scanner = Scanner()
result = scanner.scan(target="1.1.1.1", run="ip_classify", debug=True)
```

### Common Issues

1. **Slow Performance**: Reduce timeout or use Level 1 scans
2. **Missing Data**: Check network connectivity to external APIs
3. **SSL Errors**: Normal for IPs without HTTPS services
4. **Empty Results**: May indicate private IPs or non-responsive targets

### Network Requirements

The scanner requires outbound access to:
- `ipinfo.io` (IPInfo API)
- `ip-ranges.amazonaws.com` (AWS IP ranges)
- Target IPs on ports 80 and 443

---

This library guide provides comprehensive coverage of the IP Classification Scanner's capabilities and usage patterns. For additional examples and advanced use cases, see the `examples/` directory in the repository.