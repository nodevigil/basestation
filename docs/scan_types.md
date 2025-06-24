# PGDN Scan Types Reference

This document describes the different scan types available in PGDN for testing, debugging, and specific use cases.

## Quick Reference

Use `--type <scan_type>` to run specific scan types instead of the full comprehensive scan.

```bash
# Common scan types for testing and debugging
pgdn --stage scan --target example.com --org-id myorg --type nmap           # Port scanning only
pgdn --stage scan --target example.com --org-id myorg --type geo            # GeoIP lookup only
pgdn --stage scan --target example.com --org-id myorg --type web            # Web analysis only
pgdn --stage scan --target example.com --org-id myorg --type vulnerability  # CVE lookup only
pgdn --stage scan --target example.com --org-id myorg --type ssl            # SSL/TLS analysis only
pgdn --stage scan --target example.com --org-id myorg --type docker         # Docker exposure check only
pgdn --stage scan --target example.com --org-id myorg --type whatweb        # Web tech fingerprinting only
pgdn --stage scan --target example.com --org-id myorg --type full           # All scanners (default)
```

## Scan Type Details

### `--type nmap`
**Purpose**: Network port scanning and service detection  
**Use Case**: Debug port scanning issues, verify network connectivity  
**What it runs**: Only the nmap external tool  
**Output includes**: Open ports, services, timing, host state  

**Example**:
```bash
pgdn --stage scan --target 192.168.1.100 --org-id myorg --type nmap --debug
```

**Sample Output**:
```json
{
  "nmap": {
    "ip": "192.168.1.100",
    "scan_time": "2.45",
    "ports": [
      {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
      {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
      {"port": 443, "protocol": "tcp", "state": "open", "service": "https"}
    ],
    "host_state": "up"
  }
}
```

### `--type geo`
**Purpose**: Geographic location and network information  
**Use Case**: Get location context, ASN information, network attribution  
**What it runs**: Only the geo scanner module  
**Output includes**: Country, city, coordinates, ASN, organization  

**Example**:
```bash
pgdn --stage scan --target 8.8.8.8 --org-id myorg --type geo
```

**Sample Output**:
```json
{
  "geoip": {
    "country_name": "United States",
    "city_name": "Mountain View",
    "latitude": 37.4056,
    "longitude": -122.0775,
    "asn_number": 15169,
    "asn_organization": "Google LLC"
  }
}
```

### `--type web`
**Purpose**: HTTP/HTTPS analysis and web technology detection  
**Use Case**: Analyze web services, check security headers, detect technologies  
**What it runs**: Only the web scanner module  
**Output includes**: HTTP headers, technologies, security analysis  

**Example**:
```bash
pgdn --stage scan --target example.com --org-id myorg --type web
```

### `--type vulnerability`
**Purpose**: CVE lookup and vulnerability assessment  
**Use Case**: Check for known vulnerabilities in detected services  
**What it runs**: Only the vulnerability scanner module  
**Output includes**: CVE matches, severity ratings, vulnerability details  

**Example**:
```bash
pgdn --stage scan --target 192.168.1.100 --org-id myorg --type vulnerability
```

### `--type ssl`
**Purpose**: SSL/TLS certificate analysis  
**Use Case**: Check certificate validity, encryption strength, configuration  
**What it runs**: Only the ssl_test external tool  
**Output includes**: Certificate details, cipher suites, SSL/TLS configuration  

**Example**:
```bash
pgdn --stage scan --target secure.example.com --org-id myorg --type ssl
```

### `--type docker`
**Purpose**: Docker API exposure detection  
**Use Case**: Check if Docker daemon is exposed on port 2375  
**What it runs**: Only the docker_exposure external tool  
**Output includes**: Docker exposure status, API accessibility  

**Example**:
```bash
pgdn --stage scan --target 192.168.1.100 --org-id myorg --type docker
```

### `--type whatweb`
**Purpose**: Web technology fingerprinting  
**Use Case**: Identify web technologies, frameworks, CMS, servers  
**What it runs**: Only the whatweb external tool  
**Output includes**: Detected technologies, versions, plugins  

**Example**:
```bash
pgdn --stage scan --target example.com --org-id myorg --type whatweb
```

### `--type generic`
**Purpose**: Basic port scanning using internal scanner  
**Use Case**: Test internal scanning logic without external tools  
**What it runs**: Only the generic scanner module  
**Output includes**: Open ports, banners, basic service detection  

**Example**:
```bash
pgdn --stage scan --target 192.168.1.100 --org-id myorg --type generic
```

### `--type full`
**Purpose**: Complete comprehensive scanning (default behavior)  
**Use Case**: Production scans, complete security assessment  
**What it runs**: All enabled scanners and external tools  
**Output includes**: Complete scan results with all available data  

**Example**:
```bash
pgdn --stage scan --target 192.168.1.100 --org-id myorg --type full
# or simply:
pgdn --stage scan --target 192.168.1.100 --org-id myorg
```

## Common Use Cases

### Debug Port Scanning Issues
When you see incorrect port results, use nmap-only to check raw nmap output:
```bash
pgdn --stage scan --target problematic-host --org-id myorg --type nmap --debug
```

### Quick GeoIP Lookup
For fast geographic information without scanning:
```bash
pgdn --stage scan --target 8.8.8.8 --org-id myorg --type geo
```

### Web Service Analysis
To analyze only HTTP/HTTPS services:
```bash
pgdn --stage scan --target web-server.com --org-id myorg --type web
```

### Vulnerability Assessment Only
To check only for CVEs without port scanning:
```bash
pgdn --stage scan --target known-service --org-id myorg --type vulnerability
```

### Performance Testing
Compare scan types for performance characteristics:
```bash
# Fast scan
time pgdn --stage scan --target example.com --org-id myorg --type nmap

# Slow comprehensive scan  
time pgdn --stage scan --target example.com --org-id myorg --type full
```

## Advanced Usage

### Combining with Scan Levels
Scan types work with scan levels for different depth:
```bash
pgdn --stage scan --target example.com --org-id myorg --type web --scan-level 3
```

### Using with Debug Mode
Enable debug logging for troubleshooting:
```bash
pgdn --stage scan --target example.com --org-id myorg --type nmap --debug
```

### Database Scanning
Scan types also work with database-stored nodes:
```bash
pgdn --stage scan --org-id myorg --type nmap  # Scan all discovered nodes with nmap only
```

## Expert Mode: Manual Scanner Selection

For advanced users who need fine-grained control, use `--scanners` and `--external-tools`:

```bash
# Run specific scanner modules
pgdn --stage scan --target example.com --org-id myorg --scanners generic web geo

# Run specific external tools
pgdn --stage scan --target example.com --org-id myorg --external-tools nmap whatweb

# Combine both
pgdn --stage scan --target example.com --org-id myorg --scanners geo --external-tools nmap
```

**Available Scanner Modules**: `generic`, `web`, `vulnerability`, `geo`, `sui`, `filecoin`  
**Available External Tools**: `nmap`, `whatweb`, `ssl_test`, `docker_exposure`

## Troubleshooting

### No Results with Specific Type
If a scan type returns empty results:
1. Check if the target is reachable
2. Verify the service exists (e.g., web server for `--type web`)
3. Use `--debug` for detailed logging
4. Try `--type nmap` first to confirm basic connectivity

### Comparing Results
To debug discrepancies, run different scan types on the same target:
```bash
pgdn --stage scan --target example.com --org-id myorg --type nmap > nmap_only.json
pgdn --stage scan --target example.com --org-id myorg --type generic > generic_only.json
pgdn --stage scan --target example.com --org-id myorg --type full > full_scan.json
```

### Performance Issues
If scans are slow:
1. Use `--type nmap` for fastest port scanning
2. Use `--type geo` for quickest location lookup
3. Avoid `--type full` for quick tests
4. Check network connectivity and target responsiveness
