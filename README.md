# PGDN - DePIN Infrastructure Scanner

PGDN (Programmatic Global DePIN Network) is a specialized security scanning platform designed for decentralized physical infrastructure networks (DePIN). It provides automated security assessment capabilities for blockchain-based infrastructure protocols with a focus on single-target scanning and protocol-specific analysis.

## 🚀 Features

- **Simplified Scanning**: Clean CLI interface with distinct scan types
- **Protocol-Specific Scanning**: Modular protocol scanners for Sui, Filecoin, and extensible architecture for new protocols
- **Compliance Scanning**: Fast security compliance assessment focusing on dangerous ports and exposed services
- **Single-Target Focus**: Streamlined scanning of individual infrastructure nodes
- **Infrastructure Analysis**: Comprehensive port scanning, web service analysis, SSL/TLS testing
- **Vulnerability Assessment**: CVE correlation and security vulnerability detection
- **GeoIP Intelligence**: Geographic and ASN context for threat analysis
- **External Tool Integration**: Native integration with nmap, whatweb, ssl testing tools
- **Template-Based Extension**: Easy addition of new protocol scanners using provided templates
- **Simplified Library API**: Clean, single `Scanner` class for all scanning operations
- **Library + CLI**: Use as a Python library or standalone CLI tool

## 📦 Installation

### From PyPI
```bash
pip install pgdn-scanner
```

### From Source
```bash
git clone https://github.com/pgdn-network/pgdn-scanner
cd pgdn-scanner
pip install -e .
```

### Basic Installation
```bash
pip install -r requirements.txt
pip install -e .
```

### Development Setup
```bash
./scripts/dev-start.sh    # Full Docker development environment
python setup.py develop   # Development mode installation
```

## 🛠️ Quick Start

### Basic Usage

```bash
# Individual scanner runs
pgdn-scanner --target example.com --run web          # Web service detection
pgdn-scanner --target example.com --run whatweb      # Web technology fingerprinting  
pgdn-scanner --target example.com --run geo          # Geographic location detection
pgdn-scanner --target example.com --run ssl_test     # SSL/TLS certificate analysis
pgdn-scanner --target example.com --run port_scan --port 22,80,443  # Port scanning with service detection

# Node scanning with protocol-specific probes (requires protocol)
pgdn-scanner --target example.com --run node_scan --protocol sui
pgdn-scanner --target example.com --run node_scan --protocol arweave
pgdn-scanner --target example.com --run node_scan --protocol filecoin

# Advanced protocol-specific scanning (requires protocol)
pgdn-scanner --target example.com --run protocol_scan --protocol sui
pgdn-scanner --target example.com --run protocol_scan --protocol filecoin

# Compliance scanning (requires protocol)
pgdn-scanner --target example.com --run compliance --protocol sui
pgdn-scanner --target example.com --run compliance --protocol filecoin

# List available protocol scanners
pgdn-scanner --list-protocols

# Output formats
pgdn-scanner --target example.com --run web --json      # Pure JSON output
pgdn-scanner --target example.com --run compliance --protocol sui --human  # Human-readable
```

## 📜 Basic Scanning

PGDN provides a set of basic scanners for common infrastructure analysis tasks. These scanners can be run individually or in combination to gather comprehensive information about a target node.

web scanner: Detects web services and technologies running on the target.
whatweb scanner: Fingerprints web technologies and frameworks.
geo scanner: Performs GeoIP lookups to determine geographic location and ASN of the target.
ssl_test scanner: Analyzes SSL/TLS certificates for security compliance and vulnerabilities.
port_scan scanner: Respectful port scanning with service detection, banner grabbing, and SSL/TLS analysis.

## 🔌 Port Scanning

PGDN includes a respectful port scanner that provides comprehensive service detection and analysis without being aggressive or intrusive. The port scanner is designed for defensive security assessment and infrastructure monitoring.

### Port Scanner Features

- **Respectful Scanning**: Non-aggressive scanning approach suitable for production environments
- **Service Detection**: Automatic identification of services running on open ports
- **Banner Grabbing**: Capture service banners for version identification
- **SSL/TLS Analysis**: Certificate and configuration analysis for SSL-enabled services
- **HTTP Analysis**: Basic HTTP method testing and endpoint enumeration
- **Protocol-Specific Probing**: Docker, Prometheus, and database service detection
- **Confidence Scoring**: Accuracy assessment of scan results (0-100 score)
- **Multi-port Support**: Scan up to 5 ports simultaneously
- **nmap Integration**: Optional nmap service detection (can be skipped for faster scans)

### Port Scanner Usage

```bash
# Basic port scanning
pgdn-scanner --target example.com --run port_scan --port 22,80,443

# Single port scan
pgdn-scanner --target example.com --run port_scan --port 22

# Skip nmap for faster results
pgdn-scanner --target example.com --run port_scan --port 80 --skip-nmap

# JSON output with pretty formatting
pgdn-scanner --target example.com --run port_scan --port 22,80,443 --json --pretty

# Human-readable output
pgdn-scanner --target example.com --run port_scan --port 80 --human
```

### Port Scanner Output

The port scanner provides detailed information about each scanned port:

```json
{
  "target": "example.com",
  "scanner_type": "port_scan",
  "scan_summary": {
    "total_ports": 3,
    "open_ports": 2,
    "closed_ports": 1,
    "average_confidence": 85.5
  },
  "detailed_results": [
    {
      "target": "example.com",
      "port": 80,
      "is_open": true,
      "service": "nginx",
      "version": "1.18.0",
      "confidence_score": 95.0,
      "banner": "HTTP/1.1 200 OK\nServer: nginx/1.18.0",
      "ssl_info": null,
      "http_info": {
        "methods": {
          "GET": {
            "status_code": 200,
            "title": "Welcome to nginx!"
          }
        }
      }
    }
  ]
}
```

### Requirements

- **Ports Required**: Port scanning requires at least one port specified via `--port`
- **Port Limit**: Maximum of 5 ports per scan for respectful scanning
- **nmap Optional**: nmap integration is optional and can be skipped with `--skip-nmap`

## 📡 Node Scanning

Node scanner performs protocol-specific probes and connectivity tests using YAML protocol configurations. It uses generic probes for multi-protocol scanning with protocol-specific payloads and signature detection.

```bash
# Protocol-specific node scanning
pgdn-scanner --target validator-node.com --run node_scan --protocol sui
pgdn-scanner --target validator-node.com --run node_scan --protocol filecoin
```

## 🔧 Protocol Scanning

Advanced protocol scanners provide deep analysis using specialized scanners for each protocol. These scanners offer comprehensive protocol-specific features and health checks.

```bash
# Advanced protocol-specific scanning
pgdn-scanner --target validator-node.com --run protocol_scan --protocol sui
pgdn-scanner --target validator-node.com --run protocol_scan --protocol filecoin
```

## 🔍 Compliance Scanning

PGDN includes a specialized compliance scanner that focuses on detecting dangerous ports and exposed services that should not be accessible on validator nodes. This scanner helps assess the security posture of DePIN infrastructure by identifying common misconfigurations and security risks.

### What Compliance Scanning Checks

The compliance scanner performs a two-stage process:

1. **Fast Port Scan**: Rapid parallel scanning of known dangerous ports
2. **Service Detection**: Detailed nmap analysis of open ports for service identification, specific protocol checks, and security assessment

### Dangerous Services Detected

The scanner checks for **98 dangerous ports** including:

- **Database Services** (MySQL, PostgreSQL, Redis, MongoDB) - Should be internal only
- **Container APIs** (Docker, Kubernetes) - Often expose management interfaces
- **Admin Interfaces** (Web admin panels, monitoring dashboards)
- **File Sharing** (FTP, SMB, NFS) - Rarely needed on validators
- **Remote Access** (Telnet, VNC, RDP) - High security risk
- **Development Services** (Debug ports, dev servers) - Should not be in production
- **Message Queues** (RabbitMQ, Kafka) - Should be internal
- **Deprecated Protocols** (Finger, RPCbind) - Known vulnerabilities

### Compliance Scan Usage

```bash
# Compliance scanning
pgdn-scanner --target validator-node.com --run compliance --protocol sui

# Different protocols
pgdn-scanner --target validator-node.com --run compliance --protocol filecoin

# Human-readable compliance report
pgdn-scanner --target validator-node.com --run compliance --protocol sui --human

# JSON output for automation
pgdn-scanner --target validator-node.com --run compliance --protocol sui --json
```

### Compliance Results

The scanner returns a compliance score (0-100) and detailed findings:

```json
{
  "compliance_status": "FAIL",
  "compliance_score": 70.0,
  "dangerous_ports_found": 2,
  "findings": [
    {
      "port": 3306,
      "service": "mysql",
      "risk_level": "CRITICAL",
      "security_concern": "Database exposed to internet",
      "recommendation": "Close port 3306 or restrict access"
    }
  ],
  "scan_time_seconds": 12.3
}
```

### Requirements for Compliance Scanning

- **Protocol Required**: Compliance scanning requires a valid protocol (sui, filecoin, etc.)
- **Protocols Directory**: The `pgdn/protocols/` directory must exist with YAML protocol configurations
- **Protocol Files**: At least one `.yaml` protocol configuration file must be present in `pgdn/protocols/`

### Library Usage

The PGDN library provides a clean, simplified API for programmatic scanning operations. The main entry point is the `Scanner` class which handles all scanning complexity internally.

**Note:** The package is installed as `pgdn-scanner`, but you import it as `pgdn_scanner`:

#### Basic Usage

```python
from pgdn_scanner import Scanner, Config  # Import as 'pgdn_scanner'

# Initialize scanner with default configuration
scanner = Scanner()

# Basic web scanning
result = scanner.scan(
    target='192.168.1.100',
    run='web'
)

# Protocol-specific node scanning
result = scanner.scan(
    target='192.168.1.100',
    run='node_scan',
    protocol='sui'
)

# Advanced protocol scanning
result = scanner.scan(
    target='192.168.1.100',
    run='protocol_scan',
    protocol='sui'
)

# Compliance scanning
result = scanner.scan(
    target='192.168.1.100',
    run='compliance',
    protocol='sui'
)

# Check if scan was successful
if result.is_success():
    # Check for errors in the meta field
    if result.data['meta'].get('error'):
        print(f"Scan failed: {result.data['meta']['error']}")
    else:
        print(f"Scan completed in {result.data['meta']['scan_duration']} seconds")
        print(f"Found {len(result.data['data'])} results")
else:
    print(f"Scan failed: {result.error}")
```

#### CLI to Library Mapping

The library usage directly mirrors the CLI structure with a simplified `run` parameter:

| CLI Command | Library Equivalent |
|-------------|-------------------|
| `pgdn-scanner --target example.com --run web` | `scanner.scan(target='example.com', run='web')` |
| `pgdn-scanner --target example.com --run whatweb` | `scanner.scan(target='example.com', run='whatweb')` |
| `pgdn-scanner --target example.com --run geo` | `scanner.scan(target='example.com', run='geo')` |
| `pgdn-scanner --target example.com --run ssl_test` | `scanner.scan(target='example.com', run='ssl_test')` |
| `pgdn-scanner --target example.com --run port_scan --port 22,80,443` | `scanner.scan(target='example.com', run='port_scan', port='22,80,443')` |
| `pgdn-scanner --target example.com --run node_scan --protocol sui` | `scanner.scan(target='example.com', run='node_scan', protocol='sui')` |
| `pgdn-scanner --target example.com --run protocol_scan --protocol sui` | `scanner.scan(target='example.com', run='protocol_scan', protocol='sui')` |
| `pgdn-scanner --target example.com --run compliance --protocol sui` | `scanner.scan(target='example.com', run='compliance', protocol='sui')` |

#### Advanced Configuration

```python
from pgdn_scanner import Scanner, Config

# Load custom configuration
config = Config.from_file('config.json')
scanner = Scanner(config)

# Use the simplified run parameter
result = scanner.scan(
    target='192.168.1.100',
    run='web',
    debug=True
)

# For custom scanner combinations, use legacy parameters
result = scanner.scan(
    target='192.168.1.100',
    scan_level=2,
    enabled_scanners=['web', 'geo'],  # Custom scanner combination
    enabled_external_tools=['whatweb'],  # Custom external tools
    debug=True
)
```

#### Individual Scanner Types

The library follows the same pattern as the CLI with individual scanner types:

```python
from pgdn_scanner import Scanner

scanner = Scanner()

# Web service detection only
result = scanner.scan(
    target='example.com',
    run='web'
)

# Web technology fingerprinting only
result = scanner.scan(
    target='example.com',
    run='whatweb'
)

# Geographic location detection only
result = scanner.scan(
    target='example.com',
    run='geo'
)

# SSL/TLS certificate analysis only
result = scanner.scan(
    target='example.com',
    run='ssl_test'
)

# Port scanning with service detection
result = scanner.scan(
    target='example.com',
    run='port_scan',
    port='22,80,443'  # Comma-separated port list
)

# Port scanning with options
result = scanner.scan(
    target='example.com',
    run='port_scan',
    port='80',
    skip_nmap=True  # Skip nmap for faster results
)
```

#### Port Scanning

Port scanning requires a port parameter and follows the CLI pattern:

```python
from pgdn_scanner import Scanner

scanner = Scanner()

# Basic port scanning
result = scanner.scan(
    target='example.com',
    run='port_scan',
    port='22,80,443'
)

# Single port scan
result = scanner.scan(
    target='example.com',
    run='port_scan',
    port='80'
)

# Port scan with skip nmap option
result = scanner.scan(
    target='example.com',
    run='port_scan',
    port='22,80,443',
    skip_nmap=True
)

# Check port scan results
if result.is_success():
    scan_data = result.data
    if scan_data['meta'].get('error'):
        print(f"Scan failed: {scan_data['meta']['error']}")
    else:
        # Access port scan specific data
        scan_summary = scan_data.get('scan_summary', {})
        print(f"Scanned {scan_summary.get('total_ports', 0)} ports")
        print(f"Found {scan_summary.get('open_ports', 0)} open ports")
        
        # Process individual port results
        for port_result in scan_data.get('detailed_results', []):
            if port_result.get('is_open'):
                print(f"Port {port_result['port']}: {port_result.get('service', 'unknown')} "
                      f"(confidence: {port_result.get('confidence_score', 0):.1f}%)")
```

#### Compliance Scanning

Compliance scanning requires a protocol and follows the CLI pattern:

```python
from pgdn_scanner import Scanner

scanner = Scanner()

# Basic compliance scan
result = scanner.scan(
    target='validator-node.com',
    run='compliance',
    protocol='sui',
    scan_level=1
)

# Comprehensive compliance scan
result = scanner.scan(
    target='validator-node.com',
    run='compliance',
    protocol='filecoin',
    scan_level=3
)
```

#### Node Scanning

Node scanning requires a protocol and follows the CLI pattern:

```python
from pgdn_scanner import Scanner

scanner = Scanner()

# Protocol-specific node health checks
result = scanner.scan(
    target='sui-node.com',
    run='node_scan',
    protocol='sui',
    scan_level=2
)
```

#### Result Structure

All scan results return a `DictResult` object (which is a `Result[Dict[str, Any]]`) with the following structure:

**Note**: The scanner always returns `success=True` but may contain errors in the `meta.error` field. Always check `result.data['meta'].get('error')` for actual scan errors.

```python
# Successful scan
{
    "data": {
        "data": [...],  # Scan results array
        "meta": {
            "operation": "target_scan",
            "scan_level": 2,
            "scan_duration": 12.5,
            "scanners_used": ["web", "geo"],
            "tools_used": ["whatweb"],
            "target": "example.com",
            "protocol": "sui",
            "timestamp": "2024-01-15T10:30:00",
            "error": None
        }
    },
    "error": None,
    "meta": None,
    "result_type": "SUCCESS"
}

# Failed scan (error in meta field)
{
    "data": {
        "data": [],
        "meta": {
            "operation": "target_scan",
            "stage": "scan",
            "scan_level": 1,
            "scan_duration": None,
            "scanners_used": [],
            "tools_used": [],
            "total_scan_duration": 0,
            "target": "invalid-hostname.xyz",
            "protocol": None,
            "timestamp": "2024-01-15T10:30:00",
            "error": "DNS resolution failed: invalid-hostname.xyz"
        }
    },
    "error": None,
    "meta": None,
    "result_type": "SUCCESS"
}
```

#### Error Handling

```python
from pgdn_scanner import Scanner

scanner = Scanner()

try:
    result = scanner.scan(target='invalid-hostname.xyz')
    
    if result.is_success():
        # Check for errors in the meta field
        if result.data['meta'].get('error'):
            print(f"Scan failed: {result.data['meta']['error']}")
        else:
            # Process successful results
            process_scan_results(result.data)
    else:
        # Handle scan errors
        print(f"Scan failed: {result.error}")
        
except Exception as e:
    # Handle unexpected errors
    print(f"Unexpected error: {e}")
```

#### Result Methods

The `Result` class provides several useful methods:

```python
# Check result status
result.is_success()    # Always True for scanner results
result.is_error()      # Always False for scanner results
result.is_warning()    # Always False for scanner results
result.has_issues()    # Always False for scanner results

# Check for actual scan errors
if result.data['meta'].get('error'):
    print(f"Scan failed: {result.data['meta']['error']}")

# Get data safely
data = result.data              # Access scan data directly
meta = result.data['meta']      # Access metadata

# Convert to different formats
result_dict = result.to_dict()   # Convert to dictionary
result_json = result.to_json()   # Convert to JSON string
```

## 🔧 Configuration

### Basic Configuration (`config.json`)

```json
{
  "scanning": {
    "orchestrator": {
      "enabled_scanners": ["generic", "web", "vulnerability", "geo"],
      "enabled_external_tools": ["nmap", "whatweb", "ssl_test"],
      "use_external_tools": true
    },
    "scanners": {
      "sui": {
        "enabled": true,
        "module_path": "lib.scanners.sui_scanner.SuiSpecificScanner",
        "timeout": 10,
        "rpc_ports": [9000, 443, 80],
        "metrics_port": 9184
      }
    }
  }
}
```

## 🧩 Adding New Protocol Scanners

PGDN provides a template-based system for easily adding support for new DePIN protocols.

### Using the Protocol Template

1. **Copy the template**:
   ```bash
   cp lib/scanners/protocol_template.py lib/scanners/arweave_scanner.py
   ```

2. **Implement your protocol**:
   ```python
   class ArweaveScanner(ProtocolTemplate):
       def __init__(self, config=None):
           super().__init__(config)
           self.default_ports = [1984]
           self.api_endpoints = ['/info', '/peers']
       
       @property
       def scanner_type(self):
           return "arweave"
       
       def _is_protocol_response(self, content, headers):
           return "arweave" in content.lower()
   ```

3. **Add configuration**:
   ```json
   {
     "scanning": {
       "scanners": {
         "arweave": {
           "enabled": true,
           "module_path": "lib.scanners.arweave_scanner.ArweaveScanner",
           "timeout": 10,
           "default_ports": [1984]
         }
       }
     }
   }
   ```

4. **Add protocol YAML configuration**:
   ```bash
   # Create pgdn/protocols/arweave.yaml with your protocol configuration
   name: "Arweave Network"
   network_type: "blockchain"  
   default_ports: [1984]
   probes:
     - name: ARWEAVE_INFO
       payload: "GET /info HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
       ports: [1984]
   signatures:
     - label: "Arweave Node"
       regex: '"network":\s*"arweave"'
   ```

5. **Test your scanner**:
   ```bash
   pgdn-scanner --target arweave-node.com --run compliance --protocol arweave --level 1
   ```

### Template Features

The protocol template (`lib/scanners/protocol_template.py`) provides:

- **Base scanner interface** compliance
- **Progressive scan levels** (1-3) with increasing detail
- **HTTP endpoint detection** with customizable ports and paths
- **Response validation** for protocol identification
- **Comprehensive logging** and error handling
- **Extensible methods** for version detection, service enumeration, and security assessment

### Scanner Interface Requirements

All protocol scanners must:

1. Inherit from `BaseScanner`
2. Implement `scanner_type` property
3. Implement `scan(target, **kwargs)` method
4. Handle configuration through `__init__(config)`
5. Return structured results with error handling

## 📊 Scan Levels

### Level 1: Basic (Legal, Passive, Safe)
- Port connectivity testing
- Basic web service detection
- SSL/TLS certificate inspection
- GeoIP location lookup

### Level 2: Standard (Published, Atomic, Protocol-Aware)
- Level 1 + Enhanced analysis
- Protocol-specific endpoint detection
- Service version identification
- Vulnerability correlation (CVE database)

### Level 3: Comprehensive (Advanced Analysis)
- Level 2 + Deep inspection
- Advanced vulnerability scanning
- Docker exposure detection
- Web technology fingerprinting
- Network topology discovery

## 🏗️ Architecture

### Core Components

- **`pgdn/scanner.py`**: Main `Scanner` class - single entry point for all scanning operations
- **`pgdn/scanners/scan_orchestrator.py`**: Internal scanning coordination (used by Scanner class)
- **`pgdn/scanners/`**: Modular scanner implementations
  - `base_scanner.py`: Scanner registry and interface
  - `protocol_template.py`: Template for new protocol scanners
  - `protocol_scanners/`: Protocol-specific scanners with level support
    - `sui_scanner.py`: Sui blockchain protocol scanner (levels 1-3)
    - `filecoin_scanner.py`: Filecoin network protocol scanner (levels 1-3)
    - `base_protocol_scanner.py`: Base class for protocol scanners
- **`pgdn/tools/`**: External tool integrations (nmap, whatweb, ssl)
- **`cli.py`**: Command-line interface using the Scanner class

### Protocol Scanner Levels

Protocol scanners now support multiple scan levels with different intensities:

**Level 1**: Basic protocol health checks
- Basic endpoint connectivity
- Version detection
- Core service availability

**Level 2**: Standard protocol analysis  
- Extended metrics collection
- Service enumeration
- Configuration validation
- Anomaly detection

**Level 3**: Comprehensive protocol assessment
- Aggressive probing and testing
- Latency analysis
- Security configuration review
- Edge case validation

### Listing Available Protocol Scanners

```bash
# List all available scanners and protocols
pgdn-scanner --list-protocols
```

This will show you:
- Available individual scanners (web, whatweb, geo, ssl_test)
- Available protocol scanners for compliance mode
- Supported scan levels for each protocol
- Usage examples and scan level descriptions

### Scanning Flow

1. **Target Validation**: DNS resolution and basic connectivity
2. **Infrastructure Scanning**: Port scanning, web service detection, SSL analysis
3. **Protocol Detection**: Run protocol-specific scanners if specified
4. **Result Aggregation**: Combine infrastructure and protocol scan results
5. **Output Generation**: Structured JSON results with success/error handling

## 🧪 Testing

```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/test_scan_orchestrator.py
pytest tests/test_sui_scanner.py

# Run with database tests
pytest --database

# Development testing
python examples/library_usage.py
```

## 📚 Examples

Explore the `examples/` directory for:

- **Basic scanning examples** (`examples/pgdn_library_example.py`)
- **Advanced library usage** (`examples/library_usage.py`)
- **CLI automation scripts** (`examples/cli/`)
- **Library usage patterns** (`examples/library/`)
- **Protocol scanner examples**

## 🔒 Security Focus

PGDN is designed as a **defensive security tool** for:

- Infrastructure vulnerability assessment
- DePIN network security monitoring
- Protocol compliance verification
- Security posture evaluation

All scanning is designed to be non-intrusive and respectful of target systems.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add your protocol scanner using the template
4. Include tests and documentation
5. Submit a pull request

### Development Commands

```bash
# Install in development mode
pip install -e .

# Run linting and tests
pytest
python -m pytest conftest.py

# Database operations
alembic upgrade head
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- [DePIN Security Framework](https://github.com/pgdn-network/depin-security)
- [Protocol Signature Database](https://github.com/pgdn-network/protocol-signatures)

---

**PGDN Scanner** - Comprehensive security assessment for decentralized infrastructure networks.

## Notes ##

compliance_scanner is a specialized scanner that focuses on detecting dangerous ports and exposed services that should not be accessible on validator nodes. It performs a two-stage process: a fast port scan followed by detailed service detection using nmap. Run this with  `--run compliance --protocol sui --level 1` for basic compliance checks or `--level 2` for comprehensive analysis.

Level 3 compliance scanning requires a valid protocol and performs an in-depth analysis of the target node's security posture, including service enumeration, vulnerability correlation, and configuration validation.

node_scan is a protocol-specific scanner that performs basic node health checks and connectivity tests on known ports for a specific protocol. It is designed to assess the operational status of DePIN nodes and can be run with `--run node_scan --protocol sui --level 2`.   
