# PGDN - DePIN Infrastructure Scanner

PGDN (Programmatic Global DePIN Network) is a specialized security scanning platform designed for decentralized physical infrastructure networks (DePIN). It provides automated security assessment capabilities for blockchain-based infrastructure protocols with a focus on single-target scanning and protocol-specific analysis.

## 🚀 Features

- **Progressive Scan Levels**: 3-tier scanning system (basic, standard, comprehensive)
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
pgdn --target example.com --run web          # Web service detection
pgdn --target example.com --run whatweb      # Web technology fingerprinting  
pgdn --target example.com --run geo          # Geographic location detection
pgdn --target example.com --run ssl_test     # SSL/TLS certificate analysis

# Compliance scanning (requires protocol)
pgdn --target example.com --run compliance --protocol sui --level 1     # Basic compliance
pgdn --target example.com --run compliance --protocol filecoin --level 3 # Comprehensive compliance

# List available protocol scanners and their levels
pgdn --list-protocols

# Output formats
pgdn --target example.com --run web --json      # Pure JSON output
pgdn --target example.com --run compliance --protocol sui --human  # Human-readable
```

## 📜 Basic Scanning

PGDN provides a set of basic scanners for common infrastructure analysis tasks. These scanners can be run individually or in combination to gather comprehensive information about a target node.

web scanner: Detects web services and technologies running on the target.
whatweb scanner: Fingerprints web technologies and frameworks.
geo scanner: Performs GeoIP lookups to determine geographic location and ASN of the target.
ssl_test scanner: Analyzes SSL/TLS certificates for security compliance and vulnerabilities.

## Node Scanning
Node scanner performs basic node health checks and connectivity tests on known ports for a specific protocol.

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
# Basic compliance scan
pgdn --target validator-node.com --run compliance --protocol sui --level 1

# Comprehensive compliance scan with detailed analysis
pgdn --target validator-node.com --run compliance --protocol filecoin --level 3

# Human-readable compliance report
pgdn --target validator-node.com --run compliance --protocol sui --human

# JSON output for automation
pgdn --target validator-node.com --run compliance --protocol sui --json
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

#### Basic Usage

```python
from pgdn import Scanner, Config

# Initialize scanner with default configuration
scanner = Scanner()

# Basic target scanning
result = scanner.scan(
    target='192.168.1.100',
    scan_level=2
)

# Protocol-specific scanning
result = scanner.scan(
    target='192.168.1.100',
    scan_level=2,
    protocol='sui'
)

# Check if scan was successful
if result.success:
    print(f"Scan completed in {result.data['meta']['scan_duration']} seconds")
    print(f"Found {len(result.data['data'])} results")
else:
    print(f"Scan failed: {result.error}")
```

#### Advanced Configuration

```python
from pgdn import Scanner, Config

# Load custom configuration
config = Config.from_file('config.json')
scanner = Scanner(config)

# Override scanner configuration at runtime
result = scanner.scan(
    target='192.168.1.100',
    scan_level=2,
    enabled_scanners=['web', 'geo'],  # Only run specific scanners
    enabled_external_tools=['whatweb'],  # Only use specific external tools
    debug=True
)
```

#### Individual Scanner Types

```python
from pgdn import Scanner

scanner = Scanner()

# Web service detection only
result = scanner.scan(
    target='example.com',
    enabled_scanners=['web'],
    enabled_external_tools=[]
)

# Web technology fingerprinting only
result = scanner.scan(
    target='example.com',
    enabled_scanners=[],
    enabled_external_tools=['whatweb']
)

# Geographic location detection only
result = scanner.scan(
    target='example.com',
    enabled_scanners=['geo'],
    enabled_external_tools=[]
)

# SSL/TLS certificate analysis only
result = scanner.scan(
    target='example.com',
    enabled_scanners=[],
    enabled_external_tools=['ssl_test']
)
```

#### Compliance Scanning

```python
from pgdn import Scanner

scanner = Scanner()

# Basic compliance scan
result = scanner.scan(
    target='validator-node.com',
    enabled_scanners=['compliance'],
    protocol='sui',
    scan_level=1
)

# Comprehensive compliance scan
result = scanner.scan(
    target='validator-node.com',
    enabled_scanners=['compliance'],
    protocol='filecoin',
    scan_level=3
)
```

#### Node Scanning

```python
from pgdn import Scanner

scanner = Scanner()

# Protocol-specific node health checks
result = scanner.scan(
    target='sui-node.com',
    enabled_scanners=['node'],
    protocol='sui',
    scan_level=2
)
```

#### Result Structure

All scan results return a `DictResult` object with the following structure:

```python
# Successful scan
{
    "success": True,
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
    }
}

# Failed scan
{
    "success": False,
    "error": "DNS resolution failed: example.com"
}
```

#### Error Handling

```python
from pgdn import Scanner

scanner = Scanner()

try:
    result = scanner.scan(target='invalid-hostname.xyz')
    
    if result.success:
        # Process successful results
        process_scan_results(result.data)
    else:
        # Handle scan errors
        print(f"Scan failed: {result.error}")
        
except Exception as e:
    # Handle unexpected errors
    print(f"Unexpected error: {e}")
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
   pgdn --target arweave-node.com --run compliance --protocol arweave --level 1
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
pgdn --list-protocols
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
