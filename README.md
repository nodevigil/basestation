# PGDN - DePIN Infrastructure Scanner

PGDN (Programmatic Global DePIN Network) is a specialized security scanning platform designed for decentralized physical infrastructure networks (DePIN). It provides automated security assessment capabilities for blockchain-based infrastructure protocols with a focus on single-target scanning and protocol-specific analysis.

## 🚀 Features

- **Progressive Scan Levels**: 3-tier scanning system (basic, standard, comprehensive)
- **Protocol-Specific Scanning**: Modular protocol scanners for Sui, Filecoin, and extensible architecture for new protocols
- **Single-Target Focus**: Streamlined scanning of individual infrastructure nodes
- **Infrastructure Analysis**: Comprehensive port scanning, web service analysis, SSL/TLS testing
- **Vulnerability Assessment**: CVE correlation and security vulnerability detection
- **GeoIP Intelligence**: Geographic and ASN context for threat analysis
- **External Tool Integration**: Native integration with nmap, whatweb, ssl testing tools
- **Template-Based Extension**: Easy addition of new protocol scanners using provided templates
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
# Basic infrastructure scan
pgdn --target example.com

# With protocol-specific scanning
pgdn --target example.com --protocol sui --scan-level 2

# List available protocol scanners and their levels
pgdn --list-protocols

# Different scan levels
pgdn --target example.com --scan-level 1    # Basic (legal, passive)
pgdn --target example.com --scan-level 2    # Standard with GeoIP
pgdn --target example.com --scan-level 3    # Comprehensive analysis

# Protocol-specific scanning with different levels
pgdn --target sui-node.com --protocol sui --scan-level 1   # Basic health check
pgdn --target sui-node.com --protocol sui --scan-level 2   # Metrics + validator analysis
pgdn --target sui-node.com --protocol sui --scan-level 3   # Aggressive probing

# Specific scan types for testing/debugging
pgdn --target example.com --type nmap       # Port scan only
pgdn --target example.com --type web        # Web analysis only
pgdn --target example.com --type ssl        # SSL/TLS testing only
pgdn --target example.com --type whatweb    # Web tech fingerprinting
```

### Library Usage

```python
from pgdn import Scanner, Config

# Initialize scanner
config = Config.from_file('config.json')
scanner = Scanner(config)

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

# Custom scanner configuration with config options
config = Config.from_file('config.json')
config.scanning.orchestrator.enabled_scanners = ['web', 'vulnerability']
config.scanning.orchestrator.enabled_external_tools = ['nmap', 'ssl_test']
scanner = Scanner(config)
result = scanner.scan(target='192.168.1.100', scan_level=2)
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

4. **Update CLI choices**:
   ```python
   # In cli.py
   parser.add_argument(
       '--protocol',
       choices=['filecoin', 'sui', 'arweave'],  # Add your protocol
       help='Run protocol-specific scanner'
   )
   ```

5. **Test your scanner**:
   ```bash
   pgdn --target arweave-node.com --protocol arweave
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

- **`lib/scanner.py`**: Main scanning orchestration for single targets
- **`lib/pipeline.py`**: High-level pipeline management
- **`lib/scanners/`**: Modular scanner implementations
  - `scan_orchestrator.py`: Infrastructure scanning coordination
  - `base_scanner.py`: Scanner registry and interface
  - `protocol_template.py`: Template for new protocol scanners
  - `protocols/`: Protocol-specific scanners with level support
    - `sui_scanner.py`: Sui blockchain protocol scanner (levels 1-3)
    - `filecoin_scanner.py`: Filecoin network protocol scanner (levels 1-3)
    - `base_protocol_scanner.py`: Base class for protocol scanners
- **`lib/tools/`**: External tool integrations (nmap, whatweb, ssl)
- **`cli.py`**: Command-line interface and library wrapper

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
# List all available protocol scanners and their supported levels
pgdn --list-protocols
```

This will show you:
- Available protocol scanners
- Supported scan levels for each protocol
- Description of what each level does

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

- **Basic scanning examples** (`examples/library_usage.py`)
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