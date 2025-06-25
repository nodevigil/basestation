# PGDN - Agentic DePIN Infrastructure Scanner

PGDN (Programmatic Global DePIN Network) is a comprehensive security scanning platform designed specifically for decentralized physical infrastructure networks (DePIN). It provides automated reconnaissance, vulnerability scanning, and security assessment capabilities for blockchain-based infrastructure protocols.

## Features

- **Progressive Scan Levels**: 3-tier scanning system (basic, standard, comprehensive)
- **Protocol-Aware Scanning**: Automatic protocol detection with CLI override capability
- **Multi-Protocol Support**: Automated scanning for various DePIN protocols (Sui, Filecoin, etc.)
- **Intelligent Agent System**: Modular agents for reconnaissance, scanning, processing, and reporting
- **CVE Integration**: Real-time vulnerability database updates and correlation
- **GeoIP Enrichment**: Geographic and ASN context for threat intelligence
- **Parallel Processing**: Efficient concurrent scanning with queue management
- **Signature Learning**: ML-powered protocol signature detection and classification
- **Comprehensive Reporting**: JSON, CSV, and email report generation
- **Library + CLI**: Use as a Python library or standalone CLI tool

## Quick Start

### Installation

```bash
pip install pgdn
```

### Basic Usage

```bash
# Run full security assessment pipeline
pgdn

# Level 1: Basic infrastructure scanning (legal, passive, safe)
pgdn --stage scan --target 192.168.1.100 --org-id <uuid> --scan-level 1

# Level 2: Standard scanning with GeoIP + protocol detection
pgdn --stage scan --target 192.168.1.100 --org-id <uuid> --scan-level 2

# Level 3: Comprehensive scanning with aggressive tools
pgdn --stage scan --target 192.168.1.100 --org-id <uuid> --scan-level 3

# Force specific protocol (overrides database detection)
pgdn --stage scan --target 192.168.1.100 --org-id <uuid> --scan-level 2 --force-protocol sui

# Scanner type selection for testing/debugging
pgdn --stage scan --target 192.168.1.100 --org-id <uuid> --type web
pgdn --stage scan --target 192.168.1.100 --org-id <uuid> --type nmap

# Generate report for specific scan
pgdn --stage report --scan-id 123
```

### Library Usage

```python
from pgdn import initialize_application, PipelineOrchestrator
from pgdn.scanner import Scanner

# Initialize and run full pipeline
config = initialize_application("config.json")
orchestrator = PipelineOrchestrator(config)
result = orchestrator.run_full_pipeline()

# Direct scanning with levels
scanner = Scanner(config)
result_l1 = scanner.scan_target("192.168.1.100", org_id="myorg", scan_level=1)
result_l2 = scanner.scan_target("192.168.1.100", org_id="myorg", scan_level=2) 
result_l3 = scanner.scan_target("192.168.1.100", org_id="myorg", scan_level=3)

# Scan with forced protocol
result = scanner.scan_target("192.168.1.100", org_id="myorg", scan_level=2, force_protocol="sui")
```

## Documentation

- [Installation Guide](docs/installation.md)
- [Configuration](docs/configuration.md)
- [Library Documentation](docs/library.md)
- [CLI Reference](docs/cli.md)
- [Agent System](docs/agents.md)
- [Examples](examples/)

## Architecture

PGDN uses a modular agent-based architecture with distinct stages:

1. **Reconnaissance**: Discovery of DePIN infrastructure endpoints
2. **Scanning**: Security assessment and vulnerability detection
3. **Processing**: Analysis and correlation of scan results
4. **Scoring**: Risk assessment and prioritization
5. **Reporting**: Generation of security reports and notifications

## Contributing

Please read our [Contributing Guidelines](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
- [Library Documentation](docs/library.md)
- [CLI Reference](docs/cli.md)
- [Agent System](docs/agents.md)
- [Examples](examples/)

## Architecture

PGDN uses a modular agent-based architecture with distinct stages:

1. **Reconnaissance**: Discovery of DePIN infrastructure endpoints
2. **Scanning**: Security assessment and vulnerability detection
3. **Processing**: Analysis and correlation of scan results
4. **Scoring**: Risk assessment and prioritization
5. **Reporting**: Generation of security reports and notifications

## Contributing

Please read our [Contributing Guidelines](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
