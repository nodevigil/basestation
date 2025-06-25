# PGDN - Agentic DePIN Infrastructure Scanner

PGDN (Programmatic Global DePIN Network) is a comprehensive security scanning platform designed specifically for decentralized physical infrastructure networks (DePIN). It provides automated reconnaissance, vulnerability scanning, and security assessment capabilities for blockchain-based infrastructure protocols.

## Features

- **Multi-Protocol Support**: Automated scanning for various DePIN protocols (Sui, Solana, etc.)
- **Intelligent Agent System**: Modular agents for reconnaissance, scanning, processing, and reporting
- **CVE Integration**: Real-time vulnerability database updates and correlation
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

# Infrastructure scanning only
pgdn --stage scan --target 192.168.1.100 --org-id <uuid>

# Infrastructure + protocol-specific scanning
pgdn --stage scan --target 192.168.1.100 --org-id <uuid> --force-protocol sui

# Specific scanner types
pgdn --stage scan --target 192.168.1.100 --org-id <uuid> --type web
pgdn --stage scan --target 192.168.1.100 --org-id <uuid> --type whatweb

# Generate report for specific scan
pgdn --stage report --scan-id 123
```

### Library Usage

```python
from pgdn import initialize_application, PipelineOrchestrator

# Initialize and run full pipeline
config = initialize_application("config.json")
orchestrator = PipelineOrchestrator(config)
result = orchestrator.run_full_pipeline()
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
