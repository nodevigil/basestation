# Installation Guide

## Requirements

- Python 3.8 or higher
- pip package manager
- SQLite3 (for local database)
- Docker (optional, for containerized deployment)

## Installation Methods

### Option 1: pip Install (Recommended)

```bash
pip install pgdn
```

### Option 2: Development Install

```bash
git clone https://github.com/your-org/pgdn.git
cd pgdn
pip install -e .
```

### Option 3: Docker

```bash
docker pull pgdn/scanner:latest
docker run -v $(pwd)/config.json:/app/config.json pgdn/scanner:latest
```

## Verification

Verify the installation:

```bash
pgdn --version
```

## Initial Setup

### 1. Configuration

Create a configuration file:

```bash
cp config.example.json config.json
```

Edit `config.json` with your settings. See [Configuration Guide](configuration.md) for details.

### 2. Database Setup

Initialize the database:

```bash
pgdn --init-db
```

### 3. CVE Database

Populate the CVE database:

```bash
pgdn --cve-update --initial-populate
```

### 4. Test Installation

Run a test scan:

```bash
pgdn --scan-target 127.0.0.1
```

## Troubleshooting

### Common Issues

#### Permission Errors
```bash
# Fix with proper permissions
chmod +x pgdn
```

#### Database Connection Issues
```bash
# Check database path in config.json
# Ensure write permissions to database directory
```

#### Missing Dependencies
```bash
# Reinstall with all dependencies
pip install --force-reinstall pgdn
```

### Getting Help

- Check the [documentation](README.md)
- View command help: `pgdn --help`
- Check logs in the `logs/` directory
- Report issues on GitHub

## Next Steps

- Read the [Configuration Guide](configuration.md)
- Try the [Quick Start Examples](../examples/)
- Review the [CLI Reference](cli.md)
