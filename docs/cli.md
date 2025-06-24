# PGDN CLI Reference

## Overview

The PGDN command-line interface provides access to all security scanning functionality through simple commands.

## Basic Usage

```bash
pgdn [OPTIONS]
```

## Pipeline Operations

### Full Pipeline

Run the complete security assessment pipeline:

```bash
# Default full pipeline
pgdn

# With specific reconnaissance agents
pgdn --recon-agents SuiReconAgent,SolanaReconAgent

# With protocol filtering
pgdn --protocol sui
```

### Individual Stages

Execute specific pipeline stages:

```bash
# Reconnaissance stage
pgdn --stage recon

# Scanning stage
pgdn --stage scan --protocol sui

# Processing stage
pgdn --stage process

# Scoring stage
pgdn --stage score --force-rescore

# Publishing stage
pgdn --stage publish --agent PublishLedgerAgent --scan-id 123

# Signature learning
pgdn --stage signature --protocol sui

# Discovery stage
pgdn --stage discovery --host 192.168.1.1
```

## Scanning Operations

### Scan Levels

PGDN supports three progressive scan levels:

```bash
# Level 1: Basic scanning (default)
pgdn --stage scan --target 192.168.1.100 --org-id myorg

# Level 2: Standard scanning with GeoIP enrichment
pgdn --stage scan --target 192.168.1.100 --org-id myorg --scan-level 2

# Level 3: Comprehensive scanning with protocol analysis
pgdn --stage scan --target 192.168.1.100 --org-id myorg --scan-level 3

# Protocol-specific Level 3 scanning
pgdn --stage scan --protocol sui --scan-level 3
pgdn --stage scan --protocol filecoin --scan-level 3
```

### Target Scanning

Scan specific targets with different levels:

```bash
# Basic Level 1 target scan
pgdn --stage scan --target 192.168.1.100 --org-id myorg

# Level 2 with GeoIP context
pgdn --stage scan --target 192.168.1.100 --org-id myorg --scan-level 2

# Comprehensive Level 3 analysis
pgdn --stage scan --target 192.168.1.100 --org-id myorg --scan-level 3

# Debug mode with specific level
pgdn --stage scan --target 192.168.1.100 --org-id myorg --scan-level 2 --debug
```

### Database Scanning

Scan nodes from database with scan levels:

```bash
# Level 1 database scan
pgdn --stage scan --org-id myorg

# Level 2 with GeoIP enrichment
pgdn --stage scan --org-id myorg --scan-level 2

# Level 3 comprehensive analysis
pgdn --stage scan --org-id myorg --scan-level 3

# Protocol-filtered Level 3 scanning
pgdn --stage scan --protocol sui --org-id myorg --scan-level 3
```

## Report Generation

```bash
# Generate report for scan
pgdn --stage report --scan-id 123

# Custom output format
pgdn --stage report --scan-id 123 --format csv

# Auto-save report
pgdn --stage report --scan-id 123 --auto-save

# Email report
pgdn --stage report --scan-id 123 --email --recipient security@company.com

# Custom output file
pgdn --stage report --scan-id 123 --output report.json
```

## CVE Management

```bash
# Update CVE database
pgdn --cve-update

# Force update
pgdn --cve-update --force

# Update with specific days back
pgdn --cve-update --days-back 30

# Start CVE scheduler
pgdn --cve-scheduler --update-time "02:00"

# Show CVE statistics
pgdn --cve-stats
```

## Signature Management

```bash
# Learn signatures from scans
pgdn --signature-learn --protocol sui --min-confidence 0.8

# Update signature flags
pgdn --signature-update --protocol sui

# Mark signature as created
pgdn --signature-mark-created --scan-id 123

# Show signature statistics
pgdn --signature-stats --protocol sui
```

## Queue Management

```bash
# Queue full pipeline
pgdn --queue --pipeline

# Queue single stage
pgdn --queue --stage scan --protocol sui

# Queue target scan
pgdn --queue --scan-target 192.168.1.100

# Check task status
pgdn --queue-status --task-id abc123

# Cancel task
pgdn --queue-cancel --task-id abc123
```

## Configuration Options

```bash
# Custom config file
pgdn --config custom_config.json

# Set log level
pgdn --log-level DEBUG

# Use Docker configuration
pgdn --docker-config

# Override database path
pgdn --database /path/to/db.sqlite3
```

## Output Options

```bash
# JSON output
pgdn --output-format json

# Verbose output
pgdn --verbose

# Quiet mode
pgdn --quiet

# Save output to file
pgdn --output results.json
```

## Examples

### Complete Security Assessment

```bash
# Full assessment with email notification
pgdn --recon-agents SuiReconAgent \
     --stage report --auto-save --email \
     --recipient security@company.com
```

### Targeted Network Scan

```bash
# Scan specific network range
echo "192.168.1.0/24" | pgdn --scan-targets-file - \
                              --protocol sui \
                              --max-parallel 5 \
                              --debug
```

### Automated Vulnerability Updates

```bash
# Daily CVE update with signature learning
pgdn --cve-scheduler --update-time "02:00" && \
pgdn --signature-learn --protocol sui --min-confidence 0.7
```

## Exit Codes

- `0` - Success
- `1` - General error
- `2` - Configuration error
- `3` - Network error
- `4` - Database error
- `5` - Permission error