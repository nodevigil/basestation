# Modular Scanning System

This document describes the modular scanning system that consolidates scanning functionality, removes hardcoded vulnerabilities, and provides a configurable architecture similar to the scoring system.

## Overview

The new scanning system addresses the following issues from the original implementation:

1. **Consolidated Code**: Merged functionality from `scanning/scanner.py` and `agents/scan/node_scanner_agent.py`
2. **Removed Hardcoded Vulnerabilities**: Eliminated the `KNOWN_VULNS` dictionary in favor of CVE database lookups
3. **Modular Architecture**: Made scanning configurable and extensible like the scoring system
4. **Configuration-Driven**: Scanners can be enabled/disabled and configured via `config.json`

## Architecture

### Core Components

1. **`BaseScanner`**: Abstract base class for all scanners
2. **`ScannerRegistry`**: Manages registration and creation of scanner instances
3. **`ScanOrchestrator`**: Coordinates multiple scanners and external tools
4. **Individual Scanner Modules**: Specialized scanners for different purposes

### Scanner Types

#### Built-in Scanners

- **`GenericScanner`**: Basic port scanning and service detection
- **`WebScanner`**: HTTP/HTTPS specific testing and technology detection
- **`VulnerabilityScanner`**: CVE database-driven vulnerability detection

#### External Scanners

- **Protocol-specific scanners**: Sui, Filecoin, etc. (configurable via `module_path`)

## Configuration

### New Configuration Structure

```json
{
  "scanning": {
    "orchestrator": {
      "enabled_scanners": ["generic", "web", "vulnerability"],
      "use_external_tools": true
    },
    "scanners": {
      "generic": {
        "enabled": true,
        "default_ports": [22, 80, 443, 2375, 3306],
        "connection_timeout": 1,
        "banner_timeout": 2
      },
      "web": {
        "enabled": true,
        "timeout": 10,
        "max_redirects": 5,
        "user_agent": "PGDN-Scanner/1.0"
      },
      "vulnerability": {
        "enabled": true,
        "max_cves_per_banner": 5,
        "enable_database_lookup": true
      },
      "sui": {
        "enabled": true,
        "module_path": "pgdn.scanning.sui_scanner.SuiSpecificScanner"
      }
    }
  }
}
```

## Migration Guide

### For Existing Code

The system provides a new recommended approach:

```python
# New way (recommended)
from pgdn.scanning.scan_orchestrator import ScanOrchestrator
orchestrator = ScanOrchestrator(config)
result = orchestrator.scan("192.168.1.1")
```

### Key Changes

1. **Vulnerability Detection**: No more hardcoded `KNOWN_VULNS` - now uses CVE database
2. **Modular Scanners**: Can enable/disable individual scanner types
3. **Configuration-Driven**: All scanner behavior controlled via config
4. **Protocol Extensions**: Easy to add new protocol-specific scanners

## Creating Custom Scanners

### Step 1: Implement BaseScanner

```python
from pgdn.scanning.base_scanner import BaseScanner
from typing import Dict, Any

class MyCustomScanner(BaseScanner):
    @property
    def scanner_type(self) -> str:
        return "custom"
    
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        # Your scanning logic here
        return {
            "target": target,
            "custom_results": {},
            "scanner_type": self.scanner_type
        }
```

### Step 2: Register in Configuration

```json
{
  "scanners": {
    "custom": {
      "enabled": true,
      "module_path": "path.to.your.MyCustomScanner",
      "custom_config": "value"
    }
  }
}
```

### Step 3: Enable in Orchestrator

```json
{
  "orchestrator": {
    "enabled_scanners": ["generic", "web", "vulnerability", "custom"]
  }
}
```

## Benefits

### 1. Maintainability
- Single source of truth for scanning logic
- Clear separation of concerns
- Easier to test individual components

### 2. Flexibility
- Enable/disable scanners per environment
- Configure scanner behavior without code changes
- Easy addition of new scanner types

### 3. Security
- Up-to-date vulnerability data from CVE database
- No outdated hardcoded vulnerability signatures
- Consistent vulnerability detection across all scanners

### 4. Performance
- Scan only what you need
- Configurable timeouts and limits
- Parallel scanner execution where appropriate

## Testing

Run the test suite to verify the refactored system:

```bash
python tests/test_refactored_scanning.py
```

This will test:
- Scanner registry functionality
- Scan orchestrator operation
- Legacy compatibility
- Configuration loading
- Modular scanner selection

## Legacy Compatibility

The system maintains full backward compatibility:

- Old import paths still work
- Existing `Scanner` class interface preserved
- Same result format returned
- Static methods like `get_web_ports_and_schemes()` available

## Future Enhancements

1. **Plugin System**: Dynamic scanner loading from external packages
2. **Result Caching**: Cache scan results to improve performance
3. **Scan Profiles**: Predefined scanner combinations for different use cases
4. **Parallel Scanning**: Concurrent execution of independent scanners
5. **Real-time Configuration**: Hot-reload of scanner configuration

## Migration Timeline

1. **Phase 1** ✅: Implement new modular system with backward compatibility
2. **Phase 2**: Update all calling code to use new interfaces
3. **Phase 3**: Remove legacy compatibility layer
4. **Phase 4**: Add advanced features (plugins, caching, etc.)

## CLI Scan Types

The PGDN CLI now supports selective scan type execution for testing and debugging purposes. This allows you to run specific scanners or external tools individually.

### Scan Type Options

Use the `--type` flag to specify which scan components to run:

```bash
# Available scan types
pgdn --stage scan --target example.com --org-id myorg --type nmap
pgdn --stage scan --target example.com --org-id myorg --type geo
pgdn --stage scan --target example.com --org-id myorg --type generic
pgdn --stage scan --target example.com --org-id myorg --type web
pgdn --stage scan --target example.com --org-id myorg --type vulnerability
pgdn --stage scan --target example.com --org-id myorg --type ssl
pgdn --stage scan --target example.com --org-id myorg --type docker
pgdn --stage scan --target example.com --org-id myorg --type whatweb
pgdn --stage scan --target example.com --org-id myorg --type full  # Default behavior
```

### Scan Type Descriptions

| Type | Description | What it runs |
|------|-------------|--------------|
| `nmap` | Network mapping only | External nmap tool only |
| `geo` | GeoIP lookup only | GeoScanner only |
| `generic` | Basic port scanning | GenericScanner only |
| `web` | Web analysis only | WebScanner only |
| `vulnerability` | CVE detection only | VulnerabilityScanner only |
| `ssl` | SSL/TLS testing only | SSL test external tool only |
| `docker` | Docker exposure check | Docker exposure checker only |
| `whatweb` | Web technology fingerprinting | WhatWeb external tool only |
| `full` | Complete scan | All enabled scanners and external tools (default) |

### Advanced Scanner Selection

For more granular control, you can also use the direct scanner selection options:

```bash
# Select specific scanners
pgdn --stage scan --target example.com --org-id myorg --scanners generic web

# Select specific external tools  
pgdn --stage scan --target example.com --org-id myorg --external-tools nmap whatweb

# Combine both
pgdn --stage scan --target example.com --org-id myorg --scanners geo --external-tools nmap

# Disable external tools completely
pgdn --stage scan --target example.com --org-id myorg --external-tools
```

### Debugging Use Cases

#### 1. **Port Scanning Issues**
If you're seeing incorrect port results:
```bash
# Test nmap directly to see all ports
pgdn --stage scan --target example.com --org-id myorg --type nmap --debug

# Compare with generic scanner only
pgdn --stage scan --target example.com --org-id myorg --type generic --debug
```

#### 2. **GeoIP Problems**
Test geographic lookups in isolation:
```bash
pgdn --stage scan --target example.com --org-id myorg --type geo --debug
```

#### 3. **Web Service Detection**
Debug web service fingerprinting:
```bash
# Test web scanner only
pgdn --stage scan --target example.com --org-id myorg --type web --debug

# Test WhatWeb tool only
pgdn --stage scan --target example.com --org-id myorg --type whatweb --debug
```

#### 4. **SSL/TLS Issues**
Isolate SSL certificate problems:
```bash
pgdn --stage scan --target example.com --org-id myorg --type ssl --debug
```

#### 5. **Vulnerability Detection**
Test CVE lookup functionality:
```bash
pgdn --stage scan --target example.com --org-id myorg --type vulnerability --debug
```

### Example Output Comparison

**Full scan** (default):
```json
{
  "success": true,
  "target": "example.com",
  "scan_result": {
    "open_ports": [22, 80, 443, 2375, 3306, 8080, 9000, 9184],
    "geoip": {...},
    "http_headers": {...},
    "vulns": {...},
    "nmap": {...}
  }
}
```

**Nmap only** (`--type nmap`):
```json
{
  "success": true,
  "target": "example.com", 
  "scan_result": {
    "open_ports": [22, 80, 443, 2375, 3306, 8080, 9000, 9184],
    "nmap": {
      "ports": [...]
    }
  }
}
```

**Generic only** (`--type generic`):
```json
{
  "success": true,
  "target": "example.com",
  "scan_result": {
    "open_ports": [22, 80, 443, 2375, 3306],
    "banners": {...}
  }
}
```

Notice how the nmap scan finds all 8 ports while the generic scanner only finds 5. This helps identify when fallback scanning is being used instead of full nmap.
