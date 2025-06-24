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
