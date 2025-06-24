# Modular Scanning System

This document describes the modular scanning system that consolidates scanning functionality, removes hardcoded vulnerabilities, provides a configurable architecture, and implements comprehensive scan level support.

## Overview

The new scanning system addresses the following issues from the original implementation:

1. **Consolidated Code**: Merged functionality from `scanning/scanner.py` and `agents/scan/node_scanner_agent.py`
2. **Removed Hardcoded Vulnerabilities**: Eliminated the `KNOWN_VULNS` dictionary in favor of CVE database lookups
3. **Modular Architecture**: Made scanning configurable and extensible like the scoring system
4. **Configuration-Driven**: Scanners can be enabled/disabled and configured via `config.json`
5. **Scan Level Support**: Implemented levels 1-3 for progressive scanning depth and analysis
6. **GeoIP Integration**: Added geolocation and ASN enrichment capabilities

## Scan Levels

The system implements three distinct scan levels to balance thoroughness with performance:

### Level 1: Basic Scanning
- **Purpose**: Fast, essential security checks
- **Scanners**: Generic (ports/services), Web (basic HTTP checks), Vulnerability (CVE lookups)
- **Use Case**: Regular monitoring, CI/CD pipelines, quick assessments
- **Performance**: Fastest execution time

### Level 2: Standard Scanning with GeoIP
- **Purpose**: Comprehensive analysis with geographic context
- **Scanners**: All Level 1 scanners + GeoScanner (IP geolocation and ASN data)
- **Use Case**: Standard security assessments, threat intelligence gathering
- **Performance**: Moderate execution time

### Level 3: Comprehensive Scanning
- **Purpose**: Deep analysis with advanced protocol-specific checks
- **Scanners**: All Level 2 scanners + Protocol-specific scanners (Sui, Filecoin, etc.)
- **Use Case**: In-depth security audits, compliance assessments, forensics
- **Performance**: Longest execution time, most thorough analysis

## Architecture

### Core Components

1. **`BaseScanner`**: Abstract base class for all scanners with scan_level support
2. **`ScannerRegistry`**: Manages registration and creation of scanner instances
3. **`ScanOrchestrator`**: Coordinates multiple scanners, handles scan levels, and integrates external tools
4. **Individual Scanner Modules**: Specialized scanners for different purposes

### Scanner Types

#### Built-in Scanners

- **`GenericScanner`**: Basic port scanning and service detection
- **`WebScanner`**: HTTP/HTTPS specific testing and technology detection
- **`VulnerabilityScanner`**: CVE database-driven vulnerability detection
- **`GeoScanner`**: IP geolocation and ASN enrichment (Level 2+)

#### External/Protocol-Specific Scanners

- **`SuiSpecificScanner`**: Sui blockchain network analysis (Level 3)
- **`FilecoinSpecificScanner`**: Filecoin network and storage analysis (Level 3)
- **Custom Protocol Scanners**: Configurable via `module_path`

## Configuration

### Scan Level Configuration

The system supports three scan levels, configurable via CLI or programmatically:

```bash
# CLI Examples
pgdn --stage scan --scan-level 1                    # Basic scanning
pgdn --stage scan --scan-level 2                    # Standard with GeoIP
pgdn --stage scan --scan-level 3                    # Comprehensive analysis
pgdn --stage scan --scan-level 2 --protocol sui     # Level 2 with Sui focus
```

### Scanner Configuration Structure

```json
{
  "scanning": {
    "orchestrator": {
      "enabled_scanners": ["generic", "web", "vulnerability", "geo", "sui", "filecoin"],
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
      "geo": {
        "enabled": true,
        "maxmind_db_path": "/usr/share/GeoIP/GeoLite2-City.mmdb",
        "maxmind_asn_db_path": "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
        "fallback_to_api": true
      },
      "sui": {
        "enabled": true,
        "module_path": "pgdn.scanning.sui_scanner.SuiSpecificScanner"
      },
      "filecoin": {
        "enabled": true,
        "module_path": "pgdn.scanning.filecoin_scanner.FilecoinSpecificScanner"
      }
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

## Usage Examples

### CLI Usage with Scan Levels

```bash
# Basic Level 1 scanning (default)
pgdn --stage scan --target 192.168.1.1 --org-id myorg

# Level 2 scanning with GeoIP enrichment
pgdn --stage scan --target 192.168.1.1 --org-id myorg --scan-level 2

# Level 3 comprehensive scanning
pgdn --stage scan --target 192.168.1.1 --org-id myorg --scan-level 3

# Protocol-specific Level 3 scanning
pgdn --stage scan --protocol sui --scan-level 3
pgdn --stage scan --protocol filecoin --scan-level 3

# Database scanning with scan levels
pgdn --stage scan --scan-level 2 --org-id myorg
```

### Programmatic Usage

```python
# Using the Scanner class
from pgdn import Scanner
from pgdn.core.config import Config

config = Config()
scanner = Scanner(config, protocol_filter="sui")

# Scan with different levels
result_l1 = scanner.scan_target("192.168.1.1", org_id="myorg", scan_level=1)
result_l2 = scanner.scan_target("192.168.1.1", org_id="myorg", scan_level=2)
result_l3 = scanner.scan_target("192.168.1.1", org_id="myorg", scan_level=3)

# Using the orchestrator directly
from pgdn.scanning.scan_orchestrator import ScanOrchestrator

orchestrator = ScanOrchestrator(config)
result = orchestrator.scan("192.168.1.1", scan_level=2)
```

### Scan Level Results Structure

```python
# Level 1 Result
{
  "scan_level": 1,
  "target": "192.168.1.1",
  "scanner_results": {
    "generic": {...},      # Port scanning results
    "web": {...},          # HTTP/HTTPS analysis  
    "vulnerability": {...} # CVE vulnerability data
  }
}

# Level 2 Result (includes GeoIP)
{
  "scan_level": 2,
  "target": "192.168.1.1",
  "geoip": {
    "country_name": "United States",
    "city_name": "San Francisco", 
    "latitude": 37.7749,
    "longitude": -122.4194,
    "asn_number": 15169,
    "asn_organization": "Google LLC"
  },
  "scanner_results": {
    "generic": {...},
    "web": {...},
    "vulnerability": {...},
    "geo": {...}           # Detailed GeoIP data
  }
}

# Level 3 Result (includes protocol-specific)
{
  "scan_level": 3,
  "target": "192.168.1.1", 
  "geoip": {...},
  "scanner_results": {
    "generic": {...},
    "web": {...},
    "vulnerability": {...},
    "geo": {...},
    "sui": {...},          # Sui blockchain analysis
    "filecoin": {...}      # Filecoin network analysis
  }
}
```

## Migration Guide

### For Existing Code

The system provides a new recommended approach:

```python
# New way (recommended) - with scan level support
from pgdn.scanning.scan_orchestrator import ScanOrchestrator
orchestrator = ScanOrchestrator(config)
result = orchestrator.scan("192.168.1.1", scan_level=2)
```

### Key Changes

1. **Scan Level Support**: Progressive depth of analysis (1-3)
2. **GeoIP Integration**: Automatic geolocation and ASN enrichment at Level 2+
3. **Protocol-Specific Scanners**: Advanced blockchain analysis at Level 3
4. **Vulnerability Detection**: No more hardcoded `KNOWN_VULNS` - now uses CVE database
5. **Modular Scanners**: Can enable/disable individual scanner types
6. **Configuration-Driven**: All scanner behavior controlled via config

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

### 1. Progressive Scanning Depth
- **Level 1**: Fast essential checks for monitoring and CI/CD
- **Level 2**: Balanced analysis with geographic context
- **Level 3**: Comprehensive assessment for security audits

### 2. Maintainability
- Single source of truth for scanning logic
- Clear separation of concerns
- Easier to test individual components
- Scan level logic centrally managed

### 3. Flexibility
- Enable/disable scanners per environment
- Configure scanner behavior without code changes
- Easy addition of new scanner types
- Configurable scan depth based on use case

### 4. Security & Intelligence
- Up-to-date vulnerability data from CVE database
- No outdated hardcoded vulnerability signatures
- Consistent vulnerability detection across all scanners
- Geographic and ASN context for threat intelligence
- Protocol-specific security analysis for blockchain networks

### 5. Performance & Efficiency
- Scan only what you need based on selected level
- Configurable timeouts and limits
- Parallel scanner execution where appropriate
- Intelligent caching for GeoIP lookups
- Optimized for different use cases (monitoring vs auditing)

## Testing

### Comprehensive Test Suite

```bash
# Test the full scanning system
python tests/test_refactored_scanning.py

# Test scan level functionality
python test_scan_levels.py

# Debug scanner registry
python debug_registry.py

# Test specific scan levels
python -c "
from pgdn.scanning.scan_orchestrator import ScanOrchestrator
config = {...}
orchestrator = ScanOrchestrator(config)
result = orchestrator.scan('127.0.0.1', scan_level=2)
print(f'Level 2 scan completed: {result.get(\"scan_level\")}')
print(f'GeoIP included: {\"geoip\" in result}')
"
```

### Test Coverage

The test suite validates:
- Scanner registry functionality with all scanner types
- Scan orchestrator operation across all levels
- Scan level propagation to individual scanners
- GeoIP integration for Level 2+
- Protocol-specific scanner integration for Level 3
- Legacy compatibility maintained
- Configuration loading and validation
- Modular scanner selection and execution

## Legacy Compatibility

The system maintains full backward compatibility while adding scan level support:

- Old import paths still work
- Existing `Scanner` class interface preserved with optional `scan_level` parameter
- Same result format returned (enhanced with scan_level and GeoIP data)
- Static methods like `get_web_ports_and_schemes()` available
- Default scan_level=1 ensures existing code works unchanged

## Future Enhancements

1. **Advanced Scan Levels**: Level 4+ with specialized analysis capabilities
2. **Plugin System**: Dynamic scanner loading from external packages
3. **Intelligent Scan Level Selection**: Automatic level selection based on target characteristics
4. **Result Caching**: Cache scan results to improve performance across levels
5. **Scan Profiles**: Predefined scanner combinations for different use cases
6. **Real-time Configuration**: Hot-reload of scanner configuration
7. **Scan Level Analytics**: Performance and effectiveness metrics per level
8. **Custom Scan Levels**: User-defined scan level combinations
3. **Scan Profiles**: Predefined scanner combinations for different use cases
4. **Parallel Scanning**: Concurrent execution of independent scanners
## Implementation Status

### ✅ **Phase 1 - COMPLETED**: Core Modular System
- Implemented new modular system with backward compatibility
- Created BaseScanner interface and ScannerRegistry
- Built ScanOrchestrator for scanner coordination
- Integrated all existing scanner functionality

### ✅ **Phase 2 - COMPLETED**: Scan Level Implementation
- Implemented 3-tier scan level system (1-3)
- Integrated GeoScanner with MaxMind and API fallback
- Added protocol-specific scanner support (Sui, Filecoin)
- Updated CLI with `--scan-level` argument and comprehensive examples
- Enhanced all scanners with scan_level parameter support

### ✅ **Phase 3 - COMPLETED**: Integration & Testing
- Fixed protocol-specific scanner constructor compatibility
- Updated configuration structure for all scanner types
- Created comprehensive test suite for scan level functionality
- Verified end-to-end CLI and programmatic interfaces

### 🚀 **Phase 4 - PLANNED**: Advanced Features
- Add advanced scan levels (4+) with specialized capabilities
- Implement plugin system for dynamic scanner loading
- Add result caching and performance optimizations
- Create scan profiles and intelligent level selection

## Summary

The PGDN scanning system now provides:

- **3 Progressive Scan Levels**: From basic monitoring to comprehensive auditing
- **Modular Architecture**: Easy to extend and configure
- **GeoIP Integration**: Geographic and ASN context for all scans
- **Protocol-Specific Analysis**: Deep blockchain network assessment
- **Full CLI Support**: Complete command-line interface with scan level control
- **Backward Compatibility**: Existing code continues to work unchanged
- **Comprehensive Testing**: Full test coverage across all functionality

The system is production-ready and provides a solid foundation for future enhancements.
