# Protocol Migration Tool

This tool provides comprehensive migration functionality for linking protocols to agents and managing all related dependencies in the DePIN infrastructure scanner.

## Overview

The migration tool handles the complete process of:

1. **Protocol Seeding**: Uses the existing `protocol_seeder.py` to populate protocols
2. **Signature Generation**: Creates binary signatures for all protocols
3. **Validator Linking**: Links validator addresses to protocols (replaces source-based system)
4. **Dependency Validation**: Ensures all relationships are correctly established
5. **Data Consistency**: Updates signature match results and other related data

## Key Features

### 🔍 Comprehensive Dependency Checking
- Validates protocol existence and signatures
- Checks validator address linkages
- Verifies recon agent compatibility
- Identifies orphaned data

### 🔄 Safe Migration Process
- Backup-friendly operations
- Rollback-safe transactions
- Extensive validation at each step
- Detailed logging and error reporting

### 🎯 Protocol-Agent Integration
- Links validator addresses to protocols via foreign keys
- Ensures reconnaissance agents can only run with valid protocol signatures
- Maintains data integrity through proper constraints

## Usage

### Quick Start

```bash
# Check current status (safe, no changes)
python tools/protocol_migration_tool.py --check-dependencies

# Run full migration
python tools/protocol_migration_tool.py --full-migration

# Validate migration results
python tools/protocol_migration_tool.py --validate-only
```

### Interactive Guide

```bash
# Use the interactive guide for step-by-step assistance
python tools/migration_guide.py
```

## Command Line Options

| Option | Description | Safe |
|--------|-------------|------|
| `--check-dependencies` | Check all protocol dependencies | ✅ |
| `--validate-only` | Validate existing migration | ✅ |
| `--full-migration` | Run complete migration process | ⚠️ |
| `--force-update` | Force update existing data | ⚠️ |
| `--config PATH` | Use custom configuration file | - |

## Migration Process Details

### Step 1: Protocol Seeding
- Uses `DePINProtocolSeeder` to populate protocol definitions
- Creates protocols for: Sui, Filecoin, Ethereum, Celestia, Bittensor, and others
- Updates existing protocols if `--force-update` is used

### Step 2: Signature Generation
- Uses `ProtocolSignatureGeneratorAgent` to create binary signatures
- Generates optimized signatures for fast protocol matching
- Calculates uniqueness scores for each protocol

### Step 3: Validator Address Linking
- Migrates from `source` field to `protocol_id` foreign key
- Maps existing source values to appropriate protocols:
  - `sui_recon_agent`, `sui` → Sui protocol
  - `filecoin_lotus_peer`, `filecoin_api`, `filecoin` → Filecoin protocol
  - Others → Manual protocol (created if needed)

### Step 4: Data Consistency
- Updates signature match results to ensure protocol consistency
- Fixes any mismatched protocol names vs. IDs
- Validates all foreign key relationships

### Step 5: Final Validation
- Comprehensive dependency check
- Validates recon agent compatibility
- Ensures no orphaned data exists

## Dependency Analysis

The tool checks for these dependencies:

### Protocol Dependencies
- ✅ **Protocol Exists**: Protocol is defined in database
- ✅ **Signature Exists**: Protocol has generated signature
- ✅ **Validators Linked**: Validator addresses reference protocol
- ✅ **Agents Compatible**: Recon agents support protocol validation

### Data Integrity
- ✅ **No Orphaned Validators**: All validator addresses reference valid protocols
- ✅ **No Orphaned Matches**: All signature matches reference valid protocols
- ✅ **Consistent Names**: Protocol names match between tables

## Affected Models

The migration affects these database models:

### Core Models
- `Protocol`: Protocol definitions and metadata
- `ProtocolSignature`: Binary signatures for protocols
- `ValidatorAddress`: Validator addresses (links to protocols)

### Related Models
- `SignatureMatchResult`: Protocol matching results
- `HostDiscovery`: Network discovery results
- Recon agents: Sui and Filecoin agents

## Error Handling

The tool provides robust error handling:

- **Transaction Safety**: Each step uses database transactions
- **Partial Failure Recovery**: Continues processing if individual items fail
- **Detailed Logging**: Comprehensive logs to `protocol_migration.log`
- **Validation Reporting**: Clear success/failure reporting

## Backup Recommendations

Before running migration:

```bash
# PostgreSQL backup
pg_dump your_database > backup_before_migration.sql

# Or full database backup
pg_dumpall > full_backup_before_migration.sql
```

## Post-Migration Testing

After migration, test the system:

```bash
# Validate protocol signatures exist
python scripts/validate_recon_readiness.py

# Test reconnaissance agents
python -m agents.recon.sui_agent
python -m agents.recon.filecoin_agent

# Run discovery pipeline
python -m agents.discovery.discovery_agent
```

## Troubleshooting

### Common Issues

#### Missing Protocols
```bash
# If protocols are missing, re-run protocol seeding
python protocol_seeder.py --force-update
```

#### Missing Signatures
```bash
# If signatures are missing, force regeneration
python tools/protocol_migration_tool.py --full-migration --force-update
```

#### Orphaned Data
```bash
# Check for orphaned data
python tools/protocol_migration_tool.py --check-dependencies

# Clean up orphaned data manually via database
```

### Log Analysis
Check `protocol_migration.log` for detailed error information:

```bash
# View recent errors
tail -f protocol_migration.log | grep ERROR

# View migration statistics
grep "MIGRATION STATISTICS" protocol_migration.log -A 20
```

## Integration with Existing Workflow

### Before Reconnaissance
1. Ensure protocols are seeded
2. Ensure signatures are generated
3. Validate readiness: `python scripts/validate_recon_readiness.py`

### During Development
- Use `--check-dependencies` to validate system state
- Use `--validate-only` after code changes
- Monitor logs for warnings or errors

### Production Deployment
1. Backup database
2. Run migration with validation
3. Test all reconnaissance agents
4. Monitor system health

## Configuration

The tool uses the same configuration system as other agents:

```python
# Custom configuration
config = Config()
tool = ProtocolMigrationTool(config)
```

Configuration affects:
- Database connection settings
- Logging levels
- Agent-specific parameters

## Development Notes

### Adding New Protocols
1. Add protocol definition to `protocol_seeder.py`
2. Run migration to generate signatures
3. Create recon agent if needed
4. Update validation scripts

### Modifying Dependencies
1. Update database models if needed
2. Add dependency checks to migration tool
3. Update validation logic
4. Test migration with existing data

## API Reference

### Main Classes

#### `ProtocolMigrationTool`
Main migration orchestrator

```python
tool = ProtocolMigrationTool(config)
tool.run_full_migration(force_update=False)
tool.check_all_dependencies()
tool.validate_migration()
```

#### `DependencyStatus`
Dependency check results

```python
@dataclass
class DependencyStatus:
    protocol_exists: bool
    signature_exists: bool
    validators_linked: bool
    recon_agents_compatible: bool
    signature_match_results_valid: bool
    issues: List[str]
```

#### `MigrationStats`
Migration operation statistics

```python
@dataclass
class MigrationStats:
    protocols_seeded: int
    signatures_generated: int
    validators_linked: int
    errors_encountered: int
    # ... more fields
```

## Contributing

When contributing to migration functionality:

1. Add comprehensive tests
2. Update dependency checks
3. Maintain backward compatibility
4. Document configuration changes
5. Test with real data scenarios

## Support

For issues with migration:

1. Check logs in `protocol_migration.log`
2. Run dependency check for diagnosis
3. Validate system state after changes
4. Refer to troubleshooting section above
