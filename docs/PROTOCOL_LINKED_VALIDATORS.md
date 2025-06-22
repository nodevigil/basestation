# Protocol-Linked Validator Addresses Implementation

## Overview

This implementation changes the validator address storage system to link directly to protocol records instead of using string-based source identifiers. This ensures that validator addresses can only be created when the corresponding protocol signature exists in the database.

## Key Changes

### 1. Database Schema Updates

**Before:**
- `ValidatorAddress.source`: String field (e.g., "sui_recon_agent", "filecoin_api")

**After:**
- `ValidatorAddress.protocol_id`: Foreign key to `protocols.id`
- `ValidatorAddress.protocol`: SQLAlchemy relationship to Protocol model

### 2. Model Updates

#### Core Database Models (`core/database.py`)
- Updated `ValidatorAddress` model to use `protocol_id` foreign key
- Added `protocol` relationship for easy access
- Updated `__repr__` and `to_dict` methods to reflect new structure

#### Models Module (`models/validator.py`)
- Synchronized with core database model updates
- Updated to use same protocol-based structure

### 3. Reconnaissance Agent Updates

#### Sui Reconnaissance Agent (`agents/recon/sui_agent.py`)
- Added `_get_protocol_with_signature()` method to validate protocol existence and signature
- Updated `discover_nodes()` to check protocol signature before proceeding
- Modified `_parse_validator_addresses()` to accept and use `protocol_id`
- Updated `_save_nodes_to_database()` to use `protocol_id` instead of `source`
- Updated `get_active_validators()` to filter by protocol relationship

#### Filecoin Reconnaissance Agent (`agents/recon/filecoin_agent.py`)
- Added identical `_get_protocol_with_signature()` validation method
- Updated all methods to use `protocol_id` instead of `source`
- Modified `discover_peers_from_lotus()` and `_query_filecoin_api()` to accept `protocol_id`
- Updated node creation throughout the discovery pipeline

### 4. Repository Updates (`repositories/validator_repository.py`)

- **Method Updates:**
  - `add_validator()`: Now accepts `protocol_name` parameter, looks up protocol ID
  - `update_validator()`: Uses `protocol_name` instead of `source`
  - `get_validators_by_protocol()`: Replaces `get_validators_by_source()`
  - `bulk_add_validators()`: Updated to use protocol-based approach

- **Error Handling:**
  - Added validation to ensure protocols exist before creating validators
  - Proper error messages when protocols are not found

### 5. Database Migration

**Migration File:** `alembic/versions/validator_protocol_link.py`

- Adds `protocol_id` column to `validator_addresses` table
- Creates foreign key constraint to `protocols` table
- Migrates existing data based on `source` field values:
  - `sui_recon_agent`, `sui` → Links to `sui` protocol
  - `filecoin_lotus_peer`, `filecoin_api`, `filecoin` → Links to `filecoin` protocol
  - All others → Links to `manual` protocol (created if needed)
- Removes old `source` column
- Includes rollback functionality

### 6. Validation Tools

**Script:** `scripts/validate_recon_readiness.py`

- Checks which protocols have signatures before running reconnaissance
- Can validate specific protocols or all protocols
- Provides clear status reporting
- Exits with appropriate codes for automation

## Error Handling Strategy

### Efficient Error Handling
The implementation follows the requirement for "efficient error handling" by:

1. **Early Validation**: Reconnaissance agents check for protocol signatures before starting discovery
2. **Graceful Failures**: If protocols/signatures are missing, agents log clear error messages and exit early
3. **Clear Error Messages**: All error messages indicate what is missing and how to fix it
4. **No Partial States**: Transactions are rolled back if protocol validation fails

### Error Scenarios Handled

1. **Protocol Not Found**: When a reconnaissance agent tries to run but the protocol doesn't exist in the database
2. **Missing Signature**: When a protocol exists but has no generated signature
3. **Database Errors**: Proper exception handling and rollback for database operations
4. **Migration Conflicts**: Safe migration with proper constraint handling

## Usage Examples

### Running Reconnaissance (New Process)

```bash
# 1. Validate readiness
python scripts/validate_recon_readiness.py --protocols sui filecoin

# 2. If signatures are missing, generate them
python -m agents.signature.protocol_signature_generator_agent

# 3. Run reconnaissance (will now check signatures automatically)
python -m agents.recon.sui_agent
python -m agents.recon.filecoin_agent
```

### Using the Repository

```python
from repositories.validator_repository import ValidatorRepository

# Add validator with protocol linkage
repo = ValidatorRepository()
validator = repo.add_validator(
    address="validator.example.com",
    name="Example Validator", 
    protocol_name="sui"  # Links to sui protocol
)

# Get validators by protocol
sui_validators = repo.get_validators_by_protocol("sui")
```

## Migration Instructions

1. **Backup Database**: Always backup before running migrations
2. **Run Migration**: `alembic upgrade head`
3. **Validate**: Use the validation script to ensure everything is working
4. **Test Reconnaissance**: Run agents to verify they work with new structure

## Benefits

1. **Data Integrity**: Foreign key constraints ensure validator addresses always link to valid protocols
2. **Signature Dependency**: Reconnaissance can only proceed when signatures exist
3. **Better Organization**: Clear relationship between validators and their protocols
4. **Easier Querying**: Can easily find all validators for a specific protocol
5. **Consistent Structure**: All reconnaissance agents follow the same pattern
6. **Safe Operations**: Early validation prevents partial or invalid data states

## Backward Compatibility

The migration handles existing data automatically, but any external code using the `source` field will need to be updated to use the new protocol relationship structure.
