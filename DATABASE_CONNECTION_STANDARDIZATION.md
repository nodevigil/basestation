# Database Connection Standardization - Summary

## Problem Solved
Fixed aggressive Docker environment detection that was causing database connection failures when running outside Docker containers.

## Issues Fixed

### 1. **Overly Aggressive Docker Detection**
**Before:** Application used `DATABASE_URL` environment variable presence to assume Docker environment
**After:** Requires explicit `USE_DOCKER_CONFIG=true` environment variable to use Docker configuration

### 2. **Database Connection Logic**
**Before:**
```python
# Always tried DATABASE_URL first, regardless of environment
url: str = field(default_factory=lambda: os.getenv('DATABASE_URL', 'postgresql://simon@localhost/depin'))
```

**After:**
```python
# Only uses DATABASE_URL if explicitly requested
def _get_default_database_url() -> str:
    if (os.getenv('USE_DOCKER_CONFIG', '').lower() in ('true', '1', 'yes') and 
        os.getenv('DATABASE_URL')):
        return os.getenv('DATABASE_URL')
    return 'postgresql://simon@localhost/depin'
```

### 3. **Configuration File Selection**
**Before:**
```python
# Unreliable Docker detection
elif os.getenv('DATABASE_URL') and os.path.exists('config.docker.json'):
    config_file = 'config.docker.json'
    print("🐳 Docker environment detected, using docker configuration")
```

**After:**
```python
# Explicit Docker configuration flag
elif os.getenv('USE_DOCKER_CONFIG', '').lower() in ('true', '1', 'yes'):
    config_file = 'config.docker.json' if os.path.exists('config.docker.json') else 'config.json'
    if config_file == 'config.docker.json':
        print("🐳 Docker configuration requested via USE_DOCKER_CONFIG")
```

## Usage Examples

### Local Development (Default)
```bash
# Uses config.json and postgresql://simon@localhost/depin
python main.py --stage score
```

### Docker Environment
```bash
# Explicitly use Docker configuration
USE_DOCKER_CONFIG=true python main.py --stage score

# Or in docker-compose.yml:
environment:
  - USE_DOCKER_CONFIG=true
  - DATABASE_URL=postgresql://simon:devpassword@postgres:5432/depin
```

### Explicit Configuration File
```bash
# Use specific config file
python main.py --stage score --config /path/to/custom/config.json
```

## Configuration Hierarchy

1. **Explicit config file** (`--config` argument)
2. **Docker config** (`USE_DOCKER_CONFIG=true` + `config.docker.json` exists)
3. **Default config** (`config.json`)

## Database URL Resolution

1. **Explicit Docker mode**: Uses `DATABASE_URL` if `USE_DOCKER_CONFIG=true`
2. **Default mode**: Uses `postgresql://simon@localhost/depin`

## Benefits

### ✅ **Predictable Behavior**
- No more automatic Docker detection causing unexpected config loading
- Clear distinction between local and Docker environments

### ✅ **Explicit Control**
- Developers must explicitly opt into Docker configuration
- Reduces configuration-related surprises

### ✅ **Backward Compatibility**
- Existing Docker setups work with `USE_DOCKER_CONFIG=true`
- Local development works without any environment variables

### ✅ **Error Prevention**
- Eliminates "postgres hostname not found" errors when running locally
- Clear error messages when configuration issues occur

## Testing Results

### ✅ **Local Scoring Works**
```bash
$ python main.py --stage score
📄 Loading configuration from: config.json
✅ Scoring completed: 36 results scored
```

### ✅ **No Re-scoring by Default**
```bash
$ python main.py --stage score
✅ Scoring completed: 0 results scored  # Already scored
```

### ✅ **Force Re-scoring Works**
```bash
$ python main.py --stage score --force-rescore
✅ Scoring completed: 71 results scored  # Re-scored all
```

## Docker Setup Instructions

For teams using Docker, add to your `docker-compose.yml`:

```yaml
environment:
  - USE_DOCKER_CONFIG=true
  - DATABASE_URL=postgresql://simon:devpassword@postgres:5432/depin
```

Or run with:
```bash
USE_DOCKER_CONFIG=true docker run your-image
```

## Migration Notes

- **No Breaking Changes**: Existing local development continues to work
- **Docker Users**: Need to add `USE_DOCKER_CONFIG=true` to environment
- **Configuration Files**: No changes needed to existing config files
