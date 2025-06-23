# PGDN Library Installation Guide

This guide shows how to install and use the PGDN library in your own projects.

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git (for source installations)

## Installation Methods

### 1. Quick Start (Development Install)

For development or if you want to modify the library:

```bash
# Clone the repository
git clone <repository-url> pgdn-library
cd pgdn-library

# Install in editable mode (changes are immediately reflected)
pip install -e .

# Verify installation
python -c "import pgdn; print('✅ PGDN library installed successfully!')"
```

### 2. Production Install

For production use where you don't need to modify the source:

```bash
# Install from Git repository
pip install git+<repository-url>

# Or if you have the source locally
pip install /path/to/pgdn-library
```

### 3. Using in Your Project

#### Method A: Direct Installation

```bash
# In your project directory
pip install git+<repository-url>

# Or add to requirements.txt
echo "git+<repository-url>" >> requirements.txt
pip install -r requirements.txt
```

#### Method B: As a Git Submodule

```bash
# In your project root
git submodule add <repository-url> lib/pgdn
cd lib/pgdn
pip install -e .

# Or install from the submodule
pip install ./lib/pgdn
```

#### Method C: Copy Source Files

```bash
# Copy the pgdn package to your project
cp -r /path/to/pgdn-library/pgdn ./your-project/
cp -r /path/to/pgdn-library/core ./your-project/
cp -r /path/to/pgdn-library/utils ./your-project/
cp /path/to/pgdn-library/requirements.txt ./your-project/pgdn-requirements.txt

# Install dependencies
pip install -r pgdn-requirements.txt
```

## Project Integration Examples

### 1. Flask API Integration

Create a new Flask project that uses PGDN:

```bash
# Create new project
mkdir my-depin-api
cd my-depin-api

# Install Flask and PGDN
pip install flask
pip install git+<pgdn-repository-url>

# Create app.py
```

```python
# app.py
from flask import Flask, request, jsonify
import pgdn
from pgdn import PipelineOrchestrator, Scanner, ReportManager

app = Flask(__name__)

# Initialize PGDN
try:
    config = pgdn.initialize_application(config_file='config.json')
    print("✅ PGDN initialized successfully")
except Exception as e:
    print(f"❌ PGDN initialization failed: {e}")
    config = None

@app.route('/health')
def health():
    return {"status": "healthy", "pgdn_available": config is not None}

@app.route('/scan', methods=['POST'])
def scan_target():
    if not config:
        return jsonify({"error": "PGDN not initialized"}), 500
    
    data = request.get_json()
    target = data.get('target')
    protocol = data.get('protocol')
    
    if not target:
        return jsonify({"error": "Target required"}), 400
    
    try:
        scanner = pgdn.Scanner(config, protocol_filter=protocol)
        result = scanner.scan_target(target)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/pipeline', methods=['POST'])
def run_pipeline():
    if not config:
        return jsonify({"error": "PGDN not initialized"}), 500
    
    data = request.get_json() or {}
    recon_agents = data.get('recon_agents')
    
    try:
        orchestrator = pgdn.PipelineOrchestrator(config)
        result = orchestrator.run_full_pipeline(recon_agents=recon_agents)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
```

```bash
# Run the Flask app
python app.py
```

### 2. Automation Script

Create a monitoring script that uses PGDN:

```python
#!/usr/bin/env python3
# monitor.py

import time
import schedule
import logging
import pgdn
from pgdn import PipelineOrchestrator, CVEManager, ReportManager

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DePINMonitor:
    def __init__(self, config_file='config.json'):
        try:
            self.config = pgdn.initialize_application(config_file=config_file)
            logger.info("✅ PGDN monitor initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize PGDN: {e}")
            raise
    
    def daily_scan(self):
        """Run daily scanning routine."""
        logger.info("🚀 Starting daily scan...")
        
        # Update CVE database
        cve_manager = CVEManager()
        cve_result = cve_manager.update_database()
        
        if cve_result['success']:
            stats = cve_result['statistics']
            logger.info(f"📊 CVE database updated: {stats['total_cves']} total CVEs")
        else:
            logger.error(f"❌ CVE update failed: {cve_result['error']}")
        
        # Run full pipeline
        orchestrator = PipelineOrchestrator(self.config)
        pipeline_result = orchestrator.run_full_pipeline()
        
        if pipeline_result['success']:
            logger.info(f"✅ Pipeline completed: {pipeline_result['execution_id']}")
            
            # Generate report
            report_manager = ReportManager(self.config)
            report_result = report_manager.generate_report(auto_save=True)
            
            if report_result['success']:
                logger.info("📋 Report generated successfully")
            else:
                logger.error(f"❌ Report generation failed: {report_result['error']}")
        else:
            logger.error(f"❌ Pipeline failed: {pipeline_result['error']}")
    
    def hourly_check(self):
        """Run hourly health check."""
        logger.info("⏰ Running hourly health check...")
        # Add your health check logic here
    
    def start_monitoring(self):
        """Start the monitoring schedule."""
        # Schedule daily scan at 2 AM
        schedule.every().day.at("02:00").do(self.daily_scan)
        
        # Schedule hourly checks
        schedule.every().hour.do(self.hourly_check)
        
        logger.info("📅 Monitoring scheduled - daily scans at 2 AM, hourly checks")
        
        # Keep script running
        while True:
            schedule.run_pending()
            time.sleep(60)

if __name__ == "__main__":
    monitor = DePINMonitor()
    monitor.start_monitoring()
```

### 3. Docker Integration

Create a Dockerfile for your PGDN-based application:

```dockerfile
# Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install PGDN library
RUN pip install git+<pgdn-repository-url>

# Copy application code
COPY . .

# Expose port
EXPOSE 5000

# Run application
CMD ["python", "app.py"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  pgdn-api:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ./config.json:/app/config.json
      - ./logs:/app/logs
    environment:
      - PYTHONPATH=/app
    restart: unless-stopped
  
  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
    restart: unless-stopped
    
  pgdn-worker:
    build: .
    command: celery -A celery_app worker --loglevel=info
    volumes:
      - ./config.json:/app/config.json
      - ./logs:/app/logs
    depends_on:
      - redis
    environment:
      - PYTHONPATH=/app
    restart: unless-stopped
```

### 4. Testing Integration

Create tests for your PGDN integration:

```python
# test_pgdn_integration.py
import unittest
import tempfile
import json
import pgdn
from pgdn import Scanner, PipelineOrchestrator

class TestPGDNIntegration(unittest.TestCase):
    def setUp(self):
        # Create temporary config for testing
        self.test_config = {
            "database": {"url": "sqlite:///test.db"},
            "logging": {"level": "ERROR"},
            "scanning": {"timeout_seconds": 30}
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(self.test_config, f)
            self.config_file = f.name
        
        try:
            self.config = pgdn.load_config(config_file=self.config_file)
            pgdn.setup_environment(self.config)
        except Exception as e:
            self.skipTest(f"Could not initialize PGDN: {e}")
    
    def test_scanner_import(self):
        """Test that Scanner can be imported and instantiated."""
        scanner = Scanner(self.config)
        self.assertIsNotNone(scanner)
    
    def test_pipeline_orchestrator_import(self):
        """Test that PipelineOrchestrator can be imported and instantiated."""
        orchestrator = PipelineOrchestrator(self.config)
        self.assertIsNotNone(orchestrator)
    
    def test_scan_localhost(self):
        """Test scanning localhost (should always be available)."""
        scanner = Scanner(self.config)
        result = scanner.scan_target('127.0.0.1')
        
        # Should return a result dictionary
        self.assertIsInstance(result, dict)
        self.assertIn('success', result)
        self.assertIn('target', result)
        self.assertEqual(result['target'], '127.0.0.1')
    
    def tearDown(self):
        import os
        try:
            os.unlink(self.config_file)
        except:
            pass

if __name__ == '__main__':
    unittest.main()
```

## Configuration

When using PGDN in your project, you'll need to provide configuration. You can:

### 1. Use Default Configuration

```python
import pgdn

# Uses config.json in current directory
config = pgdn.load_config()
```

### 2. Specify Custom Configuration

```python
import pgdn

# Use custom config file
config = pgdn.load_config(config_file='my-config.json')

# Or initialize with custom config
config = pgdn.initialize_application(
    config_file='my-config.json',
    log_level='INFO'
)
```

### 3. Create Configuration Programmatically

```python
from core.config import Config

# Create config object
config = Config()

# Override specific settings
config.database.url = 'postgresql://user:pass@localhost/mydb'
config.scanning.max_concurrent_scans = 5
config.logging.level = 'DEBUG'
```

## Common Issues and Solutions

### Issue: Import Error
```
ImportError: No module named 'pgdn'
```

**Solution:**
```bash
# Make sure PGDN is installed
pip install git+<repository-url>

# Or if using local development
pip install -e /path/to/pgdn-library
```

### Issue: Configuration Not Found
```
FileNotFoundError: Config file not found
```

**Solution:**
```python
# Specify full path to config
config = pgdn.load_config(config_file='/full/path/to/config.json')

# Or copy config.example.json to config.json
cp config.example.json config.json
```

### Issue: Database Connection Error
```
sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) unable to open database file
```

**Solution:**
```python
# Ensure database directory exists and is writable
import os
os.makedirs('logs', exist_ok=True)

# Or use absolute path in config
{
    "database": {
        "url": "sqlite:////absolute/path/to/database.db"
    }
}
```

## Next Steps

After installing PGDN in your project:

1. **Copy configuration**: Copy `config.example.json` to `config.json` and customize
2. **Set up database**: Ensure database is accessible and properly configured
3. **Test installation**: Run the test examples above
4. **Read the API docs**: Check `docs/LIBRARY_API.md` for detailed API reference
5. **Start integrating**: Begin using PGDN components in your application

For more examples and detailed API reference, see:
- `docs/LIBRARY_API.md` - Complete API documentation
- `examples/library_usage.py` - Usage examples
- `docs/LIBRARY_ARCHITECTURE.md` - Architecture overview
