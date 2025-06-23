# PGDN Python Library

A comprehensive Python library for DePIN (Decentralized Physical Infrastructure Networks) scanning, analysis, and reporting.

## 🚀 Quick Installation

### Method 1: Git Installation (Recommended)
```bash
pip install git+https://github.com/your-org/pgdn.git
```

### Method 2: Local Development
```bash
git clone https://github.com/your-org/pgdn.git
cd pgdn
pip install -e .
```

### Method 3: Quick Installer Script
```bash
# Download the repository and run:
python install.py --method local
```

## 📖 Quick Start

```python
import pgdn

# Initialize (loads config, sets up environment)
config = pgdn.initialize_application(config_file='config.json')

# Scan a target
scanner = pgdn.Scanner(config)
result = scanner.scan_target('192.168.1.100')

if result['success']:
    print(f"✅ Scan completed for {result['target']}")
else:
    print(f"❌ Scan failed: {result['error']}")

# Run full pipeline
orchestrator = pgdn.PipelineOrchestrator(config)
pipeline_result = orchestrator.run_full_pipeline()

print(f"Pipeline: {pipeline_result['success']}")
```

## 🏗️ Core Components

| Component | Purpose | Example Usage |
|-----------|---------|---------------|
| `PipelineOrchestrator` | Full pipeline management | `orchestrator.run_full_pipeline()` |
| `Scanner` | Target scanning | `scanner.scan_target('1.2.3.4')` |
| `ReportManager` | Report generation | `reports.generate_report(scan_id=123)` |
| `CVEManager` | CVE database management | `cve.update_database()` |
| `QueueManager` | Background processing | `queue.queue_full_pipeline()` |
| `ParallelOperations` | Parallel scanning | `parallel.run_parallel_scans(targets)` |

## 📋 Common Use Cases

### 1. API Integration
```python
from flask import Flask, jsonify, request
import pgdn

app = Flask(__name__)
config = pgdn.initialize_application()

@app.route('/scan', methods=['POST'])
def scan_endpoint():
    target = request.json['target']
    scanner = pgdn.Scanner(config)
    result = scanner.scan_target(target)
    return jsonify(result)
```

### 2. Automation Scripts
```python
import pgdn
import schedule

def daily_scan():
    config = pgdn.initialize_application()
    orchestrator = pgdn.PipelineOrchestrator(config)
    result = orchestrator.run_full_pipeline()
    
    if result['success']:
        print(f"Daily scan completed: {result['execution_id']}")

schedule.every().day.at("02:00").do(daily_scan)
```

### 3. Testing Integration
```python
import unittest
import pgdn

class TestInfrastructure(unittest.TestCase):
    def setUp(self):
        self.config = pgdn.initialize_application('test_config.json')
    
    def test_scan_localhost(self):
        scanner = pgdn.Scanner(self.config)
        result = scanner.scan_target('127.0.0.1')
        self.assertTrue(result['success'])
```

## 🔧 Configuration

Create a `config.json` file or use the default configuration:

```python
# Use default config
config = pgdn.load_config()

# Use custom config file
config = pgdn.load_config(config_file='my-config.json')

# Complete initialization with custom settings
config = pgdn.initialize_application(
    config_file='config.json',
    log_level='DEBUG'
)
```

## 📁 Project Structure

When you install PGDN, you get these importable modules:

```
pgdn/
├── core.py              # Application initialization
├── pipeline.py          # Pipeline orchestration  
├── scanner.py           # Scanning operations
├── reports.py           # Report generation
├── cve.py              # CVE management
├── signatures.py       # Signature learning
├── queue.py            # Background processing
├── agents.py           # Agent management
└── parallel.py         # Parallel operations
```

## 🎯 Return Values

All PGDN functions return consistent dictionaries:

```python
{
    "success": True,                    # Operation status
    "results": [...],                   # Operation results
    "execution_id": "abc123",          # Unique execution ID
    "timestamp": "2025-06-23T10:30:00Z" # ISO timestamp
    # ... additional operation-specific fields
}

# On error:
{
    "success": False,
    "error": "Error description",
    "timestamp": "2025-06-23T10:30:00Z"
}
```

## 🛠️ Advanced Usage

### Parallel Operations
```python
# Scan multiple targets
parallel_ops = pgdn.ParallelOperations(config)
result = parallel_ops.run_parallel_scans(
    targets=['1.2.3.4', '5.6.7.8'],
    max_parallel=3,
    protocol_filter='sui'
)
```

### Background Processing
```python
# Queue operations for background processing
queue_manager = pgdn.QueueManager(config)
task_result = queue_manager.queue_full_pipeline()
task_id = task_result['task_id']

# Check status later
status = queue_manager.get_task_status(task_id)
```

### Report Generation
```python
# Generate comprehensive reports
report_manager = pgdn.ReportManager(config)
report_result = report_manager.generate_report(
    scan_id=123,
    auto_save=True,
    email_report=True,
    recipient_email='admin@example.com'
)
```

## 📚 Documentation

- **[Complete API Reference](docs/LIBRARY_API.md)** - Detailed API documentation
- **[Installation Guide](docs/INSTALLATION_GUIDE.md)** - Comprehensive installation instructions
- **[Architecture Overview](docs/LIBRARY_ARCHITECTURE.md)** - Library design and structure
- **[Usage Examples](examples/library_usage.py)** - Practical examples

## 🔍 Examples

### Web API Example
```python
# app.py - Simple Flask API
from flask import Flask, request, jsonify
import pgdn

app = Flask(__name__)
config = pgdn.initialize_application()

@app.route('/health')
def health():
    return {"status": "healthy"}

@app.route('/scan', methods=['POST'])
def scan():
    target = request.json.get('target')
    scanner = pgdn.Scanner(config)
    result = scanner.scan_target(target)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
```

### Monitoring Script Example
```python
# monitor.py - Infrastructure monitoring
import pgdn
import time

config = pgdn.initialize_application()

def monitor_targets(targets):
    scanner = pgdn.Scanner(config)
    
    for target in targets:
        result = scanner.scan_target(target)
        
        if result['success']:
            print(f"✅ {target}: Online")
        else:
            print(f"❌ {target}: {result['error']}")
        
        time.sleep(1)  # Rate limiting

# Monitor key infrastructure
targets = ['192.168.1.100', '10.0.0.50', 'server.example.com']
monitor_targets(targets)
```

## 🐛 Troubleshooting

### Common Issues

**Import Error**: `ModuleNotFoundError: No module named 'pgdn'`
```bash
# Solution: Install the library
pip install git+https://github.com/your-org/pgdn.git
```

**Config Error**: `FileNotFoundError: Config file not found`
```python
# Solution: Use absolute path or copy config.example.json
config = pgdn.load_config(config_file='/full/path/to/config.json')
```

**Database Error**: `OperationalError: unable to open database file`
```bash
# Solution: Ensure database directory exists
mkdir -p logs
chmod 755 logs
```

## 🤝 Integration Patterns

### With FastAPI
```python
from fastapi import FastAPI
import pgdn

app = FastAPI()
config = pgdn.initialize_application()

@app.post("/scan")
async def scan_target(target: str):
    scanner = pgdn.Scanner(config)
    return scanner.scan_target(target)
```

### With Docker
```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN pip install git+https://github.com/your-org/pgdn.git
COPY . .
CMD ["python", "app.py"]
```

### With Jupyter Notebooks
```python
# notebook.ipynb
import pgdn

# Interactive scanning
config = pgdn.initialize_application()
scanner = pgdn.Scanner(config, debug=True)

# Scan and visualize results
result = scanner.scan_target('target.example.com')
# ... add visualization code
```

## 📊 Performance

The PGDN library is designed for:
- **Concurrent scanning**: Up to 10 parallel scans by default
- **Background processing**: Celery integration for long-running tasks
- **Memory efficiency**: Streaming results for large datasets
- **Rate limiting**: Built-in delays to avoid overwhelming targets

## 🔒 Security

- **Encrypted configs**: Support for encrypted configuration files
- **Rate limiting**: Built-in protection against aggressive scanning
- **Access control**: Integration with authentication systems
- **Audit logging**: Comprehensive operation logging

## 📈 Monitoring

Monitor your PGDN integration:

```python
import pgdn
import logging

# Enable detailed logging
logging.basicConfig(level=logging.INFO)

# Monitor operations
config = pgdn.initialize_application(log_level='INFO')
scanner = pgdn.Scanner(config, debug=True)

# Operations will now log detailed information
result = scanner.scan_target('192.168.1.100')
```

## 🚀 Next Steps

1. **Install the library**: Choose your preferred installation method
2. **Copy configuration**: Start with `config.example.json`
3. **Run examples**: Try the examples in `examples/library_usage.py`
4. **Read the docs**: Check out the detailed API documentation
5. **Integrate**: Start using PGDN in your applications

For more help, see the complete documentation in the `docs/` directory.
