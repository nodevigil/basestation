# PGDN Library - Python API Documentation

The PGDN (Agentic DePIN Infrastructure Scanner) library provides a comprehensive Python API for programmatic access to all scanning, reporting, and infrastructure management functionality. This allows you to integrate DePIN scanning capabilities into your own applications, APIs, test suites, and automation workflows.

## Installation

There are several ways to install and use the PGDN library in your projects:

### Method 1: Development Installation (Editable)
If you're developing or modifying the PGDN library:

```bash
# Clone the repository
git clone <repository-url>
cd depin

# Install in development mode (changes are immediately reflected)
pip install -e .
```

### Method 2: Direct Installation from Source
If you want to install a specific version:

```bash
# Clone and install
git clone <repository-url>
cd depin
pip install .

# Or install directly from Git
pip install git+<repository-url>
```

### Method 3: Local Package Installation
If you have the source code locally:

```bash
# From the directory containing setup.py
pip install /path/to/depin

# Or using a wheel file
pip install dist/pgdn-1.0.0-py3-none-any.whl
```

### Method 4: Requirements File
Add to your project's `requirements.txt`:

```txt
# From Git repository
git+<repository-url>

# Or from local path (for development)
-e /path/to/depin

# Or from PyPI (when published)
pgdn>=1.0.0
```

### Method 5: Poetry (if using Poetry for dependency management)
Add to your `pyproject.toml`:

```toml
[tool.poetry.dependencies]
pgdn = {git = "<repository-url>"}

# Or for local development
pgdn = {path = "/path/to/depin", develop = true}
```

### Method 6: Docker Integration
If you're using Docker, add to your `Dockerfile`:

```dockerfile
# Copy and install PGDN library
COPY depin/ /app/depin/
RUN pip install /app/depin/

# Or install from Git
RUN pip install git+<repository-url>
```

## Quick Start

### Option 1: Using the Quick Installer
```bash
# Download and run the installer
python install.py --method local --source /path/to/pgdn

# Or for development (editable install)
python install.py --method local --source /path/to/pgdn --dev
```

### Option 2: Manual Installation
```python
from pgdn import PipelineOrchestrator, Scanner, ReportManager, CVEManager

# Initialize PGDN (loads config, sets up environment)
import pgdn
config = pgdn.initialize_application(config_file='config.json')

# Run a full pipeline
orchestrator = PipelineOrchestrator(config)
result = orchestrator.run_full_pipeline()

if result['success']:
    print(f"Pipeline completed! Execution ID: {result['execution_id']}")
else:
    print(f"Pipeline failed: {result['error']}")
```

## Core Components

### 1. PipelineOrchestrator

Orchestrates the complete four-stage DePIN scanning pipeline.

```python
from pgdn import PipelineOrchestrator
from core.config import Config

config = Config()
orchestrator = PipelineOrchestrator(config)

# Run full pipeline
result = orchestrator.run_full_pipeline(recon_agents=['SuiReconAgent'])

# Run individual stages
recon_result = orchestrator.run_recon_stage(['SuiReconAgent'])
process_result = orchestrator.run_process_stage()
score_result = orchestrator.run_scoring_stage(force_rescore=True)
publish_result = orchestrator.run_publish_stage('PublishLedgerAgent', scan_id=123)
signature_result = orchestrator.run_signature_stage()
discovery_result = orchestrator.run_discovery_stage(host='192.168.1.1')
```

### 2. Scanner

Handles direct target scanning and bulk scanning operations.

```python
from pgdn import Scanner
from core.config import Config

config = Config()
scanner = Scanner(config, protocol_filter='sui', debug=True)

# Scan a specific target
result = scanner.scan_target('139.84.148.36')
if result['success']:
    print(f"Scan completed for {result['target']}")
    scan_data = result['scan_result']
else:
    print(f"Scan failed: {result['error']}")

# Scan nodes from database
db_result = scanner.scan_nodes_from_database()

# Parallel target scanning
targets = ['10.0.0.1', '10.0.0.2', '10.0.0.3']
parallel_result = scanner.scan_parallel_targets(targets, max_parallel=3)
print(f"Completed {parallel_result['successful']}/{parallel_result['total']} scans")

# Save scan results
output_file = scanner.save_scan_result(scan_data, '139.84.148.36')
```

### 3. ReportManager

Generates and manages security analysis reports.

```python
from pgdn import ReportManager
from core.config import Config

config = Config()
report_manager = ReportManager(config)

# Generate a basic report
report_result = report_manager.generate_report(scan_id=123)

# Generate detailed report with auto-save
detailed_result = report_manager.generate_detailed_report(
    scan_id=123, 
    auto_save=True
)

# Generate email report
email_result = report_manager.generate_email_report(
    scan_id=123,
    recipient_email='admin@example.com'
)

# Generate summary report
summary_result = report_manager.generate_summary_report()
```

### 4. CVEManager

Manages CVE (Common Vulnerabilities and Exposures) database operations.

```python
from pgdn import CVEManager

cve_manager = CVEManager()

# Update CVE database
update_result = cve_manager.update_database(force_update=False)
if update_result['success']:
    stats = update_result['statistics']
    print(f"Total CVEs: {stats['total_cves']}")
    print(f"High Severity: {stats['high_severity_count']}")

# Initial population
initial_result = cve_manager.initial_populate()

# Force update
force_result = cve_manager.force_update()

# Get current statistics
stats_result = cve_manager.get_statistics()

# Start update scheduler
scheduler_result = cve_manager.start_scheduler(update_time='02:00')
```

### 5. SignatureManager

Manages protocol signature learning and updates.

```python
from pgdn import SignatureManager

signature_manager = SignatureManager()

# Learn signatures from existing scans
learn_result = signature_manager.learn_from_scans(
    protocol='sui',
    min_confidence=0.8,
    max_examples=500
)

# Update signature flags
flag_result = signature_manager.update_signature_flags(
    protocol_filter='sui'
)

# Mark specific scan as signature created
mark_result = signature_manager.mark_signature_created(scan_id=123)

# Get signature statistics
stats_result = signature_manager.get_signature_statistics()
```

### 6. QueueManager

Manages background task processing with Celery.

```python
from pgdn import QueueManager
from core.config import Config

config = Config()
queue_manager = QueueManager(config)

# Queue a full pipeline
pipeline_result = queue_manager.queue_full_pipeline(['SuiReconAgent'])
task_id = pipeline_result['task_id']

# Queue single stage
stage_result = queue_manager.queue_single_stage(
    stage='scan',
    protocol_filter='sui',
    debug=True
)

# Queue target scan
target_result = queue_manager.queue_target_scan('139.84.148.36')

# Queue parallel scans
parallel_result = queue_manager.queue_parallel_scans(
    targets=['10.0.0.1', '10.0.0.2'],
    max_parallel=2,
    protocol_filter='sui'
)

# Check task status
status_result = queue_manager.get_task_status(task_id)
print(f"Task status: {status_result['status']}")

# Wait for task completion
wait_result = queue_manager.wait_for_tasks(task_id, timeout=1800)

# Cancel task
cancel_result = queue_manager.cancel_task(task_id)
```

### 7. AgentManager

Manages agent registry and listing.

```python
from pgdn import AgentManager

agent_manager = AgentManager()

# List all available agents
agents_result = agent_manager.list_all_agents()
if agents_result['success']:
    agents = agents_result['agents']
    for category, agent_list in agents.items():
        print(f"{category}: {agent_list}")
```

## Utility Functions

### Load Targets from File

```python
from pgdn.scanner import load_targets_from_file

# Load targets from a file (one per line)
targets = load_targets_from_file('targets.txt')
print(f"Loaded {len(targets)} targets")
```

## Error Handling

All library functions return a standardized result dictionary with success status and error information:

```python
result = scanner.scan_target('invalid-host')
if result['success']:
    # Handle success
    scan_data = result['scan_result']
else:
    # Handle error
    print(f"Error: {result['error']}")
```

Result structure:
```python
{
    "success": bool,           # Operation success status
    "error": str,             # Error message (if success=False)
    "timestamp": str,         # ISO timestamp
    # Additional fields specific to each operation
}
```

## Integration Examples

### API Server Integration

```python
from flask import Flask, jsonify, request
from pgdn import Scanner, PipelineOrchestrator
from core.config import Config

app = Flask(__name__)
config = Config()

@app.route('/scan', methods=['POST'])
def scan_target():
    data = request.get_json()
    target = data.get('target')
    
    scanner = Scanner(config)
    result = scanner.scan_target(target)
    
    return jsonify(result)

@app.route('/pipeline', methods=['POST'])
def run_pipeline():
    orchestrator = PipelineOrchestrator(config)
    result = orchestrator.run_full_pipeline()
    
    return jsonify(result)
```

### Test Suite Integration

```python
import unittest
from pgdn import Scanner
from core.config import Config

class TestScanning(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.scanner = Scanner(self.config)
    
    def test_scan_target(self):
        result = self.scanner.scan_target('127.0.0.1')
        self.assertTrue(result['success'])
        self.assertIn('scan_result', result)
    
    def test_parallel_scanning(self):
        targets = ['127.0.0.1', '127.0.0.2']
        result = self.scanner.scan_parallel_targets(targets, max_parallel=2)
        self.assertTrue(result['success'])
        self.assertEqual(result['total'], 2)
```

### Automation Script Integration

```python
#!/usr/bin/env python3
"""
Automated daily scanning script
"""

import schedule
import time
from pgdn import PipelineOrchestrator, CVEManager
from core.config import Config

def daily_scan():
    """Run daily scanning routine."""
    config = Config()
    
    # Update CVE database
    cve_manager = CVEManager()
    cve_result = cve_manager.update_database()
    
    if cve_result['success']:
        print("CVE database updated successfully")
    
    # Run full pipeline
    orchestrator = PipelineOrchestrator(config)
    pipeline_result = orchestrator.run_full_pipeline()
    
    if pipeline_result['success']:
        print(f"Pipeline completed: {pipeline_result['execution_id']}")
    else:
        print(f"Pipeline failed: {pipeline_result['error']}")

# Schedule daily scan at 2 AM
schedule.every().day.at("02:00").do(daily_scan)

# Keep script running
while True:
    schedule.run_pending()
    time.sleep(60)
```

## Configuration

The library uses the same configuration system as the CLI. You can:

1. Use default configuration:
```python
from core.config import Config
config = Config()
```

2. Load from file:
```python
config_data = json.load(open('config.json'))
config = Config(config_overrides=config_data)
```

3. Override specific settings:
```python
config = Config()
config.scanning.max_concurrent_scans = 10
config.logging.level = 'DEBUG'
```

## Backwards Compatibility

The refactored CLI maintains 100% backwards compatibility. All existing CLI commands work exactly as before:

```bash
# These all work exactly as before
pgdn
pgdn --stage scan --protocol sui
pgdn --scan-target 139.84.148.36
pgdn --update-cves --initial-cves
pgdn --queue --stage scan
```

## Module Structure

```
pgdn/
├── __init__.py           # Main package exports
├── pipeline.py           # Pipeline orchestration
├── scanner.py           # Scanning operations
├── reports.py           # Report generation
├── cve.py              # CVE management
├── signatures.py       # Signature learning
├── queue.py            # Background processing
└── agents.py           # Agent management
```

Each module is focused on a specific domain and provides a clean, documented API for that functionality.
