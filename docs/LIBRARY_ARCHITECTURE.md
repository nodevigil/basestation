# PGDN Library Architecture Documentation

## Overview

The PGDN (Agentic DePIN Infrastructure Scanner) has been refactored into a clean, reusable Python library with a thin CLI wrapper. This separation allows the core functionality to be imported and used programmatically in other applications, APIs, tests, or automation scripts.

## Library Structure

```
pgdn/                           # Main library package
├── __init__.py                # Public API exports
├── core.py                    # Application initialization and configuration
├── pipeline.py               # Pipeline orchestration
├── scanner.py                # Scanning operations
├── reports.py                # Report generation and management
├── cve.py                    # CVE database management
├── signatures.py             # Protocol signature learning
├── queue.py                  # Background task management
├── agents.py                 # Agent registry and management
└── parallel.py               # Parallel operations coordination
```

## Core Principles

### 1. **Pure Python API**
- All library functions accept standard Python parameters
- No dependency on `sys.argv`, argument parsing, or CLI state
- Functions return structured dictionaries with consistent format

### 2. **CLI Independence**
- Business logic completely separated from CLI concerns
- CLI is a thin wrapper that calls library functions
- Library can be used without any CLI dependencies

### 3. **Consistent Return Format**
- All operations return dictionaries with `success` boolean
- Error information in `error` field when `success` is `False`
- Timestamps included for tracking
- Results in structured `results` or operation-specific fields

### 4. **Configuration Management**
- Centralized configuration loading in `core.py`
- Support for multiple config sources (file, environment, Docker)
- Configuration validation and error handling

## Public API Reference

### Core Application (`pgdn.core`)

```python
from pgdn import ApplicationCore, load_config, setup_environment, initialize_application

# Application initialization
app = ApplicationCore()
config = app.load_config(config_file='config.json', log_level='INFO')
app.setup_environment(config)

# Or use convenience functions
config = load_config(config_file='config.json')
setup_environment(config)

# Complete initialization
config = initialize_application(config_file='config.json', log_level='INFO')
```

### Pipeline Orchestration (`pgdn.pipeline`)

```python
from pgdn import PipelineOrchestrator

orchestrator = PipelineOrchestrator(config)

# Full pipeline
result = orchestrator.run_full_pipeline(recon_agents=['SuiReconAgent'])

# Individual stages
result = orchestrator.run_recon_stage(agent_names=['SuiReconAgent'])
result = orchestrator.run_process_stage(agent_name='ProcessingAgent')
result = orchestrator.run_scoring_stage(agent_name='ScoringAgent', force_rescore=True)
result = orchestrator.run_publish_stage('PublishLedgerAgent', scan_id=123)
result = orchestrator.run_signature_stage('ProtocolSignatureGeneratorAgent')
result = orchestrator.run_discovery_stage('DiscoveryAgent', host='192.168.1.1')
```

### Scanning Operations (`pgdn.scanner`)

```python
from pgdn import Scanner

scanner = Scanner(config, protocol_filter='sui', debug=False)

# Single target scan
result = scanner.scan_target('192.168.1.100')

# Scan from database
result = scanner.scan_nodes_from_database()

# Parallel scanning
result = scanner.scan_parallel_targets(['192.168.1.1', '192.168.1.2'], max_parallel=3)

# Save results
output_file = scanner.save_scan_result(scan_data, target)
```

### Report Management (`pgdn.reports`)

```python
from pgdn import ReportManager

report_manager = ReportManager(config)

# Generate reports
result = report_manager.generate_report(
    agent_name='ReportAgent',
    scan_id=123,
    report_format='json',
    auto_save=True,
    email_report=False
)

# Generate from file
result = report_manager.generate_from_file(
    input_file='scan_results.json',
    output_file='report.json'
)
```

### CVE Management (`pgdn.cve`)

```python
from pgdn import CVEManager

cve_manager = CVEManager()

# Update database
result = cve_manager.update_database(
    force_update=False,
    initial_populate=False,
    days_back=7
)

# Get statistics
result = cve_manager.get_statistics()

# Start scheduler
result = cve_manager.start_scheduler(update_time='02:00')
```

### Signature Learning (`pgdn.signatures`)

```python
from pgdn import SignatureManager

signature_manager = SignatureManager()

# Learn from scans
result = signature_manager.learn_from_scans(
    protocol='sui',
    min_confidence=0.7,
    max_examples=1000
)

# Update flags
result = signature_manager.update_signature_flags(protocol_filter='sui')

# Mark signature created
result = signature_manager.mark_signature_created(scan_id=123)

# Get statistics
result = signature_manager.get_signature_statistics(protocol_filter='sui')
```

### Queue Management (`pgdn.queue`)

```python
from pgdn import QueueManager

queue_manager = QueueManager(config)

# Queue operations
result = queue_manager.queue_full_pipeline(recon_agents=['SuiReconAgent'])
result = queue_manager.queue_single_stage('scan', protocol_filter='filecoin')
result = queue_manager.queue_target_scan('192.168.1.100', debug=True)

# Parallel operations
result = queue_manager.queue_parallel_scans(
    targets=['192.168.1.1', '192.168.1.2'], 
    max_parallel=3,
    protocol_filter='sui'
)

# Task management
status = queue_manager.get_task_status(task_id)
result = queue_manager.cancel_task(task_id)
results = queue_manager.wait_for_tasks([task_id1, task_id2], timeout=3600)
```

### Agent Management (`pgdn.agents`)

```python
from pgdn import AgentManager

agent_manager = AgentManager()

# List agents
result = agent_manager.list_all_agents()
# Returns: {"success": True, "agents": {"recon": [...], "scan": [...], ...}}
```

### Parallel Operations (`pgdn.parallel`)

```python
from pgdn import ParallelOperations

parallel_ops = ParallelOperations(config)

# Parallel scans
result = parallel_ops.run_parallel_scans(
    targets=['192.168.1.1', '192.168.1.2'],
    max_parallel=3,
    protocol_filter='sui',
    use_queue=True,
    wait_for_completion=True
)

# Parallel stages
result = parallel_ops.run_parallel_stages(
    stages=['recon', 'scan'],
    stage_configs={
        'recon': {'recon_agents': ['SuiReconAgent']},
        'scan': {'protocol_filter': 'sui'}
    },
    use_queue=True
)

# Load targets from file
targets = parallel_ops.load_targets_from_file('targets.txt')
```

## Usage Patterns

### 1. **Simple Script Usage**

```python
import pgdn

# Initialize
config = pgdn.initialize_application(config_file='my_config.json')

# Run pipeline
orchestrator = pgdn.PipelineOrchestrator(config)
result = orchestrator.run_full_pipeline()

if result['success']:
    print(f"Pipeline completed: {result['execution_id']}")
else:
    print(f"Pipeline failed: {result['error']}")
```

### 2. **API Integration**

```python
from flask import Flask, request, jsonify
import pgdn

app = Flask(__name__)
config = pgdn.load_config()

@app.route('/scan', methods=['POST'])
def scan_target():
    target = request.json['target']
    protocol = request.json.get('protocol')
    
    scanner = pgdn.Scanner(config, protocol_filter=protocol)
    result = scanner.scan_target(target)
    
    return jsonify(result)

@app.route('/pipeline', methods=['POST'])
def run_pipeline():
    recon_agents = request.json.get('recon_agents')
    
    orchestrator = pgdn.PipelineOrchestrator(config)
    result = orchestrator.run_full_pipeline(recon_agents)
    
    return jsonify(result)
```

### 3. **Test Integration**

```python
import unittest
import pgdn

class TestPGDN(unittest.TestCase):
    def setUp(self):
        self.config = pgdn.load_config(config_file='test_config.json')
        pgdn.setup_environment(self.config)
    
    def test_scanner(self):
        scanner = pgdn.Scanner(self.config)
        result = scanner.scan_target('127.0.0.1')
        self.assertTrue(result['success'])
    
    def test_pipeline(self):
        orchestrator = pgdn.PipelineOrchestrator(self.config)
        result = orchestrator.run_recon_stage(['MockReconAgent'])
        self.assertTrue(result['success'])
```

### 4. **Background Processing**

```python
import pgdn
from celery import Celery

# Setup
config = pgdn.load_config()
celery_app = Celery('pgdn_worker')

@celery_app.task
def async_scan(target, protocol=None):
    scanner = pgdn.Scanner(config, protocol_filter=protocol)
    return scanner.scan_target(target)

@celery_app.task  
def async_pipeline(recon_agents=None):
    orchestrator = pgdn.PipelineOrchestrator(config)
    return orchestrator.run_full_pipeline(recon_agents)

# Usage
async_scan.delay('192.168.1.100', 'sui')
async_pipeline.delay(['SuiReconAgent'])
```

## Error Handling

All library functions follow consistent error handling patterns:

```python
result = some_pgdn_function()

if result['success']:
    # Success case
    data = result['results']  # or other result fields
    execution_id = result.get('execution_id')
else:
    # Error case
    error_message = result['error']
    suggestion = result.get('suggestion')  # Sometimes provided
    print(f"Operation failed: {error_message}")
```

## Migration from CLI

### Before (CLI-dependent):
```bash
pgdn --stage scan --protocol sui --debug
```

### After (Library):
```python
import pgdn

config = pgdn.initialize_application()
scanner = pgdn.Scanner(config, protocol_filter='sui', debug=True)
result = scanner.scan_nodes_from_database()
```

## Configuration

The library supports multiple configuration sources:

1. **Explicit file path**: `load_config(config_file='custom.json')`
2. **Default file**: `load_config()` (uses `config.json`)
3. **Docker config**: `load_config(use_docker_config=True)` (uses `config.docker.json`)
4. **Environment override**: Set `USE_DOCKER_CONFIG=true`

## CLI Compatibility

The CLI remains fully functional and backward-compatible. It now serves as a thin wrapper around the library:

```python
# CLI command handlers call library functions
def run_single_stage_command(config, args):
    if args.stage == 'scan':
        scanner = Scanner(config, protocol_filter=args.protocol, debug=args.debug)
        return scanner.scan_nodes_from_database()
    # ... other stages
```

## Benefits of Refactoring

1. **Reusability**: Core functionality can be imported into any Python application
2. **Testability**: Pure functions easier to unit test and mock
3. **API Integration**: Can be embedded in web APIs, microservices, etc.
4. **Automation**: Easy to integrate into automated workflows and scripts
5. **Maintainability**: Clear separation of concerns between business logic and UI
6. **Extensibility**: New interfaces (web UI, REST API, etc.) can easily use the library

## Future Extensions

With this architecture, it's easy to add:

- **REST API**: Flask/FastAPI wrapper around the library
- **Web UI**: Frontend that calls the library via API
- **Jupyter Integration**: Notebook widgets using the library
- **Plugins**: Third-party extensions that import the library
- **Cloud Functions**: Serverless functions using library components
