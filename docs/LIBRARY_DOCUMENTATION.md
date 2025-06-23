# PGDN Library Documentation

## Overview

The PGDN (Agentic DePIN Infrastructure Scanner) has been refactored into a clean, reusable Python library with a thin CLI wrapper. This allows the core functionality to be imported and used programmatically from other Python code, APIs, test suites, or custom applications.

## Library Architecture

### Core Module Structure

```
pgdn/
├── __init__.py              # Main library entry point
├── core.py                  # Application initialization and configuration
├── pipeline.py              # Pipeline orchestration
├── scanner.py               # Individual and bulk scanning operations
├── reports.py               # Report generation and management
├── cve.py                   # CVE database management
├── signatures.py            # Protocol signature learning
├── queue.py                 # Background task management
├── agents.py                # Agent registry and management
└── parallel.py              # Parallel operations coordination
```

## Main Entry Points

### 1. Core Application (`pgdn.core`)

```python
from pgdn import ApplicationCore, load_config, setup_environment, initialize_application

# Basic setup
config = load_config("config.json")
setup_environment(config)

# Or complete initialization in one call
config = initialize_application(config_file="config.json", log_level="INFO")
```

**Classes:**
- `ApplicationCore`: Main application manager
- Functions: `load_config()`, `setup_environment()`, `initialize_application()`

### 2. Pipeline Orchestration (`pgdn.pipeline`)

```python
from pgdn import PipelineOrchestrator

orchestrator = PipelineOrchestrator(config)

# Run full pipeline
result = orchestrator.run_full_pipeline(recon_agents=['SuiReconAgent'])

# Run individual stages
recon_result = orchestrator.run_recon_stage()
scan_result = orchestrator.run_scan_stage(protocol_filter='sui')
process_result = orchestrator.run_process_stage()
score_result = orchestrator.run_scoring_stage(force_rescore=True)
publish_result = orchestrator.run_publish_stage('PublishLedgerAgent', scan_id=123)
```

**Main Methods:**
- `run_full_pipeline(recon_agents=None)`
- `run_recon_stage(agent_names=None)`
- `run_scan_stage(protocol_filter=None, debug=False)`
- `run_process_stage(agent_name=None)`
- `run_scoring_stage(agent_name=None, force_rescore=False)`
- `run_publish_stage(agent_name, scan_id)`
- `run_signature_stage(agent_name=None)`
- `run_discovery_stage(agent_name=None, host=None)`

### 3. Scanner Operations (`pgdn.scanner`)

```python
from pgdn import Scanner

scanner = Scanner(config, protocol_filter='sui', debug=False)

# Scan specific target
result = scanner.scan_target("139.84.148.36")

# Scan nodes from database
result = scanner.scan_nodes_from_database()

# Parallel scanning
result = scanner.scan_parallel_targets(["ip1", "ip2"], max_parallel=5)

# Load targets from file
targets = load_targets_from_file("targets.txt")
```

**Main Methods:**
- `scan_target(target)`
- `scan_nodes_from_database()`
- `scan_parallel_targets(targets, max_parallel=5)`
- `save_scan_result(scan_result, target)`

### 4. Report Management (`pgdn.reports`)

```python
from pgdn import ReportManager

report_manager = ReportManager(config)

result = report_manager.generate_report(
    agent_name='ReportAgent',
    scan_id=123,
    report_format='json',
    auto_save=True,
    email_report=True,
    recipient_email='admin@example.com'
)
```

**Main Methods:**
- `generate_report(agent_name, scan_id=None, input_file=None, output_file=None, report_format='json', auto_save=False, email_report=False, recipient_email=None, force_report=False)`

### 5. CVE Management (`pgdn.cve`)

```python
from pgdn import CVEManager

cve_manager = CVEManager()

# Update CVE database
result = cve_manager.update_database(
    force_update=False,
    initial_populate=False,
    days_back=7
)

# Start CVE scheduler
result = cve_manager.start_scheduler(update_time="02:00")

# Get statistics
stats = cve_manager.get_statistics()
```

**Main Methods:**
- `update_database(force_update=False, initial_populate=False, days_back=7)`
- `start_scheduler(update_time="02:00")`
- `get_statistics()`

### 6. Signature Management (`pgdn.signatures`)

```python
from pgdn import SignatureManager

signature_manager = SignatureManager()

# Learn signatures from existing scans
result = signature_manager.learn_from_scans(
    protocol='sui',
    min_confidence=0.7,
    max_examples=1000
)

# Update signature flags
result = signature_manager.update_signature_flags(protocol_filter='sui')

# Mark signature as created
result = signature_manager.mark_signature_created(scan_id=123)

# Show statistics
stats = signature_manager.show_statistics(protocol_filter='sui')
```

**Main Methods:**
- `learn_from_scans(protocol, min_confidence=0.7, max_examples=1000)`
- `update_signature_flags(protocol_filter=None)`
- `mark_signature_created(scan_id)`
- `show_statistics(protocol_filter=None)`

### 7. Queue Management (`pgdn.queue`)

```python
from pgdn import QueueManager

queue_manager = QueueManager(config)

# Queue operations
pipeline_result = queue_manager.queue_full_pipeline(recon_agents=['SuiReconAgent'])
stage_result = queue_manager.queue_single_stage('scan', protocol_filter='sui')
scan_result = queue_manager.queue_target_scan('139.84.148.36')

# Parallel operations
parallel_scans = queue_manager.queue_parallel_scans(targets, max_parallel=5)
parallel_stages = queue_manager.queue_parallel_stages(stages, stage_configs)

# Task management
status = queue_manager.get_task_status(task_id)
cancelled = queue_manager.cancel_task(task_id)
results = queue_manager.wait_for_tasks(task_ids, timeout=3600)
```

**Main Methods:**
- `queue_full_pipeline(recon_agents=None)`
- `queue_single_stage(stage, agent_name=None, ...)`
- `queue_target_scan(target, debug=False)`
- `queue_parallel_scans(targets, max_parallel, protocol_filter=None, debug=False)`
- `queue_parallel_stages(stages, stage_configs)`
- `get_task_status(task_id)`
- `cancel_task(task_id)`
- `wait_for_tasks(task_ids, timeout=None)`

### 8. Agent Management (`pgdn.agents`)

```python
from pgdn import AgentManager

agent_manager = AgentManager()

# List all available agents
agents = agent_manager.list_all_agents()
```

**Main Methods:**
- `list_all_agents()`

### 9. Parallel Operations (`pgdn.parallel`)

```python
from pgdn import ParallelOperations

parallel_ops = ParallelOperations(config)

# Parallel scans
scan_result = parallel_ops.run_parallel_scans(
    targets=['ip1', 'ip2', 'ip3'],
    max_parallel=3,
    protocol_filter='sui',
    use_queue=True,
    wait_for_completion=True
)

# Parallel stages
stage_result = parallel_ops.run_parallel_stages(
    stages=['recon', 'scan'],
    stage_configs={'recon': {...}, 'scan': {...}},
    use_queue=True
)

# Coordinated parallel operations
result = parallel_ops.coordinate_parallel_operation(
    targets=['ip1', 'ip2'],
    max_parallel=2,
    use_queue=True
)
```

**Main Methods:**
- `run_parallel_scans(targets, max_parallel=5, protocol_filter=None, debug=False, use_queue=False, wait_for_completion=False)`
- `run_parallel_stages(stages, stage_configs, use_queue=True, wait_for_completion=False)`
- `coordinate_parallel_operation(...)`

## Return Value Format

All library functions return dictionaries with a consistent structure:

```python
{
    "success": bool,              # True if operation succeeded
    "error": str,                 # Error message if success=False
    "timestamp": str,             # ISO format timestamp
    # ... operation-specific fields
}
```

## Error Handling

All library functions handle exceptions internally and return error information in the result dictionary. They do not raise exceptions for operational failures, only for programming errors (invalid arguments, etc.).

```python
result = scanner.scan_target("invalid-target")
if not result['success']:
    print(f"Scan failed: {result['error']}")
    # Handle error appropriately
```

## Configuration

The library uses the same configuration system as the CLI:

```python
from pgdn import load_config

# Load from specific file
config = load_config("custom_config.json")

# Load with Docker configuration preference
config = load_config(use_docker_config=True)

# Override log level
config = load_config(log_level="DEBUG")
```

## CLI Integration

The CLI remains fully functional and acts as a thin wrapper around the library:

```bash
# These CLI commands now use the library internally:
pgdn                                    # Uses PipelineOrchestrator.run_full_pipeline()
pgdn --stage scan --protocol sui       # Uses Scanner.scan_nodes_from_database()
pgdn --scan-target 139.84.148.36       # Uses Scanner.scan_target()
pgdn --stage report --scan-id 123      # Uses ReportManager.generate_report()
```

## Testing and Development

The library can now be easily tested and integrated:

```python
# Unit testing
import unittest
from pgdn import Scanner, load_config

class TestScanner(unittest.TestCase):
    def setUp(self):
        self.config = load_config("test_config.json")
        self.scanner = Scanner(self.config)
    
    def test_scan_target(self):
        result = self.scanner.scan_target("127.0.0.1")
        self.assertIn('success', result)

# Integration with other applications
from pgdn import PipelineOrchestrator, initialize_application

def my_application():
    config = initialize_application("my_config.json")
    orchestrator = PipelineOrchestrator(config)
    return orchestrator.run_full_pipeline()
```

## Migration from CLI

If you were previously calling the CLI programmatically, you can now use the library directly:

```python
# Old way (calling CLI subprocess)
import subprocess
result = subprocess.run(['pgdn', '--stage', 'scan'], capture_output=True)

# New way (using library)
from pgdn import load_config, Scanner, setup_environment
config = load_config()
setup_environment(config)
scanner = Scanner(config)
result = scanner.scan_nodes_from_database()
```

## Benefits of the Refactored Architecture

1. **Reusability**: Core functionality can be imported and used in any Python application
2. **Testability**: Individual components can be unit tested in isolation
3. **Flexibility**: Operations can be customized and combined programmatically
4. **Performance**: No subprocess overhead for internal operations
5. **Integration**: Easy to integrate with web APIs, schedulers, or other services
6. **Maintenance**: Clear separation between business logic and CLI concerns
7. **Backwards Compatibility**: CLI interface remains unchanged for existing users
