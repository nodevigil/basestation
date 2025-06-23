# PGDN Library Documentation

## Overview

PGDN provides a clean Python library API that allows you to integrate security scanning capabilities directly into your applications, scripts, and services.

## Installation

```bash
pip install pgdn
```

## Core Components

### Application Initialization

```python
from pgdn import initialize_application, load_config, setup_environment

# Complete initialization
config = initialize_application("config.json", log_level="INFO")

# Manual setup
config = load_config("config.json")
setup_environment(config)
```

### Pipeline Orchestration

The `PipelineOrchestrator` manages the complete security assessment workflow:

```python
from pgdn import PipelineOrchestrator

orchestrator = PipelineOrchestrator(config)

# Run complete pipeline
result = orchestrator.run_full_pipeline(recon_agents=['SuiReconAgent'])

# Run individual stages
recon_result = orchestrator.run_recon_stage()
scan_result = orchestrator.run_scan_stage(protocol_filter='sui')
process_result = orchestrator.run_process_stage()
score_result = orchestrator.run_scoring_stage(force_rescore=True)
```

#### Available Methods

- `run_full_pipeline(recon_agents=None)` - Execute complete security assessment
- `run_recon_stage(agent_names=None)` - Discovery phase
- `run_scan_stage(protocol_filter=None, debug=False)` - Security scanning
- `run_process_stage(agent_name=None)` - Result analysis
- `run_scoring_stage(agent_name=None, force_rescore=False)` - Risk assessment
- `run_publish_stage(agent_name, scan_id)` - Report publishing
- `run_signature_stage(agent_name=None)` - Protocol signature learning
- `run_discovery_stage(agent_name=None, host=None)` - Infrastructure discovery

### Scanner Operations

Direct scanning capabilities for individual targets or bulk operations:

```python
from pgdn import Scanner

scanner = Scanner(config, protocol_filter='sui', debug=False)

# Single target scanning
result = scanner.scan_target("192.168.1.100")

# Database-driven scanning
result = scanner.scan_nodes_from_database()

# Parallel scanning
targets = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
result = scanner.scan_parallel_targets(targets, max_parallel=5)
```

#### Scanner Methods

- `scan_target(target)` - Scan individual IP/hostname
- `scan_nodes_from_database()` - Scan all discovered nodes
- `scan_parallel_targets(targets, max_parallel=5)` - Concurrent scanning
- `save_scan_result(scan_result, target)` - Persist scan results

### Report Management

Generate and manage security reports:

```python
from pgdn import ReportManager

report_manager = ReportManager(config)

result = report_manager.generate_report(
    agent_name='ReportAgent',
    scan_id=123,
    report_format='json',
    auto_save=True,
    email_report=True,
    recipient_email='security@company.com'
)
```

### CVE Database Management

Manage vulnerability database updates:

```python
from pgdn import CVEManager

cve_manager = CVEManager()

# Update CVE database
result = cve_manager.update_database(force_update=False, days_back=7)

# Start automated scheduler
result = cve_manager.start_scheduler(update_time="02:00")

# Get database statistics
stats = cve_manager.get_statistics()
```

### Signature Management

Protocol signature learning and management:

```python
from pgdn import SignatureManager

signature_manager = SignatureManager()

# Learn from existing scans
result = signature_manager.learn_from_scans(
    protocol='sui',
    min_confidence=0.7,
    max_examples=1000
)

# Update signature flags
result = signature_manager.update_signature_flags(protocol_filter='sui')

# Get statistics
stats = signature_manager.show_statistics(protocol_filter='sui')
```

### Queue Management

Background task management and parallel operations:

```python
from pgdn import QueueManager

queue_manager = QueueManager(config)

# Queue pipeline operations
task_id = queue_manager.queue_full_pipeline(recon_agents=['SuiReconAgent'])

# Queue individual scans
scan_task = queue_manager.queue_target_scan('192.168.1.100')

# Parallel operations
parallel_tasks = queue_manager.queue_parallel_scans(targets, max_parallel=5)

# Task management
status = queue_manager.get_task_status(task_id)
results = queue_manager.wait_for_tasks([task_id], timeout=3600)
```

### Parallel Operations

Coordinate complex parallel workflows:

```python
from pgdn import ParallelOperations

parallel_ops = ParallelOperations(config)

# Parallel scanning with queue management
result = parallel_ops.run_parallel_scans(
    targets=['192.168.1.100', '192.168.1.101'],
    max_parallel=3,
    protocol_filter='sui',
    use_queue=True,
    wait_for_completion=True
)

# Parallel stage execution
stage_result = parallel_ops.run_parallel_stages(
    stages=['recon', 'scan'],
    stage_configs={'recon': {...}, 'scan': {...}},
    use_queue=True
)
```

## Return Values

All library functions return dictionaries with consistent structure:

```python
{
    "success": bool,        # Operation success status
    "error": str,          # Error message (if success=False)
    "timestamp": str,      # ISO format timestamp
    # ... additional operation-specific fields
}
```

## Error Handling

Library functions handle exceptions internally and return error information:

```python
result = scanner.scan_target("invalid-target")
if not result['success']:
    print(f"Scan failed: {result['error']}")
    # Handle error appropriately
else:
    print(f"Scan completed: {result}")
```

## Configuration

The library uses JSON configuration files:

```python
from pgdn import load_config

# Load from specific file
config = load_config("custom_config.json")

# Load with Docker configuration
config = load_config(use_docker_config=True)

# Override log level
config = load_config(log_level="DEBUG")
```

See [Configuration Documentation](configuration.md) for details.