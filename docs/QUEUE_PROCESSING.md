# DePIN Infrastructure Scanner - Queue Processing

This document describes the Celery-based queue processing system for background job execution.

## Overview

The queue processing system allows you to run DePIN scanner operations in the background using Celery and Redis. This is particularly useful for:

- Long-running scans that shouldn't block the terminal
- Batch processing of multiple targets
- Scheduled scanning operations
- Distributed processing across multiple workers

## Prerequisites

### Required Dependencies

```bash
pip install celery redis
```

### Redis Server

You need a running Redis server. You can either:

1. **Use Docker (Recommended):**
   ```bash
   ./celery-manage.sh start-redis
   ```

2. **Install Redis locally:**
   ```bash
   # macOS
   brew install redis
   brew services start redis
   
   # Ubuntu/Debian
   sudo apt-get install redis-server
   sudo systemctl start redis
   ```

## Quick Start

### 1. Start Services

Start all required services:
```bash
./celery-manage.sh start-all
```

This will start:
- Redis server (message broker)
- Celery worker (task processor)
- Flower (monitoring UI at http://localhost:5555)

### 2. Queue Jobs

Queue any scanner operation by adding the `--queue` flag:

```bash
# Queue full pipeline
pgdn --queue

# Queue specific stage
pgdn --stage scan --queue

# Queue target scan
pgdn --scan-target 192.168.1.100 --queue

# Queue with waiting for completion
pgdn --stage recon --queue --wait-for-completion
```

### 3. Monitor Jobs

Check task status:
```bash
# Check specific task
pgdn --task-id abc123-def456

# View all services status
./celery-manage.sh status

# Open Flower monitoring UI
open http://localhost:5555
```

## Usage Examples

### Basic Queue Operations

```bash
# Queue full pipeline for background processing
pgdn --queue

# Queue scan stage with protocol filter
pgdn --stage scan --protocol filecoin --queue

# Queue target scan with debug logging
pgdn --scan-target 139.84.148.36 --debug --queue

# Queue report generation
pgdn --stage report --scan-id 123 --queue
```

### Task Management

```bash
# Check task status
pgdn --task-id 12345678-1234-1234-1234-123456789012

# Cancel a running task
pgdn --cancel-task 12345678-1234-1234-1234-123456789012

# Queue job and wait for completion
pgdn --stage scan --queue --wait-for-completion
```

### Service Management

```bash
# Start all services
./celery-manage.sh start-all

# Check service status
./celery-manage.sh status

# View logs
./celery-manage.sh logs

# Stop all services
./celery-manage.sh stop-all
```

## Configuration

### Environment Variables

Configure Celery using environment variables:

```bash
# Redis connection
export CELERY_BROKER_URL="redis://localhost:6379/0"
export CELERY_RESULT_BACKEND="redis://localhost:6379/0"

# Worker settings
export CELERY_WORKER_PREFETCH_MULTIPLIER=1
export CELERY_WORKER_MAX_TASKS_PER_CHILD=1000

# Task settings
export CELERY_TASK_ACKS_LATE=true
export CELERY_TIMEZONE=UTC
```

### Configuration File

Add Celery configuration to your `config.json`:

```json
{
  "celery": {
    "broker_url": "redis://localhost:6379/0",
    "result_backend": "redis://localhost:6379/0",
    "worker_prefetch_multiplier": 1,
    "task_acks_late": true,
    "worker_max_tasks_per_child": 1000
  }
}
```

## Queue Architecture

### Task Queues

The system uses different queues for different types of tasks:

- **pipeline**: Full pipeline and orchestration tasks
- **scan**: Node scanning and vulnerability assessment
- **process**: Result processing and scoring
- **report**: Report generation and analysis

### Task Types

1. **Pipeline Tasks**
   - `run_full_pipeline_task`: Complete 4-stage pipeline
   - `run_single_stage_task`: Individual stage execution
   - `scan_target_task`: Direct target scanning

2. **Scan Tasks**
   - `batch_scan_nodes_task`: Batch node scanning
   - `scan_single_node_task`: Single node scanning

3. **Process Tasks**
   - `batch_process_results_task`: Batch result processing
   - `score_results_task`: Security scoring

4. **Report Tasks**
   - `generate_report_task`: Single report generation
   - `batch_generate_reports_task`: Multiple report generation

## Monitoring and Debugging

### Flower UI

Access the Flower monitoring interface at http://localhost:5555 to:
- View active tasks
- Monitor worker status
- See task execution history
- Inspect task details and results

### Task Status Checking

```bash
# Get detailed task status
pgdn --task-id <task-id>

# Example output:
# 📋 Task Status for abc123-def456:
#    Status: SUCCESS
#    Ready: ✅
#    Result: ✅ Completed successfully
#    Execution ID: exec_789
```

### Logs

View service logs:
```bash
# All service logs
./celery-manage.sh logs

# Individual container logs
docker logs depin-celery-worker
docker logs depin-redis
docker logs depin-celery-flower
```

## Advanced Usage

### Batch Processing

Queue multiple operations efficiently:

```bash
# Multiple target scans (would need custom scripting)
for ip in 192.168.1.{1..10}; do
  pgdn --scan-target $ip --queue
done

# Different protocols
pgdn --stage scan --protocol filecoin --queue
pgdn --stage scan --protocol sui --queue
```

### Custom Batch Sizes

Control batch processing parameters:

```bash
# Use larger batch sizes for bulk operations
pgdn --stage scan --queue --batch-size 20
```

### Integration with Scheduling

Combine with cron for scheduled operations:

```bash
# Add to crontab for daily scans
0 2 * * * /path/to/pgdn --stage scan --queue
```

## Troubleshooting

### Common Issues

1. **Redis Connection Error**
   ```bash
   # Check Redis status
   ./celery-manage.sh status
   
   # Restart Redis
   ./celery-manage.sh stop-redis
   ./celery-manage.sh start-redis
   ```

2. **Worker Not Processing Tasks**
   ```bash
   # Check worker logs
   docker logs depin-celery-worker
   
   # Restart worker
   ./celery-manage.sh stop-worker
   ./celery-manage.sh start-worker
   ```

3. **Task Stuck in Pending**
   - Check if worker is running
   - Verify Redis connectivity
   - Check task queue assignment

### Performance Tuning

1. **Worker Concurrency**
   - Adjust worker concurrency based on system resources
   - Modify `docker-compose.celery.yml` worker command

2. **Task Batching**
   - Use appropriate batch sizes for your workload
   - Monitor memory usage with large batches

3. **Queue Separation**
   - Use different queues for different task types
   - Scale workers per queue based on load

## Security Considerations

1. **Redis Security**
   - Use Redis AUTH if exposed to network
   - Configure Redis binding appropriately
   - Use SSL/TLS for production deployments

2. **Task Data**
   - Sensitive configuration data is passed to tasks
   - Ensure Redis instance is properly secured
   - Consider encrypting sensitive task parameters

## Production Deployment

For production deployments:

1. **Use dedicated Redis instance**
2. **Configure Redis persistence**
3. **Set up worker monitoring and auto-restart**
4. **Use proper logging configuration**
5. **Implement task result cleanup**
6. **Configure appropriate task timeouts**

## API Integration

The queue system can be integrated with external APIs:

```python
from utils.queue_manager import create_queue_manager
from core.config import Config

# Create queue manager
config = Config()
queue_manager = create_queue_manager(config)

# Queue operations programmatically
task_id = queue_manager.queue_target_scan("192.168.1.100")
status = queue_manager.get_task_status(task_id)
```
