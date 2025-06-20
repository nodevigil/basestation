"""
Celery application configuration for DePIN Infrastructure Scanner.
"""

import os
from celery import Celery

# Create Celery app with default Redis configuration
app = Celery('depin_scanner')

# Configure Celery with environment variables or defaults
app.conf.update(
    broker_url=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
    result_backend=os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0'),
    task_serializer=os.getenv('CELERY_TASK_SERIALIZER', 'json'),
    result_serializer=os.getenv('CELERY_RESULT_SERIALIZER', 'json'),
    accept_content=['json'],
    timezone=os.getenv('CELERY_TIMEZONE', 'UTC'),
    enable_utc=True,
    worker_prefetch_multiplier=int(os.getenv('CELERY_WORKER_PREFETCH_MULTIPLIER', '1')),
    task_acks_late=True,
    worker_max_tasks_per_child=int(os.getenv('CELERY_WORKER_MAX_TASKS_PER_CHILD', '1000')),
    
    # Task routing
    task_routes={
        'tasks.pipeline.*': {'queue': 'pipeline'},
        'tasks.scan.*': {'queue': 'scan'},
        'tasks.process.*': {'queue': 'process'},
        'tasks.report.*': {'queue': 'report'},
    },
    
    # Task execution options
    task_always_eager=False,
    task_eager_propagates=True,
    task_ignore_result=False,
    task_store_eager_result=True,
    
    # Worker configuration
    worker_hijack_root_logger=False,
    worker_log_color=False,
    
    # Monitoring
    worker_send_task_events=True,
    task_send_sent_event=True,
)

# Auto-discover tasks
app.autodiscover_tasks(['tasks'])

if __name__ == '__main__':
    app.start()
