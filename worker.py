#!/usr/bin/env python3
"""
Celery worker starter script for DePIN Infrastructure Scanner.
"""

import os
import sys
from celery import Celery

# Add the project root to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

# Import the Celery app
from celery_app import app

if __name__ == '__main__':
    # Start the worker
    app.worker_main([
        'worker',
        '--loglevel=info',
        '--concurrency=4',  # Adjust based on your system
        '--queues=pipeline,scan,process,report',
        '--hostname=depin-worker@%h'
    ])
