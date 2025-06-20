#!/usr/bin/env python3
"""
Integration example demonstrating queue functionality.
"""

import sys
import os
import time
import json

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def demonstrate_queue_usage():
    """Demonstrate queue functionality with examples."""
    
    print("🚀 DePIN Scanner - Queue Usage Demonstration")
    print("=" * 60)
    
    print("\n📋 Prerequisites Check:")
    print("1. Redis server should be running")
    print("2. Celery worker should be started")
    print("3. Required packages should be installed")
    
    # Check if we can import required modules
    try:
        from utils.queue_manager import create_queue_manager
        from core.config import Config
        print("✅ Queue modules imported successfully")
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        print("\nTo fix this:")
        print("1. Install dependencies: pip install celery redis")
        print("2. Start services: ./celery-manage.sh start-all")
        return False
    
    # Create queue manager
    try:
        config = Config()
        print(f"✅ Configuration loaded")
        print(f"   Broker URL: {config.celery.broker_url}")
        print(f"   Result Backend: {config.celery.result_backend}")
        
        queue_manager = create_queue_manager(config)
        print("✅ Queue manager created")
        
    except Exception as e:
        print(f"❌ Failed to create queue manager: {e}")
        return False
    
    print("\n🎯 Queue Operation Examples:")
    print("=" * 60)
    
    # Example 1: Queue a target scan (simulation)
    print("\n1. Target Scan Queuing:")
    print("   Command: pgdn --scan-target 192.168.1.100 --queue")
    print("   This would queue a scan of the specified target")
    
    # Example 2: Queue a stage
    print("\n2. Stage Queuing:")
    print("   Command: pgdn --stage recon --queue")
    print("   This would queue the reconnaissance stage")
    
    # Example 3: Queue full pipeline
    print("\n3. Full Pipeline Queuing:")
    print("   Command: pgdn --queue")
    print("   This would queue the complete 4-stage pipeline")
    
    print("\n📊 Task Management:")
    print("=" * 60)
    
    # Show task management commands
    print("\n• Check task status:")
    print("  pgdn --task-id <task-id>")
    
    print("\n• Cancel a task:")
    print("  pgdn --cancel-task <task-id>")
    
    print("\n• Monitor via web UI:")  
    print("  open http://localhost:5555")
    
    print("\n🔧 Service Management:")
    print("=" * 60)
    
    # Service management examples
    services = [
        ("Start all services", "./celery-manage.sh start-all"),
        ("Check service status", "./celery-manage.sh status"),
        ("View logs", "./celery-manage.sh logs"),
        ("Stop all services", "./celery-manage.sh stop-all")
    ]
    
    for description, command in services:
        print(f"\n• {description}:")
        print(f"  {command}")
    
    print("\n💡 Tips for Queue Usage:")
    print("=" * 60)
    
    tips = [
        "Use --queue for long-running operations to free up your terminal",
        "Monitor tasks with Flower UI at http://localhost:5555",
        "Use --wait-for-completion to queue and wait for results",
        "Batch operations are more efficient than individual tasks",
        "Check task status regularly for long-running operations",
        "Cancel stuck tasks with --cancel-task if needed"
    ]
    
    for i, tip in enumerate(tips, 1):
        print(f"{i}. {tip}")
    
    print("\n🏗️ Architecture Overview:")
    print("=" * 60)
    
    print("""
    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
    │    CLI      │    │    Redis    │    │   Worker    │
    │ (pgdn cmd)  │───▶│  (Broker)   │───▶│ (Processor) │
    └─────────────┘    └─────────────┘    └─────────────┘
           │                  │                  │
           │                  │                  ▼
           │                  │           ┌─────────────┐
           │                  │           │   Results   │
           │                  │           │ (Database)  │
           │                  │           └─────────────┘
           │                  ▼
           │           ┌─────────────┐
           └──────────▶│   Flower    │
                       │(Monitoring) │
                       └─────────────┘
    """)
    
    print("\n✨ Ready to Start!")
    print("=" * 60)
    
    print("\nTo begin using queues:")
    print("1. ./celery-manage.sh start-all")
    print("2. pgdn --stage scan --queue")
    print("3. Check status at http://localhost:5555")
    
    return True

if __name__ == "__main__":
    demonstrate_queue_usage()
