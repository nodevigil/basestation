#!/usr/bin/env python3
"""
Test script for Celery queue functionality.
"""

import sys
import os
import time

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def test_queue_manager():
    """Test the queue manager functionality."""
    try:
        from utils.queue_manager import create_queue_manager
        from core.config import Config
        
        print("🧪 Testing Queue Manager...")
        
        # Create config and queue manager
        config = Config()
        queue_manager = create_queue_manager(config)
        
        print("✅ Queue manager created successfully")
        
        # Test basic functionality (without actually queuing tasks)
        print("📋 Queue manager methods available:")
        methods = [m for m in dir(queue_manager) if not m.startswith('_') and callable(getattr(queue_manager, m))]
        for method in methods:
            print(f"   • {method}")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("   Please install Celery and Redis: pip install celery redis")
        return False
    except Exception as e:
        print(f"❌ Error testing queue manager: {e}")
        return False

def test_task_imports():
    """Test that task modules can be imported."""
    try:
        print("🧪 Testing Task Imports...")
        
        # Test task imports
        task_modules = [
            'tasks.pipeline_tasks',
            'tasks.scan_tasks', 
            'tasks.process_tasks',
            'tasks.report_tasks'
        ]
        
        for module_name in task_modules:
            try:
                __import__(module_name)
                print(f"✅ {module_name} imported successfully")
            except ImportError as e:
                print(f"❌ Failed to import {module_name}: {e}")
                return False
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing task imports: {e}")
        return False

def test_celery_app():
    """Test Celery app configuration."""
    try:
        print("🧪 Testing Celery App Configuration...")
        
        from celery_app import app
        
        print("✅ Celery app imported successfully")
        print(f"   Broker URL: {app.conf.broker_url}")
        print(f"   Result Backend: {app.conf.result_backend}")
        print(f"   Task Serializer: {app.conf.task_serializer}")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("   Please install Celery: pip install celery")
        return False
    except Exception as e:
        print(f"❌ Error testing Celery app: {e}")
        return False

def test_redis_connection():
    """Test Redis connection."""
    try:
        print("🧪 Testing Redis Connection...")
        
        import redis
        r = redis.Redis(host='localhost', port=6379, decode_responses=True)
        
        # Test connection
        r.ping()
        print("✅ Redis connection successful")
        
        # Test basic operations
        r.set('test_key', 'test_value')
        value = r.get('test_key')
        r.delete('test_key')
        
        if value == 'test_value':
            print("✅ Redis operations working")
            return True
        else:
            print("❌ Redis operations failed")
            return False
        
    except ImportError:
        print("❌ Redis not installed: pip install redis")
        return False
    except redis.exceptions.ConnectionError:
        print("❌ Redis server not running")
        print("   Start Redis with: ./celery-manage.sh start-redis")
        return False
    except Exception as e:
        print(f"❌ Error testing Redis: {e}")
        return False

def main():
    """Run all tests."""
    print("🚀 DePIN Scanner - Queue Functionality Tests")
    print("=" * 50)
    
    tests = [
        ("Queue Manager", test_queue_manager),
        ("Task Imports", test_task_imports), 
        ("Celery App", test_celery_app),
        ("Redis Connection", test_redis_connection)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        results[test_name] = test_func()
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Results Summary:")
    
    passed = sum(results.values())
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {test_name}: {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Queue functionality is ready to use.")
        print("\nNext steps:")
        print("1. Start services: ./celery-manage.sh start-all")
        print("2. Queue a job: pgdn --stage scan --queue")
        print("3. Monitor: open http://localhost:5555")
    else:
        print("⚠️  Some tests failed. Please check the requirements:")
        print("1. Install dependencies: pip install celery redis")
        print("2. Start Redis: ./celery-manage.sh start-redis")
        print("3. Run tests again: python test_queue.py")
        
        sys.exit(1)

if __name__ == "__main__":
    main()
