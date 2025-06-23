#!/usr/bin/env python3
"""
Test script to verify Docker environment setup.
"""

import subprocess
import sys
import os


def test_python_imports():
    """Test that all required Python packages can be imported."""
    print("🐍 Testing Python imports...")
    
    try:
        import sqlalchemy
        import requests
        import psycopg2
        print("  ✅ Core packages imported successfully")
    except ImportError as e:
        print(f"  ❌ Import failed: {e}")
        return False
    
    return True


def test_system_tools():
    """Test that required system tools are available."""
    print("🔧 Testing system tools...")
    
    tools = ['nmap', 'whatweb', 'curl', 'psql']
    for tool in tools:
        try:
            result = subprocess.run(['which', tool], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"  ✅ {tool}: {result.stdout.strip()}")
            else:
                print(f"  ❌ {tool}: Not found")
                return False
        except Exception as e:
            print(f"  ❌ {tool}: Error checking - {e}")
            return False
    
    return True


def test_nmap_sudo():
    """Test that nmap can be run with sudo."""
    print("🛡️  Testing nmap with sudo...")
    
    try:
        # Test a quick scan of localhost
        result = subprocess.run(
            ['sudo', 'nmap', '-T5', '-p', '22', 'localhost'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            print("  ✅ sudo nmap works")
            return True
        else:
            print(f"  ❌ sudo nmap failed: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("  ❌ sudo nmap timed out")
        return False
    except Exception as e:
        print(f"  ❌ sudo nmap error: {e}")
        return False


def test_database_connection():
    """Test database connection."""
    print("🗄️  Testing database connection...")
    
    try:
        from pgdn.core.config import Config
        from pgdn.core.database import create_tables
        
        config = Config()
        print(f"  📡 Database URL: {config.database.url}")
        
        # Try to create tables (this tests the connection)
        create_tables(config.database)
        print("  ✅ Database connection successful")
        return True
        
    except Exception as e:
        print(f"  ❌ Database connection failed: {e}")
        return False


def test_file_permissions():
    """Test file permissions and volume mounts."""
    print("📁 Testing file permissions...")
    
    try:
        # Test write permissions
        test_file = '/app/test_write.tmp'
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        print("  ✅ Write permissions OK")
        
        # Test logs directory
        if os.path.exists('/app/logs'):
            print("  ✅ Logs directory mounted")
        else:
            print("  ⚠️  Logs directory not found")
        
        return True
        
    except Exception as e:
        print(f"  ❌ File permission test failed: {e}")
        return False


def main():
    """Run all tests."""
    print("🔍 Docker Environment Test Suite")
    print("=" * 40)
    
    tests = [
        test_python_imports,
        test_system_tools,
        test_file_permissions,
        test_nmap_sudo,
        test_database_connection,
    ]
    
    results = []
    for test in tests:
        try:
            results.append(test())
        except Exception as e:
            print(f"  ❌ Test {test.__name__} crashed: {e}")
            results.append(False)
        print()
    
    # Summary
    passed = sum(results)
    total = len(results)
    
    print("=" * 40)
    print(f"📊 Test Results: {passed}/{total} passed")
    
    if passed == total:
        print("🎉 All tests passed! Docker environment is ready.")
        sys.exit(0)
    else:
        print("❌ Some tests failed. Check the output above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
