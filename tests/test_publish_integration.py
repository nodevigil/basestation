"""
Simple integration tests for publish behavior.
These tests verify the actual behavior without complex mocking.
"""

import os
import sys
import subprocess
import tempfile
import inspect
from unittest.mock import patch

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def test_default_publish_behavior():
    """Test that default publish behavior only publishes to ledger."""
    print("🧪 Testing default publish behavior (ledger only)")
    
    # Set environment to use local config, not Docker
    env = os.environ.copy()
    env.pop('USE_DOCKER_CONFIG', None)  # Remove Docker config flag
    
    # Run the CLI command and capture output
    result = subprocess.run([
        'pgdn', '--stage', 'publish', '--scan-id', '999'  # Use non-existent scan
    ], capture_output=True, text=True, cwd='/Users/simon/Documents/Code/depin', env=env)
    
    output = result.stdout + result.stderr
    
    # Should mention ledger publishing
    assert 'Publishing to blockchain ledger' in output, f"Expected ledger publishing mention, got: {output}"
    
    # Should NOT mention report publishing
    assert 'Publishing scan 999 reports' not in output, f"Should not publish reports by default, got: {output}"
    assert 'Step 2: Publishing' not in output, f"Should not have step 2 (reports), got: {output}"
    
    # Should use PublishLedgerAgent directly
    assert 'Running publish agent: PublishLedgerAgent' in output, f"Should use PublishLedgerAgent directly, got: {output}"
    
    print("✅ Default behavior correctly publishes only to ledger")


def test_walrus_not_in_default_config():
    """Test that Walrus is not in default publishing destinations."""
    print("🧪 Testing Walrus not in default config")
    
    from pgdn.core.config import Config
    config = Config()
    
    # Check if PUBLISHING_DESTINATIONS exists and what it contains
    publishing_destinations = os.getenv('PUBLISHING_DESTINATIONS', '')
    
    # Walrus should not be in default destinations
    assert 'walrus' not in publishing_destinations.lower(), f"Walrus should not be in default config: {publishing_destinations}"
    
    print("✅ Walrus correctly excluded from default config")


def test_cli_help_includes_walrus_flag():
    """Test that CLI help includes the --publish-walrus flag."""
    print("🧪 Testing CLI help includes Walrus flag")
    
    result = subprocess.run(['pgdn', '--help'], capture_output=True, text=True, cwd='/Users/simon/Documents/Code/depin')
    
    help_output = result.stdout
    
    # Should include --publish-walrus flag
    assert '--publish-walrus' in help_output, f"CLI help should include --publish-walrus flag"
    assert 'Walrus storage' in help_output, f"CLI help should mention Walrus storage"
    
    print("✅ CLI help correctly includes Walrus flag")


def test_publisher_agent_only_does_ledger():
    """Test that PublisherAgent itself only does ledger publishing."""
    print("🧪 Testing PublisherAgent only does ledger")
    
    from agents.publish.publisher_agent import PublisherAgent
    from pgdn.core.config import Config
    import inspect
    
    config = Config()
    publisher = PublisherAgent(config)
    
    # Check the source code of the execute method
    source = inspect.getsource(publisher.execute)
    
    # Should contain ledger publishing
    assert 'PublishLedgerAgent' in source, "Should import and use PublishLedgerAgent"
    
    # Should NOT automatically try to publish reports
    assert 'PublishReportAgent' not in source, "Should not automatically import PublishReportAgent"
    assert 'Step 2: Publishing' not in source, "Should not have step 2 for reports"
    
    # Should mention that reports are not published by default
    assert 'Reports are NOT published by default' in source or 'ledger only' in source, "Should clarify reports not published by default"
    
    print("✅ PublisherAgent correctly only does ledger publishing")


def test_no_walrus_imports_in_core_agents():
    """Test that core publishing agents don't import Walrus by default."""
    print("🧪 Testing no Walrus imports in core agents")
    
    # Test PublisherAgent
    import agents.publish.publisher_agent as publisher_module
    publisher_source = inspect.getsource(publisher_module)
    # Check for actual imports, not comments
    import_lines = [line.strip() for line in publisher_source.split('\n') if line.strip().startswith('import') or line.strip().startswith('from')]
    walrus_imports = [line for line in import_lines if 'walrus' in line.lower()]
    assert len(walrus_imports) == 0, f"PublisherAgent should not import Walrus: {walrus_imports}"
    
    # Test PublishLedgerAgent  
    import agents.publish.publish_ledger_agent as ledger_module
    ledger_source = inspect.getsource(ledger_module)
    import_lines = [line.strip() for line in ledger_source.split('\n') if line.strip().startswith('import') or line.strip().startswith('from')]
    walrus_imports = [line for line in import_lines if 'walrus' in line.lower()]
    assert len(walrus_imports) == 0, f"PublishLedgerAgent should not import Walrus: {walrus_imports}"
    
    print("✅ Core agents correctly have no Walrus imports")


def run_all_tests():
    """Run all tests."""
    print("🚀 Running publish behavior tests...")
    
    try:
        test_default_publish_behavior()
        test_walrus_not_in_default_config()  
        test_cli_help_includes_walrus_flag()
        test_publisher_agent_only_does_ledger()
        test_no_walrus_imports_in_core_agents()
        
        print("\n🎉 All tests passed! Publish behavior is correct:")
        print("  ✅ Default publish only does ledger")
        print("  ✅ Walrus not in default config")
        print("  ✅ CLI has Walrus flag")
        print("  ✅ PublisherAgent only does ledger")
        print("  ✅ No automatic Walrus imports")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        return False
    
    return True


if __name__ == '__main__':
    import inspect
    success = run_all_tests()
    sys.exit(0 if success else 1)
