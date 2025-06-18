# DePIN Infrastructure Scanner - Tests

This folder contains all test files for the DePIN Infrastructure Scanner.

## 🧪 Test Files

### Scoring System Tests
- **[test_refactored_scoring.py](test_refactored_scoring.py)** - Tests for the refactored scoring agent with external library support

### CVE and Vulnerability Tests  
- **[test_cve_updater.py](test_cve_updater.py)** - Tests for CVE database integration

### Scanner Tests
- **[test_sui_scanner.py](test_sui_scanner.py)** - Tests for Sui-specific scanning functionality

### Metrics and Content Tests
- **[test_metrics_content.py](test_metrics_content.py)** - Tests for metrics gathering and content analysis

### Database Tests
- **[test_uuid_migration.py](test_uuid_migration.py)** - Tests for database migration functionality

## 🚀 Running Tests

### Run All Tests
```bash
# From project root
python -m pytest tests/

# With verbose output
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ --cov=.
```

### Run Specific Test Files
```bash
# Test scoring functionality
python -m pytest tests/test_refactored_scoring.py -v

# Test CVE functionality
python -m pytest tests/test_cve_updater.py -v

# Test scanner functionality  
python -m pytest tests/test_sui_scanner.py -v
```

### Run Individual Tests
```bash
# Run specific test functions
python -m pytest tests/test_refactored_scoring.py::test_default_trust_scorer -v

# Run with detailed output
python -m pytest tests/test_refactored_scoring.py::test_scoring_agent_fallback -v -s
```

## 📝 Test Standards

All tests in this folder should follow these standards:

- **Descriptive Names**: Test functions clearly describe what they test
- **Arrange-Act-Assert**: Clear structure with setup, execution, and verification
- **Isolated**: Tests don't depend on external state or other tests
- **Fast**: Tests run quickly and don't rely on external services
- **Documented**: Complex tests include docstrings explaining their purpose

## 🔧 Test Configuration

### Prerequisites
```bash
# Install test dependencies
pip install pytest pytest-cov

# Ensure project dependencies are installed
pip install -r requirements.txt
```

### Environment Setup
```bash
# Set up test environment
export PYTHONPATH=$PYTHONPATH:/path/to/depin
export TEST_ENV=true

# Run tests
python -m pytest tests/
```

## 🆕 Adding New Tests

When adding new functionality:

1. **Create test file**: `test_your_feature.py`
2. **Import required modules**: Include necessary imports
3. **Write descriptive tests**: Test both success and failure cases
4. **Test edge cases**: Include boundary conditions and error scenarios
5. **Update this README**: Add your test file to the list above

### Test Template
```python
#!/usr/bin/env python3
"""
Test module for YourFeature functionality.
"""

import pytest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from your_module import YourClass


class TestYourFeature:
    """Test cases for YourFeature functionality."""
    
    def test_basic_functionality(self):
        """Test basic functionality works correctly."""
        # Arrange
        feature = YourClass()
        
        # Act
        result = feature.your_method()
        
        # Assert
        assert result == expected_value
    
    def test_error_handling(self):
        """Test error handling works correctly."""
        # Arrange
        feature = YourClass()
        
        # Act & Assert
        with pytest.raises(ExpectedError):
            feature.your_method_that_should_fail()
```

## 📊 Test Coverage

To generate test coverage reports:

```bash
# Generate coverage report
python -m pytest tests/ --cov=. --cov-report=html

# View coverage report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

## 🐛 Debugging Tests

### Common Issues
- **Import Errors**: Ensure PYTHONPATH includes project root
- **Configuration Issues**: Check test environment variables
- **Database Connections**: Use test database or mock connections
- **External Dependencies**: Mock external API calls

### Debug Commands
```bash
# Run tests with debug output
python -m pytest tests/ -v -s --tb=short

# Run single test with pdb
python -m pytest tests/test_your_file.py::test_function --pdb

# Capture print statements
python -m pytest tests/ -v -s --capture=no
```

---

*Write tests first, code second! 🧪*
