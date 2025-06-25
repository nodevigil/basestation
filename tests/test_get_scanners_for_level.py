#!/usr/bin/env python3
"""
Test script for the get_scanners_for_level function to verify it matches the prompt requirements.
"""

import sys
import os
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pgdn.scanning import get_scanners_for_level

def test_level_1_with_protocol():
    """Test Case 1: Level 1 with protocol 'sui'"""
    result = get_scanners_for_level(level=1, protocol="sui")
    expected = sorted(["generic", "headers", "ssl", "whatweb", "geo", "ports-lite"])
    assert sorted(result) == expected

def test_level_2_with_protocol():
    """Test Case 2: Level 2 with protocol 'sui'"""
    result = get_scanners_for_level(level=2, protocol="sui")
    expected = sorted(["generic", "headers", "ssl", "whatweb", "geo", "ports-lite", "nmap", "vulnerability", "sui"])
    assert sorted(result) == expected

def test_level_3_with_protocol():
    """Test Case 3: Level 3 with protocol 'filecoin'"""
    result = get_scanners_for_level(level=3, protocol="filecoin")
    expected = sorted(["generic", "headers", "ssl", "whatweb", "geo", "ports-lite", "nmap", "vulnerability", "dirbuster", "docker", "dnsdumpster", "filecoin"])
    assert sorted(result) == expected

def test_level_2_no_protocol():
    """Test Case 4: Level 2 with no protocol"""
    result = get_scanners_for_level(level=2, protocol=None)
    expected = sorted(["generic", "headers", "ssl", "whatweb", "geo", "ports-lite", "nmap", "vulnerability"])
    assert sorted(result) == expected

def test_invalid_level():
    """Test Case 5: Invalid level should raise ValueError"""
    with pytest.raises(ValueError):
        get_scanners_for_level(level=4)

def test_level_2_empty_protocol():
    """Test Case 6: Edge case - empty protocol string"""
    result = get_scanners_for_level(level=2, protocol="")
    expected = sorted(["generic", "headers", "ssl", "whatweb", "geo", "ports-lite", "nmap", "vulnerability"])
    assert sorted(result) == expected

def test_duplicate_handling():
    """Test Case 7: Duplicate handling - protocol same as existing scanner"""
    result = get_scanners_for_level(level=2, protocol="nmap")
    expected = sorted(["generic", "headers", "ssl", "whatweb", "geo", "ports-lite", "nmap", "vulnerability"])
    assert sorted(result) == expected
    assert len(result) == len(set(result))
