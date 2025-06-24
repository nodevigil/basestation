"""
Legacy scanner.py in pgdn module - now uses the new modular scanning system.
Maintained for backward compatibility.
"""

# Import the new modular scanning system
from pgdn.scanning.scan_orchestrator import Scanner, ScanOrchestrator

# Re-export for backward compatibility
__all__ = ['Scanner', 'ScanOrchestrator']
