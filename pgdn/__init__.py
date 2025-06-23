"""
PGDN - Agentic DePIN Infrastructure Scanner

A comprehensive infrastructure scanner for DePIN networks with agentic architecture
for reconnaissance, scanning, processing, and publishing security analysis results.

Main Entry Points:
- pgdn.pipeline: Full pipeline orchestration
- pgdn.scanner: Individual scanning operations  
- pgdn.reports: Report generation and publishing
- pgdn.cve: CVE database management
- pgdn.signatures: Protocol signature learning
- pgdn.queue: Background task management
"""

__version__ = "1.0.0"

# Import main public interfaces
from .application_core import ApplicationCore, load_config, setup_environment, initialize_application
from .pipeline import PipelineOrchestrator
from .scanner import Scanner
from .reports import ReportManager
from .cve import CVEManager
from .signatures import SignatureManager
from .queue import QueueManager
from .agents import AgentManager
from .parallel import ParallelOperations

__all__ = [
    'ApplicationCore',
    'load_config',
    'setup_environment', 
    'initialize_application',
    'PipelineOrchestrator',
    'Scanner', 
    'ReportManager',
    'CVEManager',
    'SignatureManager',
    'QueueManager',
    'AgentManager',
    'ParallelOperations'
]
