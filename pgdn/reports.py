"""
Reports Module

Provides report generation and management functionality.
This module abstracts report logic from CLI concerns.
"""

from typing import Optional, Dict, Any
from datetime import datetime

from pgdn.core.config import Config


class ReportManager:
    """
    Manager for report generation and publishing.
    
    This class provides a clean Python API for generating reports
    and managing report workflows, independent of CLI concerns.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the report manager.
        
        Args:
            config: Configuration instance
        """
        self.config = config
        self._orchestrator = None
    
    @property
    def orchestrator(self):
        """Lazy-load the orchestrator."""
        if self._orchestrator is None:
            from pgdn.utils.pipeline import create_orchestrator
            self._orchestrator = create_orchestrator(self.config)
        return self._orchestrator
    
    def generate_report(self, 
                       agent_name: str = 'ReportAgent',
                       scan_id: Optional[int] = None,
                       input_file: Optional[str] = None,
                       output_file: Optional[str] = None,
                       report_format: str = 'json',
                       auto_save: bool = False,
                       email_report: bool = False,
                       recipient_email: Optional[str] = None,
                       force_report: bool = False,
                       org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a security analysis report.
        
        Args:
            agent_name: Agent name to use for report generation
            scan_id: Specific scan ID to generate report for
            input_file: Input file for report generation (JSON scan results)
            output_file: Output file for report results (JSON format)
            report_format: Report output format ('json' or 'summary')
            auto_save: Auto-save report with timestamp filename
            email_report: Generate email notification in report
            recipient_email: Recipient email address for notification
            force_report: Force generation even if scan already processed
            org_id: Optional organization ID to filter agentic jobs
            
        Returns:
            dict: Report generation results
        """
        try:
            # Configure report options
            report_options = {
                'input_file': input_file,
                'output_file': output_file,
                'format': report_format,
                'auto_save': auto_save,
                'email_report': email_report,
                'recipient_email': recipient_email,
                'scan_id': scan_id,
                'force_report': force_report
            }
            
            results = self.orchestrator.run_report_stage(agent_name, report_options, org_id=org_id)
            
            return {
                "success": True,
                "stage": "report",
                "results": results,
                "agent": agent_name,
                "scan_id": scan_id,
                "options": report_options,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "stage": "report",
                "error": f"Report generation failed: {str(e)}",
                "agent": agent_name,
                "scan_id": scan_id,
                "timestamp": datetime.now().isoformat()
            }
    
    def generate_summary_report(self, scan_id: Optional[int] = None, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a summary report with default options.
        
        Args:
            scan_id: Optional specific scan ID to generate report for
            org_id: Optional organization ID to filter agentic jobs
            
        Returns:
            dict: Report generation results
        """
        return self.generate_report(
            agent_name='ReportAgent',
            scan_id=scan_id,
            report_format='summary',
            auto_save=False,
            org_id=org_id
        )
    
    def generate_detailed_report(self, scan_id: Optional[int] = None, auto_save: bool = True) -> Dict[str, Any]:
        """
        Generate a detailed JSON report with auto-save.
        
        Args:
            scan_id: Optional specific scan ID to generate report for
            auto_save: Whether to auto-save with timestamp
            
        Returns:
            dict: Report generation results
        """
        return self.generate_report(
            agent_name='ReportAgent',
            scan_id=scan_id,
            report_format='json',
            auto_save=auto_save
        )
    
    def generate_email_report(self, 
                             scan_id: Optional[int] = None,
                             recipient_email: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a report with email notification.
        
        Args:
            scan_id: Optional specific scan ID to generate report for
            recipient_email: Recipient email address
            
        Returns:
            dict: Report generation results
        """
        return self.generate_report(
            agent_name='ReportAgent',
            scan_id=scan_id,
            report_format='json',
            email_report=True,
            recipient_email=recipient_email,
            auto_save=True
        )
