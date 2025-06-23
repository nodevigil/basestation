"""
Publisher agent for outputting final results to various destinations.
"""

from typing import Optional, Dict, Any, List
from agents.base import PublishAgent
from pgdn.core.config import Config


class PublisherAgent(PublishAgent):
    """
    Publishing agent for outputting final results to various destinations.
    
    This agent takes processed results and publishes them to configured
    destinations such as databases, APIs, blockchains, or files.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize publisher agent.
        
        Args:
            config: Configuration instance
        """
        super().__init__(config, "PublisherAgent")
    
    def publish_results(self, processed_results: List[Dict[str, Any]]) -> bool:
        """
        Publish final results to destination (legacy method).
        
        Args:
            processed_results: Processed scan results
            
        Returns:
            True if publishing succeeded, False otherwise
        """
        self.logger.info(f"📤 Publishing {len(processed_results)} processed results")
        
        # TODO: Implement legacy publishing logic
        # This will be implemented in the next step
        
        return True
    
    def execute(self, processed_results: Optional[List[Dict[str, Any]]] = None, scan_id: Optional[int] = None, *args, **kwargs) -> bool:
        """
        Execute result publishing for a specific scan or processed results.
        
        This acts as a proxy agent that coordinates publishing to both ledger and reports.
        By default, only publishes to ledger. Reports require explicit configuration.
        
        Args:
            processed_results: Processed scan results (for legacy compatibility)
            scan_id: The ID of the scan to publish results for
            
        Returns:
            True if publishing succeeded, False otherwise
        """
        if scan_id is not None:
            self.logger.info(f"📤 Publishing results for scan ID: {scan_id} (ledger only)")
            
            try:
                # Import agents
                from agents.publish.publish_ledger_agent import PublishLedgerAgent
                
                # Initialize ledger agent
                ledger_agent = PublishLedgerAgent(self.config)
                
                # Step 1: Publish to ledger
                self.logger.info(f"📚 Publishing scan {scan_id} to blockchain ledger")
                ledger_result = ledger_agent.execute(scan_id=scan_id)
                
                if not ledger_result.get('success'):
                    self.logger.error(f"❌ Failed to publish scan {scan_id} to ledger: {ledger_result.get('message', 'Unknown error')}")
                    return False
                
                if ledger_result.get('already_published'):
                    self.logger.info(f"📚 Scan {scan_id} already published to ledger")
                else:
                    self.logger.info(f"✅ Successfully published scan {scan_id} to ledger: {ledger_result.get('transaction_hash', 'N/A')[:8]}...")
                
                # Note: Reports are NOT published by default
                # Use --publish-report or --publish-walrus CLI flags for report publishing
                
                return True
                
            except Exception as e:
                self.logger.error(f"❌ Unexpected error in publisher coordination: {e}")
                return False
                
        elif processed_results is not None:
            return self.publish_results(processed_results)
        else:
            raise ValueError("Either processed_results or scan_id must be provided")
    
    def get_detailed_results(self, scan_id: int) -> Dict[str, Any]:
        """
        Get detailed publishing results for a specific scan.
        
        This method provides detailed information about the publishing process
        that the main execute() method cannot return due to boolean constraint.
        
        Args:
            scan_id: The ID of the scan to get results for
            
        Returns:
            Dictionary containing detailed publication results
        """
        try:
            from agents.publish.publish_ledger_agent import PublishLedgerAgent
            
            ledger_agent = PublishLedgerAgent(self.config)
            ledger_result = ledger_agent.execute(scan_id=scan_id)
            
            report_published = False
            report_error = None
            
            try:
                from agents.publish.publish_report_agent import PublishReportAgent
                
                report_agent = PublishReportAgent(self.config)
                report_result = report_agent.execute(scan_id=scan_id)
                
                report_published = report_result.get('success', False)
                if not report_published:
                    report_error = report_result.get('error', 'Unknown report error')
                    
            except ImportError:
                report_error = "Report agent not available"
            except Exception as e:
                report_error = str(e)
            
            return {
                'success': ledger_result.get('success', False),
                'scan_id': scan_id,
                'ledger_published': ledger_result.get('success', False),
                'already_published': ledger_result.get('already_published', False),
                'report_published': report_published,
                'transaction_hash': ledger_result.get('transaction_hash'),
                'summary_hash': ledger_result.get('summary_hash'),
                'block_number': ledger_result.get('block_number'),
                'confirmed': ledger_result.get('confirmed', False),
                'report_error': report_error,
                'message': self._build_status_message(ledger_result, report_published, report_error)
            }
            
        except Exception as e:
            return {
                'success': False,
                'scan_id': scan_id,
                'error': str(e),
                'message': f'Publisher coordination failed: {e}'
            }
    
    def _build_status_message(self, ledger_result: Dict[str, Any], report_published: bool, report_error: Optional[str]) -> str:
        """Build a comprehensive status message."""
        if ledger_result.get('already_published'):
            if report_published:
                return "Scan already published to ledger, reports published successfully"
            elif report_error:
                return f"Scan already published to ledger, report publishing failed: {report_error}"
            else:
                return "Scan already published to ledger, report publishing skipped"
        elif ledger_result.get('success'):
            if report_published:
                return "Successfully published to both ledger and reports"
            elif report_error:
                return f"Published to ledger successfully, report publishing failed: {report_error}"
            else:
                return "Published to ledger successfully, report publishing skipped"
        else:
            return f"Failed to publish to ledger: {ledger_result.get('message', 'Unknown error')}"
    
    def run(self, scan_id: Optional[int] = None, *args, **kwargs) -> bool:
        """
        Execute result publishing for a specific scan ID.
        
        Args:
            scan_id: The ID of the scan to publish results for
            
        Returns:
            True if publishing succeeded, False otherwise
        """
        if scan_id is not None:
            return self.execute(scan_id=scan_id)
        else:
            raise ValueError("scan_id is required for this operation")
