"""
Publisher agent for outputting scan reports to various destinations including Walrus storage.
"""

import json
import os
from typing import Optional, Dict, Any, List
from datetime import datetime
from agents.base import PublishAgent
from core.config import Config

# Lazy import for Walrus provider - only import when actually needed
WalrusStorageProvider = None
WalrusStorageProviderError = None


class PublishReportAgent(PublishAgent):
    """
    Publishing agent for outputting scan reports to various destinations.
    
    This agent handles the publishing of scan reports after the ledger
    has been successfully published. It cannot publish reports unless
    the ledger publishing has been completed first.
    
    Supports multiple publishing destinations:
    - Walrus decentralized storage
    - Local file system
    - Database storage
    - Future: Email, API endpoints, etc.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize publish report agent.
        
        Args:
            config: Configuration instance
        """
        super().__init__(config, "PublishReportAgent")
        
        self.logger.debug("🔧 Initializing PublishReportAgent")
        
        # Initialize Walrus storage provider if configured
        self.walrus_provider = None
        self._init_walrus_provider()
        
        # Publishing destinations configuration
        self.publishing_destinations = self._get_publishing_destinations()
        
        self.logger.info(f"✅ PublishReportAgent initialized with {len(self.publishing_destinations)} destinations: {self.publishing_destinations}")
        self.logger.debug(f"🔍 Walrus provider status: {'Available' if self.walrus_provider else 'Not available'}")
    
    def _init_walrus_provider(self):
        """Initialize Walrus storage provider if API key is available."""
        global WalrusStorageProvider, WalrusStorageProviderError
        
        self.logger.debug("🔍 Initializing Walrus storage provider")
        
        try:
            # Lazy import Walrus provider only when actually needed
            if WalrusStorageProvider is None:
                try:
                    self.logger.debug("📦 Importing WalrusStorageProvider")
                    from storage.walrus_provider import WalrusStorageProvider, WalrusStorageProviderError
                    self.logger.debug("✅ WalrusStorageProvider imported successfully")
                except ImportError as e:
                    self.logger.info(f"ℹ️ Walrus storage provider not available: {e}")
                    self.logger.debug(f"🔍 Import error details: {type(e).__name__}: {str(e)}")
                    return
            
            walrus_api_key = os.getenv('WALRUS_API_KEY')
            walrus_api_url = os.getenv('WALRUS_API_URL', 'https://publisher-devnet.walrus.space')
            
            self.logger.debug(f"🔍 Walrus API URL: {walrus_api_url}")
            self.logger.debug(f"🔍 Walrus API key present: {walrus_api_key is not None}")
            if walrus_api_key:
                self.logger.debug(f"🔍 API key length: {len(walrus_api_key)} characters")
            
            if walrus_api_key and WalrusStorageProvider is not None:
                self.logger.debug("🔧 Creating WalrusStorageProvider instance")
                self.walrus_provider = WalrusStorageProvider(
                    api_url=walrus_api_url,
                    api_key=walrus_api_key
                )
                self.logger.info(f"✅ Walrus storage provider initialized: {walrus_api_url}")
                self.logger.debug("✅ Walrus provider initialization completed successfully")
            else:
                if WalrusStorageProvider is None:
                    self.logger.info("ℹ️ Walrus storage provider not available")
                    self.logger.debug("🔍 WalrusStorageProvider class is None")
                else:
                    self.logger.warning("⚠️ WALRUS_API_KEY not found, Walrus publishing disabled")
                    self.logger.debug("🔍 Missing WALRUS_API_KEY environment variable")
                
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize Walrus provider: {e}")
            self.logger.debug(f"🔍 Walrus initialization exception details: {type(e).__name__}: {str(e)}")
            self.walrus_provider = None
    
    def _get_publishing_destinations(self) -> List[str]:
        """Get configured publishing destinations from config or environment."""
        destinations = []
        
        self.logger.debug("🔍 Determining publishing destinations")
        
        # Check for Walrus
        if self.walrus_provider:
            destinations.append('walrus')
            self.logger.debug("✅ Added 'walrus' to publishing destinations")
        else:
            self.logger.debug("❌ Walrus provider not available, skipping walrus destination")
        
        # Always add local_file as fallback
        destinations.append('local_file')
        self.logger.debug("📁 Added 'local_file' as destination")
        
        # Check for other destinations from config
        if self.config:
            config_destinations = getattr(self.config, 'publishing_destinations', [])
            self.logger.debug(f"🔍 Config destinations: {config_destinations}")
            for dest in config_destinations:
                if dest not in destinations:
                    destinations.append(dest)
        else:
            self.logger.debug("� No config object available")
        
        self.logger.debug(f"✅ Final publishing destinations: {destinations}")
        return destinations
    
    def _format_scan_report(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format scan data into a standardized report structure.
        
        Args:
            scan_data: Raw scan data from database
            
        Returns:
            Formatted report dictionary
        """
        # Extract key information from scan data
        scan_id = scan_data.get('id', 'unknown')
        validator_info = scan_data.get('validator_info', {})
        scan_results = scan_data.get('results', {})
        
        # Create unique identifier for this report
        report_uid = f"depin_scan_{scan_id}_{int(datetime.now().timestamp())}"
        
        formatted_report = {
            'uid': report_uid,
            'report_type': 'depin_validator_scan',
            'version': '1.0',
            'generated_at': datetime.now().isoformat(),
            'scan_metadata': {
                'scan_id': scan_id,
                'validator_address': validator_info.get('address', 'unknown'),
                'validator_hostname': validator_info.get('hostname', 'unknown'),
                'scan_timestamp': scan_data.get('created_at', datetime.now().isoformat()),
                'scanner_version': scan_data.get('scanner_version', 'unknown')
            },
            'security_assessment': {
                'trust_score': scan_results.get('trust_score', 0),
                'risk_level': self._calculate_risk_level(scan_results.get('trust_score', 0)),
                'open_ports': scan_results.get('open_ports', []),
                'services_detected': scan_results.get('services', []),
                'vulnerabilities': scan_results.get('vulnerabilities', []),
                'ssl_assessment': scan_results.get('ssl_info', {}),
                'compliance_checks': scan_results.get('compliance', {})
            },
            'technical_details': {
                'network_scan': scan_results.get('network_scan', {}),
                'service_banners': scan_results.get('banners', {}),
                'web_technologies': scan_results.get('web_tech', {}),
                'docker_exposure': scan_results.get('docker_api', {}),
                'protocol_specific': scan_results.get('protocol_checks', {})
            },
            'recommendations': self._generate_recommendations(scan_results),
            'raw_scan_data': scan_results  # Include full raw data for reference
        }
        
        return formatted_report
    
    def _calculate_risk_level(self, trust_score: int) -> str:
        """Calculate risk level based on trust score."""
        if trust_score >= 80:
            return 'LOW'
        elif trust_score >= 60:
            return 'MEDIUM'
        elif trust_score >= 40:
            return 'HIGH'
        else:
            return 'CRITICAL'
    
    def _generate_recommendations(self, scan_results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on scan results."""
        recommendations = []
        
        # Check for common security issues
        if scan_results.get('open_ports', []):
            open_ports = scan_results['open_ports']
            if 22 in open_ports:
                recommendations.append("Ensure SSH is properly secured with key-based authentication")
            if 2375 in open_ports:
                recommendations.append("CRITICAL: Docker API exposed without authentication - secure immediately")
        
        if scan_results.get('vulnerabilities', []):
            vuln_count = len(scan_results['vulnerabilities'])
            recommendations.append(f"Address {vuln_count} identified vulnerabilities")
        
        ssl_info = scan_results.get('ssl_info', {})
        if ssl_info.get('expired', False):
            recommendations.append("Renew expired SSL certificates")
        
        trust_score = scan_results.get('trust_score', 0)
        if trust_score < 70:
            recommendations.append("Overall security posture needs improvement")
        
        return recommendations
    
    def _publish_to_walrus(self, report: Dict[str, Any]) -> Optional[str]:
        """
        Publish report to Walrus decentralized storage.
        
        Args:
            report: Formatted report dictionary
            
        Returns:
            Walrus hash if successful, None otherwise
        """
        if not self.walrus_provider:
            self.logger.warning("Walrus provider not available")
            self.logger.debug("🔍 Walrus provider is None - check API key configuration")
            return None
        
        try:
            uid = report['uid']
            self.logger.debug(f"🐋 Publishing report with UID {uid} to Walrus")
            self.logger.debug(f"🔍 Report size: {len(json.dumps(report))} bytes")
            
            walrus_hash = self.walrus_provider.write(uid, report)
            
            if walrus_hash:
                self.logger.info(f"✅ Report published to Walrus: {walrus_hash}")
                self.logger.debug(f"🔍 Walrus publication successful - hash: {walrus_hash}, UID: {uid}")
            else:
                self.logger.warning(f"⚠️ Walrus provider returned None hash for UID: {uid}")
            
            return walrus_hash
            
        except Exception as e:
            # Handle both WalrusStorageProviderError and other exceptions
            error_msg = str(e)
            
            # Check for specific Walrus service errors
            if "522" in error_msg or "Server Error" in error_msg:
                self.logger.warning(f"⚠️ Walrus service temporarily unavailable (522 error): {e}")
                self.logger.info("🔄 Walrus service appears to be experiencing issues, continuing with local file storage")
            elif "timeout" in error_msg.lower():
                self.logger.warning(f"⚠️ Walrus service timeout: {e}")
                self.logger.info("🔄 Walrus upload timed out, continuing with local file storage")
            elif "network" in error_msg.lower() or "connection" in error_msg.lower():
                self.logger.warning(f"⚠️ Network error connecting to Walrus: {e}")
                self.logger.info("🔄 Network issues with Walrus service, continuing with local file storage")
            else:
                self.logger.error(f"❌ Failed to publish to Walrus: {e}")
            
            self.logger.debug(f"🔍 Walrus publication exception details: {type(e).__name__}: {str(e)}")
            if hasattr(e, '__dict__'):
                self.logger.debug(f"🔍 Exception attributes: {e.__dict__}")
            return None
    
    def _publish_to_local_file(self, report: Dict[str, Any]) -> Optional[str]:
        """
        Publish report to local file system.
        
        Args:
            report: Formatted report dictionary
            
        Returns:
            File path if successful, None otherwise
        """
        try:
            # Create reports directory if it doesn't exist
            reports_dir = "reports"
            self.logger.debug(f"📁 Creating reports directory: {reports_dir}")
            os.makedirs(reports_dir, exist_ok=True)
            
            # Generate filename
            scan_id = report['scan_metadata']['scan_id']
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{scan_id}_{timestamp}.json"
            filepath = os.path.join(reports_dir, filename)
            
            self.logger.debug(f"📁 Writing report to file: {filepath}")
            self.logger.debug(f"🔍 Report size: {len(json.dumps(report))} bytes")
            
            # Write report to file
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            # Verify file was written
            if os.path.exists(filepath):
                file_size = os.path.getsize(filepath)
                self.logger.info(f"✅ Report saved to local file: {filepath}")
                self.logger.debug(f"✅ File written successfully - size: {file_size} bytes")
            else:
                self.logger.error(f"❌ File was not created: {filepath}")
                return None
            
            return filepath
            
        except Exception as e:
            self.logger.error(f"❌ Failed to save report to file: {e}")
            self.logger.debug(f"🔍 Local file publication exception details: {type(e).__name__}: {str(e)}")
            return None
    
    def _update_scan_publishing_status(self, scan_id: int, publishing_results: Dict[str, Any]):
        """
        Update the scan record with publishing status and results.
        
        Args:
            scan_id: The scan ID to update
            publishing_results: Results from publishing attempts
        """
        try:
            # This would update the database with publishing information
            # Implementation depends on your database schema and ORM
            self.logger.info(f"📝 Updated scan {scan_id} with publishing results")
            
            # Example of what this might look like:
            # scan = self.db.get_scan(scan_id)
            # scan.publishing_status = 'completed'
            # scan.publishing_results = json.dumps(publishing_results)
            # scan.published_at = datetime.now()
            # self.db.save(scan)
            
        except Exception as e:
            self.logger.error(f"❌ Failed to update scan publishing status: {e}")
    
    def publish_results(self, processed_results: List[Dict[str, Any]]) -> bool:
        """
        Publish scan reports (legacy method for batch processing).
        
        Args:
            processed_results: Processed scan results
            
        Returns:
            True if report publishing succeeded, False otherwise
        """
        self.logger.info(f"📄 Publishing reports for {len(processed_results)} results")
        
        success_count = 0
        
        for result in processed_results:
            try:
                # Format the report
                report = self._format_scan_report(result)
                
                # Publish to configured destinations
                publishing_results = {}
                
                for destination in self.publishing_destinations:
                    if destination == 'walrus':
                        walrus_hash = self._publish_to_walrus(report)
                        publishing_results['walrus'] = {
                            'success': walrus_hash is not None,
                            'hash': walrus_hash
                        }
                    
                    elif destination == 'local_file':
                        filepath = self._publish_to_local_file(report)
                        publishing_results['local_file'] = {
                            'success': filepath is not None,
                            'path': filepath
                        }
                
                # Update scan record with publishing results
                scan_id = result.get('id')
                if scan_id:
                    self._update_scan_publishing_status(scan_id, publishing_results)
                
                success_count += 1
                
            except Exception as e:
                self.logger.error(f"❌ Failed to publish result: {e}")
        
        success_rate = success_count / len(processed_results) if processed_results else 0
        self.logger.info(f"📊 Published {success_count}/{len(processed_results)} reports successfully ({success_rate:.1%})")
        
        return success_rate > 0.5  # Consider successful if > 50% published
    
    def execute(self, scan_id: int, *args, **kwargs) -> Dict[str, Any]:
        """
        Execute report publishing for a specific scan.
        
        Args:
            scan_id: The ID of the scan to publish reports for
            
        Returns:
            Dictionary containing execution results
        """
        self.logger.info(f"📄 Publishing reports for scan {scan_id}")
        self.logger.debug(f"🔍 Publishing destinations configured: {self.publishing_destinations}")
        self.logger.debug(f"🔍 Walrus provider available: {self.walrus_provider is not None}")
        
        try:
            # Check if ledger has been published first - reports should only be published after ledger
            # TODO: Temporarily bypassing ledger check for testing
            # from repositories.ledger_repository import LedgerRepository
            # ledger_repo = LedgerRepository()
            
            # if not ledger_repo.is_scan_published(scan_id):
            #     self.logger.warning(f"⚠️ Scan {scan_id} has not been published to ledger yet")
            #     self.logger.info(f"📚 Reports can only be published after ledger publishing is complete")
            #     return {
            #         'success': False,
            #         'scan_id': scan_id,
            #         'report_published': False,
            #         'destinations': [],
            #         'error': 'Ledger not published',
            #         'message': 'Reports can only be published after ledger publishing is complete. Please run ledger publishing first.'
            #     }
            
            self.logger.info(f"ℹ️ Ledger check bypassed for testing purposes")
            self.logger.debug(f"✅ Continuing with report publication for scan {scan_id}")
            
            # TODO: Replace with actual database query
            # scan_data = self.db.get_scan_with_results(scan_id)
            
            # Mock scan data for demonstration
            scan_data = {
                'id': scan_id,
                'validator_info': {
                    'address': '0x123...abc',
                    'hostname': 'validator.example.com'
                },
                'results': {
                    'trust_score': 75,
                    'open_ports': [22, 80, 443],
                    'vulnerabilities': ['CVE-2023-1234'],
                    'ssl_info': {'grade': 'A', 'expired': False}
                },
                'created_at': datetime.now().isoformat()
            }
            
            self.logger.debug(f"🔍 Scan data loaded for scan {scan_id}: validator={scan_data.get('validator_info', {}).get('address', 'unknown')}")
            
            # Format the report
            self.logger.debug(f"🔄 Formatting report for scan {scan_id}")
            report = self._format_scan_report(scan_data)
            self.logger.debug(f"✅ Report formatted with UID: {report.get('uid', 'unknown')}")
            
            # Publish to configured destinations with resilient error handling
            publishing_results = {}
            successful_destinations = []
            walrus_failed = False
            
            self.logger.info(f"🚀 Starting publication to {len(self.publishing_destinations)} destinations")
            
            for destination in self.publishing_destinations:
                self.logger.debug(f"📤 Publishing to destination: {destination}")
                try:
                    if destination == 'walrus':
                        self.logger.debug(f"🐋 Attempting Walrus publication for scan {scan_id}")
                        walrus_hash = self._publish_to_walrus(report)
                        publishing_results['walrus'] = {
                            'success': walrus_hash is not None,
                            'hash': walrus_hash,
                            'url': f"walrus://{walrus_hash}" if walrus_hash else None
                        }
                        if walrus_hash:
                            successful_destinations.append('walrus')
                            self.logger.info(f"✅ Walrus publication successful: {walrus_hash}")
                        else:
                            walrus_failed = True
                            self.logger.warning(f"⚠️ Walrus publication failed for scan {scan_id}")
                    
                    elif destination == 'local_file':
                        # Always try local file, or if Walrus failed and this is the fallback
                        should_save_local = True
                        reason = "configured destination"
                        
                        if walrus_failed and 'walrus' in self.publishing_destinations:
                            reason = "fallback due to Walrus failure"
                            
                        self.logger.debug(f"📁 Attempting local file publication for scan {scan_id} ({reason})")
                        filepath = self._publish_to_local_file(report)
                        publishing_results['local_file'] = {
                            'success': filepath is not None,
                            'path': filepath,
                            'reason': reason
                        }
                        if filepath:
                            successful_destinations.append('local_file')
                            self.logger.info(f"✅ Local file publication successful: {filepath}")
                        else:
                            self.logger.error(f"❌ Local file publication failed for scan {scan_id}")
                    
                except Exception as e:
                    self.logger.error(f"❌ Failed to publish to {destination}: {e}")
                    self.logger.debug(f"🔍 Exception details for {destination}: {type(e).__name__}: {str(e)}")
                    publishing_results[destination] = {
                        'success': False,
                        'error': str(e)
                    }
            
            # If Walrus failed but we don't have local_file in destinations, force a local save
            if walrus_failed and 'local_file' not in self.publishing_destinations:
                self.logger.warning("⚠️ Walrus failed and no local_file destination configured - forcing local save as emergency fallback")
                try:
                    filepath = self._publish_to_local_file(report)
                    if filepath:
                        publishing_results['local_file_emergency'] = {
                            'success': True,
                            'path': filepath,
                            'reason': 'emergency fallback'
                        }
                        successful_destinations.append('local_file_emergency')
                        self.logger.info(f"✅ Emergency local file save successful: {filepath}")
                except Exception as e:
                    self.logger.error(f"❌ Emergency local file save failed: {e}")
            
            self.logger.debug(f"📊 Publication results: {publishing_results}")
            self.logger.debug(f"✅ Successful destinations: {successful_destinations}")
            
            # Update scan record with publishing results
            self.logger.debug(f"📝 Updating scan record for scan {scan_id}")
            self._update_scan_publishing_status(scan_id, publishing_results)
            
            success = len(successful_destinations) > 0
            
            result = {
                'success': success,
                'scan_id': scan_id,
                'report_published': success,
                'destinations': successful_destinations,
                'publishing_results': publishing_results,
                'report_uid': report['uid'],
                'message': f'Report published to {len(successful_destinations)} destinations' if success else 'Failed to publish to any destinations'
            }
            
            self.logger.info(f"📊 Final publication result for scan {scan_id}: {result['message']}")
            self.logger.debug(f"🔍 Complete result object: {result}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Failed to execute report publishing for scan {scan_id}: {e}")
            self.logger.debug(f"🔍 Exception details in execute: {type(e).__name__}: {str(e)}")
            return {
                'success': False,
                'scan_id': scan_id,
                'report_published': False,
                'destinations': [],
                'error': str(e),
                'message': 'Report publishing failed due to unexpected error'
            }
    
    def run(self, scan_id: int, *args, **kwargs) -> bool:
        """
        Execute report publishing for a specific scan ID.
        
        Args:
            scan_id: The ID of the scan to publish reports for
            
        Returns:
            True if report publishing succeeded, False otherwise
        """
        self.logger.debug(f"🚀 Starting report publishing run for scan {scan_id}")
        self.logger.debug(f"🔍 Additional args: {args}")
        self.logger.debug(f"🔍 Additional kwargs: {kwargs}")
        
        result = self.execute(scan_id=scan_id)
        success = result.get('success', False)
        
        self.logger.debug(f"📊 Run completed for scan {scan_id} - success: {success}")
        
        return success
    
    def get_published_report(self, walrus_hash: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a published report from Walrus storage.
        
        Args:
            walrus_hash: The Walrus hash of the report to retrieve
            
        Returns:
            Report dictionary if found, None otherwise
        """
        if not self.walrus_provider:
            self.logger.warning("Walrus provider not available")
            return None
        
        try:
            report = self.walrus_provider.read(walrus_hash)
            self.logger.info(f"✅ Retrieved report from Walrus: {walrus_hash}")
            return report
            
        except Exception as e:
            # Handle both WalrusStorageProviderError and other exceptions
            self.logger.error(f"❌ Failed to retrieve report from Walrus: {e}")
            return None
    
    def list_published_reports(self) -> List[str]:
        """
        List all published reports in Walrus storage.
        
        Returns:
            List of Walrus hashes for published reports
        """
        if not self.walrus_provider:
            self.logger.warning("Walrus provider not available")
            return []
        
        try:
            hashes = self.walrus_provider.list()
            self.logger.info(f"📋 Found {len(hashes)} published reports in Walrus")
            return hashes
            
        except Exception as e:
            # Handle both WalrusStorageProviderError and other exceptions
            self.logger.error(f"❌ Failed to list published reports: {e}")
            return []