"""
Publisher agent for outputting scan reports to various destinations including Walrus storage.
"""

import json
import os
from typing import Optional, Dict, Any, List
from datetime import datetime
from agents.base import PublishAgent
from core.config import Config
from storage.walrus_provider import WalrusStorageProvider, WalrusStorageProviderError


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
        
        # Initialize Walrus storage provider if configured
        self.walrus_provider = None
        self._init_walrus_provider()
        
        # Publishing destinations configuration
        self.publishing_destinations = self._get_publishing_destinations()
    
    def _init_walrus_provider(self):
        """Initialize Walrus storage provider if API key is available."""
        try:
            walrus_api_key = os.getenv('WALRUS_API_KEY')
            walrus_api_url = os.getenv('WALRUS_API_URL', 'https://publisher-devnet.walrus.space')
            
            if walrus_api_key:
                self.walrus_provider = WalrusStorageProvider(
                    api_url=walrus_api_url,
                    api_key=walrus_api_key
                )
                self.logger.info(f"✅ Walrus storage provider initialized: {walrus_api_url}")
            else:
                self.logger.warning("⚠️ WALRUS_API_KEY not found, Walrus publishing disabled")
                
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize Walrus provider: {e}")
            self.walrus_provider = None
    
    def _get_publishing_destinations(self) -> List[str]:
        """Get configured publishing destinations from config or environment."""
        destinations = []
        
        # Check for Walrus
        if self.walrus_provider:
            destinations.append('walrus')
        
        # Check for other destinations from config
        if self.config:
            config_destinations = getattr(self.config, 'publishing_destinations', [])
            destinations.extend(config_destinations)
        
        # Default to local file if no destinations configured
        if not destinations:
            destinations.append('local_file')
        
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
            return None
        
        try:
            uid = report['uid']
            walrus_hash = self.walrus_provider.write(uid, report)
            self.logger.info(f"✅ Report published to Walrus: {walrus_hash}")
            return walrus_hash
            
        except WalrusStorageProviderError as e:
            self.logger.error(f"❌ Failed to publish to Walrus: {e}")
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
            os.makedirs(reports_dir, exist_ok=True)
            
            # Generate filename
            scan_id = report['scan_metadata']['scan_id']
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{scan_id}_{timestamp}.json"
            filepath = os.path.join(reports_dir, filename)
            
            # Write report to file
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            self.logger.info(f"✅ Report saved to local file: {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"❌ Failed to save report to file: {e}")
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
        
        try:
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
            
            # Format the report
            report = self._format_scan_report(scan_data)
            
            # Publish to configured destinations
            publishing_results = {}
            successful_destinations = []
            
            for destination in self.publishing_destinations:
                try:
                    if destination == 'walrus':
                        walrus_hash = self._publish_to_walrus(report)
                        publishing_results['walrus'] = {
                            'success': walrus_hash is not None,
                            'hash': walrus_hash,
                            'url': f"walrus://{walrus_hash}" if walrus_hash else None
                        }
                        if walrus_hash:
                            successful_destinations.append('walrus')
                    
                    elif destination == 'local_file':
                        filepath = self._publish_to_local_file(report)
                        publishing_results['local_file'] = {
                            'success': filepath is not None,
                            'path': filepath
                        }
                        if filepath:
                            successful_destinations.append('local_file')
                    
                except Exception as e:
                    self.logger.error(f"❌ Failed to publish to {destination}: {e}")
                    publishing_results[destination] = {
                        'success': False,
                        'error': str(e)
                    }
            
            # Update scan record with publishing results
            self._update_scan_publishing_status(scan_id, publishing_results)
            
            success = len(successful_destinations) > 0
            
            return {
                'success': success,
                'scan_id': scan_id,
                'report_published': success,
                'destinations': successful_destinations,
                'publishing_results': publishing_results,
                'report_uid': report['uid'],
                'message': f'Report published to {len(successful_destinations)} destinations' if success else 'Failed to publish to any destinations'
            }
            
        except Exception as e:
            self.logger.error(f"❌ Failed to execute report publishing for scan {scan_id}: {e}")
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
        result = self.execute(scan_id=scan_id)
        return result.get('success', False)
    
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
            
        except WalrusStorageProviderError as e:
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
            
        except WalrusStorageProviderError as e:
            self.logger.error(f"❌ Failed to list published reports: {e}")
            return []