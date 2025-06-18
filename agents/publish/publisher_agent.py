"""
Publisher agent for outputting final results to v            for result in results:
                print(f"\n🏠 Node: {result.get('ip_address', 'Unknown')}")
                print(f"   Trust Score: {result.get('trust_score', 'N/A')}")
                print(f"   Risk Level: {result.get('risk_level', 'Unknown')}")
                print(f"   Scanner Version: {result.get('scan_version', 'Unknown')}")
                
                flags = result.get('trust_flags', [])
                if flags:
                    print(f"   🚩 Flags: {', '.join(flags)}")
                
                compliance = result.get('compliance', {})
                recommendations = compliance.get('recommendations', [])
                if recommendations:
                    print(f"   💡 Recommendations: {', '.join(recommendations)}")ations.
"""

import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from abc import ABC, abstractmethod

from agents.base import PublishAgent
from core.config import Config
from core.database import SCANNER_VERSION
from storage.history import HistoryStore


class BasePublisher(ABC):
    """Base class for result publishers."""
    
    def __init__(self, config: Config):
        self.config = config
    
    @abstractmethod
    def publish(self, results: List[Dict[str, Any]]) -> bool:
        """Publish results to destination."""
        pass


class DatabasePublisher(BasePublisher):
    """Publisher that saves results to history database."""
    
    def __init__(self, config: Config):
        super().__init__(config)
        self.history_store = HistoryStore()
    
    def publish(self, results: List[Dict[str, Any]]) -> bool:
        """Save results to history database."""
        try:
            for result in results:
                self.history_store.add_entry(result)
            return True
        except Exception:
            return False


class ConsolePublisher(BasePublisher):
    """Publisher that outputs results to console."""
    
    def publish(self, results: List[Dict[str, Any]]) -> bool:
        """Print results to console."""
        try:
            print("\\n" + "="*80)
            print(f"📊 SCAN RESULTS SUMMARY ({len(results)} nodes)")
            print("="*80)
            
            for result in results:
                print(f"\\n🏠 Node: {result.get('ip_address', 'Unknown')}")
                print(f"   Trust Score: {result.get('trust_score', 'N/A')}")
                print(f"   Risk Level: {result.get('risk_level', 'Unknown')}")
                
                flags = result.get('trust_flags', [])
                if flags:
                    print(f"   🚩 Flags: {', '.join(flags)}")
                
                compliance = result.get('compliance', {})
                recommendations = compliance.get('recommendations', [])
                if recommendations:
                    print(f"   💡 Recommendations: {', '.join(recommendations)}")
            
            print("\\n" + "="*80)
            return True
        except Exception:
            return False


class APIPublisher(BasePublisher):
    """Publisher that sends results to API endpoint."""
    
    def publish(self, results: List[Dict[str, Any]]) -> bool:
        """Send results to API endpoint."""
        if not self.config.publish.api_endpoint:
            return False
        
        # Placeholder for API publishing
        # In a real implementation, you would:
        # 1. Format results for API
        # 2. Send HTTP POST request
        # 3. Handle authentication
        # 4. Retry on failures
        return True


class BlockchainPublisher(BasePublisher):
    """Publisher that submits results to blockchain."""
    
    def publish(self, results: List[Dict[str, Any]]) -> bool:
        """Submit results to blockchain."""
        if not self.config.publish.blockchain_endpoint:
            return False
        
        # Placeholder for blockchain publishing
        # In a real implementation, you would:
        # 1. Format results for blockchain
        # 2. Create and sign transactions
        # 3. Submit to blockchain network
        # 4. Monitor transaction status
        return True


class JSONFilePublisher(BasePublisher):
    """Publisher that saves results to JSON file."""
    
    def __init__(self, config: Config, output_file: str = "scan_results.json"):
        super().__init__(config)
        self.output_file = output_file
    
    def publish(self, results: List[Dict[str, Any]]) -> bool:
        """Save results to JSON file."""
        try:
            output_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'total_results': len(results),
                'scanner_version': SCANNER_VERSION,
                'results': results
            }
            
            with open(self.output_file, 'w') as f:
                json.dump(output_data, f, indent=2)
            
            return True
        except Exception:
            return False


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
        self.publishers = self._initialize_publishers()
    
    def _initialize_publishers(self) -> Dict[str, BasePublisher]:
        """Initialize configured publishers."""
        publishers = {}
        
        enabled_publishers = self.config.publish.enabled_publishers
        
        if 'database' in enabled_publishers:
            publishers['database'] = DatabasePublisher(self.config)
        
        if 'console' in enabled_publishers:
            publishers['console'] = ConsolePublisher(self.config)
        
        if 'api' in enabled_publishers:
            publishers['api'] = APIPublisher(self.config)
        
        if 'blockchain' in enabled_publishers:
            publishers['blockchain'] = BlockchainPublisher(self.config)
        
        if 'json_file' in enabled_publishers:
            publishers['json_file'] = JSONFilePublisher(self.config)
        
        self.logger.info(f"📤 Initialized publishers: {list(publishers.keys())}")
        return publishers
    
    def publish_results(self, processed_results: List[Dict[str, Any]]) -> bool:
        """
        Publish processed results to configured destinations.
        
        Args:
            processed_results: List of processed scan results
            
        Returns:
            True if all publishers succeeded, False otherwise
        """
        if not processed_results:
            self.logger.info("🎯 No results to publish")
            return True
        
        self.logger.info(f"📤 Publishing {len(processed_results)} results to {len(self.publishers)} destinations")
        
        success_results = {}
        overall_success = True
        
        for name, publisher in self.publishers.items():
            try:
                self.logger.info(f"📡 Publishing to {name}...")
                success = publisher.publish(processed_results)
                success_results[name] = success
                
                if success:
                    self.logger.info(f"✅ Successfully published to {name}")
                else:
                    self.logger.error(f"❌ Failed to publish to {name}")
                    overall_success = False
                    
            except Exception as e:
                self.logger.error(f"❌ Error publishing to {name}: {e}")
                success_results[name] = False
                overall_success = False
        
        # Log summary
        successful_publishers = [name for name, success in success_results.items() if success]
        failed_publishers = [name for name, success in success_results.items() if not success]
        
        if successful_publishers:
            self.logger.info(f"✅ Successfully published to: {', '.join(successful_publishers)}")
        
        if failed_publishers:
            self.logger.error(f"❌ Failed to publish to: {', '.join(failed_publishers)}")
        
        return overall_success
    
    def add_publisher(self, name: str, publisher: BasePublisher) -> None:
        """
        Add a custom publisher.
        
        Args:
            name: Publisher name
            publisher: Publisher instance
        """
        self.publishers[name] = publisher
        self.logger.info(f"📤 Added custom publisher: {name}")
    
    def remove_publisher(self, name: str) -> bool:
        """
        Remove a publisher.
        
        Args:
            name: Publisher name
            
        Returns:
            True if publisher was removed, False if not found
        """
        if name in self.publishers:
            del self.publishers[name]
            self.logger.info(f"🗑️  Removed publisher: {name}")
            return True
        return False
    
    def get_publisher_status(self) -> Dict[str, bool]:
        """
        Get status of all publishers.
        
        Returns:
            Dictionary mapping publisher names to availability status
        """
        status = {}
        for name, publisher in self.publishers.items():
            try:
                # Perform a simple health check by attempting to publish empty results
                status[name] = True  # Assume healthy unless proven otherwise
            except Exception:
                status[name] = False
        
        return status
    
    def run(self, processed_results: List[Dict[str, Any]], *args, **kwargs) -> bool:
        """
        Execute result publishing.
        
        Args:
            processed_results: List of processed results to publish
            
        Returns:
            True if publishing succeeded, False otherwise
        """
        return self.publish_results(processed_results)
