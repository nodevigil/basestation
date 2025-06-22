"""
WalrusStorageProvider - Storage provider for Walrus programmable storage network
Adapted for DePIN Validator Scanner Suite

Dependencies:
    - requests
    - python-dotenv (optional, for .env file support)
"""

import json
import requests
import os
import logging
from typing import Dict, List, Any, Optional

# Try to load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


class WalrusStorageProviderError(Exception):
    """Custom exception for Walrus storage provider errors"""
    pass


class WalrusStorageProvider:
    """
    Storage provider for the Walrus programmable storage network.
    
    Provides methods to write, read, delete, and list objects stored in Walrus
    via HTTP REST API. Specifically adapted for DePIN validator scan reports.
    """
    
    def __init__(self, api_url: str = None, api_key: str = None, logger: Optional[logging.Logger] = None):
        """
        Initialize the Walrus storage provider.
        
        Args:
            api_url (str, optional): Base URL for the Walrus API (defaults to env WALRUS_API_URL)
            api_key (str, optional): API key for authentication (defaults to env WALRUS_API_KEY)
            logger (logging.Logger, optional): Logger instance for debugging
        """
        self.logger = logger or logging.getLogger(__name__)
        
        # Load configuration from environment variables with testnet defaults
        self.api_url = (api_url or 
                       os.getenv('WALRUS_API_URL', 'https://publisher-devnet.walrus.space') or
                       'https://aggregator-devnet.walrus.space').rstrip('/')
        
        self.api_key = api_key or os.getenv('WALRUS_API_KEY')
        
        if not self.api_key:
            raise WalrusStorageProviderError("API key must be provided or set in WALRUS_API_KEY environment variable")
        
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'User-Agent': 'DePIN-Validator-Scanner/1.0'
        }
        
        self.logger.debug(f"Initialized Walrus provider with URL: {self.api_url}")
    
    def write(self, uid: str, data: dict) -> str:
        """
        Store a JSON-serializable Python dictionary as a Walrus object.
        
        Args:
            uid (str): Unique identifier that must match the 'uid' key in data
            data (dict): JSON-serializable dictionary to store
            
        Returns:
            str: Walrus object hash (pointer)
            
        Raises:
            WalrusStorageProviderError: If UID mismatch or API call fails
        """
        if data.get('uid') != uid:
            raise WalrusStorageProviderError(f"UID mismatch: provided '{uid}' but data contains '{data.get('uid')}'")
        
        # Log the size of data being uploaded
        data_size = len(json.dumps(data))
        self.logger.info(f"📤 Uploading {data_size} bytes to Walrus with UID: {uid}")
        
        try:
            response = requests.post(
                f"{self.api_url}/objects",
                headers=self.headers,
                data=json.dumps(data, default=str),  # Handle datetime objects
                timeout=60  # Increased timeout for larger scan reports
            )
            response.raise_for_status()
            
            result = response.json()
            walrus_hash = result.get('hash', result.get('object_id', ''))
            
            if not walrus_hash:
                raise WalrusStorageProviderError("No hash returned in response")
            
            self.logger.info(f"✅ Successfully uploaded to Walrus: {walrus_hash}")
            return walrus_hash
            
        except requests.exceptions.Timeout:
            raise WalrusStorageProviderError("Upload timeout - scan report may be too large")
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Network error during upload: {e}")
            raise WalrusStorageProviderError(f"Failed to write object: {str(e)}")
        except (KeyError, ValueError) as e:
            self.logger.error(f"Invalid response format: {e}")
            raise WalrusStorageProviderError(f"Invalid response format: {str(e)}")
    
    def read(self, walrus_hash: str) -> dict:
        """
        Retrieve the stored object by Walrus hash.
        
        Args:
            walrus_hash (str): Walrus object hash
            
        Returns:
            dict: Retrieved object as Python dictionary
            
        Raises:
            WalrusStorageProviderError: If API call fails
        """
        self.logger.debug(f"📥 Retrieving object from Walrus: {walrus_hash}")
        
        try:
            response = requests.get(
                f"{self.api_url}/objects/{walrus_hash}",
                headers=self.headers,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            self.logger.info(f"✅ Successfully retrieved from Walrus: {walrus_hash}")
            return data
            
        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response.status_code == 404:
                raise WalrusStorageProviderError(f"Object not found: {walrus_hash}")
            self.logger.error(f"Network error during retrieval: {e}")
            raise WalrusStorageProviderError(f"Failed to read object {walrus_hash}: {str(e)}")
        except ValueError as e:
            self.logger.error(f"Invalid JSON response: {e}")
            raise WalrusStorageProviderError(f"Invalid JSON response: {str(e)}")
    
    def delete(self, walrus_hash: str) -> None:
        """
        Delete the object by Walrus hash.
        
        Args:
            walrus_hash (str): Walrus object hash to delete
            
        Raises:
            WalrusStorageProviderError: If API call fails
        """
        self.logger.info(f"🗑️ Deleting object from Walrus: {walrus_hash}")
        
        try:
            response = requests.delete(
                f"{self.api_url}/objects/{walrus_hash}",
                headers=self.headers,
                timeout=30
            )
            response.raise_for_status()
            
            self.logger.info(f"✅ Successfully deleted from Walrus: {walrus_hash}")
            
        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response.status_code == 404:
                self.logger.warning(f"Object not found for deletion: {walrus_hash}")
                return  # Consider 404 as successful deletion
            self.logger.error(f"Network error during deletion: {e}")
            raise WalrusStorageProviderError(f"Failed to delete object {walrus_hash}: {str(e)}")
    
    def list(self) -> list:
        """
        Return a list of all Walrus object hashes accessible to the user.
        
        Returns:
            list: List of Walrus object hashes
            
        Raises:
            WalrusStorageProviderError: If API call fails
        """
        self.logger.debug("📋 Listing all objects in Walrus")
        
        try:
            response = requests.get(
                f"{self.api_url}/objects",
                headers=self.headers,
                timeout=30
            )
            response.raise_for_status()
            
            result = response.json()
            objects = result.get('objects', result.get('hashes', []))
            
            self.logger.info(f"📋 Found {len(objects)} objects in Walrus storage")
            return objects
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Network error during list operation: {e}")
            raise WalrusStorageProviderError(f"Failed to list objects: {str(e)}")
        except (KeyError, ValueError) as e:
            self.logger.error(f"Invalid response format: {e}")
            raise WalrusStorageProviderError(f"Invalid response format: {str(e)}")
    
    def health_check(self) -> bool:
        """
        Check if the Walrus service is accessible and responding.
        
        Returns:
            bool: True if service is healthy, False otherwise
        """
        try:
            # Try to list objects as a health check
            self.list()
            self.logger.info("✅ Walrus service health check passed")
            return True
        except WalrusStorageProviderError:
            self.logger.warning("❌ Walrus service health check failed")
            return False
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """
        Get storage statistics (if supported by the API).
        
        Returns:
            Dict containing storage statistics
        """
        try:
            objects = self.list()
            return {
                'total_objects': len(objects),
                'service_url': self.api_url,
                'service_healthy': True
            }
        except WalrusStorageProviderError as e:
            return {
                'total_objects': 0,
                'service_url': self.api_url,
                'service_healthy': False,
                'error': str(e)
            }


# # Sample usage for testing
# if __name__ == "__main__":
#     import logging
    
#     # Setup logging
#     logging.basicConfig(level=logging.INFO)
#     logger = logging.getLogger(__name__)
    
#     # Sample DePIN scan report data
#     depin_scan_report = {
#         "uid": "depin_scan_test_123",
#         "report_type": "depin_validator_scan",
#         "version": "1.0",
#         "generated_at": "2025-06-22T10:00:00Z",
#         "scan_metadata": {
#             "scan_id": 123,
#             "validator_address": "0x1234567890abcdef",
#             "validator_hostname": "validator.example.com",
#             "scan_timestamp": "2025-06-22T09:45:00Z",
#             "scanner_version": "1.0.0"
#         },
#         "security_assessment": {
#             "trust_score": 85,
#             "risk_level": "LOW",
#             "open_ports": [22, 80, 443],
#             "services_detected": ["ssh", "http", "https"],
#             "vulnerabilities": [],
#             "ssl_assessment": {"grade": "A", "expires": "2025-12-01"},
#             "compliance_checks": {"pci_dss": "pass", "soc2": "pass"}
#         }
#     }
    
#     try:
#         # Initialize storage provider
#         storage = WalrusStorageProvider(logger=logger)
        
#         # Test health check
#         if not storage.health_check():
#             logger.error("❌ Walrus service is not healthy, aborting test")
#             exit(1)
        
#         # Store the scan report
#         walrus_hash = storage.write("depin_scan_test_123", depin_scan_report)
#         logger.info(f"📦 Stored DePIN scan report with hash: {walrus_hash}")
        
#         # Retrieve the report
#         retrieved_report = storage.read(walrus_hash)
#         logger.info(f"📋 Retrieved report UID: {retrieved_report['uid']}")
        
#         # Get storage stats
#         stats = storage.get_storage_stats()
#         logger.info(f"📊 Storage stats: {stats}")
        
#         # List all objects
#         all_objects = storage.list()
#         logger.info(f"📋 All objects: {len(all_objects)} total")
        
#         # Clean up - delete the test report
#         storage.delete(walrus_hash)
#         logger.info(f"🗑️ Deleted test report with hash: {walrus_hash}")
        
#         logger.info("✅ All Walrus storage tests completed successfully!")
        
#     except WalrusStorageProviderError as e:
#         logger.error(f"❌ Walrus storage test failed: {e}")
#         logger.info("💡 Make sure you have:")
#         logger.info("  - Valid WALRUS_API_KEY in environment")
#         logger.info("  - Network access to Walrus devnet")
#         logger.info("  - Correct API endpoint configured")
#     except Exception as e:
#         logger.error(f"❌ Unexpected error during test: {e}")