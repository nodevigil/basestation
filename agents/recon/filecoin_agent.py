"""
Filecoin reconnaissance agent for discovering storage providers and nodes.
"""

import requests
import time
from typing import List, Dict, Any, Optional
from datetime import datetime

from agents.base import ReconAgent
from core.database import get_db_session, ValidatorAddress


class FilecoinReconAgent(ReconAgent):
    """
    Filecoin network reconnaissance agent.
    
    This agent discovers Filecoin storage providers and nodes by:
    - Querying Filecoin APIs for storage provider information
    - Extracting network addresses from provider records
    - Saving discovered nodes to the database
    """
    
    def __init__(self, config: Optional[object] = None):
        """Initialize Filecoin recon agent."""
        super().__init__(config, "FilecoinReconAgent")
        
        # Filecoin network endpoints
        self.filecoin_api_urls = [
            "https://filfox.info/api/v1/storage-provider/list",
            "https://spacegap.github.io/database/miners.json",
            # Add more Filecoin data sources here
        ]
        
        self.request_timeout = 30
        self.max_retries = 3
        self.delay_between_requests = 1.0
    
    def discover_nodes(self) -> List[Dict[str, Any]]:
        """
        Discover Filecoin storage providers and nodes.
        
        Returns:
            List of discovered node dictionaries
        """
        discovered_nodes = []
        
        self.logger.info("🔍 Starting Filecoin network reconnaissance...")
        
        # Try different data sources
        for api_url in self.filecoin_api_urls:
            try:
                self.logger.info(f"📡 Querying {api_url}")
                nodes = self._query_filecoin_api(api_url)
                discovered_nodes.extend(nodes)
                
                # Be respectful with API calls
                time.sleep(self.delay_between_requests)
                
            except Exception as e:
                self.logger.warning(f"Failed to query {api_url}: {e}")
                continue
        
        # Remove duplicates based on address
        unique_nodes = {}
        for node in discovered_nodes:
            address = node.get('address')
            if address and address not in unique_nodes:
                unique_nodes[address] = node
        
        final_nodes = list(unique_nodes.values())
        
        self.logger.info(f"🎯 Discovered {len(final_nodes)} unique Filecoin nodes from {len(discovered_nodes)} total records")
        
        # Save to database
        saved_count = self._save_nodes_to_database(final_nodes)
        self.logger.info(f"💾 Saved {saved_count} new Filecoin nodes to database")
        
        return final_nodes
    
    def _query_filecoin_api(self, api_url: str) -> List[Dict[str, Any]]:
        """Query a Filecoin API endpoint for storage provider data."""
        nodes = []
        
        try:
            response = requests.get(api_url, timeout=self.request_timeout)
            response.raise_for_status()
            
            data = response.json()
            
            # Handle different API response formats
            if isinstance(data, list):
                # Direct list of providers
                providers = data
            elif isinstance(data, dict):
                if 'miners' in data:
                    providers = data['miners']
                elif 'storage_providers' in data:
                    providers = data['storage_providers']
                elif 'data' in data:
                    providers = data['data']
                else:
                    # Try to find the main data array
                    providers = []
                    for key, value in data.items():
                        if isinstance(value, list) and len(value) > 0:
                            providers = value
                            break
            else:
                providers = []
            
            # Extract node information
            for provider in providers[:100]:  # Limit to first 100 for testing
                try:
                    node_info = self._extract_node_info(provider)
                    if node_info:
                        nodes.append(node_info)
                except Exception as e:
                    self.logger.debug(f"Failed to extract node info from provider: {e}")
                    continue
        
        except Exception as e:
            self.logger.error(f"Failed to query {api_url}: {e}")
            raise
        
        return nodes
    
    def _extract_node_info(self, provider_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract node information from provider data."""
        # Try to find network address in various fields
        address = None
        name = None
        
        # Common fields that might contain addresses
        address_fields = [
            'address', 'peer_id', 'multiaddress', 'multiaddr', 
            'network_address', 'ip', 'hostname', 'domain',
            'worker_address', 'owner_address'
        ]
        
        name_fields = [
            'name', 'label', 'organization', 'org', 'title'
        ]
        
        # Extract address
        for field in address_fields:
            if field in provider_data and provider_data[field]:
                potential_address = str(provider_data[field])
                
                # Skip if it looks like a Filecoin address (starts with 'f')
                if potential_address.startswith('f'):
                    continue
                
                # Extract IP/hostname from multiaddress format
                if '/ip4/' in potential_address:
                    try:
                        parts = potential_address.split('/ip4/')[1].split('/')
                        address = parts[0]
                        break
                    except:
                        continue
                
                # Check if it looks like an IP or hostname
                if self._is_valid_address(potential_address):
                    address = potential_address
                    break
        
        # Extract name
        for field in name_fields:
            if field in provider_data and provider_data[field]:
                name = str(provider_data[field])
                break
        
        if not address:
            return None
        
        return {
            'address': address,
            'name': name,
            'source': 'filecoin_recon_agent',
            'raw_data': provider_data
        }
    
    def _is_valid_address(self, address: str) -> bool:
        """Check if a string looks like a valid IP or hostname."""
        import re
        
        # IP address pattern
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        
        # Hostname pattern
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        return bool(re.match(ip_pattern, address) or re.match(hostname_pattern, address))
    
    def _save_nodes_to_database(self, nodes: List[Dict[str, Any]]) -> int:
        """Save discovered nodes to database."""
        saved_count = 0
        
        with get_db_session() as session:
            for node in nodes:
                try:
                    # Check if address already exists
                    existing = session.query(ValidatorAddress).filter_by(
                        address=node['address']
                    ).first()
                    
                    if not existing:
                        # Create new validator address entry
                        validator_address = ValidatorAddress(
                            address=node['address'],
                            name=node.get('name'),
                            source=node['source'],
                            created_at=datetime.utcnow(),
                            active=True
                        )
                        
                        session.add(validator_address)
                        saved_count += 1
                
                except Exception as e:
                    self.logger.warning(f"Failed to save node {node.get('address', 'unknown')}: {e}")
                    continue
            
            session.commit()
        
        return saved_count
        
        # Template implementation - replace with actual Filecoin discovery logic
        discovered_nodes = []
        
        try:
            # 1. Fetch node data from Filecoin network
            # node_data = self._fetch_filecoin_nodes()
            
            # 2. Parse network addresses
            # discovered_nodes = self._parse_node_addresses(node_data)
            
            # 3. Save to database
            # saved_count = self._save_nodes_to_database(discovered_nodes)
            
            self.logger.warning("FilecoinReconAgent is a template - implement actual discovery logic")
            return discovered_nodes
            
        except Exception as e:
            self.logger.error(f"❌ Failed to discover Filecoin nodes: {e}")
            return []
    
    def _fetch_filecoin_nodes(self) -> Optional[List[Dict[str, Any]]]:
        """
        Fetch node data from Filecoin network.
        
        TODO: Implement Filecoin-specific API calls
        
        Returns:
            Raw node data from network APIs
        """
        # Implement Filecoin API calls here
        # Example:
        # - Query miner registry
        # - Get active storage providers
        # - Fetch network participant information
        pass
    
    def _parse_node_addresses(self, node_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse node network addresses from API data.
        
        TODO: Implement Filecoin-specific address parsing
        
        Args:
            node_data: Raw node data from APIs
            
        Returns:
            List of parsed node information
        """
        # Implement address parsing logic here
        # Example:
        # - Extract multiaddresses
        # - Parse DNS names and IP addresses
        # - Resolve hostnames
        pass
    
    def _save_nodes_to_database(self, nodes: List[Dict[str, Any]]) -> int:
        """
        Save discovered nodes to the database.
        
        Args:
            nodes: List of discovered node information
            
        Returns:
            Number of nodes saved to database
        """
        if not nodes:
            return 0
        
        saved_count = 0
        
        try:
            with get_db_session() as session:
                for node in nodes:
                    # Check if node already exists
                    existing = session.query(ValidatorAddress).filter_by(
                        address=node["address"]
                    ).first()
                    
                    if existing:
                        # Update existing record
                        existing.active = True
                        existing.name = node.get("name") or existing.name
                        existing.source = "filecoin_recon_agent"
                    else:
                        # Create new record
                        new_validator = ValidatorAddress(
                            address=node["address"],
                            name=node.get("name"),
                            source="filecoin_recon_agent",
                            created_at=datetime.utcnow(),
                            active=True
                        )
                        session.add(new_validator)
                        saved_count += 1
                
                session.commit()
                
        except Exception as e:
            self.logger.error(f"Database error while saving nodes: {e}")
            return 0
        
        return saved_count
    
    def run(self, *args, **kwargs) -> List[Dict[str, Any]]:
        """
        Execute Filecoin reconnaissance.
        
        Returns:
            List of discovered nodes
        """
        return self.discover_nodes()


# Instructions for implementing new protocol agents:
#
# 1. Copy this template file to a new file (e.g., ethereum_agent.py)
# 2. Rename the class (e.g., EthereumReconAgent)
# 3. Update the agent_name in __init__
# 4. Implement protocol-specific discovery logic in discover_nodes()
# 5. Add any required configuration options to core/config.py
# 6. Import and register the agent in the main pipeline
#
# Example for Ethereum:
# - Query Ethereum beacon chain API for validator information
# - Parse validator public keys and network endpoints
# - Resolve execution client addresses
# - Save with source="ethereum_recon_agent"
