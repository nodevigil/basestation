"""
Sui network reconnaissance agent for discovering validator nodes.
"""

import requests
import re
import socket
from typing import List, Dict, Any, Optional
from datetime import datetime

from agents.base import ReconAgent
from core.database import get_db_session, ValidatorAddress, Protocol, ProtocolSignature
from core.config import Config


class SuiReconAgent(ReconAgent):
    """
    Reconnaissance agent for discovering Sui network validator nodes.
    
    This agent queries the Sui RPC endpoint to discover active validators
    and saves their network addresses to the database.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize Sui reconnaissance agent.
        
        Args:
            config: Configuration instance
        """
        super().__init__(config, "SuiReconAgent")
        self.rpc_url = self.config.recon.sui_rpc_url
        self.dns_timeout = self.config.recon.dns_timeout
        self.max_retries = self.config.recon.max_retries
    
    def discover_nodes(self) -> List[Dict[str, Any]]:
        """
        Discover Sui validator nodes from the network.
        
        Returns:
            List of discovered validator node information
        """
        self.logger.info(f"🔍 Discovering Sui validators from {self.rpc_url}")
        
        # First, ensure we have the protocol and its signature
        protocol_id = self._get_protocol_with_signature()
        if protocol_id is None:
            self.logger.error("❌ Cannot proceed without Sui protocol signature. Exiting discovery.")
            return []
        
        try:
            # Fetch validator data from Sui RPC
            validator_data = self._fetch_validator_data()
            
            if not validator_data:
                self.logger.warning("No validator data received from Sui RPC")
                return []
            
            # Parse validator addresses
            discovered_nodes = self._parse_validator_addresses(validator_data, protocol_id)
            
            # Save to database
            saved_count = self._save_nodes_to_database(discovered_nodes)
            
            self.logger.info(f"✅ Discovered {len(discovered_nodes)} validators, saved {saved_count} to database")
            
            return discovered_nodes
            
        except Exception as e:
            self.logger.error(f"❌ Failed to discover Sui validators: {e}")
            return []
    
    def _fetch_validator_data(self) -> Optional[List[Dict[str, Any]]]:
        """
        Fetch validator data from Sui RPC endpoint.
        
        Returns:
            Raw validator data from RPC, or None if failed
        """
        headers = {"Content-Type": "application/json"}
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "suix_getLatestSuiSystemState",
            "params": []
        }
        
        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    self.rpc_url,
                    json=payload,
                    headers=headers,
                    timeout=self.dns_timeout
                )
                response.raise_for_status()
                
                data = response.json()
                if "result" in data and "activeValidators" in data["result"]:
                    return data["result"]["activeValidators"]
                else:
                    self.logger.warning(f"Unexpected response format: {data}")
                    return None
                    
            except requests.exceptions.RequestException as e:
                self.logger.warning(f"RPC request failed (attempt {attempt + 1}/{self.max_retries}): {e}")
                if attempt == self.max_retries - 1:
                    raise
                    
        return None
    
    def _parse_validator_addresses(self, validator_data: List[Dict[str, Any]], protocol_id: int) -> List[Dict[str, Any]]:
        """
        Parse validator network addresses from RPC data.
        
        Args:
            validator_data: Raw validator data from RPC
            protocol_id: ID of the Sui protocol from the database
            
        Returns:
            List of parsed validator node information
        """
        discovered_nodes = []
        
        for validator in validator_data:
            try:
                # Extract network address
                net_address = validator.get("netAddress") or validator.get("net_address", "")
                if not net_address:
                    continue
                
                # Parse DNS hostname from address (e.g., "/dns/example.com/tcp/8080")
                dns_match = re.search(r"/dns/([\w\.\-]+)/", net_address)
                if not dns_match:
                    continue
                
                hostname = dns_match.group(1)
                validator_name = validator.get("name") or validator.get("name", None)
                
                # Try to resolve hostname to IP
                ip_address = self._resolve_hostname(hostname)
                
                node_info = {
                    "address": hostname,
                    "name": validator_name,
                    "protocol_id": protocol_id,
                    "ip_address": ip_address,
                    "raw_net_address": net_address,
                    "discovered_at": datetime.utcnow().isoformat()
                }
                
                discovered_nodes.append(node_info)
                
            except Exception as e:
                self.logger.warning(f"Failed to parse validator data: {e}")
                continue
        
        return discovered_nodes
    
    def _resolve_hostname(self, hostname: str) -> Optional[str]:
        """
        Resolve hostname to IP address.
        
        Args:
            hostname: Hostname to resolve
            
        Returns:
            IP address string, or None if resolution failed
        """
        try:
            ip_address = socket.gethostbyname(hostname)
            return ip_address
        except socket.gaierror as e:
            self.logger.debug(f"DNS resolution failed for {hostname}: {e}")
            return None
    
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
                    try:
                        # Check if validator already exists
                        existing = session.query(ValidatorAddress).filter_by(
                            address=node["address"]
                        ).first()
                        
                        if existing:
                            # Update existing record
                            existing.active = True
                            existing.name = node.get("name") or existing.name
                            existing.protocol_id = node["protocol_id"]
                            self.logger.debug(f"Updated existing validator: {node['address']}")
                        else:
                            # Create new record
                            new_validator = ValidatorAddress(
                                address=node["address"],
                                name=node.get("name"),
                                protocol_id=node["protocol_id"],
                                created_at=datetime.utcnow(),
                                active=True
                            )
                            session.add(new_validator)
                            saved_count += 1
                            self.logger.debug(f"Added new validator: {node['address']}")
                            
                    except Exception as e:
                        self.logger.warning(f"Failed to save validator {node.get('address', 'unknown')}: {e}")
                        continue
                
                session.commit()
                
        except Exception as e:
            self.logger.error(f"Database error while saving validators: {e}")
            return 0
        
        return saved_count
    
    def get_active_validators(self) -> List[Dict[str, Any]]:
        """
        Get active validators from the database.
        
        Returns:
            List of active validator information
        """
        try:
            with get_db_session() as session:
                # Get the Sui protocol
                sui_protocol = session.query(Protocol).filter_by(name="sui").first()
                if not sui_protocol:
                    self.logger.error("Sui protocol not found in database")
                    return []
                
                validators = session.query(ValidatorAddress).filter_by(
                    active=True,
                    protocol_id=sui_protocol.id
                ).all()
                
                return [validator.to_dict() for validator in validators]
                
        except Exception as e:
            self.logger.error(f"Failed to get active validators: {e}")
            return []
    
    def _get_protocol_with_signature(self) -> Optional[int]:
        """
        Get the Sui protocol ID and ensure it has a signature.
        
        Returns:
            Protocol ID if protocol exists and has signature, None otherwise
        """
        try:
            with get_db_session() as session:
                protocol = session.query(Protocol).filter_by(name="sui").first()
                
                if not protocol:
                    self.logger.error("❌ Sui protocol not found in database. Please run protocol seeder first.")
                    return None
                
                # Check if protocol has a signature
                signature = session.query(ProtocolSignature).filter_by(protocol_id=protocol.id).first()
                
                if not signature:
                    self.logger.error(f"❌ Sui protocol (ID: {protocol.id}) has no signature. Please run signature generation first.")
                    return None
                
                self.logger.debug(f"✅ Found Sui protocol (ID: {protocol.id}) with signature")
                return protocol.id
                
        except Exception as e:
            self.logger.error(f"❌ Failed to get Sui protocol: {e}")
            return None

    def run(self, *args, **kwargs) -> List[Dict[str, Any]]:
        """
        Execute Sui reconnaissance.
        
        Returns:
            List of discovered validator nodes
        """
        return self.discover_nodes()
