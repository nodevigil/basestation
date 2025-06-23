"""
Filecoin reconnaissance agent for discovering storage providers and nodes.
Discovers peers from both a running Lotus Docker container and public Filecoin APIs.
"""

import subprocess
import re
import requests
import time
from typing import List, Dict, Any, Optional
from datetime import datetime

from pgdn.agent_modules.base import ReconAgent
from pgdn.core.database import get_db_session, ValidatorAddress, Protocol, ProtocolSignature


class FilecoinReconAgent(ReconAgent):
    """
    Filecoin network reconnaissance agent.
    Discovers peer IPs from a running Lotus Docker container and public Filecoin APIs.
    """

    def __init__(self, config: Optional[object] = None, lotus_container_name: str = "lotus"):
        """Initialize Filecoin recon agent."""
        super().__init__(config, "FilecoinReconAgent")
        self.lotus_container_name = lotus_container_name

        # API-based endpoints
        self.filecoin_api_urls = [
            "https://filfox.info/api/v1/miner/list?pageSize=100&page=1"
        ]
        self.request_timeout = 30
        self.max_retries = 3
        self.delay_between_requests = 1.0

    def discover_nodes(self) -> List[Dict[str, Any]]:
        """
        Discover Filecoin nodes from Lotus Docker peers and public APIs.
        """
        self.logger.info("🔍 Starting Filecoin peer discovery (Docker + API)...")
        
        # First, ensure we have the protocol and its signature
        protocol_id = self._get_protocol_with_signature()
        if protocol_id is None:
            self.logger.error("❌ Cannot proceed without Filecoin protocol signature. Exiting discovery.")
            return []
        
        discovered_nodes = []

        # Docker Lotus peer scraping
        try:
            peer_nodes = self.discover_peers_from_lotus(protocol_id)
            if peer_nodes:
                self.logger.info(f"🪐 Discovered {len(peer_nodes)} peers from Lotus Docker")
                discovered_nodes.extend(peer_nodes)
        except Exception as e:
            self.logger.warning(f"Failed to discover peers from Lotus: {e}")

        # API-based discovery
        for api_url in self.filecoin_api_urls:
            try:
                self.logger.info(f"📡 Querying {api_url}")
                nodes = self._query_filecoin_api(api_url, protocol_id)
                discovered_nodes.extend(nodes)
                time.sleep(self.delay_between_requests)
            except Exception as e:
                self.logger.warning(f"Failed to query {api_url}: {e}")
                continue

        # Deduplicate nodes by address
        unique_nodes = {}
        for node in discovered_nodes:
            address = node.get('address')
            if address and address not in unique_nodes:
                unique_nodes[address] = node

        final_nodes = list(unique_nodes.values())
        self.logger.info(f"🎯 Discovered {len(final_nodes)} unique Filecoin nodes from {len(discovered_nodes)} total records")
        saved_count = self._save_nodes_to_database(final_nodes)
        self.logger.info(f"💾 Saved {saved_count} new Filecoin nodes to database")
        return final_nodes

    def discover_peers_from_lotus(self, protocol_id: int) -> List[Dict[str, Any]]:
        """
        Discover peer IPs from a running Lotus Docker container using 'lotus net peers'.
        Handles format: <peer_id>, [/ip4/<ip>/tcp/<port>]
        """
        try:
            cmd = ["docker", "exec", self.lotus_container_name, "lotus", "net", "peers"]
            output = subprocess.check_output(cmd, text=True, timeout=20)
        except Exception as e:
            self.logger.warning(f"Could not exec into Lotus container '{self.lotus_container_name}': {e}")
            return []

        nodes = []
        for line in output.splitlines():
            # Match: <peer_id>, [/ip4/<ip>/tcp/<port>]
            match = re.match(r'^([^,]+), \[\/ip4\/([\d\.]+)\/tcp\/(\d+)\]', line.strip())
            if match:
                peer_id, ip, port = match.groups()
                nodes.append({
                    "address": ip,
                    "name": f"lotus_peer_{peer_id}",
                    "protocol_id": protocol_id,
                    "raw_data": {"multiaddr": f"/ip4/{ip}/tcp/{port}", "peer_id": peer_id, "port": port}
                })
        return nodes

    def _query_filecoin_api(self, api_url: str, protocol_id: int) -> List[Dict[str, Any]]:
        """Query a Filecoin API endpoint for storage provider data."""
        nodes = []
        try:
            response = requests.get(api_url, timeout=self.request_timeout)
            response.raise_for_status()
            data = response.json()
            # Handle different API response formats
            if isinstance(data, list):
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
            for provider in providers[:100]:  # Limit to first 100 for speed/test
                try:
                    node_info = self._extract_node_info(provider, protocol_id)
                    if node_info:
                        nodes.append(node_info)
                except Exception as e:
                    self.logger.debug(f"Failed to extract node info from provider: {e}")
                    continue

        except Exception as e:
            self.logger.error(f"Failed to query {api_url}: {e}")
            # Do not raise; just return what you have so far
        return nodes

    def _extract_node_info(self, provider_data: Dict[str, Any], protocol_id: int) -> Optional[Dict[str, Any]]:
        """Extract node information from provider data."""
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
        for field in address_fields:
            if field in provider_data and provider_data[field]:
                potential_address = str(provider_data[field])
                if potential_address.startswith('f'):
                    continue
                if '/ip4/' in potential_address:
                    try:
                        parts = potential_address.split('/ip4/')[1].split('/')
                        address = parts[0]
                        break
                    except Exception:
                        continue
                if self._is_valid_address(potential_address):
                    address = potential_address
                    break
        for field in name_fields:
            if field in provider_data and provider_data[field]:
                name = str(provider_data[field])
                break
        if not address:
            return None
        return {
            'address': address,
            'name': name,
            'protocol_id': protocol_id,
            'raw_data': provider_data
        }

    def _is_valid_address(self, address: str) -> bool:
        """Check if a string looks like a valid IP or hostname."""
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(ip_pattern, address) or re.match(hostname_pattern, address))

    def _save_nodes_to_database(self, nodes: List[Dict[str, Any]]) -> int:
        """Save discovered nodes to database."""
        saved_count = 0
        if not nodes:
            return 0
        with get_db_session() as session:
            for node in nodes:
                try:
                    existing = session.query(ValidatorAddress).filter_by(
                        address=node['address']
                    ).first()
                    if not existing:
                        validator_address = ValidatorAddress(
                            address=node['address'],
                            name=node.get('name'),
                            protocol_id=node['protocol_id'],
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

    def _get_protocol_with_signature(self) -> Optional[int]:
        """
        Get the Filecoin protocol ID and ensure it has a signature.
        
        Returns:
            Protocol ID if protocol exists and has signature, None otherwise
        """
        try:
            with get_db_session() as session:
                protocol = session.query(Protocol).filter_by(name="filecoin").first()
                
                if not protocol:
                    self.logger.error("❌ Filecoin protocol not found in database. Please run protocol seeder first.")
                    return None
                
                # Check if protocol has a signature
                signature = session.query(ProtocolSignature).filter_by(protocol_id=protocol.id).first()
                
                if not signature:
                    self.logger.error(f"❌ Filecoin protocol (ID: {protocol.id}) has no signature. Please run signature generation first.")
                    return None
                
                self.logger.debug(f"✅ Found Filecoin protocol (ID: {protocol.id}) with signature")
                return protocol.id
                
        except Exception as e:
            self.logger.error(f"❌ Failed to get Filecoin protocol: {e}")
            return None

    def run(self, *args, **kwargs) -> List[Dict[str, Any]]:
        """
        Execute Filecoin reconnaissance.
        Discovers peers from Docker and public APIs.
        """
        return self.discover_nodes()

