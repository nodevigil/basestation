"""
Filecoin reconnaissance agent for discovering storage providers and nodes.
NOW: Only discovers peers from a running Lotus Docker container.
"""

import subprocess
import re
from typing import List, Dict, Any, Optional
from datetime import datetime

from agents.base import ReconAgent
from core.database import get_db_session, ValidatorAddress


class FilecoinReconAgent(ReconAgent):
    """
    Filecoin network reconnaissance agent.
    This version only discovers peer IPs from a running Lotus Docker container.
    """

    def __init__(self, config: Optional[object] = None, lotus_container_name: str = "lotus"):
        """Initialize Filecoin recon agent."""
        super().__init__(config, "FilecoinReconAgent")
        self.lotus_container_name = lotus_container_name

        # # Filecoin network endpoints (DISABLED)
        # self.filecoin_api_urls = [
        #     "https://filfox.info/api/v1/storage-provider/list",
        #     "https://spacegap.github.io/database/miners.json",
        # ]
        # self.request_timeout = 30
        # self.max_retries = 3
        # self.delay_between_requests = 1.0

    def discover_nodes(self) -> List[Dict[str, Any]]:
        """
        Discover Filecoin nodes from running Lotus Docker peer list.
        """
        discovered_nodes = []
        self.logger.info("🔍 Starting Filecoin Docker Lotus peer reconnaissance...")

        # # API-based discovery (DISABLED)
        # for api_url in self.filecoin_api_urls:
        #     try:
        #         self.logger.info(f"📡 Querying {api_url}")
        #         nodes = self._query_filecoin_api(api_url)
        #         discovered_nodes.extend(nodes)
        #         time.sleep(self.delay_between_requests)
        #     except Exception as e:
        #         self.logger.warning(f"Failed to query {api_url}: {e}")
        #         continue

        # Lotus peer scraping (ENABLED)
        try:
            peer_nodes = self.discover_peers_from_lotus()
            if peer_nodes:
                self.logger.info(f"🪐 Discovered {len(peer_nodes)} peers from Lotus Docker")
                discovered_nodes.extend(peer_nodes)
        except Exception as e:
            self.logger.warning(f"Failed to discover peers from Lotus: {e}")

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

    def discover_peers_from_lotus(self) -> List[Dict[str, Any]]:
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
                    "source": "filecoin_lotus_peer",
                    "raw_data": {"multiaddr": f"/ip4/{ip}/tcp/{port}", "peer_id": peer_id, "port": port}
                })
        return nodes

    # Commented-out API-based node extraction logic
    # def _query_filecoin_api(self, api_url: str) -> List[Dict[str, Any]]:
    #     pass

    # def _extract_node_info(self, provider_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    #     pass

    # def _is_valid_address(self, address: str) -> bool:
    #     pass

    def _save_nodes_to_database(self, nodes: List[Dict[str, Any]]) -> int:
        """Save discovered nodes to database."""
        saved_count = 0
        if not nodes:
            return 0
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

    def run(self, *args, **kwargs) -> List[Dict[str, Any]]:
        """
        Execute Filecoin reconnaissance.
        Only runs Docker-based Lotus peer discovery.
        """
        return self.discover_nodes()

