"""
Node scanner agent for performing comprehensive security scans.
"""

import socket
import time
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

from agents.base import ScanAgent
from core.database import get_db_session, ValidatorAddress, ValidatorScan
from core.config import Config
from scanning.scanner import Scanner
from scanning.sui_scanner import SuiSpecificScanner


class NodeScannerAgent(ScanAgent):
    """
    Comprehensive node scanning agent.
    
    This agent loads unscanned nodes from the database and performs
    comprehensive security scans including port scans, vulnerability
    detection, SSL testing, and protocol-specific checks.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize node scanner agent.
        
        Args:
            config: Configuration instance
        """
        super().__init__(config, "NodeScannerAgent")
        self.scan_interval_days = self.config.scanning.scan_interval_days
        self.sleep_between_scans = self.config.scanning.sleep_between_scans
        self.timeout_seconds = self.config.scanning.timeout_seconds
        self.max_concurrent_scans = self.config.scanning.max_concurrent_scans
        
        # Initialize scanners
        self.generic_scanner = Scanner()
        self.sui_scanner = SuiSpecificScanner()
    
    def scan_nodes(self, nodes: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """
        Perform security scans on network nodes.
        
        Args:
            nodes: Optional list of specific nodes to scan. If None, loads nodes needing scans.
            
        Returns:
            List of scan results
        """
        if nodes is None:
            nodes = self._get_nodes_needing_scan()
        
        if not nodes:
            self.logger.info("🎯 No nodes need scanning at this time")
            return []
        
        self.logger.info(f"📋 Found {len(nodes)} nodes that need scanning")
        
        scan_results = []
        
        # Process nodes with controlled concurrency
        if self.max_concurrent_scans > 1:
            scan_results = self._scan_nodes_concurrent(nodes)
        else:
            scan_results = self._scan_nodes_sequential(nodes)
        
        self.logger.info(f"✅ Completed scanning {len(scan_results)} nodes")
        return scan_results
    
    def _get_nodes_needing_scan(self) -> List[Dict[str, Any]]:
        """
        Get nodes that need scanning from the database.
        
        Returns:
            List of node information that needs scanning
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=self.scan_interval_days)
            
            with get_db_session() as session:
                # Query for validators that need scanning using SQLAlchemy ORM
                from sqlalchemy import and_, or_
                
                subquery = session.query(ValidatorScan.validator_address_id).filter(
                    ValidatorScan.scan_date > cutoff_date
                ).subquery()
                
                validators_needing_scan = session.query(ValidatorAddress).filter(
                    and_(
                        ValidatorAddress.active == True,
                        ~ValidatorAddress.id.in_(subquery)
                    )
                ).order_by(ValidatorAddress.created_at.desc()).all()
                
                nodes = []
                for validator in validators_needing_scan:
                    nodes.append({
                        'id': validator.id,
                        'address': validator.address,
                        'name': validator.name,
                        'source': validator.source
                    })
                
                return nodes
                
        except Exception as e:
            self.logger.error(f"Failed to get nodes needing scan: {e}")
            return []
    
    def _scan_nodes_sequential(self, nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scan nodes sequentially (one at a time).
        
        Args:
            nodes: List of nodes to scan
            
        Returns:
            List of scan results
        """
        scan_results = []
        
        for i, node in enumerate(nodes, 1):
            self.logger.info(f"🛡️  Scanning node {i}/{len(nodes)}: {node['address']}")
            
            try:
                result = self._scan_single_node(node)
                if result:
                    scan_results.append(result)
                    self._save_scan_result(result)
                
                # Sleep between scans to be respectful
                if i < len(nodes):
                    time.sleep(self.sleep_between_scans)
                    
            except Exception as e:
                self.logger.error(f"❌ Failed to scan {node['address']}: {e}")
                # Create failed result
                failed_result = self._create_failed_result(node, str(e))
                scan_results.append(failed_result)
                self._save_scan_result(failed_result)
        
        return scan_results
    
    def _scan_nodes_concurrent(self, nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scan nodes concurrently using thread pool.
        
        Args:
            nodes: List of nodes to scan
            
        Returns:
            List of scan results
        """
        scan_results = []
        
        with ThreadPoolExecutor(max_workers=self.max_concurrent_scans) as executor:
            # Submit scan tasks
            future_to_node = {
                executor.submit(self._scan_single_node, node): node
                for node in nodes
            }
            
            # Process completed scans
            for future in as_completed(future_to_node):
                node = future_to_node[future]
                
                try:
                    result = future.result()
                    if result:
                        scan_results.append(result)
                        self._save_scan_result(result)
                    
                except Exception as e:
                    self.logger.error(f"❌ Failed to scan {node['address']}: {e}")
                    # Create failed result
                    failed_result = self._create_failed_result(node, str(e))
                    scan_results.append(failed_result)
                    self._save_scan_result(failed_result)
        
        return scan_results
    
    def _scan_single_node(self, node: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Perform comprehensive scan on a single node.
        
        Args:
            node: Node information
            
        Returns:
            Scan result dictionary, or None if scan failed
        """
        address = node['address']
        
        try:
            # Resolve hostname to IP
            ip_address = self._resolve_hostname(address)
            if not ip_address:
                raise Exception(f"DNS resolution failed for {address}")
            
            self.logger.debug(f"🌍 Resolved {address} to IP: {ip_address}")
            
            # Perform generic security scan
            generic_result = self.generic_scanner.scan(ip_address)
            
            # Perform protocol-specific scans based on source
            protocol_result = None
            if node['source'].startswith('sui'):
                self.logger.info(f"🔍 Running Sui-specific scan for {address} (source: {node['source']})")
                protocol_result = self.sui_scanner.scan(ip_address)
                self.logger.debug(f"🔍 Sui scan result for {address}: {protocol_result}")
            # Add more protocol-specific scanners here as needed
            
            # Combine results
            scan_result = {
                'node_id': node['id'],
                'address': address,
                'ip_address': ip_address,
                'scan_date': datetime.utcnow().isoformat(),
                'generic_scan': generic_result,
                'protocol_scan': protocol_result,
                'source': node['source'],
                'failed': False
            }
            
            return scan_result
            
        except Exception as e:
            self.logger.warning(f"Scan failed for {address}: {e}")
            raise
    
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
        except socket.gaierror:
            return None
    
    def _create_failed_result(self, node: Dict[str, Any], error_message: str) -> Dict[str, Any]:
        """
        Create a failed scan result.
        
        Args:
            node: Node information
            error_message: Error message
            
        Returns:
            Failed scan result dictionary
        """
        return {
            'node_id': node['id'],
            'address': node['address'],
            'ip_address': None,
            'scan_date': datetime.utcnow().isoformat(),
            'generic_scan': None,
            'protocol_scan': None,
            'source': node['source'],
            'failed': True,
            'error_message': error_message
        }
    
    def _save_scan_result(self, result: Dict[str, Any]) -> None:
        """
        Save scan result to database.
        
        Args:
            result: Scan result to save
        """
        try:
            with get_db_session() as session:
                scan_record = ValidatorScan(
                    validator_address_id=result['node_id'],
                    scan_date=datetime.utcnow(),
                    ip_address=result.get('ip_address'),
                    score=None,  # Will be computed by ProcessAgent
                    scan_hash=None,  # Will be computed by ProcessAgent
                    scan_results=result,
                    failed=result.get('failed', False)
                )
                
                session.add(scan_record)
                session.commit()
                
                self.logger.debug(f"✅ Saved scan result for {result['address']}")
                
        except Exception as e:
            self.logger.error(f"Failed to save scan result for {result.get('address', 'unknown')}: {e}")
    
    def get_recent_scans(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Get recent scan results from database.
        
        Args:
            days: Number of days to look back
            
        Returns:
            List of recent scan results
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            with get_db_session() as session:
                scans = session.query(ValidatorScan).filter(
                    ValidatorScan.scan_date >= cutoff_date
                ).all()
                
                return [scan.to_dict() for scan in scans]
                
        except Exception as e:
            self.logger.error(f"Failed to get recent scans: {e}")
            return []
    
    def run(self, nodes: Optional[List[Dict[str, Any]]] = None, *args, **kwargs) -> List[Dict[str, Any]]:
        """
        Execute node scanning.
        
        Args:
            nodes: Optional list of specific nodes to scan
            
        Returns:
            List of scan results
        """
        return self.scan_nodes(nodes)
