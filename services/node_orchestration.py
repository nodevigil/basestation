"""
Node Orchestration Service

Handles the orchestration logic for node scanning workflows based on
organization validation and node status.
"""

from typing import Dict, Any, Optional
import uuid
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from models.validator import Organization, Node, Protocol
from pgdn.core.database import get_db_session


class NodeOrchestrationService:
    """Service for managing node scanning orchestration."""
    
    def __init__(self):
        pass
    
    def validate_scan_request(self, org_id: str, target: str, protocol_filter: Optional[str] = None, infrastructure_only: bool = False) -> Dict[str, Any]:
        """
        Validate a scan request and determine the appropriate workflow.
        
        Args:
            org_id: Organization UUID string
            target: Target IP/hostname to scan
            protocol_filter: Optional protocol name filter
            infrastructure_only: If True, bypass protocol requirements for infrastructure scans
            
        Returns:
            Dict containing validation results and next action
        """
        try:
            org_uuid = uuid.UUID(org_id)
        except (ValueError, TypeError):
            return {
                "success": False,
                "error": "Invalid organization ID format - must be a valid UUID",
                "next_action": None
            }
        
        with get_db_session() as session:
            # 1. Validate organization exists
            org = session.query(Organization).filter(Organization.uuid == org_id).first()
            if not org:
                return {
                    "success": False,
                    "error": "Organisation not found",
                    "next_action": None
                }
            
            if not org.is_active:
                return {
                    "success": False,
                    "error": "Organisation is not active",
                    "next_action": None
                }
            
            # 2. Check if node exists in the database
            node = self._find_node_by_target(session, target, org_id)
            
            if not node:
                # Node doesn't exist - create it
                node = self._create_new_node(session, target, org_id)
                session.commit()
            
            # 3. Determine workflow based on node status and protocol
            return self._determine_workflow(session, node, protocol_filter, infrastructure_only)
    
    def _find_node_by_target(self, session: Session, target: str, org_id: str) -> Optional[Node]:
        """Find a node by target (IP/hostname) and organization."""
        # Look for node with target in meta field
        nodes = session.query(Node).filter(
            Node.org_id == org_id
        ).all()
        
        for node in nodes:
            if node.meta and (
                node.meta.get('ip') == target or 
                node.meta.get('hostname') == target or
                node.meta.get('target') == target
            ):
                return node
        
        return None
    
    def _create_new_node(self, session: Session, target: str, org_id: str) -> Node:
        """Create a new node record."""
        meta = {
            'target': target,
            'ip': target if self._is_ip_address(target) else None,
            'hostname': target if not self._is_ip_address(target) else None
        }
        
        node = Node(
            org_id=org_id,
            status='new',
            meta=meta
        )
        
        session.add(node)
        session.flush()  # Get the UUID
        return node
    
    def _determine_workflow(self, session: Session, node: Node, protocol_filter: Optional[str], infrastructure_only: bool = False) -> Dict[str, Any]:
        """Determine the appropriate workflow based on node status and protocol."""
        
        # If protocol filter is provided, try to find the protocol
        protocol = None
        if protocol_filter:
            protocol = session.query(Protocol).filter(Protocol.name == protocol_filter).first()
            if not protocol:
                return {
                    "success": False,
                    "error": f"Protocol '{protocol_filter}' not found",
                    "next_action": None
                }
        
        # Workflow logic based on node status
        if node.status == 'new':
            if protocol_filter and protocol:
                # Protocol provided - update node and proceed to scan
                node.protocol_id = protocol.id
                node.status = 'discovered'
                session.commit()
                
                return {
                    "success": True,
                    "status": "ready_to_scan",
                    "node_id": str(node.uuid),
                    "org_id": str(node.org_id),
                    "protocol": protocol.name,
                    "next_action": None
                }
            elif infrastructure_only:
                # Infrastructure-only scan - can proceed without protocol
                node.status = 'infrastructure_scanned'
                session.commit()
                
                return {
                    "success": True,
                    "status": "ready_to_scan",
                    "node_id": str(node.uuid),
                    "org_id": str(node.org_id),
                    "protocol": None,
                    "next_action": None
                }
            else:
                # No protocol provided - discovery required
                return {
                    "success": False,
                    "error": "Protocol not provided and node requires discovery",
                    "next_action": "run-discovery",
                    "node_id": str(node.uuid),
                    "org_id": str(node.org_id)
                }
        
        elif node.status == 'discovered':
            if node.protocol_id:
                # Node has been discovered with protocol - ready to scan
                protocol_obj = session.query(Protocol).filter(Protocol.id == node.protocol_id).first()
                return {
                    "success": True,
                    "status": "ready_to_scan",
                    "node_id": str(node.uuid),
                    "org_id": str(node.org_id),
                    "protocol": protocol_obj.name if protocol_obj else None,
                    "next_action": None
                }
            else:
                # Discovery incomplete - need to run discovery
                return {
                    "success": False,
                    "error": "Node discovery incomplete - no protocol identified",
                    "next_action": "run-discovery",
                    "node_id": str(node.uuid),
                    "org_id": str(node.org_id)
                }
        
        elif node.status == 'scanned':
            # Node already scanned - check if it has a protocol
            if node.protocol_id:
                protocol_obj = session.query(Protocol).filter(Protocol.id == node.protocol_id).first()
                return {
                    "success": True,
                    "status": "ready_to_scan",
                    "node_id": str(node.uuid),
                    "org_id": str(node.org_id),
                    "protocol": protocol_obj.name if protocol_obj else None,
                    "next_action": None,
                    "note": "Node previously scanned - will rescan"
                }
            else:
                # Node was scanned but has no protocol - requires discovery
                return {
                    "success": False,
                    "error": "Node has been scanned but no protocol identified - requires discovery",
                    "next_action": "run-discovery",
                    "node_id": str(node.uuid),
                    "org_id": str(node.org_id)
                }
        
        elif node.status == 'error':
            # Node in error state - can retry
            return {
                "success": True,
                "status": "ready_to_scan",
                "node_id": str(node.uuid),
                "org_id": str(node.org_id),
                "protocol": None,
                "next_action": None,
                "note": "Node in error state - will retry scan"
            }
        
        else:
            return {
                "success": False,
                "error": f"Unknown node status: {node.status}",
                "next_action": None
            }
    
    def update_node_after_discovery(self, node_id: str, protocol_name: str) -> Dict[str, Any]:
        """Update node after successful discovery."""
        try:
            node_uuid = uuid.UUID(node_id)
        except (ValueError, TypeError):
            return {
                "success": False,
                "error": "Invalid node ID format"
            }
        
        with get_db_session() as session:
            node = session.query(Node).filter(Node.uuid == node_uuid).first()
            if not node:
                return {
                    "success": False,
                    "error": "Node not found"
                }
            
            # Find protocol
            protocol = session.query(Protocol).filter(Protocol.name == protocol_name).first()
            if not protocol:
                return {
                    "success": False,
                    "error": f"Protocol '{protocol_name}' not found"
                }
            
            # Update node
            node.protocol_id = protocol.id
            node.status = 'discovered'
            session.commit()
            
            return {
                "success": True,
                "message": f"Node {node_id} updated with protocol {protocol_name}",
                "node_id": node_id,
                "protocol": protocol_name,
                "status": "discovered"
            }
    
    def update_node_after_scan(self, node_id: str, scan_successful: bool = True) -> Dict[str, Any]:
        """Update node status after scan completion."""
        try:
            node_uuid = uuid.UUID(node_id)
        except (ValueError, TypeError):
            return {
                "success": False,
                "error": "Invalid node ID format"
            }
        
        with get_db_session() as session:
            node = session.query(Node).filter(Node.uuid == node_uuid).first()
            if not node:
                return {
                    "success": False,
                    "error": "Node not found"
                }
            
            # Update status based on scan result
            node.status = 'scanned' if scan_successful else 'error'
            session.commit()
            
            return {
                "success": True,
                "message": f"Node {node_id} marked as {node.status}",
                "node_id": node_id,
                "status": node.status
            }
    
    def get_node_info(self, node_id: str) -> Dict[str, Any]:
        """Get node information by ID."""
        try:
            node_uuid = uuid.UUID(node_id)
        except (ValueError, TypeError):
            return {
                "success": False,
                "error": "Invalid node ID format"
            }
        
        with get_db_session() as session:
            node = session.query(Node).filter(Node.uuid == node_uuid).first()
            if not node:
                return {
                    "success": False,
                    "error": "Node not found"
                }
            
            protocol_name = None
            if node.protocol_id:
                protocol = session.query(Protocol).filter(Protocol.id == node.protocol_id).first()
                protocol_name = protocol.name if protocol else None
            
            return {
                "success": True,
                "node": {
                    "uuid": str(node.uuid),
                    "org_id": str(node.org_id),
                    "status": node.status,
                    "protocol": protocol_name,
                    "meta": node.meta,
                    "created_at": node.created_at.isoformat() if node.created_at else None,
                    "updated_at": node.updated_at.isoformat() if node.updated_at else None
                }
            }
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
