"""
Test suite for node orchestration workflow functionality.

Tests the complete orchestration workflow including:
- Organization validation
- Node creation and state management
- Discovery workflow enforcement
- Scanner integration
- CLI integration
"""

import pytest
import uuid
from datetime import datetime
from unittest.mock import patch, MagicMock
import sqlalchemy

from services.node_orchestration import NodeOrchestrationService
from models.validator import Organization, Node, Protocol
from pgdn.scanner import Scanner
from pgdn.core.config import Config


class TestNodeOrchestrationService:
    """Test the NodeOrchestrationService class."""
    
    @pytest.fixture
    def orchestration_service(self):
        """Create orchestration service instance."""
        return NodeOrchestrationService()
    
    @pytest.fixture
    def test_org(self, test_session):
        """Create a test organization."""
        unique = str(uuid.uuid4())
        org = Organization(
            uuid=str(uuid.uuid4()),
            name=f"Test Organization {unique}",
            slug=f"test-org-{unique}",
            is_active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        test_session.add(org)
        test_session.commit()
        test_session.refresh(org)
        return org
    
    @pytest.fixture
    def test_protocol(self, test_session):
        """Create a test protocol."""
        unique = str(uuid.uuid4())
        protocol = Protocol(
            uuid=str(uuid.uuid4()),
            name=f"sui-{unique}",
            display_name="Sui Network",
            category="blockchain",
            ports=[9000, 9184],
            endpoints=["/metrics", "/health"],
            banners=["sui"],
            rpc_methods=["sui_getCommitteeInfo"],
            metrics_keywords=["sui_node"],
            http_paths=["/metrics"],
            identification_hints={"ports": [9000], "keywords": ["sui"]},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        test_session.add(protocol)
        test_session.commit()
        test_session.refresh(protocol)
        return protocol
    
    def test_validate_invalid_org_id_format(self, orchestration_service):
        """Test validation with invalid organization ID format."""
        result = orchestration_service.validate_scan_request(
            org_id="invalid-uuid",
            target="192.168.1.1"
        )
        
        assert result["success"] is False
        assert "Invalid organization ID format" in result["error"]
        assert result["next_action"] is None
    
    def test_validate_nonexistent_organization(self, orchestration_service):
        """Test validation with non-existent organization."""
        fake_uuid = str(uuid.uuid4())
        result = orchestration_service.validate_scan_request(
            org_id=fake_uuid,
            target="192.168.1.1"
        )
        
        assert result["success"] is False
        assert result["error"] == "Organisation not found"
        assert result["next_action"] is None
    
    def test_validate_inactive_organization(self, orchestration_service, test_session):
        """Test validation with inactive organization."""
        # Create inactive organization
        unique = str(uuid.uuid4())
        org = Organization(
            uuid=str(uuid.uuid4()),
            name=f"Inactive Org {unique}",
            slug=f"inactive-org-{unique}",
            is_active=False,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        test_session.add(org)
        test_session.commit()
        
        result = orchestration_service.validate_scan_request(
            org_id=org.uuid,
            target="192.168.1.1"
        )
        
        assert result["success"] is False
        assert result["error"] == "Organisation is not active"
        assert result["next_action"] is None
    
    def test_new_node_without_protocol_requires_discovery(self, orchestration_service, test_org):
        """Test that new node without protocol requires discovery."""
        result = orchestration_service.validate_scan_request(
            org_id=test_org.uuid,
            target="192.168.1.100"
        )
        
        assert result["success"] is False
        assert result["error"] == "Protocol not provided and node requires discovery"
        assert result["next_action"] == "run-discovery"
        assert "node_id" in result
        assert result["org_id"] == test_org.uuid
    
    def test_new_node_with_protocol_ready_to_scan(self, orchestration_service, test_org, test_protocol):
        """Test that new node with protocol is ready to scan."""
        result = orchestration_service.validate_scan_request(
            org_id=test_org.uuid,
            target="192.168.1.200",
            protocol_filter=test_protocol.name
        )
        
        assert result["success"] is True
        assert result["status"] == "ready_to_scan"
        assert result["protocol"] == test_protocol.name
        assert result["next_action"] is None
        assert "node_id" in result
    
    def test_discovered_node_ready_to_scan(self, orchestration_service, test_org, test_protocol, test_session):
        """Test that discovered node with protocol is ready to scan."""
        # Create a discovered node
        node = Node(
            org_id=test_org.uuid,
            status="discovered",
            protocol_id=test_protocol.id,
            meta={"target": "192.168.1.150", "ip": "192.168.1.150"},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        test_session.add(node)
        test_session.commit()
        
        result = orchestration_service.validate_scan_request(
            org_id=test_org.uuid,
            target="192.168.1.150"
        )
        
        assert result["success"] is True
        assert result["status"] == "ready_to_scan"
        assert result["protocol"] == test_protocol.name
        assert result["next_action"] is None
    
    def test_update_node_after_discovery(self, orchestration_service, test_org, test_protocol, test_session):
        """Test updating node after discovery completion."""
        # Create a new node
        node = Node(
            org_id=test_org.uuid,
            status="new",
            meta={"target": "192.168.1.175", "ip": "192.168.1.175"},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        test_session.add(node)
        test_session.commit()
        
        result = orchestration_service.update_node_after_discovery(
            node_id=str(node.uuid),
            protocol_name=test_protocol.name
        )
        
        assert result["success"] is True
        assert result["protocol"] == test_protocol.name
        assert result["status"] == "discovered"
        
        # Verify node was actually updated
        test_session.refresh(node)
        assert node.status == "discovered"
        assert node.protocol_id == test_protocol.id
    
    def test_update_node_after_scan_success(self, orchestration_service, test_org, test_protocol, test_session):
        """Test updating node after successful scan."""
        # Create a discovered node
        node = Node(
            org_id=test_org.uuid,
            status="discovered",
            protocol_id=test_protocol.id,
            meta={"target": "192.168.1.180", "ip": "192.168.1.180"},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        test_session.add(node)
        test_session.commit()
        
        result = orchestration_service.update_node_after_scan(
            node_id=str(node.uuid),
            scan_successful=True
        )
        
        assert result["success"] is True
        assert result["status"] == "scanned"
        
        # Verify node was actually updated
        test_session.refresh(node)
        assert node.status == "scanned"
    
    def test_update_node_after_scan_failure(self, orchestration_service, test_org, test_protocol, test_session):
        """Test updating node after failed scan."""
        # Create a discovered node
        node = Node(
            org_id=test_org.uuid,
            status="discovered",
            protocol_id=test_protocol.id,
            meta={"target": "192.168.1.185", "ip": "192.168.1.185"},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        test_session.add(node)
        test_session.commit()
        
        result = orchestration_service.update_node_after_scan(
            node_id=str(node.uuid),
            scan_successful=False
        )
        
        assert result["success"] is True
        assert result["status"] == "error"
        
        # Verify node was actually updated
        test_session.refresh(node)
        assert node.status == "error"
    
    def test_get_node_info(self, orchestration_service, test_org, test_protocol, test_session):
        """Test getting node information."""
        # Create a node
        node = Node(
            org_id=test_org.uuid,
            status="discovered",
            protocol_id=test_protocol.id,
            meta={"target": "192.168.1.190", "ip": "192.168.1.190"},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        test_session.add(node)
        test_session.commit()
        
        result = orchestration_service.get_node_info(str(node.uuid))
        
        assert result["success"] is True
        assert "node" in result
        node_info = result["node"]
        assert node_info["uuid"] == str(node.uuid)
        assert node_info["org_id"] == test_org.uuid
        assert node_info["status"] == "discovered"
        assert node_info["protocol"] == test_protocol.name
        assert node_info["meta"]["target"] == "192.168.1.190"


class TestScannerOrchestrationIntegration:
    """Test Scanner integration with orchestration workflow."""
    
    @pytest.fixture
    def mock_config(self):
        """Create a mock configuration."""
        return MagicMock(spec=Config)
    
    @pytest.fixture
    def test_org(self, test_session):
        """Create a test organization."""
        unique = str(uuid.uuid4())
        org = Organization(
            uuid=str(uuid.uuid4()),
            name=f"Scanner Test Org {unique}",
            slug=f"scanner-test-org-{unique}",
            is_active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        test_session.add(org)
        test_session.commit()
        test_session.refresh(org)
        return org
    
    def test_scanner_requires_org_id(self, mock_config):
        """Test that scanner requires org_id for target scanning."""
        scanner = Scanner(mock_config)
        
        result = scanner.scan_target("192.168.1.1")
        
        assert result["success"] is False
        assert "Organization ID is required" in result["error"]
    
    @patch('pgdn.agent_modules.scan.node_scanner_agent.NodeScannerAgent')
    def test_scanner_orchestration_discovery_required(self, mock_scanner_agent, mock_config, test_org):
        """Test scanner orchestration when discovery is required."""
        scanner = Scanner(mock_config, protocol_filter=None)
        
        # Mock the scanner agent to avoid actual scanning
        mock_scanner_agent.return_value.scan_nodes.return_value = [{"mock": "result"}]
        
        # This should trigger discovery requirement
        result = scanner.scan_target("192.168.1.222", org_id=test_org.uuid)
        
        assert result["success"] is False
        assert result["error"] == "Protocol not provided and node requires discovery"
        assert result["next_action"] == "run-discovery"
        assert "node_id" in result
    
    @patch('pgdn.agent_modules.scan.node_scanner_agent.NodeScannerAgent')
    def test_scanner_orchestration_with_protocol(self, mock_scanner_agent, mock_config, test_org, test_session):
        """Test scanner orchestration with protocol provided."""
        # Create test protocol
        unique = str(uuid.uuid4())
        protocol = Protocol(
            uuid=str(uuid.uuid4()),
            name=f"filecoin-{unique}",
            display_name="Filecoin",
            category="storage",
            ports=[1234, 5678],
            endpoints=["/api/v0/id"],
            banners=["filecoin"],
            rpc_methods=["Filecoin.ID"],
            metrics_keywords=["filecoin"],
            http_paths=["/api/v0/id"],
            identification_hints={"ports": [1234], "keywords": ["filecoin"]},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        test_session.add(protocol)
        test_session.commit()
        
        scanner = Scanner(mock_config, protocol_filter=protocol.name)
        
        # Mock the scanner agent
        mock_agent_instance = mock_scanner_agent.return_value
        mock_agent_instance.scan_nodes.return_value = [{"mock": "scan_result"}]
        
        result = scanner.scan_target("192.168.1.233", org_id=test_org.uuid)
        
        assert result["success"] is True
        assert result["protocol"] == protocol.name
        assert "node_id" in result
        assert "scan_result" in result


class TestOrganizationUUIDTrigger:
    """Test the PostgreSQL UUID trigger for organizations."""
    
    def test_organization_uuid_auto_generated(self, test_session):
        """Test that UUID is automatically generated for new organizations."""
        # Create organization without specifying UUID
        unique = str(uuid.uuid4())
        org = Organization(
            name=f"Auto UUID Test Org {unique}",
            slug=f"auto-uuid-test-org-{unique}",
            is_active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        # UUID should be None before insert
        assert org.uuid is None
        
        test_session.add(org)
        test_session.commit()
        test_session.refresh(org)
        
        # UUID should be automatically generated
        assert org.uuid is not None
        assert len(org.uuid) == 36  # Standard UUID string length
        # Verify it's a valid UUID format
        uuid_obj = uuid.UUID(org.uuid)
        assert str(uuid_obj) == org.uuid
    
    def test_organization_uuid_preserved_when_provided(self, test_session):
        """Test that manually provided UUID is preserved."""
        custom_uuid = str(uuid.uuid4())
        unique = str(uuid.uuid4())
        
        org = Organization(
            uuid=custom_uuid,
            name=f"Custom UUID Test Org {unique}",
            slug=f"custom-uuid-test-org-{unique}",
            is_active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        test_session.add(org)
        test_session.commit()
        test_session.refresh(org)
        
        # Custom UUID should be preserved
        assert org.uuid == custom_uuid


class TestNodeTableIntegration:
    """Test the nodes table and its relationships."""
    
    @pytest.fixture
    def test_org(self, test_session):
        """Create a test organization."""
        unique = str(uuid.uuid4())
        org = Organization(
            uuid=str(uuid.uuid4()),
            name=f"Node Test Org {unique}",
            slug=f"node-test-org-{unique}",
            is_active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        test_session.add(org)
        test_session.commit()
        test_session.refresh(org)
        return org
    
    @pytest.fixture
    def test_protocol(self, test_session):
        """Create a test protocol."""
        unique = str(uuid.uuid4())
        protocol = Protocol(
            uuid=str(uuid.uuid4()),
            name=f"ethereum-{unique}",
            display_name="Ethereum",
            category="blockchain",
            ports=[8545, 30303],
            endpoints=["/"],
            banners=["geth"],
            rpc_methods=["eth_blockNumber"],
            metrics_keywords=["ethereum"],
            http_paths=["/"],
            identification_hints={"ports": [8545], "keywords": ["ethereum"]},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        test_session.add(protocol)
        test_session.commit()
        test_session.refresh(protocol)
        return protocol
    
    def test_create_node_with_organization(self, test_session, test_org):
        """Test creating a node with organization relationship."""
        node = Node(
            org_id=test_org.uuid,
            status="new",
            meta={"target": "192.168.1.250", "ip": "192.168.1.250"},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        test_session.add(node)
        test_session.commit()
        test_session.refresh(node)
        
        # Verify node was created
        assert node.uuid is not None
        assert node.org_id == test_org.uuid
        assert node.status == "new"
        assert node.meta["target"] == "192.168.1.250"
        
        # Test relationship
        assert node.organization.name == test_org.name
    
    def test_create_node_with_protocol(self, test_session, test_org, test_protocol):
        """Test creating a node with protocol relationship."""
        node = Node(
            org_id=test_org.uuid,
            status="discovered",
            protocol_id=test_protocol.id,
            meta={"target": "192.168.1.251", "ip": "192.168.1.251"},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        test_session.add(node)
        test_session.commit()
        test_session.refresh(node)
        
        # Verify relationships
        assert node.organization.name == test_org.name
        assert node.protocol.name == test_protocol.name
        assert node.protocol_id == test_protocol.id
    
    def test_node_status_transitions(self, test_session, test_org, test_protocol):
        """Test node status transitions through workflow."""
        # Create new node
        node = Node(
            org_id=test_org.uuid,
            status="new",
            meta={"target": "192.168.1.252", "ip": "192.168.1.252"},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        test_session.add(node)
        test_session.commit()
        
        # Transition to discovered
        node.status = "discovered"
        node.protocol_id = test_protocol.id
        test_session.commit()
        test_session.refresh(node)
        
        assert node.status == "discovered"
        assert node.protocol_id == test_protocol.id
        
        # Transition to scanned
        node.status = "scanned"
        test_session.commit()
        test_session.refresh(node)
        
        assert node.status == "scanned"
    
    def test_multiple_nodes_per_organization(self, test_session, test_org):
        """Test that organizations can have multiple nodes."""
        nodes = []
        for i in range(3):
            node = Node(
                org_id=test_org.uuid,
                status="new",
                meta={"target": f"192.168.1.{253+i}", "ip": f"192.168.1.{253+i}"},
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            test_session.add(node)
            nodes.append(node)
        
        test_session.commit()
        
        # Verify all nodes are associated with the organization
        for node in nodes:
            test_session.refresh(node)
            assert node.org_id == test_org.uuid
            assert node.organization.name == test_org.name
        
        # Verify organization has multiple nodes
        test_session.refresh(test_org)
        assert len(test_org.nodes) == 3


class TestDiscoveryAgentIntegration:
    """Test Discovery agent integration with orchestration."""
    
    @pytest.fixture
    def test_org(self, test_session):
        """Create a test organization."""
        unique = str(uuid.uuid4())
        org = Organization(
            uuid=str(uuid.uuid4()),
            name=f"Discovery Test Org {unique}",
            slug=f"discovery-test-org-{unique}",
            is_active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        test_session.add(org)
        test_session.commit()
        test_session.refresh(org)
        return org
    
    @pytest.fixture
    def test_protocol(self, test_session):
        """Create a test protocol."""
        unique = str(uuid.uuid4())
        protocol = Protocol(
            uuid=str(uuid.uuid4()),
            name=f"sui-{unique}",
            display_name="Sui Network",
            category="blockchain",
            ports=[9000, 9184],
            endpoints=["/metrics"],
            banners=["sui"],
            rpc_methods=["sui_getCommitteeInfo"],
            metrics_keywords=["sui_node"],
            http_paths=["/metrics"],
            identification_hints={"ports": [9000], "keywords": ["sui"]},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        test_session.add(protocol)
        test_session.commit()
        test_session.refresh(protocol)
        return protocol
    
    @patch('pgdn.agent_modules.discovery.discovery_agent.DiscoveryAgent.run')
    def test_discover_node_success(self, mock_run, test_org, test_protocol, test_session):
        """Test successful node discovery with orchestration update."""
        from pgdn.agent_modules.discovery.discovery_agent import DiscoveryAgent
        from pgdn.core.config import Config
        
        # Create a node for discovery
        node = Node(
            org_id=test_org.uuid,
            status="new",
            meta={"target": "192.168.1.100", "ip": "192.168.1.100"},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        test_session.add(node)
        test_session.commit()
        
        # Mock discovery result using the actual protocol name from the fixture
        mock_run.return_value = [{
            "host": "192.168.1.100",
            "protocol": test_protocol.name,  # Use the actual protocol name with UUID
            "confidence": "high",
            "confidence_score": 0.9
        }]
        
        # Create discovery agent and test node discovery
        config = MagicMock(spec=Config)
        discovery_agent = DiscoveryAgent(config)
        
        result = discovery_agent.discover_node(
            node_id=str(node.uuid),
            host="192.168.1.100"
        )
        
        assert result["success"] is True
        assert result["protocol"] == test_protocol.name
        assert "orchestration_update" in result
        
        # Verify node was updated
        test_session.refresh(node)
        assert node.status == "discovered"
        assert node.protocol_id == test_protocol.id
    
    @patch('pgdn.agent_modules.discovery.discovery_agent.DiscoveryAgent.run')
    def test_discover_node_no_protocol_found(self, mock_run, test_org, test_session):
        """Test node discovery when no protocol is identified."""
        from pgdn.agent_modules.discovery.discovery_agent import DiscoveryAgent
        from pgdn.core.config import Config
        
        # Create a node for discovery
        node = Node(
            org_id=test_org.uuid,
            status="new",
            meta={"target": "192.168.1.101", "ip": "192.168.1.101"},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        test_session.add(node)
        test_session.commit()
        
        # Mock discovery result with no protocol
        mock_run.return_value = [{
            "host": "192.168.1.101",
            "protocol": None,
            "confidence": "unknown",
            "confidence_score": 0.0
        }]
        
        # Create discovery agent and test node discovery
        config = MagicMock(spec=Config)
        discovery_agent = DiscoveryAgent(config)
        
        result = discovery_agent.discover_node(
            node_id=str(node.uuid),
            host="192.168.1.101"
        )
        
        assert result["success"] is False
        assert "No protocol identified" in result["error"]
        
        # Verify node status wasn't changed
        test_session.refresh(node)
        assert node.status == "new"
        assert node.protocol_id is None
