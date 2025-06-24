#!/usr/bin/env python3
"""
Test script to demonstrate the node orchestration workflow.
"""

import sys
import os
sys.path.append('.')

from services.node_orchestration import NodeOrchestrationService

def test_orchestration_workflow():
    """Test the orchestration workflow."""
    print("🔧 Testing Node Orchestration Workflow")
    print("=" * 50)
    
    orchestration = NodeOrchestrationService()
    
    # Test 1: Invalid organization ID
    print("\n1. Testing invalid organization ID:")
    result = orchestration.validate_scan_request(
        org_id="invalid-uuid",
        target="192.168.1.1"
    )
    print(f"   Result: {result}")
    
    # Test 2: Non-existent organization
    print("\n2. Testing non-existent organization:")
    result = orchestration.validate_scan_request(
        org_id="00000000-0000-0000-0000-000000000999",
        target="192.168.1.1"
    )
    print(f"   Result: {result}")
    
    # Test 3: Valid organization, new node, no protocol
    print("\n3. Testing new node without protocol (should require discovery):")
    result = orchestration.validate_scan_request(
        org_id="00000000-0000-0000-0000-000000000001",
        target="192.168.1.100"
    )
    print(f"   Result: {result}")
    
    if result.get("success") is False and result.get("next_action") == "run-discovery":
        node_id = result.get("node_id")
        print(f"   ✓ Discovery required for node: {node_id}")
        
        # Test 4: Simulate discovery completing
        print("\n4. Simulating discovery completion:")
        update_result = orchestration.update_node_after_discovery(
            node_id=node_id,
            protocol_name="sui"
        )
        print(f"   Update result: {update_result}")
        
        # Test 5: Try scanning again after discovery
        print("\n5. Trying scan again after discovery:")
        result = orchestration.validate_scan_request(
            org_id="00000000-0000-0000-0000-000000000001",
            target="192.168.1.100"
        )
        print(f"   Result: {result}")
        
        # Test 6: Get node info
        print("\n6. Getting node information:")
        info_result = orchestration.get_node_info(node_id)
        print(f"   Node info: {info_result}")
    
    # Test 7: Valid organization, new node, with protocol
    print("\n7. Testing new node with protocol provided:")
    result = orchestration.validate_scan_request(
        org_id="00000000-0000-0000-0000-000000000001",
        target="192.168.1.200",
        protocol_filter="filecoin"
    )
    print(f"   Result: {result}")

    print("\n" + "=" * 50)
    print("✅ Orchestration workflow test completed!")

if __name__ == "__main__":
    test_orchestration_workflow()
