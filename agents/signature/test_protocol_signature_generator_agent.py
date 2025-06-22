import pytest
from unittest.mock import MagicMock, patch
from agents.signature.protocol_signature_generator_agent import ProtocolSignatureGeneratorAgent

@pytest.fixture
def agent():
    # Patch the logger to avoid actual logging during tests
    agent = ProtocolSignatureGeneratorAgent()
    agent.logger = MagicMock()
    return agent

def test_process_results_returns_input_unchanged(agent):
    # Arrange
    scan_results = [
        {"id": 1, "result": "foo"},
        {"id": 2, "result": "bar"}
    ]
    # Patch _generate_signatures_from_protocols to avoid DB access
    agent._generate_signatures_from_protocols = MagicMock(return_value=["proto1", "proto2"])

    # Act
    result = agent.process_results(scan_results)

    # Assert
    assert result == scan_results
    agent._generate_signatures_from_protocols.assert_called_once()
    agent.logger.info.assert_any_call("✅ Generated/updated 2 protocol signatures")

def test_process_results_handles_empty_scan_results(agent):
    scan_results = []
    agent._generate_signatures_from_protocols = MagicMock(return_value=[])
    result = agent.process_results(scan_results)
    assert result == []
    agent._generate_signatures_from_protocols.assert_called_once()
    agent.logger.info.assert_any_call("✅ Generated/updated 0 protocol signatures")

def test_process_results_logs_number_of_signatures(agent):
    scan_results = [{}]
    agent._generate_signatures_from_protocols = MagicMock(return_value=["a", "b", "c"])
    agent.process_results(scan_results)
    agent.logger.info.assert_any_call("✅ Generated/updated 3 protocol signatures")