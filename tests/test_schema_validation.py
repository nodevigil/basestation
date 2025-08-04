"""
Tests for schema validation and standardized scan result formats.
"""

import pytest
import time
from unittest.mock import Mock, patch
from pgdn_scanner.core.schema import (
    ScanResultSchema, ScanType, ScanLevel, ScanStatus, ErrorType
)
from pgdn_scanner.scanners.scan_orchestrator import ScanOrchestrator


class TestScanResultSchema:
    """Test the standardized schema validation."""
    
    def test_create_scan_result(self):
        """Test creating a standardized scan result."""
        result = ScanResultSchema.create_scan_result(
            scan_type=ScanType.PORT_SCAN.value,
            target="example.com",
            result={"open_ports": [80, 443]},
            scan_duration=1.5,
            confidence=0.95,
            status=ScanStatus.SUCCESS.value
        )
        
        assert result["scan_type"] == "port_scan"
        assert result["target"] == "example.com"
        assert result["result"]["open_ports"] == [80, 443]
        assert result["metadata"]["scan_duration"] == 1.5
        assert result["metadata"]["confidence"] == 0.95
        assert result["metadata"]["status"] == "success"
        assert "timestamp" in result["metadata"]
    
    def test_create_response_structure(self):
        """Test creating the standardized response structure."""
        scan_data = [
            ScanResultSchema.create_scan_result(
                scan_type=ScanType.WEB.value,
                target="example.com",
                result={"status_code": 200},
                scan_duration=2.0
            )
        ]
        
        response = ScanResultSchema.create_response_structure(
            data=scan_data,
            scan_level=ScanLevel.BASIC.value,
            target="example.com",
            tools_used=["web_scanner"],
            scan_start_time=time.time() - 10,
            scan_end_time=time.time()
        )
        
        assert "data" in response
        assert "meta" in response
        assert isinstance(response["data"], list)
        assert len(response["data"]) == 1
        assert response["meta"]["operation"] == "scan"
        assert response["meta"]["scan_level"] == "basic"
        assert response["meta"]["total_scans"] == 1
        assert response["meta"]["successful_scans"] == 1
        assert response["meta"]["failed_scans"] == 0
        assert response["meta"]["target"] == "example.com"
        assert response["meta"]["tools_used"] == ["web_scanner"]
    
    def test_create_error_response(self):
        """Test creating standardized error response."""
        response = ScanResultSchema.create_error_response(
            error_type=ErrorType.TIMEOUT.value,
            error_message="Connection timeout after 30 seconds",
            error_code="CONN_TIMEOUT",
            target="example.com",
            scan_level=ScanLevel.BASIC.value,
            scan_duration=30.0
        )
        
        assert response["data"] == []
        assert response["meta"]["failed_scans"] == 0  # No scans attempted
        assert response["meta"]["error"]["error_type"] == "timeout"
        assert response["meta"]["error"]["error_message"] == "Connection timeout after 30 seconds"
        assert response["meta"]["error"]["error_code"] == "CONN_TIMEOUT"
        assert response["meta"]["target"] == "example.com"
    
    def test_validate_scan_result_valid(self):
        """Test validation of valid scan result."""
        valid_result = {
            "data": [
                {
                    "scan_type": "web",
                    "target": "example.com",
                    "result": {"status_code": 200},
                    "metadata": {
                        "scan_duration": 1.5,
                        "timestamp": "2025-07-29T12:34:56Z",
                        "status": "success"
                    }
                }
            ],
            "meta": {
                "operation": "scan",
                "scan_level": "basic",
                "total_scans": 1,
                "successful_scans": 1,
                "failed_scans": 0,
                "scan_duration": 1.5,
                "scanner_version": "pgdn-scanner-v1.9.5",
                "scan_start": 1752823059,
                "scan_end": 1752823061
            }
        }
        
        assert ScanResultSchema.validate_scan_result(valid_result) is True
    
    def test_validate_scan_result_invalid(self):
        """Test validation of invalid scan results."""
        # Missing data field
        invalid_1 = {
            "meta": {"operation": "scan"}
        }
        assert ScanResultSchema.validate_scan_result(invalid_1) is False
        
        # Data not an array
        invalid_2 = {
            "data": {"scan_type": "web"},
            "meta": {"operation": "scan"}
        }
        assert ScanResultSchema.validate_scan_result(invalid_2) is False
        
        # Missing required fields in data item
        invalid_3 = {
            "data": [{"scan_type": "web"}],
            "meta": {"operation": "scan"}
        }
        assert ScanResultSchema.validate_scan_result(invalid_3) is False
    
    def test_format_discovery_result(self):
        """Test discovery result formatting."""
        result = ScanResultSchema.format_discovery_result(
            protocols_detected=["sui", "grpc"],
            node_type="validator",
            network="mainnet",
            endpoints=[{"protocol": "grpc", "port": 8080, "status": "active"}],
            capabilities=["consensus", "rpc"]
        )
        
        assert result["protocols_detected"] == ["sui", "grpc"]
        assert result["node_type"] == "validator"
        assert result["network"] == "mainnet"
        assert len(result["endpoints"]) == 1
        assert result["endpoints"][0]["protocol"] == "grpc"
        assert result["capabilities"] == ["consensus", "rpc"]
    
    def test_format_port_scan_result(self):
        """Test port scan result formatting."""
        result = ScanResultSchema.format_port_scan_result(
            open_ports=[22, 80, 443],
            closed_ports=[21, 25],
            filtered_ports=[135],
            port_details=[
                {"port": 80, "protocol": "tcp", "service": "http", "version": "nginx/1.18.0"}
            ]
        )
        
        assert result["open_ports"] == [22, 80, 443]
        assert result["closed_ports"] == [21, 25]
        assert result["filtered_ports"] == [135]
        assert len(result["port_details"]) == 1
        assert result["port_details"][0]["service"] == "http"
    
    def test_format_ssl_result(self):
        """Test SSL result formatting."""
        certificate = {
            "subject": "CN=example.com",
            "issuer": "Let's Encrypt",
            "valid_from": "2025-01-01T00:00:00Z",
            "valid_to": "2025-04-01T00:00:00Z",
            "is_valid": True
        }
        
        result = ScanResultSchema.format_ssl_result(
            certificate=certificate,
            ssl_version="TLSv1.3",
            cipher_suites=["TLS_AES_256_GCM_SHA384"],
            vulnerabilities=[]
        )
        
        assert result["certificate"]["subject"] == "CN=example.com"
        assert result["ssl_version"] == "TLSv1.3"
        assert result["cipher_suites"] == ["TLS_AES_256_GCM_SHA384"]
        assert result["vulnerabilities"] == []
    
    def test_format_web_result(self):
        """Test web result formatting."""
        result = ScanResultSchema.format_web_result(
            status_code=200,
            headers={"server": "nginx/1.18.0", "content-type": "text/html"},
            technologies=["nginx", "html"],
            security_headers={"present": ["X-Frame-Options"], "missing": ["CSP"]},
            endpoints=[{"path": "/admin", "status_code": 403}]
        )
        
        assert result["status_code"] == 200
        assert result["headers"]["server"] == "nginx/1.18.0"
        assert result["technologies"] == ["nginx", "html"]
        assert result["security_headers"]["present"] == ["X-Frame-Options"] 
        assert len(result["endpoints"]) == 1
    
    def test_format_geo_result(self):
        """Test geo result formatting."""
        result = ScanResultSchema.format_geo_result(
            country="United States",
            city="New York",
            latitude=40.7128,
            longitude=-74.0060,
            asn="AS13335",
            organization="Cloudflare"
        )
        
        assert result["country"] == "United States"
        assert result["city"] == "New York"
        assert result["latitude"] == 40.7128
        assert result["longitude"] == -74.0060
        assert result["asn"] == "AS13335"
        assert result["organization"] == "Cloudflare"


class TestScanOrchestratorSchema:
    """Test that ScanOrchestrator enforces the schema."""
    
    @patch('pgdn_scanner.scanners.scan_orchestrator.nmap_scan')
    def test_orchestrator_returns_structured_format(self, mock_nmap):
        """Test that orchestrator returns properly structured results."""
        # Mock nmap results
        mock_nmap.return_value = {
            "ports": [
                {"port": 80, "state": "open", "service": "http"},
                {"port": 443, "state": "open", "service": "https"}
            ]
        }
        
        config = {
            'orchestrator': {
                'enabled_scanners': [],
                'use_external_tools': True,
                'enabled_external_tools': ['nmap']
            }
        }
        
        orchestrator = ScanOrchestrator(config)
        orchestrator._enabled_external_tools_set = True
        orchestrator.enabled_external_tools = ['nmap']
        
        result = orchestrator.scan(
            target="example.com",
            scan_level=1
        )
        
        # Validate structure
        assert ScanResultSchema.validate_scan_result(result) is True
        
        # Check data array
        assert isinstance(result["data"], list)
        assert len(result["data"]) >= 1
        
        # Find nmap result
        nmap_result = None
        for scan_result in result["data"]:
            if scan_result["scan_type"] == "port_scan":
                nmap_result = scan_result
                break
        
        assert nmap_result is not None
        assert nmap_result["target"] == "example.com"
        assert "open_ports" in nmap_result["result"]
        assert 80 in nmap_result["result"]["open_ports"]
        assert 443 in nmap_result["result"]["open_ports"]
        
        # Check metadata
        assert result["meta"]["operation"] == "scan"
        assert result["meta"]["target"] == "example.com"
        assert "nmap" in result["meta"]["tools_used"]
    
    def test_orchestrator_handles_scanner_errors(self):
        """Test that orchestrator properly handles scanner errors."""
        config = {
            'orchestrator': {
                'enabled_scanners': ['nonexistent_scanner'],
                'use_external_tools': False
            }
        }
        
        orchestrator = ScanOrchestrator(config)
        orchestrator._enabled_scanners_set = True
        orchestrator.enabled_scanners = ['nonexistent_scanner']
        
        result = orchestrator.scan(
            target="example.com",
            scan_level=1
        )
        
        # Should still return valid structure even with errors
        assert ScanResultSchema.validate_scan_result(result) is True
        assert result["meta"]["failed_scans"] >= 0


class TestSchemaBackwardCompatibility:
    """Test that the schema changes maintain backward compatibility where needed."""
    
    def test_schema_enums_values(self):
        """Test that enum values are as expected."""
        assert ScanType.DISCOVERY.value == "discovery"
        assert ScanType.PORT_SCAN.value == "port_scan"
        assert ScanType.SSL.value == "ssl"
        assert ScanType.WEB.value == "web"
        assert ScanType.WHATWEB.value == "whatweb"
        assert ScanType.GEO.value == "geo"
        assert ScanType.COMPLIANCE.value == "compliance"
        assert ScanType.NODE_SCAN.value == "node_scan"
        
        assert ScanLevel.DISCOVERY.value == "discovery"
        assert ScanLevel.BASIC.value == "basic"
        assert ScanLevel.DEEP.value == "deep"
        
        assert ScanStatus.SUCCESS.value == "success"
        assert ScanStatus.PARTIAL.value == "partial"
        assert ScanStatus.FAILED.value == "failed"


if __name__ == "__main__":
    pytest.main([__file__])