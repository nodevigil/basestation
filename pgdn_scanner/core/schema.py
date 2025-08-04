"""
Standardized schema enforcement for all scan results.
Ensures consistent data + meta structure across all scan types.
"""

from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timezone
import time
import uuid
from enum import Enum


class ScanType(Enum):
    """Standardized scan types."""
    DISCOVERY = "discovery"
    PORT_SCAN = "port_scan"
    SSL = "ssl"
    WEB = "web"
    WHATWEB = "whatweb"
    GEO = "geo"
    COMPLIANCE = "compliance"
    NODE_SCAN = "node_scan"


class ScanLevel(Enum):
    """Standardized scan levels."""
    DISCOVERY = "discovery"
    BASIC = "basic"  
    DEEP = "deep"


class ScanStatus(Enum):
    """Standardized scan status values."""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class ErrorType(Enum):
    """Standardized error types."""
    TIMEOUT = "timeout"
    CONNECTION_REFUSED = "connection_refused"
    DNS_RESOLUTION = "dns_resolution"
    SCANNER_ERROR = "scanner_error"
    INVALID_TARGET = "invalid_target"
    PERMISSION_DENIED = "permission_denied"


class ScanResultSchema:
    """Schema validation and formatting for scan results."""
    
    @staticmethod
    def create_scan_result(
        scan_type: str,
        target: str,
        result: Dict[str, Any],
        scan_duration: float,
        confidence: Optional[float] = None,
        status: str = "success"
    ) -> Dict[str, Any]:
        """Create a standardized scan result object.
        
        Args:
            scan_type: Type of scan performed
            target: Target hostname or IP
            result: Scan-specific structured data
            scan_duration: Duration of scan in seconds
            confidence: Confidence level (0.0-1.0) if applicable
            status: Scan status (success/partial/failed)
            
        Returns:
            Standardized scan result object
        """
        result_obj = {
            "scan_type": scan_type,
            "target": target,
            "result": result,
            "metadata": {
                "scan_duration": round(scan_duration, 3),
                "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                "status": status
            }
        }
        
        if confidence is not None:
            result_obj["metadata"]["confidence"] = round(confidence, 3)
            
        return result_obj

    @staticmethod
    def create_response_structure(
        data: List[Dict[str, Any]],
        scan_level: str = "basic",
        target: Optional[str] = None,
        tools_used: Optional[List[str]] = None,
        scan_start_time: Optional[float] = None,
        scan_end_time: Optional[float] = None,
        error: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create the standardized response structure with data array and meta object.
        
        Args:
            data: Array of scan result objects
            scan_level: Level of scanning performed
            target: Original target requested
            tools_used: List of tools/scanners used
            scan_start_time: Unix timestamp of scan start
            scan_end_time: Unix timestamp of scan end
            error: Error information if scan failed
            
        Returns:
            Standardized response structure
        """
        current_time = time.time()
        start_time = scan_start_time or current_time
        end_time = scan_end_time or current_time
        total_duration = round(end_time - start_time, 3)
        
        successful_scans = len([d for d in data if d.get("metadata", {}).get("status") == "success"])
        failed_scans = len(data) - successful_scans
        
        meta = {
            "operation": "scan",
            "scan_level": scan_level,
            "total_scans": len(data),
            "successful_scans": successful_scans,
            "failed_scans": failed_scans,
            "scan_duration": total_duration,
            "scanner_version": "pgdn-scanner-v1.10.1",
            "scan_start": int(start_time),
            "scan_end": int(end_time)
        }
        
        if target:
            meta["target"] = target
            
        if tools_used:
            meta["tools_used"] = tools_used
            
        if error:
            meta["error"] = error
            
        return {
            "data": data,
            "meta": meta
        }

    @staticmethod
    def create_error_response(
        error_type: str,
        error_message: str,
        error_code: Optional[str] = None,
        target: Optional[str] = None,
        scan_level: str = "basic",
        scan_duration: Optional[float] = None
    ) -> Dict[str, Any]:
        """Create standardized error response.
        
        Args:
            error_type: Type of error that occurred
            error_message: Human-readable error message
            error_code: Optional error code
            target: Target that failed
            scan_level: Level of scan attempted
            scan_duration: Duration before failure
            
        Returns:
            Standardized error response
        """
        current_time = time.time()
        duration = scan_duration or 0.0
        
        error_info = {
            "error_type": error_type,
            "error_message": error_message
        }
        
        if error_code:
            error_info["error_code"] = error_code
            
        return ScanResultSchema.create_response_structure(
            data=[],
            scan_level=scan_level,
            target=target,
            scan_start_time=current_time - duration,
            scan_end_time=current_time,
            error=error_info
        )

    @staticmethod
    def validate_scan_result(result: Dict[str, Any]) -> bool:
        """Validate that a scan result follows the required schema.
        
        Args:
            result: Scan result to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            # Check top-level structure
            if not isinstance(result, dict):
                return False
                
            if "data" not in result or "meta" not in result:
                return False
                
            # Validate data array
            data = result["data"]
            if not isinstance(data, list):
                return False
                
            # Validate each data item
            for item in data:
                if not isinstance(item, dict):
                    return False
                    
                required_fields = ["scan_type", "target", "result", "metadata"]
                if not all(field in item for field in required_fields):
                    return False
                    
                # Validate metadata
                metadata = item["metadata"]
                if not isinstance(metadata, dict):
                    return False
                    
                required_meta_fields = ["scan_duration", "timestamp", "status"]
                if not all(field in metadata for field in required_meta_fields):
                    return False
                    
            # Validate meta object
            meta = result["meta"]
            if not isinstance(meta, dict):
                return False
                
            required_meta_fields = [
                "operation", "scan_level", "total_scans", "successful_scans", 
                "failed_scans", "scan_duration", "scanner_version", 
                "scan_start", "scan_end"
            ]
            
            if not all(field in meta for field in required_meta_fields):
                return False
                
            return True
            
        except Exception:
            return False

    @staticmethod
    def format_discovery_result(
        protocols_detected: List[str],
        node_type: Optional[str] = None,
        network: Optional[str] = None,
        endpoints: Optional[List[Dict[str, Any]]] = None,
        capabilities: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Format discovery scan results.
        
        Args:
            protocols_detected: List of detected protocols
            node_type: Type of node detected
            network: Network name (mainnet, testnet, etc.)
            endpoints: List of endpoint information
            capabilities: List of node capabilities
            
        Returns:
            Formatted discovery result
        """
        result = {
            "protocols_detected": protocols_detected or []
        }
        
        if node_type:
            result["node_type"] = node_type
            
        if network:
            result["network"] = network
            
        if endpoints:
            result["endpoints"] = endpoints
            
        if capabilities:
            result["capabilities"] = capabilities
            
        return result

    @staticmethod
    def format_port_scan_result(
        open_ports: List[int],
        closed_ports: Optional[List[int]] = None,
        filtered_ports: Optional[List[int]] = None,
        port_details: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Format port scan results.
        
        Args:
            open_ports: List of open ports
            closed_ports: List of closed ports
            filtered_ports: List of filtered ports
            port_details: Detailed information about ports
            
        Returns:
            Formatted port scan result
        """
        result = {
            "open_ports": open_ports
        }
        
        if closed_ports:
            result["closed_ports"] = closed_ports
            
        if filtered_ports:
            result["filtered_ports"] = filtered_ports
            
        if port_details:
            result["port_details"] = port_details
            
        return result

    @staticmethod
    def format_ssl_result(
        certificate: Optional[Dict[str, Any]] = None,
        ssl_version: Optional[str] = None,
        cipher_suites: Optional[List[str]] = None,
        vulnerabilities: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Format SSL scan results.
        
        Args:
            certificate: Certificate information
            ssl_version: SSL/TLS version
            cipher_suites: List of supported cipher suites
            vulnerabilities: List of SSL vulnerabilities
            
        Returns:
            Formatted SSL result
        """
        result = {}
        
        if certificate:
            result["certificate"] = certificate
            
        if ssl_version:
            result["ssl_version"] = ssl_version
            
        if cipher_suites:
            result["cipher_suites"] = cipher_suites
            
        if vulnerabilities is not None:
            result["vulnerabilities"] = vulnerabilities
            
        return result

    @staticmethod
    def format_web_result(
        status_code: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
        technologies: Optional[List[str]] = None,
        security_headers: Optional[Dict[str, Any]] = None,
        endpoints: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Format web scan results.
        
        Args:
            status_code: HTTP status code
            headers: HTTP response headers
            technologies: Detected web technologies
            security_headers: Security header analysis
            endpoints: Discovered endpoints
            
        Returns:
            Formatted web result
        """
        result = {}
        
        if status_code is not None:
            result["status_code"] = status_code
            
        if headers:
            result["headers"] = headers
            
        if technologies:
            result["technologies"] = technologies
            
        if security_headers:
            result["security_headers"] = security_headers
            
        if endpoints:
            result["endpoints"] = endpoints
            
        return result

    @staticmethod
    def format_geo_result(
        country: Optional[str] = None,
        city: Optional[str] = None,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        asn: Optional[str] = None,
        organization: Optional[str] = None
    ) -> Dict[str, Any]:
        """Format geo scan results.
        
        Args:
            country: Country name
            city: City name
            latitude: Latitude coordinate
            longitude: Longitude coordinate
            asn: ASN number
            organization: Organization name
            
        Returns:
            Formatted geo result
        """
        result = {}
        
        if country:
            result["country"] = country
            
        if city:
            result["city"] = city
            
        if latitude is not None:
            result["latitude"] = latitude
            
        if longitude is not None:
            result["longitude"] = longitude
            
        if asn:
            result["asn"] = asn
            
        if organization:
            result["organization"] = organization
            
        return result