from typing import List, Optional


def get_scanners_for_protocol_compliance(level: int, protocol: str) -> List[str]:
    """
    Determines which scanners to run for protocol compliance scans.
    This is only used for --run compliance scans, not individual scanner runs.

    Args:
        level: Scan level (1-3) for the advanced protocol scanner
        protocol: Protocol name (e.g., 'sui', 'filecoin') for protocol-specific scanners

    Returns:
        List containing only the protocol scanner

    Raises:
        ValueError: If level is not 1, 2, or 3
    """
    if level not in [1, 2, 3]:
        raise ValueError(f"Invalid scan level: {level}. Must be 1, 2, or 3.")

    # For compliance scans, only run the advanced protocol scanner with the specified level
    protocol_lower = protocol.lower().strip()
    if protocol_lower:
        return [protocol_lower]
    
    return []


def get_scanners_for_level(level: int, protocol: Optional[str] = None) -> List[str]:
    """
    Legacy function for backward compatibility.
    Now primarily used for protocol compliance scans.
    
    Args:
        level: Scan level (1-3)
        protocol: Optional protocol name for compliance scans

    Returns:
        List of scanner module names to run
    """
    if protocol:
        # For compliance scans, use the new function
        return get_scanners_for_protocol_compliance(level, protocol)
    else:
        # For individual scans, this shouldn't be called anymore
        # But keeping minimal logic for backward compatibility
        return ["web"]


def get_supported_protocols() -> List[str]:
    """
    Get list of supported protocol scanners from YAML configurations.
    
    Returns:
        List of supported protocol names
    """
    try:
        from ..protocol_loader import ProtocolLoader
        loader = ProtocolLoader()
        return loader.list_available_protocols()
    except Exception:
        # Fallback to basic list if protocol loader fails
        return ['sui', 'filecoin', 'arweave', 'web']


def is_protocol_scanner(scanner_name: str) -> bool:
    """
    Check if a scanner is a protocol-specific scanner.
    
    Args:
        scanner_name: Name of the scanner
        
    Returns:
        True if it's a protocol scanner
    """
    return scanner_name.lower() in get_supported_protocols()
