from typing import List, Optional


def get_scanners_for_level(level: int, protocol: Optional[str] = None) -> List[str]:
    """
    Determines which scanners to run based on the scan level and optional protocol name.
    This function implements the logic described in the scanner routing specification.

    Args:
        level: Scan level (1-3) determining which scanners to include
        protocol: Optional protocol name (e.g., 'sui', 'filecoin') for protocol-specific scanners

    Returns:
        List of scanner module names to run

    Raises:
        ValueError: If level is not 1, 2, or 3
    """
    if level not in [1, 2, 3]:
        raise ValueError(f"Invalid scan level: {level}. Must be 1, 2, or 3.")

    # Map scanners to actual available implementations
    # Level 1: Legal, passive, and safe scanners  
    level_1 = ["generic", "web", "ssl_test", "whatweb", "geo"]
    # Level 2: Published, atomic, protocol-aware scanners
    level_2_add = ["nmap", "vulnerability"]
    # Level 3: Aggressive, exploratory scanners
    level_3_add = ["dirbuster", "docker_exposure", "dnsdumpster"]

    scanners = []
    if level >= 1:
        scanners.extend(level_1)
    if level >= 2:
        scanners.extend(level_2_add)
    if level >= 3:
        scanners.extend(level_3_add)

    # Add protocol-specific scanner for level 2 and above
    if level >= 2 and protocol:
        protocol_lower = protocol.lower().strip()
        if protocol_lower:
            scanners.append(protocol_lower)

    # Return a list with unique scanner names while preserving order
    return list(dict.fromkeys(scanners))
