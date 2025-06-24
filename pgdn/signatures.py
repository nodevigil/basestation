"""
Signature Management Module

Provides protocol signature learning and management functionality.
This module abstracts signature operations from CLI concerns.
"""

from typing import Dict, Any, Optional
from datetime import datetime


class SignatureManager:
    """
    Manager for protocol signature learning and management.
    
    This class provides a clean Python API for learning signatures
    from existing scans and managing signature data, independent of CLI concerns.
    """
    
    def __init__(self):
        """Initialize the signature manager."""
        pass
    
    def learn_from_scans(self,
                        protocol: str,
                        min_confidence: float = 0.7,
                        max_examples: int = 1000,
                        org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Learn improved protocol signatures from existing scan data.
        
        Args:
            protocol: Protocol name for signature learning (e.g., 'sui', 'filecoin', 'ethereum')
            min_confidence: Minimum confidence threshold for scans to include
            max_examples: Maximum examples to process per protocol
            org_id: Optional organization ID to filter agentic jobs
            
        Returns:
            dict: Signature learning results
        """
        try:
            from pgdn.agent_modules.signature.signature_learning_agent import SignatureLearningAgent
            
            learning_agent = SignatureLearningAgent()
            
            results = learning_agent.learn_signatures_from_scans(
                protocol_name=protocol,
                min_confidence=min_confidence,
                max_examples=max_examples,
                org_id=org_id
            )
            
            return {
                "success": True,
                "operation": "signature_learning",
                "protocol": protocol,
                "min_confidence": min_confidence,
                "max_examples": max_examples,
                "results": results,
                "timestamp": datetime.now().isoformat()
            }
            
        except ImportError:
            return {
                "success": False,
                "error": "Signature learning agent not available. Ensure signature learning modules are installed.",
                "protocol": protocol,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Signature learning failed: {str(e)}",
                "protocol": protocol,
                "min_confidence": min_confidence,
                "max_examples": max_examples,
                "timestamp": datetime.now().isoformat()
            }
    
    def update_signature_flags(self, protocol_filter: Optional[str] = None, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Update signature_created flags for scans that have been processed.
        
        Args:
            protocol_filter: Optional protocol filter for flag updates
            
        Returns:
            dict: Flag update results
        """
        try:
            from pgdn.agent_modules.signature.signature_flag_manager import SignatureFlagManager
            
            flag_manager = SignatureFlagManager()
            
            results = flag_manager.update_signature_flags(protocol_filter=protocol_filter)
            
            return {
                "success": True,
                "operation": "flag_update",
                "protocol_filter": protocol_filter,
                "results": results,
                "timestamp": datetime.now().isoformat()
            }
            
        except ImportError:
            return {
                "success": False,
                "error": "Signature flag manager not available. Ensure signature management modules are installed.",
                "protocol_filter": protocol_filter,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Signature flag update failed: {str(e)}",
                "protocol_filter": protocol_filter,
                "timestamp": datetime.now().isoformat()
            }
    
    def mark_signature_created(self, scan_id: int, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Mark a specific scan ID as having its signature created.
        
        Args:
            scan_id: Scan ID to mark as signature created
            
        Returns:
            dict: Mark operation results
        """
        try:
            from pgdn.agent_modules.signature.signature_flag_manager import SignatureFlagManager
            
            flag_manager = SignatureFlagManager()
            
            success = flag_manager.mark_signature_created(scan_id)
            
            return {
                "success": success,
                "operation": "mark_signature_created",
                "scan_id": scan_id,
                "message": f"Scan {scan_id} {'marked' if success else 'failed to mark'} as signature created",
                "timestamp": datetime.now().isoformat()
            }
            
        except ImportError:
            return {
                "success": False,
                "error": "Signature flag manager not available. Ensure signature management modules are installed.",
                "scan_id": scan_id,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Mark signature created failed: {str(e)}",
                "scan_id": scan_id,
                "timestamp": datetime.now().isoformat()
            }
    
    def get_signature_statistics(self, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get statistics about signature creation status for scans.
        
        Returns:
            dict: Signature statistics
        """
        try:
            from pgdn.agent_modules.signature.signature_flag_manager import SignatureFlagManager
            
            flag_manager = SignatureFlagManager()
            
            stats = flag_manager.get_signature_statistics()
            
            return {
                "success": True,
                "operation": "signature_statistics",
                "statistics": stats,
                "timestamp": datetime.now().isoformat()
            }
            
        except ImportError:
            return {
                "success": False,
                "error": "Signature flag manager not available. Ensure signature management modules are installed.",
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Getting signature statistics failed: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
