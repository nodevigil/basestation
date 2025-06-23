"""
Walrus storage provider for the DePIN scanner.
This module re-exports the WalrusStorageProvider from contracts.reports.storage
to maintain backward compatibility with the expected import structure.
"""

# Re-export from the actual location
try:
    from contracts.reports.storage import WalrusStorageProvider, WalrusStorageProviderError
except ImportError:
    # Fallback for when contracts module is not available
    WalrusStorageProvider = None
    
    class WalrusStorageProviderError(Exception):
        """Fallback exception when Walrus provider is not available"""
        pass

__all__ = ['WalrusStorageProvider', 'WalrusStorageProviderError']
