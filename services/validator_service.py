from repositories.validator_repository import ValidatorRepository
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# TODO: Fix import - from sui_discoverer import fetch_sui_validator_hosts
import socket
from typing import List

class ValidatorService:
    """Service for managing validator data and integration"""
    
    def __init__(self):
        self.repo = ValidatorRepository()
    
    def import_sui_validators(self) -> List[str]:
        """Import Sui validators from the network"""
        print("Fetching Sui validators...")
        # TODO: Fix this method to use the correct discovery module
        # hosts = fetch_sui_validator_hosts()
        from discovery.sui import SuiDiscovery
        hosts = SuiDiscovery().get_hosts()
        
        validators_data = []
        for host in hosts:
            # Try to resolve hostname to get IP address
            try:
                ip_address = socket.gethostbyname(host)
                validators_data.append({
                    'address': ip_address,
                    'name': host,
                    'source': 'sui_network',
                    'active': True
                })
            except socket.gaierror:
                # If can't resolve, store the hostname as address
                validators_data.append({
                    'address': host,
                    'name': host,
                    'source': 'sui_network',
                    'active': True
                })
        
        with ValidatorRepository() as repo:
            added_validators = repo.bulk_add_validators(validators_data)
            
        print(f"Imported {len(added_validators)} Sui validators")
        return [v.address for v in added_validators]
    
    def get_active_validators(self, source: str = None) -> List[dict]:
        """Get all active validators, optionally filtered by source"""
        with ValidatorRepository() as repo:
            if source:
                validators = repo.get_validators_by_source(source, active_only=True)
            else:
                validators = repo.get_all_validators(active_only=True)
            
            return [v.to_dict() for v in validators]
    
    def add_manual_validator(self, address: str, name: str = None) -> dict:
        """Manually add a validator address"""
        with ValidatorRepository() as repo:
            validator = repo.add_validator(
                address=address,
                name=name or address,
                source='manual',
                active=True
            )
            return validator.to_dict() if validator else None
    
    def deactivate_validator(self, address: str) -> bool:
        """Deactivate a validator"""
        with ValidatorRepository() as repo:
            return repo.deactivate_validator(address)
    
    def get_validator_stats(self) -> dict:
        """Get statistics about validators"""
        with ValidatorRepository() as repo:
            all_validators = repo.get_all_validators(active_only=False)
            active_validators = repo.get_all_validators(active_only=True)
            
            sources = {}
            for validator in all_validators:
                source = validator.source
                if source not in sources:
                    sources[source] = {'total': 0, 'active': 0}
                sources[source]['total'] += 1
                if validator.active:
                    sources[source]['active'] += 1
            
            return {
                'total_validators': len(all_validators),
                'active_validators': len(active_validators),
                'inactive_validators': len(all_validators) - len(active_validators),
                'sources': sources
            }
