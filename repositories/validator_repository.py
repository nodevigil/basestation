from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from models.validator import ValidatorAddress
from database import SessionLocal, get_db
from typing import List, Optional
from datetime import datetime

class ValidatorRepository:
    """Repository for managing validator addresses"""
    
    def __init__(self, db: Session = None):
        self.db = db or SessionLocal()
        self._should_close = db is None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._should_close:
            self.db.close()
    
    def add_validator(self, address: str, name: str = None, source: str = "manual", active: bool = True) -> ValidatorAddress:
        """Add a new validator address"""
        try:
            validator = ValidatorAddress(
                address=address,
                name=name,
                source=source,
                created_at=datetime.utcnow(),
                active=active
            )
            self.db.add(validator)
            self.db.commit()
            self.db.refresh(validator)
            return validator
        except IntegrityError:
            self.db.rollback()
            # If validator already exists, update it
            return self.update_validator(address, name=name, source=source, active=active)
    
    def get_validator(self, address: str) -> Optional[ValidatorAddress]:
        """Get a validator by address"""
        return self.db.query(ValidatorAddress).filter(ValidatorAddress.address == address).first()
    
    def get_validator_by_id(self, validator_id: int) -> Optional[ValidatorAddress]:
        """Get a validator by ID"""
        return self.db.query(ValidatorAddress).filter(ValidatorAddress.id == validator_id).first()
    
    def get_all_validators(self, active_only: bool = True) -> List[ValidatorAddress]:
        """Get all validators"""
        query = self.db.query(ValidatorAddress)
        if active_only:
            query = query.filter(ValidatorAddress.active == True)
        return query.all()
    
    def get_validators_by_source(self, source: str, active_only: bool = True) -> List[ValidatorAddress]:
        """Get validators by source"""
        query = self.db.query(ValidatorAddress).filter(ValidatorAddress.source == source)
        if active_only:
            query = query.filter(ValidatorAddress.active == True)
        return query.all()
    
    def update_validator(self, address: str, name: str = None, source: str = None, active: bool = None) -> Optional[ValidatorAddress]:
        """Update an existing validator"""
        validator = self.get_validator(address)
        if not validator:
            return None
        
        if name is not None:
            validator.name = name
        if source is not None:
            validator.source = source
        if active is not None:
            validator.active = active
        
        self.db.commit()
        self.db.refresh(validator)
        return validator
    
    def deactivate_validator(self, address: str) -> bool:
        """Deactivate a validator (soft delete)"""
        validator = self.get_validator(address)
        if validator:
            validator.active = False
            self.db.commit()
            return True
        return False
    
    def delete_validator(self, address: str) -> bool:
        """Permanently delete a validator"""
        validator = self.get_validator(address)
        if validator:
            self.db.delete(validator)
            self.db.commit()
            return True
        return False
    
    def bulk_add_validators(self, validators_data: List[dict]) -> List[ValidatorAddress]:
        """Bulk add validators from a list of dictionaries"""
        validators = []
        for data in validators_data:
            try:
                validator = ValidatorAddress(
                    address=data['address'],
                    name=data.get('name'),
                    source=data.get('source', 'bulk_import'),
                    created_at=datetime.utcnow(),
                    active=data.get('active', True)
                )
                self.db.add(validator)
                validators.append(validator)
            except Exception as e:
                print(f"Error adding validator {data.get('address')}: {e}")
                continue
        
        try:
            self.db.commit()
            for validator in validators:
                self.db.refresh(validator)
        except IntegrityError:
            self.db.rollback()
            # Handle duplicates individually
            validators = []
            for data in validators_data:
                validator = self.add_validator(
                    address=data['address'],
                    name=data.get('name'),
                    source=data.get('source', 'bulk_import'),
                    active=data.get('active', True)
                )
                if validator:
                    validators.append(validator)
        
        return validators
