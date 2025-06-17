from sqlalchemy import Column, String, DateTime, Boolean, Integer, ForeignKey, JSON, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime

Base = declarative_base()

class ValidatorAddress(Base):
    __tablename__ = 'validator_addresses'

    id = Column(Integer, primary_key=True, autoincrement=True)
    address = Column(String(255), unique=True, nullable=False)
    name = Column(String(255), nullable=True)
    source = Column(String(100), nullable=False)  # e.g., 'sui', 'ethereum', 'manual'
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    
    # Relationship to scans
    scans = relationship("ValidatorScan", back_populates="validator_address")

    def __repr__(self):
        return f"<ValidatorAddress(address='{self.address}', name='{self.name}', source='{self.source}', active={self.active})>"

    def to_dict(self):
        return {
            'address': self.address,
            'name': self.name,
            'source': self.source,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'active': self.active
        }


class ValidatorScan(Base):
    __tablename__ = 'validator_scans'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    validator_address_id = Column(Integer, ForeignKey('validator_addresses.id'), nullable=False)
    scan_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
    score = Column(Integer, nullable=True)
    scan_hash = Column(String(64), nullable=True)  # SHA-256 hash
    scan_results = Column(JSON, nullable=True)  # JSON field to store scan results
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    failed = Column(Boolean, default=False, nullable=False)  # New column to mark failed scans
    
    # Relationship back to validator address
    validator_address = relationship("ValidatorAddress", back_populates="scans")
    
    def __repr__(self):
        return f"<ValidatorScan(id={self.id}, validator_address_id='{self.validator_address_id}', score={self.score}, scan_date='{self.scan_date}')>"
    
    def to_dict(self):
        return {
            'id': self.id,
            'validator_address_id': self.validator_address_id,
            'scan_date': self.scan_date.isoformat() if self.scan_date else None,
            'ip_address': self.ip_address,
            'score': self.score,
            'scan_hash': self.scan_hash,
            'scan_results': self.scan_results,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'failed': self.failed,
        }
