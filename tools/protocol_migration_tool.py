#!/usr/bin/env python3
"""
Comprehensive Protocol Migration Tool

This tool handles the complete migration process for linking protocols to agents and their dependencies:
1. Validates and seeds protocols from protocol_seeder
2. Generates signatures for all protocols
3. Links validator addresses to protocols
4. Validates all relationships and dependencies
5. Updates signature match results
6. Provides comprehensive dependency checking

Usage:
    python tools/protocol_migration_tool.py --full-migration
    python tools/protocol_migration_tool.py --check-dependencies
    python tools/protocol_migration_tool.py --validate-only
"""

import sys
import os
import argparse
import logging
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime
from dataclasses import dataclass

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import (
    get_db_session, Protocol, ProtocolSignature, ValidatorAddress, 
    SignatureMatchResult, HostDiscovery
)
from core.config import Config
from protocol_seeder import DePINProtocolSeeder
from agents.signature.protocol_signature_generator_agent import ProtocolSignatureGeneratorAgent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('protocol_migration.log')
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class MigrationStats:
    """Statistics for migration operations."""
    protocols_seeded: int = 0
    protocols_updated: int = 0
    signatures_generated: int = 0
    signatures_updated: int = 0
    validators_linked: int = 0
    validators_updated: int = 0
    signature_matches_updated: int = 0
    errors_encountered: int = 0
    warnings_encountered: int = 0


@dataclass
class DependencyStatus:
    """Status of protocol dependencies."""
    protocol_exists: bool = False
    signature_exists: bool = False
    validators_linked: bool = False
    recon_agents_compatible: bool = False
    signature_match_results_valid: bool = False
    issues: List[str] = None
    
    def __post_init__(self):
        if self.issues is None:
            self.issues = []


class ProtocolMigrationTool:
    """
    Comprehensive tool for managing protocol migrations and dependencies.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize the migration tool."""
        self.config = config or Config()
        self.stats = MigrationStats()
        
        # Initialize components
        self.protocol_seeder = DePINProtocolSeeder(config)
        self.signature_generator = ProtocolSignatureGeneratorAgent(config)
        
        logger.info("🔧 Protocol Migration Tool initialized")
    
    def check_all_dependencies(self) -> Dict[str, DependencyStatus]:
        """
        Check all protocol dependencies comprehensively.
        
        Returns:
            Dictionary mapping protocol names to their dependency status
        """
        logger.info("🔍 Checking all protocol dependencies...")
        
        dependency_status = {}
        
        try:
            with get_db_session() as session:
                # Get all protocols
                protocols = session.query(Protocol).all()
                
                if not protocols:
                    logger.warning("⚠️  No protocols found in database")
                    return dependency_status
                
                for protocol in protocols:
                    status = self._check_protocol_dependencies(session, protocol)
                    dependency_status[protocol.name] = status
                
                # Check for orphaned validator addresses
                self._check_orphaned_validators(session, dependency_status)
                
                # Check for orphaned signature match results
                self._check_orphaned_signature_matches(session, dependency_status)
                
        except Exception as e:
            logger.error(f"❌ Failed to check dependencies: {e}")
            return {}
        
        # Report summary
        self._report_dependency_summary(dependency_status)
        
        return dependency_status
    
    def _check_protocol_dependencies(self, session, protocol: Protocol) -> DependencyStatus:
        """Check dependencies for a specific protocol."""
        status = DependencyStatus()
        status.protocol_exists = True
        
        # Check if signature exists
        signature = session.query(ProtocolSignature).filter_by(protocol_id=protocol.id).first()
        status.signature_exists = signature is not None
        
        if not status.signature_exists:
            status.issues.append(f"Missing protocol signature")
        
        # Check if any validators are linked
        validator_count = session.query(ValidatorAddress).filter_by(protocol_id=protocol.id).count()
        status.validators_linked = validator_count > 0
        
        # Check recon agent compatibility
        status.recon_agents_compatible = self._check_recon_agent_compatibility(protocol.name)
        
        # Check signature match results validity
        if status.signature_exists:
            invalid_matches = session.query(SignatureMatchResult).filter(
                SignatureMatchResult.protocol_id == protocol.id,
                SignatureMatchResult.protocol_name != protocol.name
            ).count()
            
            status.signature_match_results_valid = invalid_matches == 0
            
            if invalid_matches > 0:
                status.issues.append(f"{invalid_matches} signature match results have mismatched protocol names")
        else:
            status.signature_match_results_valid = True  # No signature, so no invalid matches
        
        return status
    
    def _check_recon_agent_compatibility(self, protocol_name: str) -> bool:
        """Check if recon agents exist and are compatible with protocol."""
        # Check for known recon agents
        known_recon_protocols = ['sui', 'filecoin']
        
        if protocol_name in known_recon_protocols:
            try:
                # Try to import the appropriate agent
                if protocol_name == 'sui':
                    from agents.recon.sui_agent import SuiReconAgent
                    # Check if agent has the new protocol validation method
                    agent = SuiReconAgent()
                    return hasattr(agent, '_get_protocol_with_signature')
                elif protocol_name == 'filecoin':
                    from agents.recon.filecoin_agent import FilecoinReconAgent
                    agent = FilecoinReconAgent()
                    return hasattr(agent, '_get_protocol_with_signature')
            except ImportError:
                return False
        
        return True  # For protocols without specific recon agents, assume compatible
    
    def _check_orphaned_validators(self, session, dependency_status: Dict[str, DependencyStatus]):
        """Check for validator addresses that reference non-existent protocols."""
        try:
            # Find validators with invalid protocol_id references
            orphaned_validators = session.execute("""
                SELECT va.id, va.address, va.protocol_id 
                FROM validator_addresses va 
                LEFT JOIN protocols p ON va.protocol_id = p.id 
                WHERE p.id IS NULL
            """).fetchall()
            
            if orphaned_validators:
                logger.warning(f"⚠️  Found {len(orphaned_validators)} orphaned validator addresses")
                
                # Add to dependency status
                for validator in orphaned_validators:
                    logger.warning(f"   - Validator {validator.address} references non-existent protocol_id {validator.protocol_id}")
                
                # Create a special entry for orphaned validators
                dependency_status['__orphaned_validators__'] = DependencyStatus(
                    issues=[f"{len(orphaned_validators)} validator addresses reference non-existent protocols"]
                )
            
        except Exception as e:
            logger.warning(f"Failed to check orphaned validators: {e}")
    
    def _check_orphaned_signature_matches(self, session, dependency_status: Dict[str, DependencyStatus]):
        """Check for signature match results that reference non-existent protocols."""
        try:
            orphaned_matches = session.execute("""
                SELECT smr.id, smr.protocol_id, smr.protocol_name 
                FROM signature_match_results smr 
                LEFT JOIN protocols p ON smr.protocol_id = p.id 
                WHERE smr.protocol_id IS NOT NULL AND p.id IS NULL
            """).fetchall()
            
            if orphaned_matches:
                logger.warning(f"⚠️  Found {len(orphaned_matches)} orphaned signature match results")
                
                dependency_status['__orphaned_signature_matches__'] = DependencyStatus(
                    issues=[f"{len(orphaned_matches)} signature match results reference non-existent protocols"]
                )
            
        except Exception as e:
            logger.warning(f"Failed to check orphaned signature matches: {e}")
    
    def _report_dependency_summary(self, dependency_status: Dict[str, DependencyStatus]):
        """Report a summary of dependency check results."""
        logger.info("\n" + "="*60)
        logger.info("📋 DEPENDENCY CHECK SUMMARY")
        logger.info("="*60)
        
        total_protocols = len([k for k in dependency_status.keys() if not k.startswith('__')])
        protocols_with_signatures = len([s for s in dependency_status.values() if s.signature_exists])
        protocols_with_validators = len([s for s in dependency_status.values() if s.validators_linked])
        
        logger.info(f"📊 Total Protocols: {total_protocols}")
        logger.info(f"🔏 Protocols with Signatures: {protocols_with_signatures}/{total_protocols}")
        logger.info(f"🎯 Protocols with Linked Validators: {protocols_with_validators}/{total_protocols}")
        
        # Report issues
        total_issues = sum(len(status.issues) for status in dependency_status.values())
        if total_issues > 0:
            logger.warning(f"\n⚠️  Found {total_issues} dependency issues:")
            
            for protocol_name, status in dependency_status.items():
                if status.issues:
                    logger.warning(f"\n  {protocol_name}:")
                    for issue in status.issues:
                        logger.warning(f"    • {issue}")
        else:
            logger.info("\n✅ No dependency issues found!")
        
        logger.info("="*60)
    
    def run_full_migration(self, force_update: bool = False) -> bool:
        """
        Run the complete migration process.
        
        Args:
            force_update: Whether to force updates of existing data
            
        Returns:
            True if migration completed successfully, False otherwise
        """
        logger.info("🚀 Starting full protocol migration...")
        
        try:
            # Step 1: Seed protocols
            logger.info("\n📋 Step 1: Seeding protocols...")
            success = self._seed_protocols(force_update)
            if not success:
                logger.error("❌ Protocol seeding failed")
                return False
            
            # Step 2: Generate signatures
            logger.info("\n🔏 Step 2: Generating protocol signatures...")
            success = self._generate_signatures(force_update)
            if not success:
                logger.error("❌ Signature generation failed")
                return False
            
            # Step 3: Link existing validators
            logger.info("\n🔗 Step 3: Linking validator addresses...")
            success = self._link_validator_addresses()
            if not success:
                logger.error("❌ Validator linking failed")
                return False
            
            # Step 4: Update signature match results
            logger.info("\n🎯 Step 4: Updating signature match results...")
            success = self._update_signature_match_results()
            if not success:
                logger.warning("⚠️  Signature match results update had issues")
            
            # Step 5: Final validation
            logger.info("\n✅ Step 5: Final validation...")
            dependency_status = self.check_all_dependencies()
            
            # Report final statistics
            self._report_migration_stats()
            
            logger.info("🎉 Full migration completed successfully!")
            return True
            
        except Exception as e:
            logger.error(f"❌ Migration failed: {e}")
            return False
    
    def _seed_protocols(self, force_update: bool = False) -> bool:
        """Seed protocols using the protocol seeder."""
        try:
            initial_count = self._count_protocols()
            
            self.protocol_seeder.seed_protocols(force_update=force_update)
            
            final_count = self._count_protocols()
            self.stats.protocols_seeded = max(0, final_count - initial_count)
            
            if force_update:
                self.stats.protocols_updated = initial_count
            
            logger.info(f"✅ Protocol seeding completed")
            return True
            
        except Exception as e:
            logger.error(f"❌ Protocol seeding failed: {e}")
            self.stats.errors_encountered += 1
            return False
    
    def _generate_signatures(self, force_update: bool = False) -> bool:
        """Generate signatures for all protocols."""
        try:
            if force_update:
                # If force update, we'll delete existing signatures first to force regeneration
                with get_db_session() as session:
                    deleted_count = session.query(ProtocolSignature).delete()
                    session.commit()
                    logger.info(f"🗑️  Deleted {deleted_count} existing signatures for force update")
            
            # Use the signature generator agent to generate all signatures
            initial_signature_count = self._count_signatures()
            
            # Generate signatures using the agent
            updated_protocols = self.signature_generator._generate_signatures_from_protocols()
            
            final_signature_count = self._count_signatures()
            
            if force_update:
                self.stats.signatures_updated = len(updated_protocols)
                self.stats.signatures_generated = 0
            else:
                self.stats.signatures_generated = final_signature_count - initial_signature_count
                self.stats.signatures_updated = len(updated_protocols) - self.stats.signatures_generated
            
            logger.info(f"✅ Signature generation completed for {len(updated_protocols)} protocols")
            return True
            
        except Exception as e:
            logger.error(f"❌ Signature generation failed: {e}")
            self.stats.errors_encountered += 1
            return False
    
    def _link_validator_addresses(self) -> bool:
        """Link existing validator addresses to protocols based on their source field."""
        try:
            with get_db_session() as session:
                # Check if validators still have source field (not migrated)
                try:
                    validators_with_source = session.execute(
                        "SELECT COUNT(*) as count FROM validator_addresses WHERE source IS NOT NULL"
                    ).scalar()
                    
                    if validators_with_source == 0:
                        logger.info("✅ Validators already linked to protocols")
                        return True
                        
                except Exception:
                    # Probably source column doesn't exist anymore
                    logger.info("✅ Validators already migrated to protocol-based structure")
                    return True
                
                # If we reach here, we need to migrate from source to protocol_id
                logger.info("🔄 Migrating validators from source-based to protocol-based structure...")
                
                # Get protocol mappings
                protocol_map = {p.name: p.id for p in session.query(Protocol).all()}
                
                # Define source to protocol mappings
                source_mappings = {
                    'sui_recon_agent': 'sui',
                    'sui': 'sui',
                    'filecoin_lotus_peer': 'filecoin',
                    'filecoin_api': 'filecoin',
                    'filecoin': 'filecoin',
                    'manual': 'manual'
                }
                
                # Create manual protocol if it doesn't exist
                if 'manual' not in protocol_map:
                    manual_protocol = Protocol(
                        name='manual',
                        display_name='Manual Entry',
                        category='Manual',
                        ports=[],
                        endpoints=[],
                        banners=[],
                        rpc_methods=[],
                        metrics_keywords=[],
                        http_paths=[],
                        identification_hints=[]
                    )
                    session.add(manual_protocol)
                    session.flush()
                    protocol_map['manual'] = manual_protocol.id
                
                # Update validators
                validators = session.execute("SELECT id, source, address FROM validator_addresses").fetchall()
                
                for validator in validators:
                    try:
                        source = validator.source
                        protocol_name = source_mappings.get(source, 'manual')
                        protocol_id = protocol_map.get(protocol_name)
                        
                        if protocol_id:
                            session.execute(
                                "UPDATE validator_addresses SET protocol_id = :protocol_id WHERE id = :id",
                                {'protocol_id': protocol_id, 'id': validator.id}
                            )
                            self.stats.validators_linked += 1
                        else:
                            logger.warning(f"⚠️  No protocol found for source '{source}' on validator {validator.address}")
                            self.stats.warnings_encountered += 1
                    
                    except Exception as e:
                        logger.error(f"❌ Failed to link validator {validator.address}: {e}")
                        self.stats.errors_encountered += 1
                        continue
                
                session.commit()
                logger.info(f"✅ Validator linking completed")
                return True
                
        except Exception as e:
            logger.error(f"❌ Validator linking failed: {e}")
            self.stats.errors_encountered += 1
            return False
    
    def _update_signature_match_results(self) -> bool:
        """Update signature match results to ensure protocol consistency."""
        try:
            with get_db_session() as session:
                # Find mismatched signature results
                mismatched = session.execute("""
                    SELECT smr.id, smr.protocol_name, p.name as actual_protocol_name, p.id as protocol_id
                    FROM signature_match_results smr
                    JOIN protocols p ON smr.protocol_id = p.id
                    WHERE smr.protocol_name != p.name
                """).fetchall()
                
                if not mismatched:
                    logger.info("✅ All signature match results are consistent")
                    return True
                
                logger.info(f"🔄 Fixing {len(mismatched)} mismatched signature results...")
                
                for result in mismatched:
                    session.execute(
                        "UPDATE signature_match_results SET protocol_name = :name WHERE id = :id",
                        {'name': result.actual_protocol_name, 'id': result.id}
                    )
                    self.stats.signature_matches_updated += 1
                
                session.commit()
                logger.info(f"✅ Signature match results updated")
                return True
                
        except Exception as e:
            logger.warning(f"⚠️  Failed to update signature match results: {e}")
            self.stats.warnings_encountered += 1
            return False
    
    def _count_protocols(self) -> int:
        """Count protocols in database."""
        try:
            with get_db_session() as session:
                return session.query(Protocol).count()
        except:
            return 0
    
    def _count_signatures(self) -> int:
        """Count protocol signatures in database."""
        try:
            with get_db_session() as session:
                return session.query(ProtocolSignature).count()
        except:
            return 0
    
    def _report_migration_stats(self):
        """Report final migration statistics."""
        logger.info("\n" + "="*60)
        logger.info("📊 MIGRATION STATISTICS")
        logger.info("="*60)
        logger.info(f"📋 Protocols Seeded: {self.stats.protocols_seeded}")
        logger.info(f"✏️  Protocols Updated: {self.stats.protocols_updated}")
        logger.info(f"🔏 Signatures Generated: {self.stats.signatures_generated}")
        logger.info(f"🔄 Signatures Updated: {self.stats.signatures_updated}")
        logger.info(f"🔗 Validators Linked: {self.stats.validators_linked}")
        logger.info(f"🎯 Signature Matches Updated: {self.stats.signature_matches_updated}")
        logger.info(f"⚠️  Warnings: {self.stats.warnings_encountered}")
        logger.info(f"❌ Errors: {self.stats.errors_encountered}")
        logger.info("="*60)
    
    def validate_migration(self) -> bool:
        """Validate the migration results."""
        logger.info("🔍 Validating migration results...")
        
        dependency_status = self.check_all_dependencies()
        
        # Check for critical issues
        critical_issues = 0
        for protocol_name, status in dependency_status.items():
            if protocol_name.startswith('__'):
                continue
                
            if not status.signature_exists:
                critical_issues += 1
            
            if not status.recon_agents_compatible:
                critical_issues += 1
        
        # Check for orphaned data
        orphaned_validators = '__orphaned_validators__' in dependency_status
        orphaned_matches = '__orphaned_signature_matches__' in dependency_status
        
        if critical_issues == 0 and not orphaned_validators and not orphaned_matches:
            logger.info("✅ Migration validation passed!")
            return True
        else:
            logger.error(f"❌ Migration validation failed: {critical_issues} critical issues found")
            if orphaned_validators:
                logger.error("❌ Orphaned validator addresses detected")
            if orphaned_matches:
                logger.error("❌ Orphaned signature match results detected")
            return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Protocol Migration Tool')
    parser.add_argument('--full-migration', action='store_true',
                       help='Run complete migration process')
    parser.add_argument('--check-dependencies', action='store_true',
                       help='Check all protocol dependencies')
    parser.add_argument('--validate-only', action='store_true',
                       help='Validate existing migration')
    parser.add_argument('--force-update', action='store_true',
                       help='Force update existing data')
    parser.add_argument('--config', type=str,
                       help='Path to configuration file')
    
    args = parser.parse_args()
    
    # Initialize tool
    config = None
    if args.config:
        logger.info(f"Loading config from: {args.config}")
    
    tool = ProtocolMigrationTool(config)
    
    try:
        if args.check_dependencies:
            tool.check_all_dependencies()
        elif args.validate_only:
            success = tool.validate_migration()
            sys.exit(0 if success else 1)
        elif args.full_migration:
            success = tool.run_full_migration(force_update=args.force_update)
            if success:
                logger.info("✅ Migration completed successfully")
                # Final validation
                if tool.validate_migration():
                    logger.info("🎉 All validations passed!")
                    sys.exit(0)
                else:
                    logger.error("❌ Migration completed but validation failed")
                    sys.exit(1)
            else:
                logger.error("❌ Migration failed")
                sys.exit(1)
        else:
            parser.print_help()
            sys.exit(1)
    
    except KeyboardInterrupt:
        logger.info("⏹️  Migration interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Migration tool failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
