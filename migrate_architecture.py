"""
Migration script to help transition from old to new architecture.

This script demonstrates how to migrate existing functionality
while maintaining backward compatibility.
"""

import os
import sys
import shutil
from pathlib import Path
from typing import List, Dict, Any

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from core.config import Config
from core.logging import setup_logging, get_logger
from core.database import create_tables, get_database_manager
from utils.pipeline import create_orchestrator


class ArchitectureMigrator:
    """
    Helps migrate from the old monolithic architecture to the new agentic architecture.
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.project_root = Path(__file__).parent
        
    def backup_old_files(self) -> bool:
        """
        Create backup of old architecture files.
        
        Returns:
            True if backup succeeded, False otherwise
        """
        try:
            backup_dir = self.project_root / "backup_old_architecture"
            backup_dir.mkdir(exist_ok=True)
            
            old_files = [
                "main.py",
                "scanner_agent.py", 
                "manage_validators.py",
                "view_scans.py",
                "setup_database.py"
            ]
            
            backed_up = []
            for file_name in old_files:
                file_path = self.project_root / file_name
                if file_path.exists():
                    backup_path = backup_dir / file_name
                    shutil.copy2(file_path, backup_path)
                    backed_up.append(file_name)
                    self.logger.info(f"✅ Backed up {file_name}")
            
            if backed_up:
                self.logger.info(f"📦 Created backup in: {backup_dir}")
                self.logger.info(f"   Backed up files: {', '.join(backed_up)}")
                return True
            else:
                self.logger.info("ℹ️  No old files found to backup")
                return True
                
        except Exception as e:
            self.logger.error(f"❌ Failed to backup old files: {e}")
            return False
    
    def validate_new_architecture(self) -> bool:
        """
        Validate that the new architecture is properly set up.
        
        Returns:
            True if validation passes, False otherwise
        """
        try:
            self.logger.info("🔍 Validating new architecture...")
            
            # Check required directories
            required_dirs = [
                "agents/recon",
                "agents/scan", 
                "agents/process",
                "agents/publish",
                "core",
                "utils"
            ]
            
            for dir_path in required_dirs:
                full_path = self.project_root / dir_path
                if not full_path.exists():
                    self.logger.error(f"❌ Missing directory: {dir_path}")
                    return False
                self.logger.debug(f"✅ Found directory: {dir_path}")
            
            # Check core modules
            try:
                from core.config import Config
                from core.database import get_database_manager
                from core.logging import setup_logging
                self.logger.debug("✅ Core modules import successfully")
            except ImportError as e:
                self.logger.error(f"❌ Failed to import core modules: {e}")
                return False
            
            # Check agent base classes
            try:
                from agents.base import BaseAgent, ReconAgent, ScanAgent, ProcessAgent, PublishAgent
                self.logger.debug("✅ Agent base classes import successfully")
            except ImportError as e:
                self.logger.error(f"❌ Failed to import agent base classes: {e}")
                return False
            
            # Check specific agents
            try:
                from agents.recon.sui_agent import SuiReconAgent
                from agents.scan.node_scanner_agent import NodeScannerAgent
                from agents.process.processor_agent import ProcessorAgent
                from agents.publish.publisher_agent import PublisherAgent
                self.logger.debug("✅ Specific agents import successfully")
            except ImportError as e:
                self.logger.error(f"❌ Failed to import specific agents: {e}")
                return False
            
            # Check utilities
            try:
                from utils.agent_registry import get_agent_registry
                from utils.pipeline import create_orchestrator
                self.logger.debug("✅ Utility modules import successfully")
            except ImportError as e:
                self.logger.error(f"❌ Failed to import utility modules: {e}")
                return False
            
            self.logger.info("✅ New architecture validation passed")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Architecture validation failed: {e}")
            return False
    
    def test_database_connectivity(self) -> bool:
        """
        Test database connectivity with new architecture.
        
        Returns:
            True if database test passes, False otherwise
        """
        try:
            self.logger.info("🗄️  Testing database connectivity...")
            
            config = Config()
            db_manager = get_database_manager(config.database)
            
            # Test connectivity
            if not db_manager.health_check():
                self.logger.error("❌ Database health check failed")
                return False
            
            # Try to create tables
            create_tables(config.database)
            self.logger.info("✅ Database tables created/verified")
            
            self.logger.info("✅ Database connectivity test passed")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Database connectivity test failed: {e}")
            return False
    
    def test_agent_discovery(self) -> bool:
        """
        Test agent discovery and registration.
        
        Returns:
            True if agent discovery works, False otherwise
        """
        try:
            self.logger.info("🤖 Testing agent discovery...")
            
            from utils.agent_registry import get_agent_registry
            registry = get_agent_registry()
            
            agents = registry.list_all_agents()
            
            # Check that we have at least one agent in each category
            required_categories = ['recon', 'scan', 'process', 'publish']
            for category in required_categories:
                if category not in agents or not agents[category]:
                    self.logger.error(f"❌ No {category} agents discovered")
                    return False
                self.logger.debug(f"✅ Found {len(agents[category])} {category} agents")
            
            self.logger.info("✅ Agent discovery test passed")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Agent discovery test failed: {e}")
            return False
    
    def test_pipeline_orchestration(self) -> bool:
        """
        Test pipeline orchestration without actually running scans.
        
        Returns:
            True if orchestration test passes, False otherwise
        """
        try:
            self.logger.info("🔄 Testing pipeline orchestration...")
            
            config = Config()
            orchestrator = create_orchestrator(config)
            
            # Test orchestrator creation
            status = orchestrator.get_pipeline_status()
            if not status:
                self.logger.error("❌ Failed to get pipeline status")
                return False
            
            # Test agent listing
            available_agents = orchestrator.list_available_agents()
            if not available_agents:
                self.logger.error("❌ No agents available to orchestrator")
                return False
            
            self.logger.info("✅ Pipeline orchestration test passed")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Pipeline orchestration test failed: {e}")
            return False
    
    def run_full_migration_check(self) -> bool:
        """
        Run the complete migration validation process.
        
        Returns:
            True if all checks pass, False otherwise
        """
        self.logger.info("🚀 Starting migration validation...")
        
        checks = [
            ("Architecture Validation", self.validate_new_architecture),
            ("Database Connectivity", self.test_database_connectivity),
            ("Agent Discovery", self.test_agent_discovery),
            ("Pipeline Orchestration", self.test_pipeline_orchestration)
        ]
        
        all_passed = True
        results = {}
        
        for check_name, check_func in checks:
            try:
                self.logger.info(f"🔍 Running {check_name}...")
                result = check_func()
                results[check_name] = result
                
                if result:
                    self.logger.info(f"✅ {check_name}: PASSED")
                else:
                    self.logger.error(f"❌ {check_name}: FAILED")
                    all_passed = False
                    
            except Exception as e:
                self.logger.error(f"❌ {check_name}: ERROR - {e}")
                results[check_name] = False
                all_passed = False
        
        # Print summary
        self.logger.info("📊 Migration Validation Summary:")
        for check_name, result in results.items():
            status = "✅ PASS" if result else "❌ FAIL"
            self.logger.info(f"   {check_name}: {status}")
        
        if all_passed:
            self.logger.info("🎉 All migration checks passed! New architecture is ready.")
            self.logger.info("")
            self.logger.info("Next steps:")
            self.logger.info("  1. Replace old main.py with main_new.py")
            self.logger.info("  2. Run: python main_new.py --list-agents")
            self.logger.info("  3. Run: python main_new.py --stage recon")
            self.logger.info("  4. Run: python main_new.py (full pipeline)")
        else:
            self.logger.error("❌ Some migration checks failed. Please address the issues above.")
        
        return all_passed


def main():
    """Main migration script entry point."""
    print("🔄 DePIN Infrastructure Scanner - Architecture Migration")
    print("="*60)
    
    # Setup basic logging
    setup_logging()
    
    migrator = ArchitectureMigrator()
    
    # Backup old files
    if not migrator.backup_old_files():
        print("❌ Failed to backup old files")
        sys.exit(1)
    
    # Run migration validation
    if migrator.run_full_migration_check():
        print("\n🎉 Migration validation completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Migration validation failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
