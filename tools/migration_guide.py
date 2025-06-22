#!/usr/bin/env python3
"""
Protocol Migration Usage Guide

This script demonstrates how to use the protocol migration tool for different scenarios.
"""

import os
import sys
import subprocess
from typing import List

def run_command(cmd: List[str], description: str) -> bool:
    """Run a command and return success status."""
    print(f"\n🔹 {description}")
    print(f"💻 Running: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"✅ Success!")
        if result.stdout:
            print(f"📄 Output:\n{result.stdout}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed!")
        if e.stderr:
            print(f"📄 Error:\n{e.stderr}")
        return False
    except Exception as e:
        print(f"❌ Failed: {e}")
        return False

def main():
    """Main usage guide."""
    print("🔧 Protocol Migration Tool - Usage Guide")
    print("=" * 50)
    
    # Change to project directory
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(project_root)
    print(f"📁 Working directory: {project_root}")
    
    scenarios = [
        {
            "name": "Check Dependencies Only",
            "description": "Check all protocol dependencies without making changes",
            "command": ["python", "tools/protocol_migration_tool.py", "--check-dependencies"],
            "safe": True
        },
        {
            "name": "Validate Existing Migration",
            "description": "Validate that an existing migration is working correctly",
            "command": ["python", "tools/protocol_migration_tool.py", "--validate-only"],
            "safe": True
        },
        {
            "name": "Fresh Full Migration",
            "description": "Run complete migration (protocols + signatures + linking)",
            "command": ["python", "tools/protocol_migration_tool.py", "--full-migration"],
            "safe": False
        },
        {
            "name": "Force Update Migration",
            "description": "Force update all existing protocols and signatures",
            "command": ["python", "tools/protocol_migration_tool.py", "--full-migration", "--force-update"],
            "safe": False
        },
    ]
    
    print("\n📋 Available Migration Scenarios:")
    print("-" * 40)
    
    for i, scenario in enumerate(scenarios, 1):
        safety = "🟢 Safe" if scenario["safe"] else "🟡 Modifies Data"
        print(f"{i}. {scenario['name']} ({safety})")
        print(f"   {scenario['description']}")
        print(f"   Command: {' '.join(scenario['command'])}")
        print()
    
    # Interactive selection
    try:
        choice = input("Select scenario (1-4) or 'q' to quit: ").strip()
        
        if choice.lower() == 'q':
            print("👋 Goodbye!")
            return
        
        choice_idx = int(choice) - 1
        
        if choice_idx < 0 or choice_idx >= len(scenarios):
            print("❌ Invalid choice!")
            return
        
        selected = scenarios[choice_idx]
        
        if not selected["safe"]:
            confirm = input(f"⚠️  This will modify data. Continue? (y/N): ").strip().lower()
            if confirm != 'y':
                print("❌ Cancelled by user")
                return
        
        print(f"\n🚀 Running: {selected['name']}")
        success = run_command(selected["command"], selected["description"])
        
        if success:
            print(f"\n🎉 {selected['name']} completed successfully!")
        else:
            print(f"\n❌ {selected['name']} failed!")
            
    except KeyboardInterrupt:
        print("\n⏹️  Interrupted by user")
    except ValueError:
        print("❌ Invalid input! Please enter a number 1-4")
    except Exception as e:
        print(f"❌ Error: {e}")

def show_recommended_workflow():
    """Show the recommended migration workflow."""
    print("\n" + "=" * 60)
    print("📋 RECOMMENDED MIGRATION WORKFLOW")
    print("=" * 60)
    
    steps = [
        "1. Check Dependencies (Safe)",
        "   python tools/protocol_migration_tool.py --check-dependencies",
        "",
        "2. Backup Database (Recommended)",
        "   pg_dump your_database > backup_before_migration.sql",
        "",
        "3. Run Migration (Modifies Data)",
        "   python tools/protocol_migration_tool.py --full-migration",
        "",
        "4. Validate Results (Safe)",
        "   python tools/protocol_migration_tool.py --validate-only",
        "",
        "5. Test Reconnaissance Agents",
        "   python scripts/validate_recon_readiness.py",
        "   python -m agents.recon.sui_agent",
        "   python -m agents.recon.filecoin_agent",
    ]
    
    for step in steps:
        print(step)
    
    print("=" * 60)

if __name__ == "__main__":
    main()
    show_recommended_workflow()
