#!/usr/bin/env python3
"""
Quick installer script for PGDN library
"""

import os
import sys
import subprocess
import tempfile
import shutil
from pathlib import Path

def run_command(cmd, description):
    """Run a command and return success status."""
    print(f"📦 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e.stderr}")
        return False

def install_pgdn(method='pip', source_path=None, git_url=None):
    """Install PGDN library using specified method."""
    
    print("🚀 PGDN Library Installer")
    print("=" * 40)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ is required")
        return False
    
    print(f"✅ Python {sys.version.split()[0]} detected")
    
    # Install based on method
    if method == 'pip' and git_url:
        # Install from Git
        cmd = f"pip install git+{git_url}"
        success = run_command(cmd, "Installing from Git repository")
        
    elif method == 'local' and source_path:
        # Install from local source
        if not os.path.exists(source_path):
            print(f"❌ Source path not found: {source_path}")
            return False
        
        cmd = f"pip install -e {source_path}"
        success = run_command(cmd, "Installing from local source")
        
    elif method == 'wheel' and source_path:
        # Build and install wheel
        original_dir = os.getcwd()
        try:
            os.chdir(source_path)
            
            # Build wheel
            if not run_command("python -m build --wheel", "Building wheel package"):
                return False
            
            # Find the wheel file
            dist_dir = Path(source_path) / 'dist'
            wheel_files = list(dist_dir.glob('*.whl'))
            
            if not wheel_files:
                print("❌ No wheel file found")
                return False
            
            wheel_file = wheel_files[-1]  # Use latest wheel
            cmd = f"pip install {wheel_file}"
            success = run_command(cmd, f"Installing wheel {wheel_file.name}")
            
        finally:
            os.chdir(original_dir)
    
    else:
        print("❌ Invalid installation method or missing parameters")
        return False
    
    if success:
        # Test installation
        print("🧪 Testing installation...")
        try:
            from lib import Scanner, Config
            print("✅ PGDN library imported successfully")
            
            # Show available components
            components = [
                'Scanner', 'Config'
            ]
            
            print(f"📦 Available components: {', '.join(components)}")
            print("\n🎉 Installation completed successfully!")
            
            print("\n📋 Quick start:")
            print("   from lib import Scanner, Config")
            print("   config = Config.from_file('config.json')")
            print("   scanner = Scanner(config)")
            print("   result = scanner.scan(target='example.com', org_id='test', protocol='sui')")
            
            return True
            
        except ImportError as e:
            print(f"❌ Import test failed: {e}")
            return False
    
    return False

def main():
    """Main installer function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="PGDN Library Installer")
    parser.add_argument('--method', choices=['pip', 'local', 'wheel'], default='local',
                       help='Installation method')
    parser.add_argument('--source', help='Path to PGDN source code')
    parser.add_argument('--git-url', help='Git repository URL')
    parser.add_argument('--dev', action='store_true', 
                       help='Install in development mode (editable)')
    
    args = parser.parse_args()
    
    # Auto-detect source path if not provided
    if not args.source and args.method in ['local', 'wheel']:
        current_dir = Path(__file__).parent.parent
        if (current_dir / 'setup.py').exists():
            args.source = str(current_dir)
            print(f"📍 Auto-detected source path: {args.source}")
        else:
            print("❌ Could not auto-detect source path. Please specify --source")
            return False
    
    # Install dependencies first
    dependencies = ['setuptools', 'wheel', 'build']
    for dep in dependencies:
        run_command(f"pip install {dep}", f"Installing {dep}")
    
    # Run installation
    success = install_pgdn(
        method=args.method,
        source_path=args.source,
        git_url=args.git_url
    )
    
    if success:
        print("\n✅ Installation successful!")
        return True
    else:
        print("\n❌ Installation failed!")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
