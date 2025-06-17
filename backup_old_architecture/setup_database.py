#!/usr/bin/env python3
"""
Database setup script for the DePIN validator project
"""
import os
import sys
import subprocess
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError, ProgrammingError

def check_postgresql():
    """Check if PostgreSQL is running"""
    try:
        result = subprocess.run(['pg_isready'], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        print("PostgreSQL is not installed or not in PATH")
        return False

def create_database():
    """Create the database if it doesn't exist"""
    # Connect to default postgres database first
    admin_url = 'postgresql://simon@localhost/postgres'
    
    try:
        engine = create_engine(admin_url)
        with engine.connect() as conn:
            # Use autocommit mode for CREATE DATABASE
            conn.execute(text("COMMIT"))
            try:
                conn.execute(text("CREATE DATABASE depin"))
                print("✅ Database 'depin' created successfully")
            except ProgrammingError as e:
                if "already exists" in str(e):
                    print("✅ Database 'depin' already exists")
                else:
                    raise
    except OperationalError as e:
        print(f"❌ Error connecting to PostgreSQL: {e}")
        print("\nMake sure:")
        print("1. PostgreSQL is running")
        print("2. User 'simon' has database creation privileges")
        print("3. You can connect with: psql -U simon -d postgres")
        return False
    
    return True

def run_migrations():
    """Run Alembic migrations"""
    try:
        python_path = "/Users/simon/Documents/Code/depin/myenv/bin/python"
        result = subprocess.run([python_path, '-m', 'alembic', 'upgrade', 'head'], 
                              cwd='/Users/simon/Documents/Code/depin',
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Database migrations completed successfully")
            return True
        else:
            print(f"❌ Migration failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error running migrations: {e}")
        return False

def main():
    print("🚀 Setting up DePIN Validator Database")
    print("=" * 40)
    
    # Check PostgreSQL
    print("1. Checking PostgreSQL...")
    if not check_postgresql():
        print("❌ PostgreSQL is not running. Please start PostgreSQL first.")
        print("\nOn macOS with Homebrew:")
        print("  brew services start postgresql")
        print("\nOr start manually:")
        print("  pg_ctl -D /opt/homebrew/var/postgres start")
        sys.exit(1)
    
    print("✅ PostgreSQL is running")
    
    # Create database
    print("\n2. Creating database...")
    if not create_database():
        sys.exit(1)
    
    # Run migrations
    print("\n3. Running migrations...")
    if not run_migrations():
        sys.exit(1)
    
    print("\n🎉 Database setup completed!")
    print("\nYou can now:")
    print("  - Import Sui validators: python manage_validators.py import-sui")
    print("  - List validators: python manage_validators.py list")
    print("  - Add validators manually: python manage_validators.py add <address>")
    print("  - View stats: python manage_validators.py stats")

if __name__ == '__main__':
    main()
