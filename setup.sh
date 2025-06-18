#!/bin/bash
set -e

echo "🚀 DePIN Infrastructure Scanner Setup"
echo "====================================="

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check Python version
echo "Checking Python version..."
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
if python3 -c 'import sys; exit(1 if sys.version_info < (3, 8) else 0)'; then
    print_status "Python $PYTHON_VERSION is compatible"
else
    print_error "Python $PYTHON_VERSION is too old. Please install Python 3.8 or higher."
    exit 1
fi

# Check PostgreSQL
echo "Checking PostgreSQL..."
if ! command -v psql &> /dev/null; then
    print_warning "PostgreSQL client not found. Please install PostgreSQL."
    print_warning "On macOS: brew install postgresql"
    print_warning "On Ubuntu: sudo apt-get install postgresql-client"
else
    print_status "PostgreSQL client found"
fi

# Create virtual environment
echo "Setting up Python virtual environment..."
if [ ! -d "myenv" ]; then
    python3 -m venv myenv
    print_status "Virtual environment created"
else
    print_warning "Virtual environment already exists"
fi

# Activate virtual environment and install dependencies
echo "Installing dependencies..."
source myenv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
print_status "Dependencies installed"

# Setup configuration
echo "Setting up configuration..."
if [ ! -f "config.json" ]; then
    cp config.example.json config.json
    print_status "Configuration file created (config.json)"
    print_warning "Please edit config.json with your database credentials"
else
    print_warning "Configuration file already exists"
fi

# Database setup
echo "Setting up database..."
read -p "Do you want to create the database 'depin'? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if createdb depin 2>/dev/null; then
        print_status "Database 'depin' created"
    else
        print_warning "Database 'depin' might already exist or creation failed"
    fi
    
    # Run migrations
    echo "Running database migrations..."
    alembic upgrade head
    print_status "Database schema initialized"
fi

# Test installation
echo "Testing installation..."
if pgdn --list-agents > /dev/null 2>&1; then
    print_status "Installation successful!"
else
    print_error "Installation test failed. Please check the logs above."
    exit 1
fi

echo ""
echo "🎉 Setup Complete!"
echo ""
echo "Next steps:"
echo "1. Edit config.json with your database settings"
echo "2. Run: source myenv/bin/activate"
echo "3. Run: pgdn --list-agents"
echo "4. Run: pgdn --log-level INFO"
echo ""
echo "For help, see README_new.md"
