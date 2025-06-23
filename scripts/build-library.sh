#!/bin/bash
# build-library.sh - Script to build and package the PGDN library

set -e  # Exit on any error

echo "🏗️  Building PGDN Library Package"
echo "================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# Check if we're in the right directory
if [ ! -f "setup.py" ] || [ ! -f "pyproject.toml" ]; then
    print_error "setup.py or pyproject.toml not found. Please run this script from the PGDN root directory."
    exit 1
fi

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is required but not installed."
    exit 1
fi

# Check if pip is available
if ! command -v pip &> /dev/null; then
    print_error "pip is required but not installed."
    exit 1
fi

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf build/
rm -rf dist/
rm -rf *.egg-info/
print_status "Cleaned previous builds"

# Install build dependencies
echo "📦 Installing build dependencies..."
pip install --upgrade pip setuptools wheel build twine
print_status "Build dependencies installed"

# Build the package
echo "🔨 Building package..."
python -m build
print_status "Package built successfully"

# List created packages
echo "📋 Created packages:"
ls -la dist/

# Validate the package
echo "🔍 Validating package..."
python -m twine check dist/*
print_status "Package validation passed"

# Test installation in virtual environment
echo "🧪 Testing installation..."
python -m venv test_env
source test_env/bin/activate

# Install the built package
pip install dist/*.whl

# Test import
if python -c "import pgdn; print('✅ Import test passed')" 2>/dev/null; then
    print_status "Installation test passed"
else
    print_error "Installation test failed"
    deactivate
    rm -rf test_env
    exit 1
fi

# Cleanup test environment
deactivate
rm -rf test_env

echo ""
echo "🎉 Build completed successfully!"
echo ""
echo "📁 Package files created in dist/:"
echo "   - $(ls dist/*.whl 2>/dev/null || echo 'No .whl file found')"
echo "   - $(ls dist/*.tar.gz 2>/dev/null || echo 'No .tar.gz file found')"
echo ""
echo "📋 Installation instructions:"
echo "   Local install:     pip install dist/*.whl"
echo "   Development:       pip install -e ."
echo "   From Git:          pip install git+<repository-url>"
echo ""
echo "📚 Next steps:"
echo "   1. Test the package: pip install dist/*.whl"
echo "   2. Upload to PyPI:   python -m twine upload dist/*"
echo "   3. Create release:   git tag v1.0.0 && git push --tags"
