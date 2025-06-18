#!/bin/bash

# Development startup script for DePIN Scanner

echo "🐳 Starting DePIN Scanner in Docker..."

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Build and start services
echo "📦 Building containers..."
docker-compose build

echo "🚀 Starting services..."
docker-compose up -d postgres redis

echo "⏳ Waiting for database to be ready..."
docker-compose exec postgres pg_isready -U simon -d depin

echo "🔧 Running database migrations..."
docker-compose run --rm app python -c "
from core.database import create_tables
from core.config import Config
config = Config('config.docker.json')
create_tables(config.database)
print('✅ Database initialized')
"

echo "✅ Setup complete!"
echo ""
echo "🔧 Development commands:"
echo "  docker-compose run --rm app pgdn --help"
echo "  docker-compose run --rm app pgdn --stage recon --protocol sui"
echo "  docker-compose run --rm app pgdn --scan-target <ip>"
echo "  docker-compose exec app /bin/bash  # Get a shell inside container"
echo ""
echo "🛑 To stop: docker-compose down"
echo "🧹 To cleanup: docker-compose down -v (removes data volumes)"
