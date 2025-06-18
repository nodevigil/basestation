#!/bin/bash

# Quick commands for Docker development

case "$1" in
    "build")
        echo "🔨 Building containers..."
        docker-compose build
        ;;
    "up")
        echo "🚀 Starting all services..."
        docker-compose up -d
        ;;
    "down")
        echo "🛑 Stopping all services..."
        docker-compose down
        ;;
    "logs")
        echo "📋 Showing logs..."
        docker-compose logs -f ${2:-app}
        ;;
    "shell")
        echo "🐚 Opening shell in app container..."
        docker-compose exec app /bin/bash
        ;;
    "run")
        echo "▶️  Running command in app container..."
        shift
        docker-compose run --rm app "$@"
        ;;
    "scan")
        if [ -z "$2" ]; then
            echo "❌ Please provide an IP address to scan"
            echo "Usage: $0 scan <ip_address>"
            exit 1
        fi
        echo "🔍 Scanning $2..."
        docker-compose run --rm app pgdn --scan-target "$2"
        ;;
    "recon")
        protocol=${2:-sui}
        echo "🔍 Running reconnaissance for $protocol..."
        docker-compose run --rm app pgdn --stage recon --protocol "$protocol"
        ;;
    "reset")
        echo "🧹 Resetting everything (removes volumes)..."
        docker-compose down -v
        docker-compose build
        ;;
    "test")
        echo "🧪 Running Docker environment tests..."
        docker-compose run --rm app python scripts/test-docker-env.py
        ;;
    "pytest")
        echo "🧪 Running pytest..."
        docker-compose run --rm app python -m pytest
        ;;
    *)
        echo "🐳 DePIN Scanner Docker Helper"
        echo ""
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  build     - Build containers"
        echo "  up        - Start all services"
        echo "  down      - Stop all services"
        echo "  logs      - Show logs (optionally specify service)"
        echo "  shell     - Open bash shell in app container"
        echo "  run       - Run command in app container"
        echo "  scan      - Scan an IP address"
        echo "  recon     - Run reconnaissance (sui/filecoin)"
        echo "  reset     - Reset everything (removes data)"
        echo "  test      - Test Docker environment setup"
        echo "  pytest    - Run Python tests"
        echo ""
        echo "Examples:"
        echo "  $0 build"
        echo "  $0 scan 1.1.1.1"
        echo "  $0 recon sui"
        echo "  $0 run pgdn --help"
        echo "  $0 logs postgres"
        echo "  $0 test"
        ;;
esac
