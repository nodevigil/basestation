#!/bin/bash

# DePIN Infrastructure Scanner - Celery Management Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_help() {
    echo "DePIN Infrastructure Scanner - Celery Management"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  start-redis    Start Redis server using Docker"
    echo "  stop-redis     Stop Redis server"
    echo "  start-worker   Start Celery worker"
    echo "  stop-worker    Stop Celery worker"
    echo "  start-flower   Start Celery Flower monitoring"
    echo "  stop-flower    Stop Celery Flower"
    echo "  start-all      Start Redis, worker, and Flower"
    echo "  stop-all       Stop all services"
    echo "  status         Show status of all services"
    echo "  logs           Show logs from services"
    echo "  install        Install required dependencies"
    echo "  help           Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 start-all                # Start all services"
    echo "  $0 status                   # Check service status"
    echo "  $0 logs                     # View service logs"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running"
        exit 1
    fi
}

check_redis() {
    if ! docker ps | grep -q "depin-redis"; then
        return 1
    fi
    return 0
}

start_redis() {
    print_status "Starting Redis server..."
    check_docker
    
    if check_redis; then
        print_warning "Redis is already running"
        return 0
    fi
    
    docker-compose -f docker-compose.celery.yml up -d redis
    
    # Wait for Redis to be ready
    for i in {1..30}; do
        if docker exec depin-redis redis-cli ping &> /dev/null; then
            print_success "Redis started successfully"
            return 0
        fi
        sleep 1
    done
    
    print_error "Redis failed to start within 30 seconds"
    exit 1
}

stop_redis() {
    print_status "Stopping Redis server..."
    check_docker
    
    docker-compose -f docker-compose.celery.yml stop redis
    docker-compose -f docker-compose.celery.yml rm -f redis
    print_success "Redis stopped"
}

start_worker() {
    print_status "Starting Celery worker..."
    
    if ! check_redis; then
        print_warning "Redis is not running. Starting Redis first..."
        start_redis
    fi
    
    check_docker
    docker-compose -f docker-compose.celery.yml up -d celery-worker
    print_success "Celery worker started"
}

stop_worker() {
    print_status "Stopping Celery worker..."
    check_docker
    
    docker-compose -f docker-compose.celery.yml stop celery-worker
    docker-compose -f docker-compose.celery.yml rm -f celery-worker
    print_success "Celery worker stopped"
}

start_flower() {
    print_status "Starting Celery Flower monitoring..."
    
    if ! check_redis; then
        print_warning "Redis is not running. Starting Redis first..."
        start_redis
    fi
    
    check_docker
    docker-compose -f docker-compose.celery.yml up -d celery-flower
    print_success "Celery Flower started at http://localhost:5555"
}

stop_flower() {
    print_status "Stopping Celery Flower..."
    check_docker
    
    docker-compose -f docker-compose.celery.yml stop celery-flower
    docker-compose -f docker-compose.celery.yml rm -f celery-flower
    print_success "Celery Flower stopped"
}

start_all() {
    print_status "Starting all services..."
    start_redis
    start_worker
    start_flower
    print_success "All services started successfully"
    echo ""
    echo "Services:"
    echo "  - Redis: localhost:6379"
    echo "  - Celery Worker: Running in background"
    echo "  - Flower UI: http://localhost:5555"
}

stop_all() {
    print_status "Stopping all services..."
    stop_flower
    stop_worker
    stop_redis
    print_success "All services stopped"
}

show_status() {
    print_status "Service Status:"
    echo ""
    
    # Check Redis
    if check_redis; then
        echo -e "  Redis:        ${GREEN}Running${NC}"
    else
        echo -e "  Redis:        ${RED}Stopped${NC}"
    fi
    
    # Check Celery Worker
    if docker ps | grep -q "depin-celery-worker"; then
        echo -e "  Celery Worker: ${GREEN}Running${NC}"
    else
        echo -e "  Celery Worker: ${RED}Stopped${NC}"
    fi
    
    # Check Flower
    if docker ps | grep -q "depin-celery-flower"; then
        echo -e "  Flower:       ${GREEN}Running${NC} (http://localhost:5555)"
    else
        echo -e "  Flower:       ${RED}Stopped${NC}"
    fi
}

show_logs() {
    print_status "Showing service logs (Ctrl+C to exit)..."
    check_docker
    docker-compose -f docker-compose.celery.yml logs -f
}

install_deps() {
    print_status "Installing required dependencies..."
    
    # Install Python dependencies
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
        print_success "Python dependencies installed"
    else
        print_error "requirements.txt not found"
        exit 1
    fi
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_warning "Docker is not installed. Please install Docker to use containerized services."
    else
        print_success "Docker is available"
    fi
}

# Main command processing
case "${1:-help}" in
    start-redis)
        start_redis
        ;;
    stop-redis)
        stop_redis
        ;;
    start-worker)
        start_worker
        ;;
    stop-worker)
        stop_worker
        ;;
    start-flower)
        start_flower
        ;;
    stop-flower)
        stop_flower
        ;;
    start-all)
        start_all
        ;;
    stop-all)
        stop_all
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs
        ;;
    install)
        install_deps
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        print_error "Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac
