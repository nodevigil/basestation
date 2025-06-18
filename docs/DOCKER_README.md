# DePIN Infrastructure Scanner - Docker Setup

This guide explains how to run the DePIN Infrastructure Scanner in Docker, which provides access to Linux-based security tools unavailable on macOS.

## 🐳 Docker Setup

### Prerequisites

- Docker Desktop installed and running
- Docker Compose (included with Docker Desktop)

### Quick Start

1. **Clone and navigate to the project**:
   ```bash
   cd /Users/simon/Documents/Code/depin
   ```

2. **Copy environment file**:
   ```bash
   cp .env.example .env
   ```

3. **Start the services**:
   ```bash
   ./scripts/dev-start.sh
   ```

4. **Run commands in the container**:
   ```bash
   # Get help
   ./docker-dev.sh run python main.py --help
   
   # Run reconnaissance
   ./docker-dev.sh recon sui
   
   # Scan a specific IP
   ./docker-dev.sh scan 1.1.1.1
   
   # Get a shell in the container
   ./docker-dev.sh shell
   ```

## 🏗️ Architecture

The Docker setup includes:

- **App Container**: Python application with Linux security tools
- **PostgreSQL**: Database for storing scan results
- **Redis**: Caching/queuing (for future use)

### Key Features

✅ **Linux Tools**: Access to `nmap`, `whatweb`, and other Linux-only tools  
✅ **Live Editing**: Your code changes are reflected immediately  
✅ **Persistent Data**: Database data survives container restarts  
✅ **Network Capabilities**: Raw socket access for advanced scanning  

## 📁 Docker Files Overview

```
├── Dockerfile              # App container definition
├── docker-compose.yml      # Multi-container setup
├── docker-dev.sh          # Quick command helper
├── .env.example           # Environment variables template
├── config.docker.json    # Docker-specific configuration
└── scripts/
    ├── dev-start.sh      # Development setup script
    └── init-db.sql       # Database initialization
```

## 🚀 Development Workflow

### Starting Development

```bash
# Start all services
./docker-dev.sh up

# View logs
./docker-dev.sh logs app

# Get a shell for debugging
./docker-dev.sh shell
```

### Running Scans

```bash
# Run reconnaissance to discover nodes
./docker-dev.sh recon sui

# Scan discovered nodes
./docker-dev.sh run python main.py --stage scan

# Scan specific target
./docker-dev.sh scan 139.84.148.36

# Scan with protocol filter
./docker-dev.sh run python main.py --stage scan --protocol filecoin
```

### Database Operations

```bash
# Access database directly
docker-compose exec postgres psql -U simon -d depin

# View scan results
docker-compose exec postgres psql -U simon -d depin -c "SELECT address, source, created_at FROM validator_addresses;"

# Reset database
./docker-dev.sh reset
```

## 🛠️ Available Tools in Container

The Docker container includes these Linux-based security tools:

- **nmap**: Network port scanner with sudo privileges
- **whatweb**: Web application scanner  
- **openssl**: SSL/TLS analysis tools
- **curl/wget**: HTTP clients for testing
- **PostgreSQL client**: Database operations

### Example: Using nmap with sudo

```bash
# Get shell in container
./docker-dev.sh shell

# Run nmap with sudo (works in container, not on macOS)
sudo nmap -sS -T5 -p 22,80,443 1.1.1.1
```

## 🔧 Configuration

### Environment Variables

Key environment variables (see `.env.example`):

```bash
# Database
DATABASE_URL=postgresql://simon:devpassword@postgres:5432/depin

# Scanning
SCAN_TIMEOUT=45
MAX_CONCURRENT_SCANS=1

# Logging  
LOG_LEVEL=INFO
```

### Configuration Files

- `config.json`: Local development (macOS)
- `config.docker.json`: Docker environment (auto-detected)

The application automatically detects Docker environment and uses the appropriate config.

## 📊 Data Persistence

Data is persisted in Docker volumes:

- `postgres_data`: Database data
- `redis_data`: Redis data
- `./logs`: Application logs (mounted from host)

## 🧹 Cleanup

```bash
# Stop services
./docker-dev.sh down

# Remove all data (destructive!)
./docker-dev.sh reset

# Remove Docker images (free up space)
docker system prune -a
```

## 🐛 Troubleshooting

### Container won't start
```bash
# Check Docker is running
docker info

# View container logs
./docker-dev.sh logs app

# Rebuild containers
./docker-dev.sh build
```

### Database connection issues
```bash
# Check database status
./docker-dev.sh logs postgres

# Test connection
docker-compose exec app python -c "
from core.database import create_tables
from core.config import Config
config = Config()
print('Database URL:', config.database.url)
"
```

### Permission issues with nmap
```bash
# Verify sudo access in container
./docker-dev.sh shell
sudo whoami  # Should return 'root'
```

## 🔄 Code Development

Your code changes are immediately available in the container:

1. Edit files on macOS using your preferred editor
2. Changes are reflected instantly via volume mount
3. Run/test in the Linux container environment
4. No need to rebuild containers for code changes

This gives you the best of both worlds: familiar macOS development environment with Linux toolchain access.

## 📈 Performance Tips

- Use `--network host` in docker-compose.yml for fastest network scanning
- Adjust `MAX_CONCURRENT_SCANS` based on your system resources
- Use SSD storage for Docker volumes for better database performance
