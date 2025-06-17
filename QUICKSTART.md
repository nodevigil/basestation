# 🚀 Quick Start Guide

## Step 1: Prepare Environment

```bash
# Navigate to project directory
cd /Users/simon/Documents/Code/depin

# Create environment file
cp .env.example .env

# Make scripts executable (if not already)
chmod +x scripts/dev-start.sh docker-dev.sh scripts/test-docker-env.py
```

## Step 2: Start Docker Environment

```bash
# Option A: Use the setup script (recommended)
./scripts/dev-start.sh

# Option B: Manual setup
./docker-dev.sh build
./docker-dev.sh up
```

## Step 3: Test Everything Works

```bash
# Run environment tests
./docker-dev.sh test

# If all tests pass, you're ready to go!
```

## Step 4: Try Some Commands

```bash
# Get help
./docker-dev.sh run python main.py --help

# Run reconnaissance to discover Sui nodes
./docker-dev.sh recon sui

# Scan a specific IP with Linux tools
./docker-dev.sh scan 1.1.1.1

# Get a shell in the container
./docker-dev.sh shell
```

## 🎯 Key Benefits Achieved

✅ **Linux Tools**: `sudo nmap` and other Linux-only tools now work  
✅ **Live Editing**: Edit code on macOS, runs immediately in Linux container  
✅ **Database**: PostgreSQL automatically set up and configured  
✅ **Persistence**: Data survives container restarts  
✅ **Easy Commands**: Simple `./docker-dev.sh` shortcuts for everything  

## 🛠️ Development Workflow

1. **Edit code** on macOS with your favorite editor
2. **Run/test** in Linux container with `./docker-dev.sh`
3. **Debug** with `./docker-dev.sh shell` to get container access
4. **View logs** with `./docker-dev.sh logs`

## 📚 More Information

- See `DOCKER_README.md` for complete documentation
- Use `./docker-dev.sh` without arguments to see all available commands
- Environment variables can be customized in `.env` file

## 🆘 If Something Goes Wrong

```bash
# Reset everything
./docker-dev.sh reset

# Check Docker is running
docker info

# View detailed logs
./docker-dev.sh logs app
```

That's it! You now have a fully dockerized DePIN scanner with Linux security tools. 🎉
