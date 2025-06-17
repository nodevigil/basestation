#!/bin/bash

# DePIN Scanner Quick Commands
# Usage: ./quick.sh [command]

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if virtual environment is activated
if [[ "$VIRTUAL_ENV" == "" ]]; then
    echo -e "${YELLOW}⚠️  Virtual environment not activated${NC}"
    echo "Run: source myenv/bin/activate"
    exit 1
fi

case "$1" in
    "setup"|"init")
        echo -e "${BLUE}🔧 Initializing database...${NC}"
        alembic upgrade head
        echo -e "${GREEN}✅ Database initialized${NC}"
        ;;
    
    "recon"|"discover")
        echo -e "${BLUE}🔍 Running node discovery...${NC}"
        python main.py --stage recon --log-level INFO
        ;;
    
    "scan"|"security")
        if [ "$2" ]; then
            echo -e "${BLUE}🛡️  Running security scans for $2 protocol...${NC}"
            python main.py --stage scan --protocol "$2" --log-level INFO
        else
            echo -e "${BLUE}🛡️  Running security scans...${NC}"
            python main.py --stage scan --log-level INFO
        fi
        ;;
    
    "process"|"analyze")
        echo -e "${BLUE}📊 Processing scan results...${NC}"
        python main.py --stage process --log-level INFO
        ;;
    
    "publish"|"output")
        echo -e "${BLUE}📤 Publishing results...${NC}"
        python main.py --stage publish --log-level INFO
        ;;
    
    "full"|"run")
        echo -e "${BLUE}🚀 Running full pipeline...${NC}"
        python main.py --log-level INFO
        ;;
    
    "debug")
        echo -e "${BLUE}🐛 Running with debug logging...${NC}"
        python main.py --log-level DEBUG
        ;;
    
    "agents"|"list")
        echo -e "${BLUE}🤖 Listing available agents...${NC}"
        python main.py --list-agents
        ;;
    
    "status"|"check")
        echo -e "${BLUE}📊 Checking system status...${NC}"
        echo "Recent scans:"
        psql -d depin -c "SELECT COUNT(*) as recent_scans FROM validator_scans WHERE scan_date > NOW() - INTERVAL '24 hours';" 2>/dev/null || echo "Database not accessible"
        echo "Total discovered nodes:"
        psql -d depin -c "SELECT COUNT(*) as total_nodes FROM validator_addresses;" 2>/dev/null || echo "Database not accessible"
        ;;
    
    "logs"|"tail")
        echo -e "${BLUE}📋 Showing recent logs...${NC}"
        if [ -f "depin.log" ]; then
            tail -f depin.log
        else
            echo "No log file found. Run with logging enabled first."
        fi
        ;;
    
    "clean"|"reset")
        echo -e "${YELLOW}⚠️  This will delete all scan data!${NC}"
        read -p "Are you sure? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            psql -d depin -c "TRUNCATE validator_scans, validator_addresses RESTART IDENTITY CASCADE;" 2>/dev/null
            echo -e "${GREEN}✅ Database cleaned${NC}"
        fi
        ;;
    
    "help"|"")
        echo "DePIN Scanner Quick Commands"
        echo "============================"
        echo ""
        echo "Setup & Initialization:"
        echo "  ./quick.sh setup     - Initialize database schema"
        echo ""
        echo "Pipeline Stages:"
        echo "  ./quick.sh recon     - Run node discovery"
        echo "  ./quick.sh scan      - Run security scanning (all protocols)"
        echo "  ./quick.sh scan sui  - Run security scanning (Sui nodes only)"
        echo "  ./quick.sh scan filecoin - Run security scanning (Filecoin nodes only)"
        echo "  ./quick.sh process   - Process scan results"
        echo "  ./quick.sh publish   - Publish results"
        echo "  ./quick.sh full      - Run complete pipeline"
        echo ""
        echo "Development & Debug:"
        echo "  ./quick.sh debug     - Run with debug logging"
        echo "  ./quick.sh agents    - List available agents"
        echo "  ./quick.sh status    - Check system status"
        echo "  ./quick.sh logs      - Tail log files"
        echo ""
        echo "Database:"
        echo "  ./quick.sh clean     - Clear all scan data (WARNING: destructive)"
        echo ""
        echo "Examples:"
        echo "  ./quick.sh full           # Run complete scan"
        echo "  ./quick.sh recon          # Just discover nodes"
        echo "  ./quick.sh scan filecoin  # Scan only Filecoin nodes"
        echo "  ./quick.sh scan sui       # Scan only Sui nodes"
        echo "  ./quick.sh debug          # Debug issues"
        ;;
    
    *)
        echo -e "${YELLOW}Unknown command: $1${NC}"
        echo "Run './quick.sh help' for available commands"
        exit 1
        ;;
esac
