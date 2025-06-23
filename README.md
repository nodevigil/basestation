# 🐦 PGND - Agentic DePIN Infrastructure Scanner

A modular, extensible infrastructure scanner for DePIN (Decentralized Physical Infrastructure) networks with an agentic, staged pipeline architecture.

## ⚡ Quick Start

**New to the project?** Use our automated setup:
```bash
git clone <repository-url>
cd depin
./setup.sh
```

**Already set up?** Use the console command:
```bash
source myenv/bin/activate  # Activate virtual environment
pgdn                       # Run complete pipeline
pgdn --help               # See all options
```

## 🏗️ Architecture Overview

The scanner is built around a four-stage pipeline with specialized agents:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   STAGE 1   │    │   STAGE 2   │    │   STAGE 3   │    │   STAGE 4   │
│    RECON    │───▶│    SCAN     │───▶│   PROCESS   │───▶│   PUBLISH   │
│   AGENTS    │    │   AGENTS    │    │   AGENTS    │    │   AGENTS    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
     │                   │                   │                   │
┌────▼────┐         ┌────▼────┐         ┌────▼────┐         ┌────▼────┐
│Protocol │         │Security │         │Trust    │         │Database │
│Discovery│         │Scanning │         │Scoring  │         │API      │
│(Sui,    │         │Port Scan│         │Analysis │         │Files    │
│Filecoin)│         │Vuln Scan│         │Enrich   │         │Blockchain│
└─────────┘         └─────────┘         └─────────┘         └─────────┘
```

## 📋 Prerequisites

- **Python**: 3.8 or higher
- **PostgreSQL**: 12 or higher
- **Operating System**: macOS, Linux, or Windows
- **Memory**: Minimum 4GB RAM recommended
- **Network**: Internet connection for node discovery and scanning

### Stage Descriptions

1. **Recon Agents**: Protocol-specific node discovery (e.g., Sui validators, Filecoin miners)
2. **Scan Agent**: Comprehensive security scanning (ports, vulnerabilities, SSL, etc.)
3. **Process Agent**: Data processing, trust scoring, and enrichment
4. **Publish Agent**: Output results to various destinations (database, API, blockchain)

## 📁 Project Structure

```
depin/
├── agents/                     # All agent implementations
│   ├── recon/                  # Protocol-specific discovery agents
│   │   ├── sui_agent.py        # Sui network reconnaissance
│   │   └── filecoin_agent.py   # Filecoin template (example)
│   ├── scan/                   # Security scanning agents
│   │   └── node_scanner_agent.py
│   ├── process/                # Data processing agents
│   │   └── processor_agent.py
│   ├── publish/                # Result publishing agents
│   │   └── publisher_agent.py
│   └── base.py                 # Base agent classes
├── core/                       # Core functionality
│   ├── config.py               # Configuration management
│   ├── database.py             # Database models and management
│   └── logging.py              # Centralized logging
├── utils/                      # Utilities and orchestration
│   ├── agent_registry.py       # Dynamic agent discovery
│   └── pipeline.py             # Pipeline orchestration
├── cli.py                      # Command-line interface
├── setup.py                    # Package setup (for pgdn console script)
├── pgdn_entry.py               # Console script entry point
├── requirements.txt            # Python dependencies
├── config.example.json         # Example configuration
└── [additional files...]       # Database, Docker, documentation, etc.
```

## 🚀 Installation & Setup

### Option 1: Console Script Installation (Recommended)

This method installs `pgdn` as a console command that you can run from anywhere:

```bash
# Clone the repository
git clone <repository-url>
cd depin

# Create and activate virtual environment
python3 -m venv myenv
source myenv/bin/activate  # On Windows: myenv\Scripts\activate

# Install the package in development mode (creates pgdn command)
pip install -e .

# Verify installation
pgdn --help
```

### Option 2: Quick Setup Script
```bash
# Clone the repository
git clone <repository-url>
cd depin

# Run the automated setup script
./setup.sh

# Follow the prompts to complete setup
```

### Option 3: Manual Setup
```bash
# Clone the repository
git clone <repository-url>
cd depin
git clone <repository-url>
cd depin
```

#### Set Up Python Environment
```bash
# Create a virtual environment
python3 -m venv myenv

# Activate the virtual environment
# On macOS/Linux:
source myenv/bin/activate
# On Windows:
# myenv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

#### Set Up PostgreSQL Database
```bash
# Install PostgreSQL (macOS with Homebrew)
brew install postgresql
brew services start postgresql

# Create database
createdb depin

# Or connect to existing PostgreSQL instance and create database:
psql -U postgres
CREATE DATABASE depin;
\q
```

#### Configure the Application
```bash
# Copy the example configuration
cp config.example.json config.json

# Edit config.json with your database credentials
{
  "database": {
    "url": "postgresql://your_username@localhost/depin"
  }
}
```

#### Initialize Database Schema
```bash
# Run database migrations
alembic upgrade head
```

### 2. Verify Installation

#### Using pgdn command (if installed via pip)
```bash
# Test the setup
pgdn --list-agents

# Expected output:
# 📋 Available Agents:
# ========================================
# 
# RECON AGENTS:
#   • SuiReconAgent
#   • FilecoinReconAgent
# 
# SCAN AGENTS:
#   • NodeScannerAgent
# 
# PROCESS AGENTS:
#   • ProcessorAgent
#   • ScoringAgent
# 
# PUBLISH AGENTS:
#   • PublisherAgent
```

#### Using python command (alternative method)
```bash
# Test the setup
pgdn --list-agents

# Expected output:
# 🤖 Available Agents:
# Recon Agents:
#   - SuiReconAgent: Discovers Sui network validators
# Scan Agents:
#   - NodeScannerAgent: Comprehensive security scanning
# Process Agents:
#   - ProcessorAgent: Data processing and trust scoring
# Publish Agents:
#   - PublisherAgent: Multi-destination result publishing
```

### 3. Basic Usage

#### Using pgdn Command (Recommended)

If you installed using `pip install -e .`, you can use the `pgdn` command:

```bash
# Run all stages with default settings
pgdn

# Run with debug logging
pgdn --log-level DEBUG

# Run with custom configuration
pgdn --config config.json

# Run individual stages
pgdn --stage recon
pgdn --stage scan
pgdn --stage process
pgdn --stage publish

# Run with protocol filtering
pgdn --stage scan --protocol filecoin
pgdn --stage scan --protocol sui

# Run specific recon agent
pgdn --stage recon --recon-agents SuiReconAgent

# Scan specific target
pgdn --scan-target 139.84.148.36

# List available agents
pgdn --list-agents

# Update CVE database
pgdn --update-cves
pgdn --update-cves --initial-cves  # Initial population
```

#### Alternative: Using Python Directly
```bash
# If you prefer to run without installing the package
python cli.py                    # Run complete pipeline
python cli.py --help            # See all options
python cli.py --stage scan      # Run specific stage
python cli.py --log-level DEBUG # Run with debug logging
python cli.py --config config.json # Run with custom configuration

# Run individual stages
python cli.py --stage recon
python cli.py --stage scan
python cli.py --stage process
python cli.py --stage publish

# Run specific recon agent
python cli.py --stage recon --recon-agents SuiReconAgent

# List available agents
python cli.py --list-agents
```

### 4. Configuration Options

#### Environment Variables
```bash
# Database configuration
export DATABASE_URL="postgresql://user:password@localhost/depin"
export DB_POOL_SIZE=10

# Scanning configuration  
export SCAN_INTERVAL_DAYS=7
export SLEEP_BETWEEN_SCANS=5.0
export MAX_CONCURRENT_SCANS=5

# Logging configuration
export LOG_LEVEL=INFO
export DISABLE_SQLALCHEMY_LOGS=true

# Publishing configuration
export ENABLED_PUBLISHERS="database,console,json_file"
```

#### JSON Configuration File
Edit `config.json` to customize settings:
```json
{
  "database": {
    "url": "postgresql://user@localhost/depin",
    "pool_size": 10,
    "max_overflow": 20
  },
  "scanning": {
    "scan_interval_days": 7,
    "sleep_between_scans": 5.0,
    "max_concurrent_scans": 5
  },
  "logging": {
    "level": "INFO"
  },
  "publish": {
    "enabled_publishers": ["database", "console", "json_file"]
  }
}
```

## 🔧 Key Features

### Console Script Integration
- **Easy Installation**: Install as a Python package with `pip install -e .`
- **Global Command**: Use `pgdn` command from anywhere in your terminal
- **Familiar Interface**: Same arguments as `python cli.py` but more convenient
- **Development Mode**: Changes to code are immediately reflected

### Modular Agent System
- **Pluggable**: Drop new agents into respective folders
- **Protocol Agnostic**: Each protocol gets its own recon agent
- **Extensible**: Easy to add new scanning capabilities
- **Type Safe**: Strong typing throughout with Python type hints

### Flexible Execution
- **Full Pipeline**: Run all stages in sequence
- **Stage-by-Stage**: Run individual stages independently  
- **Concurrent**: Support for parallel execution where appropriate
- **Configurable**: Extensive configuration options

### Robust Data Management
- **Database Integration**: PostgreSQL with SQLAlchemy ORM
- **Connection Pooling**: Efficient database connection management
- **Migration Support**: Alembic for database schema changes
- **Data Validation**: Strong validation and error handling

### Comprehensive Logging
- **Structured Logging**: Consistent logging across all components
- **Configurable Levels**: Debug, Info, Warning, Error, Critical
- **Agent Tracking**: Individual agent execution tracking
- **Performance Metrics**: Execution time and statistics

## 🤖 Adding New Agents

### 1. Reconnaissance Agent (New Protocol)

Create a new file in `agents/recon/` (e.g., `ethereum_agent.py`):

```python
from agents.base import ReconAgent
from core.database import get_db_session, ValidatorAddress

class EthereumReconAgent(ReconAgent):
    def discover_nodes(self) -> List[Dict[str, Any]]:
        # 1. Query Ethereum beacon chain API
        # 2. Parse validator information  
        # 3. Save to database with source="ethereum_recon_agent"
        # 4. Return discovered nodes
        pass
```

The agent will be automatically discovered and available via:
```bash
pgdn --stage recon --recon-agents EthereumReconAgent
```

### 2. Custom Scanner Agent

Create specialized scanning logic in `agents/scan/`:

```python
from agents.base import ScanAgent

class CustomScannerAgent(ScanAgent):
    def scan_nodes(self, nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Custom scanning logic
        pass
```

### 3. Custom Publisher

Add new output destinations in `agents/publish/`:

```python
from agents.publish.publisher_agent import BasePublisher

class SlackPublisher(BasePublisher):
    def publish(self, results: List[Dict[str, Any]]) -> bool:
        # Send results to Slack
        pass
```

## 📊 Data Flow

### Database Schema

```sql
-- Validator addresses (discovered nodes)
validator_addresses:
  - id (primary key)
  - address (hostname/IP)
  - name (optional)
  - source (protocol: sui, filecoin, etc.)
  - active (boolean)
  - created_at

-- Scan results
validator_scans:
  - id (primary key) 
  - validator_address_id (foreign key)
  - scan_date
  - ip_address
  - score (trust score)
  - scan_hash (content hash)
  - scan_results (JSON - full results)
  - failed (boolean)
```

### Processing Pipeline

1. **Recon**: `discover_nodes()` → Database → Node list
2. **Scan**: Database → `scan_nodes()` → Raw scan results → Database  
3. **Process**: Database → `process_results()` → Enriched results → Database
4. **Publish**: Database → `publish_results()` → Multiple destinations

## 🔒 Security Scanning Capabilities

### Generic Security Scans
- **Port Scanning**: Nmap integration for open port detection
- **SSL/TLS Testing**: Certificate validation and configuration analysis
- **HTTP Security**: Security header analysis
- **Vulnerability Detection**: Known vulnerability matching
- **Docker Exposure**: Docker daemon exposure detection

### Protocol-Specific Scans
- **Sui**: RPC endpoint testing, node health checks
- **Filecoin**: Storage provider validation (template)
- **Extensible**: Easy to add protocol-specific checks

### Trust Scoring Algorithm
```python
# Base score starts at 100
score = 100

# Deductions for security issues
if docker_exposed: score -= 30    # Critical: Docker socket exposed
if ssh_open: score -= 10          # Medium: SSH port open  
if ssl_misconfigured: score -= 25 # High: SSL/TLS issues
for vulnerability: score -= 15    # High: Known vulnerabilities

# Risk classification
if score >= 90: risk = "LOW"
elif score >= 70: risk = "MEDIUM"  
elif score >= 50: risk = "HIGH"
else: risk = "CRITICAL"
```

### External Scoring Libraries

The scanner supports **external scoring libraries** for advanced, proprietary scoring algorithms while maintaining full backward compatibility with the built-in scorer.

#### Built-in vs External Scoring

| Feature | Built-in Scorer | External Scorer |
|---------|----------------|-----------------|
| **Availability** | Always available | Optional, graceful fallback |
| **Customization** | Fixed algorithm | Fully customizable |
| **Privacy** | Open source | Private/proprietary |
| **Advanced Features** | Basic security scoring | ML, behavioral analysis, compliance |
| **Integration** | Zero configuration | Simple configuration |

#### Quick Setup

**1. Install External Scorer:**
```bash
# From private repository
pip install git+https://github.com/yourorg/pgdn-scoring.git

# Or local development
pip install -e ../pgdn_scoring_lib/
```

**2. Configure in `config.json`:**
```json
{
  "scoring": {
    "scorer_path": "pgdn.scoring.default_scorer.DefaultScorer",
    "fallback_to_builtin": true
  }
}
```

**3. Run with External Scorer:**
```bash
pgdn --stage score --config config.json
# Output: ✅ Loaded external scorer: pgdn.scoring.default_scorer.DefaultScorer
```

#### Development Workflow

```bash
# Create external scorer library
mkdir ../pgdn_scoring_lib
cd ../pgdn_scoring_lib

# Implement your scorer with required interface
class YourScorer:
    def score(self, scan_data):
        return {
            "score": 85,                    # Required: 0-100
            "flags": ["issue1", "issue2"],  # Required: Security flags
            "summary": "Custom analysis",   # Required: Human readable
            # Optional: Your custom fields
        }

# Install in development mode
cd ../depin
pip install -e ../pgdn_scoring_lib/

# Test immediately (no reinstall needed for changes)
pgdn --stage score
```

#### Fallback Strategy

The scanner follows a **graceful fallback hierarchy**:

1. **Config-specified scorer** → `config.scoring.scorer_path`
2. **Default external scorer** → `pgdn.scoring.default_scorer.DefaultScorer`  
3. **Built-in scorer** → Always available, identical to original behavior

This ensures **zero downtime** and **100% reliability** even if external libraries are unavailable.

#### Advanced Features

External scorers can implement advanced features not available in the built-in scorer:

- **Machine Learning**: Behavioral analysis and anomaly detection
- **Threat Intelligence**: Real-time threat feed integration
- **Compliance Scoring**: SOC2, ISO27001, industry-specific standards
- **Geolocation Risk**: IP-based geographic risk assessment
- **Temporal Analysis**: Historical trend analysis and prediction

Example enhanced scoring output:
```json
{
  "score": 85,
  "flags": ["SSH exposed", "ML: Behavioral anomaly detected"],
  "summary": "Advanced ML Score: 85/100. ML Risk: MODERATE",
  "pgdn_metrics": {
    "security_grade": "B",
    "compliance_score": 92,
    "ml_risk_level": "MODERATE"
  },
  "ml_analysis": {
    "confidence": 0.85,
    "anomaly_score": 0.3
  }
}
```

> 📚 **Documentation**: See `docs/EXTERNAL_SCORER_GUIDE.md` for complete implementation guide

## 📈 Monitoring and Observability

### Execution Tracking
- Unique execution IDs for each pipeline run
- Stage-by-stage timing and results
- Agent execution statistics
- Error tracking and reporting

### Logging Structure
```
2024-06-17 10:30:00 INFO [agents.SuiReconAgent]: 🔍 Discovering Sui validators...
2024-06-17 10:30:05 INFO [agents.SuiReconAgent]: ✅ Discovered 150 validators, saved 12 to database
2024-06-17 10:30:10 INFO [agents.NodeScannerAgent]: 🛡️ Scanning 12 nodes...
2024-06-17 10:32:15 INFO [agents.ProcessorAgent]: 📊 Processing 12 scan results...
2024-06-17 10:32:20 INFO [agents.PublisherAgent]: 📤 Publishing to database,console...
```

## 🚦 Error Handling and Recovery

### Graceful Degradation
- Failed scans are marked and stored for retry
- Pipeline continues even if individual nodes fail
- Comprehensive error logging with context

### Retry Logic
- DNS resolution failures are logged but don't stop processing
- Database connection issues trigger automatic retry
- Network timeouts are handled gracefully

### Concurrency Control
- Database transactions prevent conflicts between multiple agents
- Connection pooling manages database resources efficiently
- Configurable concurrent scan limits

## 🔧 Configuration Options

### Database Settings
```bash
DATABASE_URL=postgresql://user:password@host:port/database
DB_POOL_SIZE=10              # Connection pool size
DB_MAX_OVERFLOW=20           # Max additional connections
DB_POOL_TIMEOUT=30           # Connection timeout seconds
DB_POOL_RECYCLE=3600         # Connection recycle time
```

### Scanning Settings
```bash
SCAN_INTERVAL_DAYS=7         # How often to rescan nodes
SLEEP_BETWEEN_SCANS=5.0      # Delay between scans (respectful)
SCAN_TIMEOUT=30              # Individual scan timeout
MAX_CONCURRENT_SCANS=5       # Parallel scan limit
ENABLE_VULN_SCAN=true        # Enable vulnerability scanning
ENABLE_SSL_TEST=true         # Enable SSL/TLS testing
```

### Publishing Settings
```bash
ENABLED_PUBLISHERS=database,console,json_file
API_ENDPOINT=https://api.example.com/scans
BLOCKCHAIN_ENDPOINT=https://rpc.blockchain.com
```

## 🧪 Testing and Development

### Running Tests
```bash
# Run specific test files
python test_sui_scanner.py
python test_metrics_content.py

# Run with verbose output
python -v test_sui_scanner.py
```

### Development Workflow
```bash
# 1. Make code changes
# 2. Test individual components
pgdn --stage recon --log-level DEBUG

# 3. Run full pipeline test
pgdn --log-level DEBUG

# 4. Check database results
psql -d depin -c "SELECT COUNT(*) FROM validator_addresses;"
psql -d depin -c "SELECT COUNT(*) FROM validator_scans;"
```

### Database Management
```bash
# View current migration status
alembic current

# Create new migration (after model changes)
alembic revision --autogenerate -m "Description of changes"

# Apply migrations
alembic upgrade head

# Rollback migrations
alembic downgrade -1
```

### Troubleshooting

#### Common Issues

**Database Connection Error**
```bash
# Check if PostgreSQL is running
brew services list | grep postgresql

# Restart PostgreSQL
brew services restart postgresql

# Test database connection
psql -d depin -c "SELECT version();"
```

**Python Import Errors**
```bash
# Ensure virtual environment is activated
source myenv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt

# Check Python path
python -c "import sys; print(sys.path)"
```

**No Agents Found**
```bash
# Check agent registry
python -c "from utils.agent_registry import get_agent_registry; print(get_agent_registry().list_agents())"

# Verify agent files exist
ls -la agents/recon/
ls -la agents/scan/
```

#### Debug Mode
```bash
# Run with maximum verbosity
pgdn --log-level DEBUG

# Monitor database activity
tail -f /usr/local/var/log/postgresql/*.log
```

#### Performance Monitoring
```bash
# Monitor system resources during scans
top -pid $(pgrep -f python)

# Check database performance
psql -d depin -c "SELECT * FROM pg_stat_activity WHERE datname = 'depin';"
```

## 🏭 Production Deployment

### Production Configuration
```bash
# Create production config
cp config.example.json config.production.json

# Edit production settings
{
  "database": {
    "url": "postgresql://user:password@production-host:5432/depin",
    "pool_size": 20,
    "max_overflow": 40,
    "pool_timeout": 60
  },
  "scanning": {
    "max_concurrent_scans": 10,
    "scan_interval_days": 1,
    "sleep_between_scans": 2.0
  },
  "logging": {
    "level": "INFO",
    "disable_sqlalchemy": true
  }
}
```

### Scheduling with Cron
```bash
# Edit crontab
crontab -e

# Add scheduled runs (daily at 2 AM)
0 2 * * * cd /path/to/depin && source myenv/bin/activate && pgdn --config config.production.json >> /var/log/depin.log 2>&1

# Run recon every 6 hours
0 */6 * * * cd /path/to/depin && source myenv/bin/activate && pgdn --stage recon --config config.production.json >> /var/log/depin-recon.log 2>&1
```

### Process Management with systemd
Create `/etc/systemd/system/depin-scanner.service`:
```ini
[Unit]
Description=DePIN Infrastructure Scanner
After=network.target postgresql.service

[Service]
Type=oneshot
User=depin
WorkingDirectory=/opt/depin
Environment=PATH=/opt/depin/myenv/bin
ExecStart=/opt/depin/myenv/bin/pgdn --config config.production.json
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable depin-scanner.service
sudo systemctl start depin-scanner.service
sudo systemctl status depin-scanner.service
```

### Docker Deployment
```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 depin && chown -R depin:depin /app
USER depin

# Default command
CMD ["pgdn"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: depin
      POSTGRES_USER: depin
      POSTGRES_PASSWORD: secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  scanner:
    build: .
    depends_on:
      - postgres
    environment:
      DATABASE_URL: postgresql://depin:secure_password@postgres:5432/depin
    volumes:
      - ./config.production.json:/app/config.json
      - ./logs:/app/logs

volumes:
  postgres_data:
```

Deploy with Docker:
```bash
# Build and run
docker-compose up -d

# Run specific stages
docker-compose exec scanner pgdn --stage recon

# View logs
docker-compose logs -f scanner
```

## � Monitoring and Alerts

### Log Analysis
```bash
# Monitor application logs
tail -f /var/log/depin.log

# Filter for errors
grep "ERROR\|CRITICAL" /var/log/depin.log

# Monitor scan progress
grep "Scanning\|Discovered\|Processing" /var/log/depin.log
```

### Database Monitoring
```sql
-- Monitor scan history
SELECT 
    DATE(scan_date) as scan_day,
    COUNT(*) as scans_completed,
    AVG(score) as avg_trust_score
FROM validator_scans 
WHERE scan_date >= NOW() - INTERVAL '7 days'
GROUP BY DATE(scan_date)
ORDER BY scan_day DESC;

-- Check for failed scans
SELECT 
    va.address,
    vs.scan_date,
    vs.scan_results->>'error' as error_message
FROM validator_scans vs
JOIN validator_addresses va ON vs.validator_address_id = va.id
WHERE vs.failed = true
ORDER BY vs.scan_date DESC
LIMIT 10;

-- Monitor agent performance
SELECT 
    source,
    COUNT(*) as nodes_discovered,
    MAX(created_at) as last_discovery
FROM validator_addresses 
GROUP BY source
ORDER BY nodes_discovered DESC;
```

### Health Checks
```bash
# Create health check script
cat > health_check.sh << 'EOF'
#!/bin/bash
set -e

# Check database connectivity
python -c "from core.database import get_db_session; get_db_session().execute('SELECT 1')"

# Check recent activity
RECENT_SCANS=$(psql -d depin -t -c "SELECT COUNT(*) FROM validator_scans WHERE scan_date > NOW() - INTERVAL '24 hours'")
if [ "$RECENT_SCANS" -eq 0 ]; then
    echo "WARNING: No scans completed in the last 24 hours"
    exit 1
fi

echo "Health check passed - $RECENT_SCANS scans in last 24 hours"
EOF

chmod +x health_check.sh
```

## 📚 Usage Examples

### Example 1: First-Time Setup and Run
```bash
# Complete setup from scratch
git clone <repository-url>
cd depin

# Set up environment
python3 -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt

# Set up database
createdb depin
cp config.example.json config.json
# Edit config.json with your database URL

# Initialize schema
alembic upgrade head

# Run first scan
pgdn --log-level INFO

# Expected output:
# 🐦 PGND - Agentic DePIN Infrastructure Scanner
# ============================================================
# 📋 Running full pipeline with all stages:
#    🔍 Stage 1: Reconnaissance (Node Discovery)
#    🛡️  Stage 2: Scanning (Security Analysis)  
#    📊 Stage 3: Processing (Trust Score & Enrichment)
#    📤 Stage 4: Publishing (Results Output)
#
# 🔍 Starting Stage 1: Reconnaissance
# [SuiReconAgent]: 🔍 Discovering Sui validators...
# [SuiReconAgent]: ✅ Discovered 150 validators, saved 12 new to database
```

### Example 2: Daily Monitoring Workflow
```bash
# Morning routine: Check overnight discoveries
pgdn --stage recon --log-level INFO

# Afternoon: Run security scans
pgdn --stage scan --log-level INFO

# Evening: Process and review results
pgdn --stage process --stage publish --log-level INFO

# Check results in database
psql -d depin -c "
SELECT 
    va.address,
    vs.score,
    vs.scan_date,
    CASE 
        WHEN vs.score >= 90 THEN 'LOW RISK'
        WHEN vs.score >= 70 THEN 'MEDIUM RISK'
        WHEN vs.score >= 50 THEN 'HIGH RISK'
        ELSE 'CRITICAL RISK'
    END as risk_level
FROM validator_scans vs
JOIN validator_addresses va ON vs.validator_address_id = va.id
WHERE DATE(vs.scan_date) = CURRENT_DATE
ORDER BY vs.score ASC
LIMIT 10;
"
```

### Example 3: Investigating Security Issues
```bash
# Find nodes with critical security issues
pgdn --stage scan --log-level DEBUG

# Query for high-risk nodes
psql -d depin -c "
SELECT 
    va.address,
    vs.score,
    vs.scan_results->>'security_issues' as issues
FROM validator_scans vs
JOIN validator_addresses va ON vs.validator_address_id = va.id
WHERE vs.score < 50
ORDER BY vs.scan_date DESC;
"

# Re-scan specific problematic nodes
# (This would require modifying the scanner to accept specific addresses)
```

### Example 4: Custom Protocol Integration
```bash
# 1. Create new recon agent for your protocol
cat > agents/recon/my_protocol_agent.py << 'EOF'
from typing import List, Dict, Any
from agents.base import ReconAgent
from core.database import get_db_session, ValidatorAddress

class MyProtocolReconAgent(ReconAgent):
    def discover_nodes(self) -> List[Dict[str, Any]]:
        """Discover nodes for MyProtocol network"""
        # Your protocol-specific discovery logic here
        nodes = []
        
        # Example: Query your protocol's API
        # response = requests.get("https://api.myprotocol.com/validators")
        # for validator in response.json():
        #     nodes.append({
        #         'address': validator['hostname'],
        #         'name': validator.get('name'),
        #         'source': 'my_protocol_recon_agent'
        #     })
        
        return nodes
EOF

# 2. Test the new agent
pgdn --stage recon --recon-agents MyProtocolReconAgent --log-level DEBUG

# 3. Run full pipeline with new protocol
pgdn --log-level INFO
```

## 🔍 Common Workflows

### Daily Operations
1. **Morning Discovery**: `pgdn --stage recon`
2. **Scan Security**: `pgdn --stage scan`
3. **Process Results**: `pgdn --stage process`
4. **Review Reports**: Check database or output files

### Weekly Analysis
1. **Full Pipeline**: `pgdn --log-level INFO`
2. **Trend Analysis**: Query database for weekly patterns
3. **Risk Assessment**: Review high-risk nodes
4. **Performance Tuning**: Adjust configuration based on results

### Incident Response
1. **Emergency Scan**: `pgdn --stage scan --log-level DEBUG`
2. **Risk Assessment**: Query critical vulnerabilities
3. **Generate Reports**: Export results for stakeholders
4. **Follow-up**: Schedule re-scans for remediated issues

## � Background Processing & Queues

The DePIN scanner supports background job processing using Celery and Redis for scalable, distributed operations.

### Quick Start with Queues

1. **Start Queue Services**:
   ```bash
   # Start Redis and Celery worker
   ./celery-manage.sh start-all
   ```

2. **Queue Operations**:
   ```bash
   # Queue any operation by adding --queue flag
   pgdn --queue                          # Queue full pipeline
   pgdn --stage scan --queue             # Queue scan stage
   pgdn --scan-target 192.168.1.100 --queue  # Queue target scan
   ```

3. **Monitor Tasks**:
   ```bash
   # Check task status
   pgdn --task-id abc123-def456
   
   # Open monitoring UI
   open http://localhost:5555
   ```

### Queue Benefits

- **Non-blocking Operations**: Long scans don't block your terminal
- **Batch Processing**: Process multiple targets efficiently
- **Scalability**: Add more workers for parallel processing
- **Reliability**: Tasks are persisted and can be retried
- **Monitoring**: Full visibility into task execution

### Queue Examples

```bash
# Background scanning with different protocols
pgdn --stage scan --protocol filecoin --queue
pgdn --stage scan --protocol sui --queue

# Queue multiple target scans
pgdn --scan-target 192.168.1.100 --queue
pgdn --scan-target 10.0.0.50 --queue

# Queue with completion waiting
pgdn --stage recon --queue --wait-for-completion

# Task management
pgdn --task-id 12345-67890  # Check status
pgdn --cancel-task 12345-67890  # Cancel task
```

See [Queue Processing Guide](docs/QUEUE_PROCESSING.md) for detailed documentation.

## 🔮 Future Enhancements

### Enhanced Queue Processing
- **Priority Queues**: High-priority security scans
- **Scheduled Jobs**: Cron-like scheduling for regular scans  
- **Worker Pools**: Specialized workers for different protocols
- **Auto-scaling**: Dynamic worker scaling based on queue depth

### Additional Protocols
- **Ethereum**: Beacon chain and execution layer validation
- **Solana**: Validator and RPC node scanning  
- **Cosmos**: IBC relayer and validator discovery
- **Generic**: REST API-based protocol discovery

### Advanced Analytics
- **Time Series**: Historical trend analysis
- **Anomaly Detection**: ML-based unusual behavior detection
- **Geolocation**: IP-based geographic distribution analysis
- **Compliance**: Automated compliance checking (SOC2, ISO27001)

### Enhanced Publishing
- **Real-time Dashboards**: Grafana/Kibana integration
- **Alerting**: Slack/Discord/PagerDuty notifications  
- **Blockchain Publishing**: On-chain result attestation
- **API Gateway**: RESTful API for external integrations

## 📝 Contributing

### Adding New Protocols
1. Create recon agent in `agents/recon/your_protocol_agent.py`
2. Inherit from `ReconAgent` base class
3. Implement `discover_nodes()` method
4. Add any protocol-specific configuration to `core/config.py`
5. Test with `pgdn --stage recon --recon-agents YourProtocolAgent`

### Adding New Scanners
1. Create scanner in `agents/scan/your_scanner_agent.py`  
2. Inherit from `ScanAgent` base class
3. Implement `scan_nodes()` method
4. Test with `pgdn --stage scan --agent YourScannerAgent`

### Architecture Guidelines
- Use strong typing with Python type hints
- Follow existing logging patterns
- Include comprehensive docstrings
- Handle errors gracefully with proper logging
- Use configuration system for all settings
- Write modular, testable code

## � Documentation

Comprehensive documentation is available in the `docs/` folder:

### Getting Started
- **[Quick Start Guide](docs/QUICKSTART.md)** - Get up and running in minutes
- **[Docker Setup](docs/DOCKER_README.md)** - Containerized development environment
- **[Database Setup](docs/DATABASE_CONNECTION_STANDARDIZATION.md)** - Database configuration guide

### Library Usage (Python API)
- **[Library README](docs/LIBRARY_README.md)** - Complete library installation and usage guide
- **[Library API Documentation](docs/LIBRARY_API.md)** - Python API reference and examples
- **[Library Architecture](docs/LIBRARY_ARCHITECTURE.md)** - Library design and structure
- **[Installation Guide](docs/INSTALLATION_GUIDE.md)** - Multiple installation methods

### Advanced Features  
- **[External Scorer Integration](docs/EXTERNAL_SCORER_GUIDE.md)** - Complete guide to custom scoring libraries
- **[Scoring Agent Refactoring](docs/SCORING_REFACTORING_COMPLETE.md)** - Technical implementation details
- **[CVE Integration](docs/CVE_UPDATER_README.md)** - Vulnerability database integration

### Development
- **Tests**: All test files are in the `tests/` folder
- **Examples**: Configuration examples and sample implementations
- **API Documentation**: Generated from code docstrings

### Quick Reference

| Task | Command | Documentation |
|------|---------|---------------|
| **Setup** | `./setup.sh` | [QUICKSTART.md](docs/QUICKSTART.md) |
| **Docker** | `./docker-dev.sh` | [DOCKER_README.md](docs/DOCKER_README.md) |
| **External Scorer** | `pip install -e ../scorer/` | [EXTERNAL_SCORER_GUIDE.md](docs/EXTERNAL_SCORER_GUIDE.md) |
| **Full Pipeline** | `pgdn` | Main README (this file) |
| **Tests** | `python -m pytest tests/` | Test files in `tests/` folder |

## �📄 License

[Add your license information here]

## 📦 Package Structure

### Console Script Files
- **`setup.py`**: Package definition and console script entry point configuration
- **`pgdn_entry.py`**: Console script entry point that imports and calls the CLI

When you run `pip install -e .`, these files work together to create the `pgdn` command that's available system-wide in your virtual environment.

## 🤝 Support

[Add support/contact information here]

---

*Built with ❤️ for the DePIN ecosystem*
