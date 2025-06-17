# DePIN Infrastructure Scanner - Agentic Architecture

A modular, extensible infrastructure scanner for DePIN (Decentralized Physical Infrastructure) networks with an agentic, staged pipeline architecture.

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

### Stage Descriptions

1. **Recon Agents**: Protocol-specific node discovery (e.g., Sui validators, Filecoin miners)
2. **Scan Agent**: Comprehensive security scanning (ports, vulnerabilities, SSL, etc.)
3. **Process Agent**: Data processing, trust scoring, and enrichment
4. **Publish Agent**: Output results to various destinations (database, API, blockchain)

## 📁 Project Structure

```
basestation/
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
├── main_new.py                 # New main entry point
├── migrate_architecture.py     # Migration helper script
└── [legacy files...]          # Original architecture files
```

## 🚀 Quick Start

### 1. Migration from Old Architecture

If you're upgrading from the old architecture:

```bash
# Run the migration validation script
python migrate_architecture.py

# If validation passes, replace the main file
mv main.py main_old.py
mv main_new.py main.py
```

### 2. Basic Usage

```bash
# List available agents
python main.py --list-agents

# Run full pipeline (all stages)
python main.py

# Run specific stage
python main.py --stage recon
python main.py --stage scan  
python main.py --stage process
python main.py --stage publish

# Run specific recon agent
python main.py --stage recon --recon-agents SuiReconAgent
```

### 3. Configuration

The system uses environment variables and configuration files:

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

Or use a JSON configuration file:

```bash
python main.py --config config.json --log-level DEBUG
```

## 🔧 Key Features

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
python main.py --stage recon --recon-agents EthereumReconAgent
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

## 🧪 Testing and Validation

### Migration Testing
```bash
# Validate new architecture
python migrate_architecture.py

# Test individual stages
python main.py --stage recon --log-level DEBUG
python main.py --stage scan --log-level DEBUG
```

### Integration Testing
```bash
# Test full pipeline with verbose logging
python main.py --log-level DEBUG

# Test specific protocol
python main.py --stage recon --recon-agents SuiReconAgent
```

## 🔮 Future Enhancements

### Scalability Improvements
- **Distributed Processing**: Redis/Celery for distributed task execution
- **Load Balancing**: Multiple scanner instances with work distribution
- **Streaming**: Real-time result streaming for large networks

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
5. Test with `python main.py --stage recon --recon-agents YourProtocolAgent`

### Adding New Scanners
1. Create scanner in `agents/scan/your_scanner_agent.py`  
2. Inherit from `ScanAgent` base class
3. Implement `scan_nodes()` method
4. Test with `python main.py --stage scan --agent YourScannerAgent`

### Architecture Guidelines
- Use strong typing with Python type hints
- Follow existing logging patterns
- Include comprehensive docstrings
- Handle errors gracefully with proper logging
- Use configuration system for all settings
- Write modular, testable code

## 📄 License

[Add your license information here]

## 🤝 Support

[Add support/contact information here]

---

*Built with ❤️ for the DePIN ecosystem*
