# Agent System

## Overview

PGDN uses a modular agent-based architecture where different agents handle specific aspects of the security scanning pipeline. Each agent is designed to be independent, configurable, and extensible.

## Agent Types

### 1. Reconnaissance Agents

Discover DePIN infrastructure endpoints and gather initial intelligence.

**Available Agents:**
- `SuiReconAgent` - Discovers Sui network nodes
- `SolanaReconAgent` - Discovers Solana network infrastructure
- `GenericReconAgent` - General network reconnaissance

**Example Configuration:**
```json
{
  "agents": {
    "recon_agents": ["SuiReconAgent"],
    "agent_config": {
      "SuiReconAgent": {
        "api_endpoint": "https://api.sui.io",
        "max_nodes": 1000,
        "timeout": 30
      }
    }
  }
}
```

### 2. Scanning Agents

Perform security assessments on discovered targets.

**Available Agents:**
- `NmapScanAgent` - Network port scanning with nmap
- `ServiceScanAgent` - Service fingerprinting and analysis
- `VulnerabilityScanAgent` - Vulnerability detection
- `SSLScanAgent` - SSL/TLS security assessment

**Example Configuration:**
```json
{
  "agents": {
    "scan_agents": ["NmapScanAgent", "ServiceScanAgent"],
    "agent_config": {
      "NmapScanAgent": {
        "scan_type": "comprehensive",
        "additional_options": "-A -sC",
        "port_range": "1-10000"
      },
      "ServiceScanAgent": {
        "deep_scan": true,
        "banner_grab": true
      }
    }
  }
}
```

### 3. Processing Agents

Analyze and correlate scan results.

**Available Agents:**
- `ProcessAgent` - General result processing
- `VulnerabilityProcessor` - CVE correlation and analysis
- `ServiceProcessor` - Service classification and analysis

### 4. Scoring Agents

Assess risk levels and prioritize findings.

**Available Agents:**
- `BasicScoreAgent` - Basic CVSS-based scoring
- `AdvancedScoreAgent` - ML-enhanced risk scoring
- `CustomScoreAgent` - Custom scoring algorithms

**Example Configuration:**
```json
{
  "agents": {
    "score_agents": ["AdvancedScoreAgent"],
    "agent_config": {
      "AdvancedScoreAgent": {
        "model_path": "/opt/pgdn/models/risk_model.pkl",
        "confidence_threshold": 0.8,
        "weight_factors": {
          "cvss_score": 0.4,
          "exploit_availability": 0.3,
          "asset_criticality": 0.3
        }
      }
    }
  }
}
```

### 5. Publishing Agents

Generate reports and notifications.

**Available Agents:**
- `ReportAgent` - Standard report generation
- `EmailAgent` - Email notifications
- `SlackAgent` - Slack notifications
- `WebhookAgent` - Custom webhook notifications

### 6. Signature Agents

Learn and manage protocol signatures.

**Available Agents:**
- `SignatureLearningAgent` - ML-based signature detection
- `SignatureUpdateAgent` - Signature database management

## Agent Lifecycle

### 1. Initialization
```python
from pgdn.agents import AgentManager

agent_manager = AgentManager()
agents = agent_manager.initialize_agents(config)
```

### 2. Execution
```python
# Run specific agent type
recon_results = agent_manager.run_recon_agents(target_specs)
scan_results = agent_manager.run_scan_agents(targets)
```

### 3. Result Handling
```python
# Process agent results
for result in scan_results:
    if result['success']:
        process_scan_result(result)
    else:
        handle_scan_error(result)
```

## Custom Agents

### Creating a Custom Agent

1. **Inherit from Base Agent**
```python
from pgdn.agents.base import BaseAgent

class CustomScanAgent(BaseAgent):
    def __init__(self, config):
        super().__init__(config)
        self.agent_type = "scan"
        self.name = "CustomScanAgent"
    
    def execute(self, target, **kwargs):
        # Implement custom scanning logic
        try:
            result = self.perform_custom_scan(target)
            return self.format_success_result(result)
        except Exception as e:
            return self.format_error_result(str(e))
    
    def perform_custom_scan(self, target):
        # Custom scanning implementation
        pass
```

2. **Register the Agent**
```python
from pgdn.agents import register_agent

register_agent('CustomScanAgent', CustomScanAgent)
```

3. **Configure the Agent**
```json
{
  "agents": {
    "scan_agents": ["CustomScanAgent"],
    "agent_config": {
      "CustomScanAgent": {
        "custom_param": "value"
      }
    }
  }
}
```

### Agent Interface

All agents must implement the base interface:

```python
class BaseAgent:
    def __init__(self, config):
        """Initialize agent with configuration"""
        pass
    
    def execute(self, target, **kwargs):
        """Execute agent action on target"""
        pass
    
    def validate_config(self):
        """Validate agent configuration"""
        pass
    
    def get_capabilities(self):
        """Return agent capabilities"""
        pass
```

## Agent Configuration

### Global Agent Settings
```json
{
  "agents": {
    "timeout": 300,
    "max_retries": 3,
    "parallel_execution": true,
    "error_handling": "continue"
  }
}
```

### Agent-Specific Settings
```json
{
  "agents": {
    "agent_config": {
      "NmapScanAgent": {
        "scan_intensity": 4,
        "timing_template": "T4",
        "version_detection": true
      },
      "ReportAgent": {
        "template": "detailed",
        "include_raw_data": false,
        "format": "json"
      }
    }
  }
}
```

## Agent Coordination

### Sequential Execution
```python
# Agents run in sequence
orchestrator.run_recon_stage()
orchestrator.run_scan_stage()
orchestrator.run_process_stage()
```

### Parallel Execution
```python
# Multiple agents run concurrently
parallel_ops.run_parallel_stages(['recon', 'scan'])
```

### Conditional Execution
```python
# Agents run based on conditions
if recon_result['targets_found'] > 0:
    scan_result = orchestrator.run_scan_stage()
```

## Monitoring and Logging

### Agent Status
```python
# Check agent status
agent_status = agent_manager.get_agent_status()
for agent, status in agent_status.items():
    print(f"{agent}: {status}")
```

### Agent Metrics
```python
# Get agent performance metrics
metrics = agent_manager.get_agent_metrics()
print(f"Average execution time: {metrics['avg_execution_time']}")
print(f"Success rate: {metrics['success_rate']}")
```

### Logging Configuration
```json
{
  "logging": {
    "agents": {
      "level": "INFO",
      "separate_files": true,
      "file_pattern": "logs/agent_{agent_name}.log"
    }
  }
}
```

## Best Practices

### 1. Error Handling
- Always return structured result dictionaries
- Include detailed error messages
- Implement proper timeout handling

### 2. Configuration
- Validate configuration on initialization
- Provide sensible defaults
- Document all configuration options

### 3. Performance
- Implement efficient algorithms
- Use connection pooling where appropriate
- Cache expensive operations

### 4. Security
- Sanitize all inputs
- Use secure communication protocols
- Implement rate limiting

### 5. Testing
- Write unit tests for each agent
- Test with various target types
- Validate error conditions

## Troubleshooting

### Common Issues

**Agent Not Found**
```bash
# Check agent registration
pgdn --list-agents
```

**Configuration Errors**
```bash
# Validate agent configuration
pgdn --validate-config --agent NmapScanAgent
```

**Performance Issues**
```bash
# Check agent metrics
pgdn --agent-metrics --agent ScanAgent
```

### Debugging

Enable debug logging for specific agents:
```json
{
  "logging": {
    "agents": {
      "NmapScanAgent": "DEBUG"
    }
  }
}
```
