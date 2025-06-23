# Configuration Guide

## Overview

PGDN uses JSON configuration files to manage settings for scanning, database connections, agent behaviors, and reporting.

## Configuration Files

### Primary Configuration
- `config.json` - Main configuration file
- `config.example.json` - Template with default values
- `config.docker.json` - Docker-specific overrides

### Loading Priority

1. Command-line specified config (`--config file.json`)
2. `config.docker.json` (if `--docker-config` flag is used)
3. `config.json` (default)
4. `config.example.json` (fallback)

## Configuration Structure

```json
{
  "database": {
    "path": "scanning.db",
    "type": "sqlite",
    "connection_timeout": 30
  },
  "scanning": {
    "timeout": 30,
    "max_parallel": 5,
    "retry_attempts": 3,
    "protocols": ["sui", "solana"]
  },
  "agents": {
    "scan_agents": ["NmapScanAgent", "ServiceScanAgent"],
    "recon_agents": ["SuiReconAgent"],
    "process_agents": ["ProcessAgent"],
    "score_agents": ["BasicScoreAgent"],
    "report_agents": ["ReportAgent"]
  },
  "reporting": {
    "email": {
      "enabled": false,
      "smtp_server": "smtp.example.com",
      "smtp_port": 587,
      "username": "",
      "password": "",
      "from_address": "pgdn@example.com"
    },
    "formats": ["json", "csv"],
    "output_directory": "reports/"
  },
  "logging": {
    "level": "INFO",
    "file": "logs/pgdn.log",
    "max_file_size": "10MB",
    "backup_count": 5
  },
  "cve": {
    "database_path": "cve.db",
    "update_interval": "24h",
    "api_key": "",
    "sources": ["nvd"]
  },
  "queue": {
    "broker": "redis://localhost:6379/0",
    "backend": "redis://localhost:6379/0",
    "task_timeout": 3600
  }
}
```

## Section Details

### Database Configuration

```json
{
  "database": {
    "path": "scanning.db",           // SQLite database file path
    "type": "sqlite",               // Database type (sqlite only currently)
    "connection_timeout": 30,       // Connection timeout in seconds
    "pragma": {                     // SQLite-specific settings
      "journal_mode": "WAL",
      "synchronous": "NORMAL"
    }
  }
}
```

### Scanning Configuration

```json
{
  "scanning": {
    "timeout": 30,                  // Scan timeout per target
    "max_parallel": 5,              // Maximum parallel scans
    "retry_attempts": 3,            // Retry failed scans
    "protocols": ["sui", "solana"], // Supported protocols
    "port_ranges": [                // Port scanning ranges
      "22,80,443,8080",
      "9000-9999"
    ],
    "nmap_options": "-sS -O",       // Additional nmap options
    "excluded_hosts": [             // Hosts to skip
      "127.0.0.1",
      "localhost"
    ]
  }
}
```

### Agent Configuration

```json
{
  "agents": {
    "scan_agents": [
      "NmapScanAgent",
      "ServiceScanAgent"
    ],
    "recon_agents": [
      "SuiReconAgent"
    ],
    "process_agents": [
      "ProcessAgent"
    ],
    "score_agents": [
      "BasicScoreAgent"
    ],
    "report_agents": [
      "ReportAgent"
    ],
    "agent_config": {               // Agent-specific settings
      "NmapScanAgent": {
        "additional_options": "-A"
      },
      "SuiReconAgent": {
        "api_endpoint": "https://api.sui.io"
      }
    }
  }
}
```

### Reporting Configuration

```json
{
  "reporting": {
    "email": {
      "enabled": true,
      "smtp_server": "smtp.gmail.com",
      "smtp_port": 587,
      "use_tls": true,
      "username": "your-email@gmail.com",
      "password": "app-password",
      "from_address": "pgdn@yourcompany.com",
      "default_recipients": [
        "security@yourcompany.com"
      ]
    },
    "formats": ["json", "csv", "html"],
    "output_directory": "reports/",
    "auto_save": true,
    "include_raw_data": false
  }
}
```

### Logging Configuration

```json
{
  "logging": {
    "level": "INFO",                // DEBUG, INFO, WARNING, ERROR, CRITICAL
    "file": "logs/pgdn.log",
    "console": true,                // Also log to console
    "max_file_size": "10MB",
    "backup_count": 5,
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  }
}
```

### CVE Configuration

```json
{
  "cve": {
    "database_path": "cve.db",
    "update_interval": "24h",       // Auto-update interval
    "api_key": "your-nvd-api-key",  // Optional for rate limiting
    "sources": ["nvd"],             // CVE data sources
    "severity_filter": ["HIGH", "CRITICAL"],
    "max_age_days": 365            // Only include CVEs from last year
  }
}
```

### Queue Configuration (Optional)

```json
{
  "queue": {
    "enabled": true,
    "broker": "redis://localhost:6379/0",
    "backend": "redis://localhost:6379/0",
    "task_timeout": 3600,
    "worker_concurrency": 4,
    "queue_names": {
      "scan": "pgdn_scan",
      "process": "pgdn_process",
      "report": "pgdn_report"
    }
  }
}
```

## Environment Variables

Override configuration with environment variables:

```bash
export PGDN_DATABASE_PATH="/custom/path/db.sqlite"
export PGDN_LOG_LEVEL="DEBUG"
export PGDN_SMTP_PASSWORD="your-password"
export PGDN_CVE_API_KEY="your-api-key"
```

## Docker Configuration

For Docker deployments, use `config.docker.json`:

```json
{
  "database": {
    "path": "/app/data/scanning.db"
  },
  "logging": {
    "file": "/app/logs/pgdn.log"
  },
  "reporting": {
    "output_directory": "/app/reports/"
  }
}
```

## Configuration Validation

Validate your configuration:

```bash
pgdn --validate-config
```

## Security Considerations

- Store sensitive values (passwords, API keys) in environment variables
- Use appropriate file permissions (600) for config files
- Regularly rotate API keys and passwords
- Consider using encrypted configuration for production

## Examples

### Minimal Configuration
```json
{
  "database": {"path": "pgdn.db"},
  "scanning": {"timeout": 30},
  "logging": {"level": "INFO"}
}
```

### Production Configuration
```json
{
  "database": {
    "path": "/opt/pgdn/data/scanning.db"
  },
  "scanning": {
    "timeout": 60,
    "max_parallel": 10,
    "protocols": ["sui", "solana"]
  },
  "reporting": {
    "email": {
      "enabled": true,
      "smtp_server": "smtp.company.com",
      "smtp_port": 587,
      "use_tls": true
    },
    "auto_save": true
  },
  "logging": {
    "level": "INFO",
    "file": "/opt/pgdn/logs/pgdn.log"
  }
}
```
