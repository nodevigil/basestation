# External Scorer Integration Guide

## Overview

The refactored ScoringAgent now supports dynamic loading of external scoring libraries while maintaining full backward compatibility with the built-in scoring logic.

## Architecture

```
ScoringAgent
├── Dynamic Scorer Loading
│   ├── External Library (pgdn.scoring.*)
│   ├── Built-in DefaultTrustScorer (fallback)
│   └── Graceful error handling
└── Unified Interface
    ├── score(scan_data) -> trust_result
    └── Compatible with existing pipeline
```

## Built-in DefaultTrustScorer

The built-in scorer combines the original `analysis/trust.py` logic:

```python
class DefaultTrustScorer:
    def score(self, scan_data):
        score = 100
        flags = []
        
        # Critical: Docker socket exposed
        if 2375 in scan_data.get('open_ports', []):
            score -= 30
            flags.append("Docker socket exposed")
            
        # Medium: SSH port open
        if 22 in scan_data.get('open_ports', []):
            score -= 10
            flags.append("SSH port open")
            
        # High: TLS misconfigured
        tls = scan_data.get("tls", {})
        if tls.get("issuer") in (None, "Self-signed") or not tls.get("expiry"):
            score -= 25
            flags.append("TLS misconfigured")
            
        # High: Known vulnerabilities
        for vuln in scan_data.get("vulns", {}).values():
            score -= 15
            flags.append(f"Known vuln: {vuln}")

        return {
            "score": score,
            "flags": flags,
            "summary": f"Trust Score: {score}. Flags: {', '.join(flags)}.",
            # ... additional fields
        }
```

## External Scorer Integration

### 1. Create External Scorer Library

Your private repo should implement a scorer with this interface:

```python
# pgdn/scoring/default_scorer.py
class DefaultScorer:
    def score(self, scan_data):
        """
        Score scan data and return trust result.
        
        Args:
            scan_data (dict): Generic scan data with keys:
                - ip: IP address
                - open_ports: List of open port numbers
                - tls: TLS configuration info
                - vulns: Dictionary of vulnerabilities
                - docker_exposure: Docker exposure info
                
        Returns:
            dict: Trust result with keys:
                - score: Trust score (0-100)
                - flags: List of security flags
                - summary: Human-readable summary
                - (optional) additional fields
        """
        # Your advanced scoring logic here
        return {
            "score": 85,
            "flags": ["Advanced analysis completed"],
            "summary": "Advanced trust analysis completed",
            "advanced_metrics": {...}  # Your custom fields
        }
```

### 2. Install External Library

```bash
# Install your private scoring library
pip install git+https://github.com/yourorg/pgdn-scoring.git
```

### 3. Configuration Options

#### Option A: Configuration File
```json
{
  "scorer_path": "pgdn.scoring.advanced_scorer.AdvancedScorer",
  "database": {...},
  "scanning": {...}
}
```

#### Option B: Environment Variable
```bash
export SCORER_PATH="pgdn.scoring.advanced_scorer.AdvancedScorer"
```

#### Option C: Runtime Configuration
```python
from agents.score.scoring_agent import ScoringAgent
from core.config import Config

config = Config()
config.scorer_path = "pgdn.scoring.advanced_scorer.AdvancedScorer"
scoring_agent = ScoringAgent(config)
```

## Usage Examples

### Standard Usage (Built-in Scorer)
```python
from agents.score.scoring_agent import ScoringAgent

# Uses built-in DefaultTrustScorer
scoring_agent = ScoringAgent()
results = scoring_agent.process_results(scan_results)
```

### External Scorer Usage
```python
from agents.score.scoring_agent import ScoringAgent
from core.config import Config

# Configure external scorer
config = Config()
config.scorer_path = "pgdn.scoring.default_scorer.DefaultScorer"

# Will use external scorer if available, fallback to built-in
scoring_agent = ScoringAgent(config)
results = scoring_agent.process_results(scan_results)
```

### Command Line Usage
```bash
# Uses built-in scorer
python main.py --stage score

# With external scorer configured
SCORER_PATH="pgdn.scoring.advanced_scorer.AdvancedScorer" python main.py --stage score
```

## Fallback Behavior

The ScoringAgent follows this fallback hierarchy:

1. **Config-specified scorer**: `config.scorer_path` if set
2. **Default external scorer**: `pgdn.scoring.default_scorer.DefaultScorer`
3. **Built-in scorer**: `DefaultTrustScorer` (always available)

Each step gracefully handles import failures and logs the outcome.

## Log Messages

```
✅ Loaded external scorer: pgdn.scoring.advanced_scorer.AdvancedScorer
⚠️  External scorer 'pgdn.scoring.custom.CustomScorer' not available: No module named 'pgdn'
📊 Using built-in DefaultTrustScorer
```

## Backward Compatibility

- Existing code continues to work without changes
- Built-in scorer provides identical results to original `trust.py`
- Database schema remains unchanged
- API interface remains unchanged

## Testing External Scorers

```python
# Test your external scorer directly
from pgdn.scoring.default_scorer import DefaultScorer

scorer = DefaultScorer()
result = scorer.score({
    'ip': '192.168.1.100',
    'open_ports': [22, 80, 443],
    'tls': {'issuer': 'Let\'s Encrypt', 'expiry': '2024-12-31'},
    'vulns': {},
    'docker_exposure': {'exposed': False}
})

print(f"Score: {result['score']}")
print(f"Flags: {result['flags']}")
```

## Migration Strategy

1. **Phase 1**: Deploy refactored ScoringAgent (backward compatible)
2. **Phase 2**: Develop and test external scorer library
3. **Phase 3**: Configure external scorer in production
4. **Phase 4**: Monitor and validate results

This approach ensures zero downtime and allows gradual migration to the external scoring library.
