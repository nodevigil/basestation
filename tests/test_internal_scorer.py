# test_internal_scorer.py
import logging
import sys
import os

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s [%(name)s]: %(message)s'
)

# Import and test the scorer with external config
from agents.score.scoring_agent import ScoringAgent
from core.config import Config

# Load configuration (will use external config if available)
config = Config()
scoring_agent = ScoringAgent(config)

test_data = [{
    'ip': '192.168.1.100',
    'open_ports': [22, 80, 443],
    'tls': {'issuer': 'Test CA', 'expiry': '2024-12-31'},
    'vulns': {},
    'docker_exposure': {'exposed': False}
}]

print("Testing scorer with external configuration...")
results = scoring_agent.process_results(test_data)
print(f"Results: {results}")