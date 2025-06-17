from discovery.sui import fetch_sui_validator_hosts, resolve_hosts_to_ips
from scanner.vuln_scanner import scan_node
from analyzer.trust_scorer import score_and_summarize
from memory.history_store import HistoryStore
import json

class ScannerAgent:
    def __init__(self):
        self.history = HistoryStore()
        self.hosts = []
        self.ips = []

    def plan(self):
        self.hosts = fetch_sui_validator_hosts()
        self.ips = resolve_hosts_to_ips(self.hosts)
        print(f"Discovered {len(self.ips)} validator IPs")

    def act(self):
        return [scan_node(ip) for ip in self.ips]

    def analyze(self, results):
        return [score_and_summarize(res) for res in results]

    def publish(self, reports):
        for report in reports:
            print(json.dumps(report, indent=2))
            self.history.add_entry(report)

    def run(self):
        self.plan()
        results = self.act()
        reports = self.analyze(results)
        self.publish(reports)
