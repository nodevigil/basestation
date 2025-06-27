import httpx
import logging
import time
from .base_protocol_scanner import ProtocolScanner


class SuiScanner(ProtocolScanner):
    """
    Advanced Sui node scanner with scan levels:
      1 - Lite
      2 - Medium (metrics, heuristics, anomalies, validator checks)
      3 - Ferocious (latency, probing, header dump, simulated calls)
    """

    def __init__(self, config=None):
        super().__init__(config)
        
        # Sui-specific configuration
        self.ports = self.config.get('ports', (9000, 9184, 443, 80))
        self.timeout = self.config.get('timeout', 10)
        self.debug = self.config.get('debug', False)
        
        self.logger = logging.getLogger(__name__)
    
    @property
    def protocol_name(self) -> str:
        """Return the protocol name."""
        return "sui"
    
    def get_supported_levels(self) -> list[int]:
        """Sui scanner supports all three levels."""
        return [1, 2, 3]
    
    def describe_levels(self) -> dict[int, str]:
        """Describe what each scan level does for Sui."""
        return {
            1: "Basic Sui node health checks (system_state, checkpoints)",
            2: "Extended metrics collection, validator analysis, and anomaly detection",
            3: "Aggressive probing with latency testing, header analysis, and edge case validation"
        }

    async def scan_protocol(self, target: str, scan_level: int, **kwargs) -> dict:
        """Perform Sui-specific scan at the specified level."""
        results = []
        
        for port in self.ports:
            base_url = f"http://{target}:{port}"
            result = {
                "ip": target,
                "port": port,
                "healthy": False,
                "epoch": None,
                "checkpoint_height": None,
                "validator_count": None,
                "metrics": {},
                "metrics_available": False,
                "public_metrics": False,
                "header_signals": [],
                "misconfigs": [],
                "latency_ms": None,
                "anomalies": [],
                "validator_consistency_issues": []
            }

            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    # Level 1: Basic probes
                    sys = await self.try_fetch_json(client, f"{base_url}/v1/system_state")
                    if sys:
                        result["epoch"] = sys.get("epoch")
                        result["healthy"] = True

                    checkpoints = await self.try_fetch_json(client, f"{base_url}/v1/checkpoints")
                    if checkpoints:
                        result["checkpoint_height"] = checkpoints.get("nextCursor")

                    # Level 2: Metrics & Validator analysis + anomaly checks
                    if scan_level >= 2:
                        m = await client.get(f"{base_url}/metrics")
                        if m.status_code == 200:
                            result["metrics_available"] = True
                            result["metrics"] = self.parse_metrics(m.text)
                            if "sui_checkpoint_height" in result["metrics"]:
                                result["checkpoint_height"] = result["metrics"]["sui_checkpoint_height"]
                        elif m.status_code in (200, 403, 401):
                            result["public_metrics"] = True
                            result["misconfigs"].append("metrics exposed without auth")

                        validators = await self.try_fetch_json(client, f"{base_url}/v1/validators")
                        if validators and "active_validators" in validators:
                            val_list = validators["active_validators"]
                            result["validator_count"] = len(val_list)
                            if len(val_list) < 5:
                                result["misconfigs"].append("very low validator count")

                            # Validator consistency checks (metrics vs JSON)
                            for val in val_list:
                                name = val.get("name")
                                stake = float(val.get("stake_amount", 0))
                                apy = float(val.get("apy", 0))
                                if apy < 0 or stake <= 0:
                                    result["validator_consistency_issues"].append(f"Invalid stake/APY for {name}")

                        # Anomaly: metrics have validator stake but /v1 doesn't
                        if not validators and "validator_stake_total" in result["metrics"]:
                            result["anomalies"].append("Stake seen in metrics but no validator list returned")

                    # Level 3: Probing, latency, headers
                    if scan_level == 3:
                        start = time.time()
                        await client.get(f"{base_url}/v1/system_state")
                        result["latency_ms"] = round((time.time() - start) * 1000, 2)

                        headers = await client.get(f"{base_url}/v1/checkpoints")
                        result["header_signals"] = [k.lower() for k in headers.headers.keys() if "sui" in k.lower() or "narwhal" in k.lower()]

                        # Simulate a malformed request to /transactions
                        bad_tx = await client.post(f"{base_url}/v1/transactions", json={"invalid": "data"})
                        if bad_tx.status_code not in (400, 422):
                            result["anomalies"].append("Unexpected response to malformed transaction")

            except Exception as e:
                if self.debug:
                    self.logger.debug(f"Scan error {target}:{port} - {e}")
                continue

            results.append(result)
        return results

    async def try_fetch_json(self, client, url):
        try:
            r = await client.get(url)
            if r.status_code == 200:
                return r.json()
        except Exception:
            return None

    def parse_metrics(self, text):
        metrics = {}
        for line in text.splitlines():
            if any(kw in line for kw in ["sui_", "narwhal_", "bullshark_", "checkpoint_", "validator_"]):
                parts = line.split()
                if len(parts) == 2:
                    k, v = parts
                    try:
                        metrics[k.strip()] = float(v)
                    except ValueError:
                        continue
        return metrics
