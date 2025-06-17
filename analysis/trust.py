from datetime import datetime
import hashlib
import json

class TrustScorer:
    def score(self, scan_data):
        score = 100
        flags = []

        if 2375 in scan_data['open_ports']:
            score -= 30
            flags.append("Docker socket exposed")
        if 22 in scan_data['open_ports']:
            score -= 10
            flags.append("SSH port open")
        tls = scan_data.get("tls", {})
        if tls.get("issuer") in (None, "Self-signed") or not tls.get("expiry"):
            score -= 25
            flags.append("TLS misconfigured")
        for vuln in scan_data.get("vulns", {}).values():
            score -= 15
            flags.append(f"Known vuln: {vuln}")

        summary = f"Trust Score: {score}. Flags: {', '.join(flags)}."

        return {
            "ip": scan_data["ip"],
            "score": score,
            "flags": flags,
            "summary": summary,
            "timestamp": datetime.utcnow().isoformat(),
            "hash": hashlib.sha256(json.dumps(scan_data, sort_keys=True).encode()).hexdigest(),
            "docker_exposure": scan_data.get("docker_exposure", {"exposed": False})
        }
