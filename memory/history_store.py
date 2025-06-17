import json

class HistoryStore:
    def __init__(self, path="scan_history.json"):
        self.path = path
        self.data = self._load()

    def _load(self):
        try:
            with open(self.path) as f:
                return json.load(f)
        except:
            return []

    def add_entry(self, report):
        self.data.append(report)
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2)

    def find_by_ip(self, ip):
        return [r for r in self.data if r.get("ip") == ip]
