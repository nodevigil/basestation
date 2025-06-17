import os
import requests
import re
import socket
import psycopg2
from datetime import datetime
from db_config import db_config

class SuiDiscovery:
    def __init__(self):
        # Use the centralized database configuration
        self.pg_conn_str = self._get_postgres_connection_string()

    def _get_postgres_connection_string(self):
        """Convert SQLAlchemy database URL to psycopg2 connection string format"""
        db_url = db_config.database_url
        
        # Handle different URL formats
        if db_url.startswith('postgresql://'):
            # Parse the URL: postgresql://user:password@host:port/database
            import urllib.parse
            parsed = urllib.parse.urlparse(db_url)
            
            conn_parts = []
            if parsed.hostname:
                conn_parts.append(f"host={parsed.hostname}")
            if parsed.port:
                conn_parts.append(f"port={parsed.port}")
            if parsed.username:
                conn_parts.append(f"user={parsed.username}")
            if parsed.password:
                conn_parts.append(f"password={parsed.password}")
            if parsed.path and len(parsed.path) > 1:  # Remove leading '/'
                conn_parts.append(f"dbname={parsed.path[1:]}")
            
            return " ".join(conn_parts)
        else:
            # Fallback to environment variable or default
            return os.getenv("PG_CONN", "dbname=depin user=simon host=localhost")

    def get_hosts(self):
        url = "https://fullnode.mainnet.sui.io"
        headers = {"Content-Type": "application/json"}
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "suix_getLatestSuiSystemState",
            "params": []
        }
        try:
            res = requests.post(url, json=payload, headers=headers, timeout=10)
            res.raise_for_status()
            validators = res.json()["result"]["activeValidators"]
            hosts = []
            for v in validators:
                addr = v.get("netAddress") or v.get("net_address", "")
                match = re.search(r"/dns/([\w\.\-]+)/", addr)
                if match:
                    host = match.group(1)
                    name = v.get("name", None)
                    hosts.append((host, name))
            # Save to DB
            self.save_addresses_to_db(hosts)
            # Return just the hostnames for further processing
            return [host for host, _ in hosts]
        except Exception as e:
            print(f"Error fetching validators: {e}")
            return []

    def save_addresses_to_db(self, hosts):
        try:
            conn = psycopg2.connect(self.pg_conn_str)
            cur = conn.cursor()
            for host, name in hosts:
                cur.execute("""
                    INSERT INTO validator_addresses (address, name, source, created_at, active)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (address) DO UPDATE
                    SET active = EXCLUDED.active,
                        name = COALESCE(EXCLUDED.name, validator_addresses.name),
                        source = EXCLUDED.source,
                        created_at = EXCLUDED.created_at
                """, (host, name, "sui_discovery", datetime.utcnow(), True))
            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            print(f"DB error saving validator addresses: {e}")

    def resolve_hosts_to_ips(self, hosts):
        ips = []
        for h in hosts:
            try:
                ips.append(socket.gethostbyname(h))
            except Exception as e:
                print(f"DNS error for {h}: {e}")
        return ips
