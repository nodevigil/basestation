import socket
import ssl
import httpx
from tools.nmap import nmap_scan
from tools.whatweb import whatweb_scan
from tools.ssltester import ssl_test
from tools.docker import DockerExposureChecker
from utils.cve_updater import search_cves_for_banner

class Scanner:
    ## TODO add more known vulnerabilities and their CVEs
    KNOWN_VULNS = {
        "nginx/1.14.0": "CVE-2019-20372 - Heap buffer overflow in HTTP/2",
        "OpenSSH_7.2p2": "CVE-2016-0777 - Information leak via roaming feature",
        "Apache/2.4.7": "CVE-2017-15710 - mod_auth_digest DoS"
    }

    def grab_banner(self, ip, port):
        try:
            with socket.create_connection((ip, port), timeout=2) as sock:
                sock.sendall(b"\\n")
                banner = sock.recv(1024).decode(errors="ignore").strip()
                return banner
        except Exception:
            return None

    def match_known_vulns(self, banner):
        """Match banner against known vulnerabilities from database.
        
        Args:
            banner: Service banner string
            
        Returns:
            List of matching CVE dictionaries or None
        """
        if not banner:
            return None
        
        # First check static KNOWN_VULNS for backwards compatibility
        for key, cve in self.KNOWN_VULNS.items():
            if key.lower() in banner.lower():
                return [{"cve_id": cve.split(" - ")[0], "description": cve}]
        
        # Then check database for more comprehensive matches
        try:
            database_cves = search_cves_for_banner(banner)
            if database_cves:
                return database_cves[:5]  # Return top 5 matches
        except Exception as e:
            # Fallback to static check if database is unavailable
            pass
        
        return None

    def get_tls_info(self, ip):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=ip) as ssock:
                ssock.settimeout(2)
                ssock.connect((ip, 443))
                cert = ssock.getpeercert()
                return {
                    "issuer": cert.get("issuer"),
                    "expiry": cert.get("notAfter")
                }
        except Exception:
            return {}

    def get_http_headers(self, ip, port):
        try:
            url = f"https://{ip}" if port == 443 else f"http://{ip}"
            r = httpx.get(url, timeout=2)
            return dict(r.headers)
        except Exception:
            return {}

    @staticmethod
    def get_web_ports_and_schemes(nmap_result):
        web_ports = []
        if isinstance(nmap_result, dict) and "ports" in nmap_result:
            for port_info in nmap_result["ports"]:
                service = port_info.get("service", "")
                port = int(port_info["port"])
                if service == "https" or port == 443:
                    web_ports.append((port, "https"))
                elif service in ("http", "http-proxy") or port in (80, 8080):
                    web_ports.append((port, "http"))
        return web_ports

    def scan(self, ip, ports=(22, 80, 443, 2375, 3306)):
        # --- Basic Python scan ---
        open_ports = []
        tls_info = {}
        http_headers = {}
        banners = {}
        vuln_matches = {}

        for port in ports:
            try:
                with socket.socket() as sock:
                    sock.settimeout(1)
                    if sock.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
                        banner = self.grab_banner(ip, port)
                        if banner:
                            banners[port] = banner
                            vuln = self.match_known_vulns(banner)
                            if vuln:
                                vuln_matches[port] = vuln
                        if port == 443:
                            tls_info = self.get_tls_info(ip)
                        if port in (80, 443):
                            http_headers = self.get_http_headers(ip, port)
            except Exception:
                continue

        # --- Nmap scan first ---
        try:
            nmap_results = nmap_scan(ip)
        except Exception as e:
            nmap_results = {"error": str(e)}

        # --- Dynamic WhatWeb on open web ports ---
        web_ports = self.get_web_ports_and_schemes(nmap_results)
        whatweb_results = {}
        for port, scheme in web_ports:
            try:
                result = whatweb_scan(ip, port=port, scheme=scheme)
                # Only store successful results (not errors or timeouts)
                if result and (not isinstance(result, dict) or not result.get("error")):
                    whatweb_results[f"{scheme}://{ip}:{port}"] = result
            except Exception as e:
                # Skip failed scans - don't store them
                pass

        # --- SSL test ---
        try:
            ssl_results = ssl_test(ip, port=443)
        except Exception as e:
            ssl_results = {"error": str(e)}

        # --- Docker exposure check ---
        docker_exposure = {"exposed": False}
        if 2375 in open_ports:
            docker_exposure = DockerExposureChecker.check(ip)

        return {
            "ip": ip,
            "open_ports": open_ports,
            "banners": banners,
            "vulns": vuln_matches,
            "tls": tls_info,
            "http_headers": http_headers,
            "docker_exposure": docker_exposure,
            "nmap": nmap_results,
            "whatweb": whatweb_results,
            "ssl_test": ssl_results
        }
