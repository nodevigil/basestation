import requests
import logging

class DockerExposureChecker:
    @staticmethod
    def check(ip, port=2375):
        """Check if Docker API is exposed and exploitable"""
        try:
            url = f"http://{ip}:{port}/version"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                logging.warning(f"!!! Docker API open on {ip}:{port} — CRITICAL")
                return {
                    "exposed": True,
                    "docker_version": response.json().get("Version"),
                    "severity": "CRITICAL"
                }
        except Exception as e:
            logging.debug(f"Docker exposure check error on {ip}: {e}")
        return {"exposed": False}
