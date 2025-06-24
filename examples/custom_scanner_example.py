#!/usr/bin/env python3
"""
Example: Creating a custom scanner for the modular scanning system.
Shows how to extend BaseScanner to create protocol-specific scanners.
"""

import sys
import os
import socket
from typing import Dict, Any, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pgdn.scanning.base_scanner import BaseScanner, ScannerRegistry
from pgdn.scanning.scan_orchestrator import ScanOrchestrator


class CustomDatabaseScanner(BaseScanner):
    """Example custom scanner for database services."""
    
    @property
    def scanner_type(self) -> str:
        return "database"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.database_ports = self.config.get('database_ports', [3306, 5432, 27017, 6379])
        self.timeout = self.config.get('timeout', 3)
    
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Scan for database services."""
        self.logger.info(f"Running database scan on {target}")
        
        detected_databases = {}
        open_db_ports = []
        
        for port in self.database_ports:
            if self._is_port_open(target, port):
                open_db_ports.append(port)
                db_type = self._identify_database_type(target, port)
                if db_type:
                    detected_databases[port] = db_type
        
        return {
            "target": target,
            "open_database_ports": open_db_ports,
            "detected_databases": detected_databases,
            "scanner_type": self.scanner_type,
            "security_warnings": self._generate_security_warnings(open_db_ports)
        }
    
    def _is_port_open(self, target: str, port: int) -> bool:
        """Check if a port is open."""
        try:
            with socket.socket() as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))
                return result == 0
        except Exception:
            return False
    
    def _identify_database_type(self, target: str, port: int) -> Optional[str]:
        """Identify database type by port."""
        db_types = {
            3306: "MySQL",
            5432: "PostgreSQL", 
            27017: "MongoDB",
            6379: "Redis",
            1433: "SQL Server",
            1521: "Oracle"
        }
        return db_types.get(port)
    
    def _generate_security_warnings(self, open_ports: list) -> list:
        """Generate security warnings for open database ports."""
        warnings = []
        
        for port in open_ports:
            if port == 27017:
                warnings.append("MongoDB detected - ensure authentication is enabled")
            elif port == 6379:
                warnings.append("Redis detected - should not be exposed to internet")
            elif port in [3306, 5432]:
                warnings.append(f"Database on port {port} - verify access controls")
        
        return warnings


class CustomAPIScanner(BaseScanner):
    """Example custom scanner for API services."""
    
    @property
    def scanner_type(self) -> str:
        return "api"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.api_paths = self.config.get('api_paths', ['/api', '/v1', '/graphql', '/swagger'])
        self.timeout = self.config.get('timeout', 5)
    
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Scan for API endpoints."""
        self.logger.info(f"Running API scan on {target}")
        
        discovered_apis = {}
        
        # Check common web ports for API endpoints
        web_ports = [80, 443, 8080, 8443]
        
        for port in web_ports:
            if self._is_port_open(target, port):
                scheme = "https" if port in [443, 8443] else "http"
                apis = self._check_api_endpoints(target, port, scheme)
                if apis:
                    discovered_apis[f"{scheme}://{target}:{port}"] = apis
        
        return {
            "target": target,
            "discovered_apis": discovered_apis,
            "scanner_type": self.scanner_type,
            "api_security_findings": self._analyze_api_security(discovered_apis)
        }
    
    def _is_port_open(self, target: str, port: int) -> bool:
        """Check if a port is open."""
        try:
            with socket.socket() as sock:
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                return result == 0
        except Exception:
            return False
    
    def _check_api_endpoints(self, target: str, port: int, scheme: str) -> list:
        """Check for API endpoints."""
        found_apis = []
        
        # This is a simplified example - in reality you'd use HTTP requests
        for path in self.api_paths:
            # Simulate API discovery
            url = f"{scheme}://{target}:{port}{path}"
            found_apis.append({
                "path": path,
                "url": url,
                "status": "found"  # In reality, check HTTP response
            })
        
        return found_apis
    
    def _analyze_api_security(self, apis: dict) -> list:
        """Analyze API security findings."""
        findings = []
        
        for base_url, endpoints in apis.items():
            if any("/swagger" in ep["path"] for ep in endpoints):
                findings.append("Swagger documentation exposed")
            if any("/graphql" in ep["path"] for ep in endpoints):
                findings.append("GraphQL endpoint detected - check for introspection")
        
        return findings


def demonstrate_custom_scanners():
    """Demonstrate using custom scanners."""
    print("🔧 Custom Scanner Examples")
    print("-" * 30)
    
    # Create registry and register custom scanners
    config = {
        'scanners': {
            'database': {
                'enabled': True,
                'database_ports': [3306, 5432, 27017],
                'timeout': 2
            },
            'api': {
                'enabled': True,
                'api_paths': ['/api', '/v1', '/graphql'],
                'timeout': 3
            }
        }
    }
    
    registry = ScannerRegistry(config)
    
    # Register our custom scanners
    registry.register_scanner('database', CustomDatabaseScanner)
    registry.register_scanner('api', CustomAPIScanner)
    
    print(f"Available scanners: {registry.get_available_scanners()}")
    
    # Test database scanner
    print("\n📊 Testing Database Scanner:")
    db_scanner = registry.get_scanner('database')
    if db_scanner:
        db_results = db_scanner.scan("127.0.0.1")
        print(f"Database scan results: {db_results}")
    
    # Test API scanner
    print("\n🌐 Testing API Scanner:")
    api_scanner = registry.get_scanner('api')
    if api_scanner:
        api_results = api_scanner.scan("127.0.0.1")
        print(f"API scan results: {api_results}")


def demonstrate_orchestrator_with_custom_scanners():
    """Show how to use custom scanners with the orchestrator."""
    print("\n🎯 Orchestrator with Custom Scanners")
    print("-" * 40)
    
    # Create a custom orchestrator that includes our scanners
    class CustomScanOrchestrator(ScanOrchestrator):
        def __init__(self, config):
            super().__init__(config)
            # Register custom scanners
            self.scanner_registry.register_scanner('database', CustomDatabaseScanner)
            self.scanner_registry.register_scanner('api', CustomAPIScanner)
    
    config = {
        'orchestrator': {
            'enabled_scanners': ['generic', 'database', 'api'],
            'use_external_tools': False
        },
        'scanners': {
            'generic': {
                'enabled': True,
                'default_ports': [22, 80, 443],
                'connection_timeout': 1
            },
            'database': {
                'enabled': True,
                'database_ports': [3306, 5432],
                'timeout': 2
            },
            'api': {
                'enabled': True,
                'api_paths': ['/api', '/v1'],
                'timeout': 3
            }
        }
    }
    
    orchestrator = CustomScanOrchestrator(config)
    
    target = "127.0.0.1"
    print(f"Scanning {target} with custom orchestrator...")
    
    # This would normally run all enabled scanners
    # For demo purposes, just show the configuration
    print(f"Enabled scanners: {config['orchestrator']['enabled_scanners']}")
    print("Custom scanners are now part of the scanning pipeline!")


if __name__ == "__main__":
    print("🚀 Custom Scanner Examples\n")
    
    try:
        demonstrate_custom_scanners()
        demonstrate_orchestrator_with_custom_scanners()
        
        print("\n✅ Custom scanner examples completed!")
        print("\n📝 Key takeaways:")
        print("   • Extend BaseScanner to create custom scanners")
        print("   • Register scanners with ScannerRegistry")
        print("   • Configure scanners in config.json")
        print("   • Use with ScanOrchestrator for integrated scanning")
        
    except Exception as e:
        print(f"\n❌ Example failed: {e}")
        import traceback
        traceback.print_exc()
