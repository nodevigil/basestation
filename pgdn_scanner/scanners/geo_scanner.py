"""
GeoIP scanner for IP geolocation and ASN enrichment.
"""

import socket
import ipaddress
from typing import Dict, Any, Optional
from .base_scanner import BaseScanner

# Optional imports for GeoIP functionality
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import geoip2.database
    import geoip2.errors
    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False


class GeoScanner(BaseScanner):
    """GeoIP scanner for geolocation and ASN enrichment."""
    
    @property
    def scanner_type(self) -> str:
        return "geo"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.maxmind_db_path = self.config.get('maxmind_db_path', '/usr/share/GeoIP/GeoLite2-City.mmdb')
        self.maxmind_asn_db_path = self.config.get('maxmind_asn_db_path', '/usr/share/GeoIP/GeoLite2-ASN.mmdb')
        self.fallback_to_api = self.config.get('fallback_to_api', True)
        self.cache = {}  # Simple cache for lookups
    
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform GeoIP scan.
        
        Args:
            target: IP address or hostname to scan
            **kwargs: Additional scan parameters (including scan_level)
            
        Returns:
            GeoIP scan results
        """
        scan_level = kwargs.get('scan_level', 1)
        
        # Resolve hostname to IP if needed
        try:
            ip_address = socket.gethostbyname(target)
        except socket.gaierror:
            return {
                "target": target,
                "scan_level": scan_level,
                "error": "DNS resolution failed",
                "scanner_type": self.scanner_type
            }
        
        # Check if it's a private IP
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private:
                return {
                    "target": target,
                    "ip_address": ip_address,
                    "scan_level": scan_level,
                    "country_name": "Private Network",
                    "city_name": "Private Network", 
                    "latitude": None,
                    "longitude": None,
                    "asn_number": None,
                    "asn_organization": "Private Network",
                    "scanner_type": self.scanner_type
                }
        except ValueError:
            pass
        
        # Check cache first
        if ip_address in self.cache:
            cached_result = self.cache[ip_address].copy()
            cached_result["target"] = target
            cached_result["scan_level"] = scan_level
            return cached_result
        
        geo_info = self._get_geo_info(ip_address)
        asn_info = self._get_asn_info(ip_address)
        
        result = {
            "target": target,
            "ip_address": ip_address,
            "scan_level": scan_level,
            "country_name": geo_info.get("country_name"),
            "city_name": geo_info.get("city_name"),
            "latitude": geo_info.get("latitude"),
            "longitude": geo_info.get("longitude"),
            "asn_number": asn_info.get("asn_number"),
            "asn_organization": asn_info.get("asn_organization"),
            "scanner_type": self.scanner_type
        }
        
        # Cache the result (without target and scan_level fields)
        cache_result = result.copy()
        del cache_result["target"]
        del cache_result["scan_level"]
        self.cache[ip_address] = cache_result
        
        return result
    
    def _get_geo_info(self, ip_address: str) -> Dict[str, Any]:
        """Get geographic information for IP address.
        
        Args:
            ip_address: IP address
            
        Returns:
            Geographic information
        """
        try:
            # Try MaxMind database first if available
            if HAS_GEOIP2:
                with geoip2.database.Reader(self.maxmind_db_path) as reader:
                    response = reader.city(ip_address)
                    return {
                        "country_name": response.country.name,
                        "city_name": response.city.name,
                        "latitude": float(response.location.latitude) if response.location.latitude else None,
                        "longitude": float(response.location.longitude) if response.location.longitude else None
                    }
        except Exception as e:
            self.logger.debug(f"MaxMind lookup failed for {ip_address}: {e}")
            
        # Fallback to API if enabled and available
        if self.fallback_to_api and HAS_REQUESTS:
            return self._get_geo_info_api(ip_address)
        
        return {
            "country_name": None,
            "city_name": None,
            "latitude": None,
            "longitude": None
        }
    
    def _get_asn_info(self, ip_address: str) -> Dict[str, Any]:
        """Get ASN information for IP address.
        
        Args:
            ip_address: IP address
            
        Returns:
            ASN information
        """
        try:
            # Try MaxMind ASN database first if available
            if HAS_GEOIP2:
                with geoip2.database.Reader(self.maxmind_asn_db_path) as reader:
                    response = reader.asn(ip_address)
                    return {
                        "asn_number": response.autonomous_system_number,
                        "asn_organization": response.autonomous_system_organization
                    }
        except Exception as e:
            self.logger.debug(f"MaxMind ASN lookup failed for {ip_address}: {e}")
            
        # Fallback to API if enabled and available
        if self.fallback_to_api and HAS_REQUESTS:
            return self._get_asn_info_api(ip_address)
        
        return {
            "asn_number": None,
            "asn_organization": None
        }
    
    def _get_geo_info_api(self, ip_address: str) -> Dict[str, Any]:
        """Get geographic information via API fallback.
        
        Args:
            ip_address: IP address
            
        Returns:
            Geographic information
        """
        if not HAS_REQUESTS:
            return {
                "country_name": None,
                "city_name": None,
                "latitude": None,
                "longitude": None
            }
        
        try:
            # Use ip-api.com as a free fallback
            response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return {
                        "country_name": data.get("country"),
                        "city_name": data.get("city"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon")
                    }
        except Exception as e:
            self.logger.debug(f"API geo lookup failed for {ip_address}: {e}")
        
        return {
            "country_name": None,
            "city_name": None,
            "latitude": None,
            "longitude": None
        }
    
    def _get_asn_info_api(self, ip_address: str) -> Dict[str, Any]:
        """Get ASN information via API fallback.
        
        Args:
            ip_address: IP address
            
        Returns:
            ASN information
        """
        if not HAS_REQUESTS:
            return {
                "asn_number": None,
                "asn_organization": None
            }
        
        try:
            # Use ip-api.com for ASN info as well
            response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=as,asname", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    as_info = data.get("as", "")
                    asn_number = None
                    if as_info.startswith("AS"):
                        try:
                            asn_number = int(as_info.split()[0][2:])  # Remove "AS" prefix
                        except (ValueError, IndexError):
                            pass
                    
                    return {
                        "asn_number": asn_number,
                        "asn_organization": data.get("asname")
                    }
        except Exception as e:
            self.logger.debug(f"API ASN lookup failed for {ip_address}: {e}")
        
        return {
            "asn_number": None,
            "asn_organization": None
        }
