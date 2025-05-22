#!/usr/bin/env python3
"""
geolocation_osint.py — FastMCP tool for IP geolocation and geographical intelligence

FastMCP tools
────────────
    geolocate_ip(ip_address, ...)
    bulk_geolocate(ip_addresses, ...)
    reverse_geo_lookup(lat, lon, ...)
    trace_route_geo(target, ...)

Returns
───────
    {
      "status": "success",
      "ip_address": "8.8.8.8",
      "location": {
        "country": "United States",
        "city": "Mountain View",
        "latitude": 37.4056,
        "longitude": -122.0775
      },
      "network_info": {...}
    }

Dependencies
────────────
    pip install requests geoip2 maxminddb-geolite2

Setup
─────
    For enhanced accuracy, download MaxMind GeoLite2 database:
    1. Create account at https://www.maxmind.com/en/geolite2/signup
    2. Download GeoLite2-City.mmdb
    3. Set GEOIP_DB_PATH environment variable
    
    For IP info API (optional):
    1. Get API key from https://ipinfo.io/
    2. Set IPINFO_API_KEY environment variable
"""

import json
import os
import sys
import socket
import subprocess
import time
import logging
import hashlib
from typing import Any, Dict, List, Optional, Union, Tuple
import ipaddress
import re

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import geoip2.database
    import geoip2.errors
    from maxminddb import open_database
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False

from fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("geolocation_osint")

mcp = FastMCP("geolocation")  # MCP route → /geolocation
_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
os.makedirs(_CACHE_DIR, exist_ok=True)

# Configuration
GEOIP_DB_PATH = os.environ.get("GEOIP_DB_PATH", "")
IPINFO_API_KEY = os.environ.get("IPINFO_API_KEY", "")

# Rate limiting
_LAST_CALL_AT: float = 0.0
DEFAULT_RATE_LIMIT = 0.5  # Requests per second


def _rate_limit(calls_per_second: float = DEFAULT_RATE_LIMIT) -> None:
    """Rate limiting for external API calls"""
    global _LAST_CALL_AT
    
    min_interval = 1.0 / calls_per_second
    wait = _LAST_CALL_AT + min_interval - time.time()
    if wait > 0:
        time.sleep(wait)
    _LAST_CALL_AT = time.time()


def _get_cache_key(operation: str, **kwargs) -> str:
    """Generate a cache key"""
    serializable_kwargs = {
        k: v for k, v in kwargs.items() 
        if isinstance(v, (str, int, float, bool, type(None)))
    }
    cache_str = f"{operation}_{json.dumps(serializable_kwargs, sort_keys=True)}"
    return hashlib.md5(cache_str.encode()).hexdigest()


def _get_from_cache(cache_key: str, max_age: int = 86400) -> Optional[Dict[str, Any]]:
    """Try to get results from cache"""
    cache_file = os.path.join(_CACHE_DIR, f"{cache_key}.json")
    
    if os.path.exists(cache_file):
        file_age = time.time() - os.path.getmtime(cache_file)
        if file_age < max_age:
            try:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
    return None


def _save_to_cache(cache_key: str, data: Dict[str, Any]) -> None:
    """Save results to cache"""
    cache_file = os.path.join(_CACHE_DIR, f"{cache_key}.json")
    try:
        with open(cache_file, 'w') as f:
            json.dump(data, f)
    except IOError as e:
        logger.warning(f"Cache write error: {e}")


def _validate_ip(ip_address: str) -> bool:
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def _validate_coordinates(lat: float, lon: float) -> bool:
    """Validate latitude and longitude"""
    return -90 <= lat <= 90 and -180 <= lon <= 180


def _resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve hostname to IP address"""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


@mcp.tool()
def check_geolocation_tools() -> Dict[str, Union[str, Dict[str, bool]]]:
    """
    Check which geolocation tools and dependencies are available.
    
    Returns:
        A dictionary with tool availability status
    """
    deps = {
        "requests": REQUESTS_AVAILABLE,
        "geoip2": GEOIP2_AVAILABLE,
        "traceroute": subprocess.run(["which", "traceroute"], capture_output=True).returncode == 0,
        "ping": subprocess.run(["which", "ping"], capture_output=True).returncode == 0
    }
    
    # Check if GeoIP database is available
    geoip_db_available = False
    if GEOIP2_AVAILABLE:
        if GEOIP_DB_PATH and os.path.exists(GEOIP_DB_PATH):
            geoip_db_available = True
        else:
            # Try to find database in common locations
            common_paths = [
                "/usr/share/GeoIP/GeoLite2-City.mmdb",
                "/var/lib/GeoIP/GeoLite2-City.mmdb",
                os.path.expanduser("~/GeoLite2-City.mmdb"),
                "./GeoLite2-City.mmdb"
            ]
            for path in common_paths:
                if os.path.exists(path):
                    geoip_db_available = True
                    break
    
    deps["geoip_database"] = geoip_db_available
    deps["ipinfo_api"] = bool(IPINFO_API_KEY)
    
    missing = []
    if not deps["requests"]:
        missing.append("requests: pip install requests")
    if not deps["geoip2"]:
        missing.append("geoip2: pip install geoip2 maxminddb-geolite2")
    if not deps["geoip_database"]:
        missing.append("GeoIP database: Download from MaxMind or set GEOIP_DB_PATH")
    if not deps["traceroute"]:
        missing.append("traceroute: Install traceroute package")
    
    return {
        "status": "ok" if all(deps.values()) else "missing_dependencies",
        "dependencies": deps,
        "installation_instructions": missing
    }


@mcp.tool()
def geolocate_ip(
    ip_address: str,
    use_cache: bool = True,
    cache_max_age: int = 86400,  # 24 hours
    include_network_info: bool = True
) -> Dict[str, Any]:
    """
    Geolocate an IP address using multiple methods.
    
    Args:
        ip_address: IP address to geolocate (or hostname to resolve)
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        include_network_info: Whether to include network/ISP information
        
    Returns:
        Dict with geolocation information
    """
    # Handle hostname resolution
    original_input = ip_address
    if not _validate_ip(ip_address):
        resolved_ip = _resolve_hostname(ip_address)
        if resolved_ip:
            ip_address = resolved_ip
        else:
            return {
                "status": "error",
                "message": f"Invalid IP address or unable to resolve hostname: {original_input}"
            }
    
    # Check for private/local IPs
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return {
                "status": "success",
                "ip_address": ip_address,
                "original_input": original_input,
                "location": {
                    "country": "Private/Local Network",
                    "city": "N/A",
                    "region": "N/A",
                    "latitude": None,
                    "longitude": None,
                    "timezone": None
                },
                "network_info": {
                    "ip_type": "private" if ip_obj.is_private else "local",
                    "asn": None,
                    "org": "Private/Local Network"
                },
                "accuracy": "N/A"
            }
    except ValueError:
        pass
    
    # Check cache
    if use_cache:
        cache_key = _get_cache_key("geolocate", ip_address=ip_address)
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            cached_result["original_input"] = original_input
            return cached_result
    
    result = {
        "status": "success",
        "ip_address": ip_address,
        "original_input": original_input,
        "location": {},
        "network_info": {},
        "sources": []
    }
    
    # Method 1: MaxMind GeoIP2 Database
    if GEOIP2_AVAILABLE:
        db_path = GEOIP_DB_PATH
        if not db_path:
            # Try common locations
            common_paths = [
                "/usr/share/GeoIP/GeoLite2-City.mmdb",
                "/var/lib/GeoIP/GeoLite2-City.mmdb",
                os.path.expanduser("~/GeoLite2-City.mmdb"),
                "./GeoLite2-City.mmdb"
            ]
            for path in common_paths:
                if os.path.exists(path):
                    db_path = path
                    break
        
        if db_path and os.path.exists(db_path):
            try:
                with geoip2.database.Reader(db_path) as reader:
                    response = reader.city(ip_address)
                    
                    geoip_data = {
                        "country": response.country.name,
                        "country_code": response.country.iso_code,
                        "city": response.city.name,
                        "region": response.subdivisions.most_specific.name,
                        "region_code": response.subdivisions.most_specific.iso_code,
                        "latitude": float(response.location.latitude) if response.location.latitude else None,
                        "longitude": float(response.location.longitude) if response.location.longitude else None,
                        "timezone": response.location.time_zone,
                        "accuracy_radius": response.location.accuracy_radius,
                        "postal_code": response.postal.code
                    }
                    
                    result["location"].update(geoip_data)
                    result["sources"].append("MaxMind GeoIP2")
                    result["accuracy"] = f"±{response.location.accuracy_radius}km" if response.location.accuracy_radius else "Unknown"
                    
            except geoip2.errors.AddressNotFoundError:
                logger.warning(f"IP {ip_address} not found in GeoIP database")
            except Exception as e:
                logger.warning(f"GeoIP lookup failed: {e}")
    
    # Method 2: IPInfo.io API
    if REQUESTS_AVAILABLE:
        try:
            _rate_limit()
            
            url = f"https://ipinfo.io/{ip_address}/json"
            headers = {}
            if IPINFO_API_KEY:
                headers["Authorization"] = f"Bearer {IPINFO_API_KEY}"
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            ipinfo_data = response.json()
            
            # Extract location data
            if "loc" in ipinfo_data:
                lat, lon = map(float, ipinfo_data["loc"].split(","))
                if not result["location"].get("latitude"):
                    result["location"]["latitude"] = lat
                    result["location"]["longitude"] = lon
            
            if not result["location"].get("country") and ipinfo_data.get("country"):
                result["location"]["country"] = ipinfo_data["country"]
            
            if not result["location"].get("city") and ipinfo_data.get("city"):
                result["location"]["city"] = ipinfo_data["city"]
            
            if not result["location"].get("region") and ipinfo_data.get("region"):
                result["location"]["region"] = ipinfo_data["region"]
            
            if not result["location"].get("timezone") and ipinfo_data.get("timezone"):
                result["location"]["timezone"] = ipinfo_data["timezone"]
            
            # Network information
            if include_network_info:
                network_data = {
                    "hostname": ipinfo_data.get("hostname"),
                    "org": ipinfo_data.get("org"),
                    "postal": ipinfo_data.get("postal")
                }
                result["network_info"].update(network_data)
            
            result["sources"].append("IPInfo.io")
            
        except Exception as e:
            logger.warning(f"IPInfo.io lookup failed: {e}")
    
    # Method 3: Free GeoLocation APIs (as fallback)
    if not result["location"].get("latitude") and REQUESTS_AVAILABLE:
        free_apis = [
            f"http://ip-api.com/json/{ip_address}",
            f"https://ipapi.co/{ip_address}/json/",
        ]
        
        for api_url in free_apis:
            try:
                _rate_limit()
                response = requests.get(api_url, timeout=10)
                response.raise_for_status()
                
                api_data = response.json()
                
                # ip-api.com format
                if "lat" in api_data and "lon" in api_data:
                    if not result["location"].get("latitude"):
                        result["location"]["latitude"] = api_data["lat"]
                        result["location"]["longitude"] = api_data["lon"]
                    
                    if not result["location"].get("country"):
                        result["location"]["country"] = api_data.get("country")
                    if not result["location"].get("city"):
                        result["location"]["city"] = api_data.get("city")
                    if not result["location"].get("region"):
                        result["location"]["region"] = api_data.get("regionName")
                    
                    if include_network_info:
                        result["network_info"]["isp"] = api_data.get("isp")
                        result["network_info"]["as"] = api_data.get("as")
                    
                    result["sources"].append("ip-api.com")
                    break
                
                # ipapi.co format
                elif "latitude" in api_data and "longitude" in api_data:
                    if not result["location"].get("latitude"):
                        result["location"]["latitude"] = api_data["latitude"]
                        result["location"]["longitude"] = api_data["longitude"]
                    
                    if not result["location"].get("country"):
                        result["location"]["country"] = api_data.get("country_name")
                    if not result["location"].get("city"):
                        result["location"]["city"] = api_data.get("city")
                    if not result["location"].get("region"):
                        result["location"]["region"] = api_data.get("region")
                    
                    result["sources"].append("ipapi.co")
                    break
                
            except Exception as e:
                logger.warning(f"Free API lookup failed for {api_url}: {e}")
                continue
    
    # Add additional network information using whois if available
    if include_network_info and subprocess.run(["which", "whois"], capture_output=True).returncode == 0:
        try:
            proc = subprocess.run(
                ["whois", ip_address],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if proc.returncode == 0 and proc.stdout:
                whois_output = proc.stdout.lower()
                
                # Extract ASN and organization info
                for line in whois_output.split('\n'):
                    if 'originas' in line or 'origin as' in line:
                        asn_match = re.search(r'as(\d+)', line)
                        if asn_match and not result["network_info"].get("asn"):
                            result["network_info"]["asn"] = f"AS{asn_match.group(1)}"
                    
                    if 'orgname' in line and ':' in line:
                        org = line.split(':', 1)[1].strip()
                        if org and not result["network_info"].get("organization"):
                            result["network_info"]["organization"] = org
                            
        except Exception as e:
            logger.warning(f"WHOIS lookup failed: {e}")
    
    # Ensure we have at least basic location info
    if not any(result["location"].values()):
        result["location"] = {
            "country": "Unknown",
            "city": "Unknown",
            "region": "Unknown",
            "latitude": None,
            "longitude": None,
            "timezone": None
        }
        result["accuracy"] = "Unknown"
    
    # Cache successful results
    if use_cache and result["location"]:
        _save_to_cache(cache_key, result)
    
    return result


@mcp.tool()
def bulk_geolocate(
    ip_addresses: List[str],
    max_ips: int = 50,
    delay_between_requests: float = 1.0
) -> Dict[str, Any]:
    """
    Geolocate multiple IP addresses in bulk.
    
    Args:
        ip_addresses: List of IP addresses to geolocate
        max_ips: Maximum number of IPs to process
        delay_between_requests: Delay between requests in seconds
        
    Returns:
        Dict with geolocation results for all IPs
    """
    if not ip_addresses:
        return {
            "status": "error",
            "message": "No IP addresses provided"
        }
    
    # Limit the number of IPs
    ips_to_process = ip_addresses[:max_ips]
    
    result = {
        "status": "success",
        "total_ips": len(ip_addresses),
        "processed_ips": len(ips_to_process),
        "results": {},
        "summary": {
            "successful": 0,
            "failed": 0,
            "countries": {},
            "coordinates": []
        }
    }
    
    for i, ip in enumerate(ips_to_process):
        logger.info(f"Processing IP {i+1}/{len(ips_to_process)}: {ip}")
        
        geo_result = geolocate_ip(ip, use_cache=True)
        result["results"][ip] = geo_result
        
        if geo_result["status"] == "success":
            result["summary"]["successful"] += 1
            
            # Count countries
            country = geo_result["location"].get("country", "Unknown")
            result["summary"]["countries"][country] = result["summary"]["countries"].get(country, 0) + 1
            
            # Collect coordinates for mapping
            lat = geo_result["location"].get("latitude")
            lon = geo_result["location"].get("longitude")
            if lat is not None and lon is not None:
                result["summary"]["coordinates"].append({
                    "ip": ip,
                    "latitude": lat,
                    "longitude": lon,
                    "city": geo_result["location"].get("city", "Unknown"),
                    "country": country
                })
        else:
            result["summary"]["failed"] += 1
        
        # Add delay between requests to be respectful
        if i < len(ips_to_process) - 1:
            time.sleep(delay_between_requests)
    
    return result


@mcp.tool()
def reverse_geo_lookup(
    latitude: float,
    longitude: float,
    use_cache: bool = True
) -> Dict[str, Any]:
    """
    Perform reverse geocoding to get location details from coordinates.
    
    Args:
        latitude: Latitude coordinate
        longitude: Longitude coordinate
        use_cache: Whether to use caching
        
    Returns:
        Dict with location information
    """
    if not _validate_coordinates(latitude, longitude):
        return {
            "status": "error",
            "message": "Invalid coordinates. Latitude must be -90 to 90, longitude -180 to 180"
        }
    
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    # Check cache
    if use_cache:
        cache_key = _get_cache_key("reverse_geo", lat=latitude, lon=longitude)
        cached_result = _get_from_cache(cache_key, 86400)  # 24 hours
        if cached_result:
            return cached_result
    
    result = {
        "status": "success",
        "latitude": latitude,
        "longitude": longitude,
        "location": {},
        "sources": []
    }
    
    # Try OpenStreetMap Nominatim (free)
    try:
        _rate_limit()
        
        url = "https://nominatim.openstreetmap.org/reverse"
        params = {
            "lat": latitude,
            "lon": longitude,
            "format": "json",
            "addressdetails": 1
        }
        headers = {
            "User-Agent": "OSINT-Tool/1.0"
        }
        
        response = requests.get(url, params=params, headers=headers, timeout=15)
        response.raise_for_status()
        
        data = response.json()
        
        if "address" in data:
            address = data["address"]
            location_data = {
                "display_name": data.get("display_name"),
                "country": address.get("country"),
                "country_code": address.get("country_code"),
                "state": address.get("state"),
                "city": address.get("city") or address.get("town") or address.get("village"),
                "suburb": address.get("suburb"),
                "road": address.get("road"),
                "house_number": address.get("house_number"),
                "postcode": address.get("postcode")
            }
            
            result["location"] = location_data
            result["sources"].append("OpenStreetMap Nominatim")
        
    except Exception as e:
        logger.warning(f"Reverse geocoding failed: {e}")
        result["location"] = {
            "error": "Reverse geocoding failed",
            "coordinates": f"{latitude}, {longitude}"
        }
    
    # Cache successful results
    if use_cache and result["location"]:
        _save_to_cache(cache_key, result)
    
    return result


@mcp.tool()
def trace_route_geo(
    target: str,
    max_hops: int = 30,
    timeout: int = 60
) -> Dict[str, Any]:
    """
    Perform a traceroute and geolocate each hop.
    
    Args:
        target: Target hostname or IP address
        max_hops: Maximum number of hops
        timeout: Timeout for the entire operation
        
    Returns:
        Dict with traceroute results and geolocation for each hop
    """
    # Check if traceroute is available
    if subprocess.run(["which", "traceroute"], capture_output=True).returncode != 0:
        return {
            "status": "error",
            "message": "traceroute command not available. Install traceroute package."
        }
    
    # Resolve target if needed
    target_ip = target
    if not _validate_ip(target):
        resolved_ip = _resolve_hostname(target)
        if resolved_ip:
            target_ip = resolved_ip
        else:
            return {
                "status": "error",
                "message": f"Unable to resolve target: {target}"
            }
    
    result = {
        "status": "success",
        "target": target,
        "target_ip": target_ip,
        "hops": [],
        "path_countries": [],
        "total_hops": 0
    }
    
    try:
        # Run traceroute
        cmd = ["traceroute", "-n", "-m", str(max_hops), target_ip]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if proc.returncode != 0:
            return {
                "status": "error",
                "message": f"traceroute failed: {proc.stderr}"
            }
        
        # Parse traceroute output
        lines = proc.stdout.strip().split('\n')[1:]  # Skip header
        
        for line in lines:
            if not line.strip():
                continue
            
            # Parse hop line
            parts = line.split()
            if len(parts) < 2:
                continue
            
            hop_num = parts[0]
            hop_data = {
                "hop_number": int(hop_num),
                "ip_address": None,
                "rtt": [],
                "location": None
            }
            
            # Extract IP and RTT values
            for part in parts[1:]:
                # Check if it's an IP address
                if _validate_ip(part):
                    hop_data["ip_address"] = part
                # Check if it's a time value
                elif "ms" in part:
                    try:
                        rtt = float(part.replace("ms", ""))
                        hop_data["rtt"].append(rtt)
                    except ValueError:
                        pass
                # Skip asterisks (timeouts)
                elif part == "*":
                    continue
            
            # Geolocate the hop if we have an IP
            if hop_data["ip_address"]:
                geo_result = geolocate_ip(hop_data["ip_address"], use_cache=True)
                if geo_result["status"] == "success":
                    hop_data["location"] = geo_result["location"]
                    
                    # Track countries in the path
                    country = geo_result["location"].get("country")
                    if country and country not in result["path_countries"] and country != "Unknown":
                        result["path_countries"].append(country)
            
            result["hops"].append(hop_data)
        
        result["total_hops"] = len(result["hops"])
        
        return result
        
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "message": f"traceroute timed out after {timeout} seconds"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"traceroute failed: {str(e)}"
        }


@mcp.tool()
def get_my_location() -> Dict[str, Any]:
    """
    Get the geolocation of your current public IP address.
    
    Returns:
        Dict with your current location information
    """
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    try:
        # Get public IP
        _rate_limit()
        response = requests.get("https://httpbin.org/ip", timeout=10)
        response.raise_for_status()
        
        public_ip = response.json()["origin"]
        
        # Geolocate the IP
        return geolocate_ip(public_ip, use_cache=False)
        
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to get current location: {str(e)}"
        }


if __name__ == "__main__":
    mcp.run(transport="stdio")