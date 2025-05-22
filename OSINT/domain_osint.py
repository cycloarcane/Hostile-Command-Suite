#!/usr/bin/env python3
"""
domain_osint.py — FastMCP tool for domain and DNS reconnaissance

FastMCP tools
────────────
    whois_lookup(domain, ...)
    dns_enumeration(domain, record_types=["A", "AAAA", "MX", "NS"], ...)
    subdomain_enumeration(domain, wordlist=None, ...)
    censys_domain_search(domain, api_id=None, api_secret=None, ...)

Returns
───────
    {
      "status": "success",
      "domain": "example.com",
      "whois_data": {...},
      "dns_records": {...},
      "subdomains": [...]
    }

Dependencies
────────────
    pip install dnspython requests whois python-whois

Setup
─────
    For Censys integration:
    1. Create account at https://search.censys.io/
    2. Get API credentials from https://search.censys.io/account/api
    3. Set CENSYS_API_ID and CENSYS_API_SECRET environment variables
"""

import json
import os
import sys
import subprocess
import socket
import time
import logging
import hashlib
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse
import ipaddress

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("domain_osint")

mcp = FastMCP("domain")  # MCP route → /domain
_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
os.makedirs(_CACHE_DIR, exist_ok=True)

# API configuration
CENSYS_API_ID = os.environ.get("CENSYS_API_ID", "")
CENSYS_API_SECRET = os.environ.get("CENSYS_API_SECRET", "")
CENSYS_BASE_URL = "https://search.censys.io/api/v2"

# Rate limiting
_LAST_CALL_AT: float = 0.0
DEFAULT_RATE_LIMIT = 0.5  # Requests per second


def _check_dependencies() -> Dict[str, bool]:
    """Check which dependencies are available"""
    return {
        "dnspython": DNS_AVAILABLE,
        "whois": WHOIS_AVAILABLE,
        "requests": REQUESTS_AVAILABLE,
        "dig": subprocess.run(["which", "dig"], capture_output=True).returncode == 0,
        "nslookup": subprocess.run(["which", "nslookup"], capture_output=True).returncode == 0
    }


def _rate_limit(calls_per_second: float = DEFAULT_RATE_LIMIT) -> None:
    """Rate limiting to be respectful to APIs"""
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


def _get_from_cache(cache_key: str, max_age: int = 3600) -> Optional[Dict[str, Any]]:
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


def _validate_domain(domain: str) -> bool:
    """Validate domain name format"""
    if not domain or len(domain) > 253:
        return False
    
    # Remove protocol if present
    if "://" in domain:
        domain = urlparse(f"http://{domain}").netloc or urlparse(domain).netloc
    
    # Basic domain validation
    parts = domain.split(".")
    if len(parts) < 2:
        return False
    
    for part in parts:
        if not part or len(part) > 63:
            return False
        if not part.replace("-", "").isalnum():
            return False
        if part.startswith("-") or part.endswith("-"):
            return False
    
    return True


@mcp.tool()
def check_domain_tools() -> Dict[str, Union[str, Dict[str, bool]]]:
    """
    Check which domain reconnaissance tools and dependencies are available.
    
    Returns:
        A dictionary with tool availability status
    """
    deps = _check_dependencies()
    
    missing = []
    if not deps["dnspython"]:
        missing.append("dnspython: pip install dnspython")
    if not deps["whois"]:
        missing.append("whois: pip install python-whois")
    if not deps["requests"]:
        missing.append("requests: pip install requests")
    if not deps["dig"]:
        missing.append("dig: Install bind-utils or dnsutils package")
    
    censys_configured = bool(CENSYS_API_ID and CENSYS_API_SECRET)
    
    return {
        "status": "ok" if all(deps.values()) else "missing_dependencies",
        "dependencies": deps,
        "censys_configured": censys_configured,
        "installation_instructions": missing
    }


@mcp.tool()
def whois_lookup(
    domain: str,
    use_cache: bool = True,
    cache_max_age: int = 86400  # 24 hours
) -> Dict[str, Any]:
    """
    Perform WHOIS lookup for a domain.
    
    Args:
        domain: Domain name to lookup
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with WHOIS information
    """
    if not _validate_domain(domain):
        return {
            "status": "error",
            "message": "Invalid domain name format"
        }
    
    # Clean domain
    domain = domain.lower().strip()
    if "://" in domain:
        domain = urlparse(f"http://{domain}").netloc or urlparse(domain).netloc
    
    # Check cache
    if use_cache:
        cache_key = _get_cache_key("whois", domain=domain)
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    result = {
        "status": "success",
        "domain": domain,
        "whois_data": {},
        "parsed_data": {}
    }
    
    try:
        _rate_limit()
        
        # Method 1: python-whois library
        if WHOIS_AVAILABLE:
            try:
                w = python_whois.whois(domain)
                if w:
                    # Convert whois object to dictionary
                    whois_dict = {}
                    for key, value in w.items() if hasattr(w, 'items') else vars(w).items():
                        if value is not None:
                            # Handle datetime objects
                            if hasattr(value, 'isoformat'):
                                whois_dict[key] = value.isoformat()
                            elif isinstance(value, list):
                                whois_dict[key] = [str(v) for v in value]
                            else:
                                whois_dict[key] = str(value)
                    
                    result["whois_data"]["python_whois"] = whois_dict
                    
                    # Extract key information
                    parsed = {}
                    if hasattr(w, 'registrar') and w.registrar:
                        parsed["registrar"] = str(w.registrar)
                    if hasattr(w, 'creation_date') and w.creation_date:
                        parsed["creation_date"] = str(w.creation_date)
                    if hasattr(w, 'expiration_date') and w.expiration_date:
                        parsed["expiration_date"] = str(w.expiration_date)
                    if hasattr(w, 'name_servers') and w.name_servers:
                        parsed["name_servers"] = [str(ns) for ns in w.name_servers]
                    if hasattr(w, 'emails') and w.emails:
                        parsed["emails"] = [str(email) for email in w.emails]
                    
                    result["parsed_data"] = parsed
                    
            except Exception as e:
                logger.warning(f"python-whois lookup failed: {e}")
        
        # Method 2: System whois command
        try:
            proc = subprocess.run(
                ["whois", domain],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if proc.returncode == 0 and proc.stdout:
                result["whois_data"]["system_whois"] = proc.stdout
                
                # Parse some basic info from raw whois
                raw_parsed = {}
                lines = proc.stdout.lower().split('\n')
                
                for line in lines:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        if 'registrar' in key and not raw_parsed.get('registrar'):
                            raw_parsed['registrar'] = value
                        elif 'creation' in key or 'created' in key:
                            raw_parsed['creation_date'] = value
                        elif 'expir' in key:
                            raw_parsed['expiration_date'] = value
                        elif 'name server' in key or 'nserver' in key:
                            if 'name_servers' not in raw_parsed:
                                raw_parsed['name_servers'] = []
                            raw_parsed['name_servers'].append(value)
                
                if raw_parsed:
                    result["parsed_data"].update(raw_parsed)
                    
        except Exception as e:
            logger.warning(f"System whois lookup failed: {e}")
        
        # Cache successful results
        if use_cache and result["whois_data"]:
            _save_to_cache(cache_key, result)
        
        return result
        
    except Exception as e:
        return {
            "status": "error",
            "domain": domain,
            "message": f"WHOIS lookup failed: {str(e)}"
        }


@mcp.tool()
def dns_enumeration(
    domain: str,
    record_types: List[str] = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"],
    use_cache: bool = True,
    cache_max_age: int = 3600  # 1 hour
) -> Dict[str, Any]:
    """
    Perform DNS enumeration for a domain.
    
    Args:
        domain: Domain name to enumerate
        record_types: List of DNS record types to query
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with DNS records
    """
    if not _validate_domain(domain):
        return {
            "status": "error",
            "message": "Invalid domain name format"
        }
    
    domain = domain.lower().strip()
    if "://" in domain:
        domain = urlparse(f"http://{domain}").netloc or urlparse(domain).netloc
    
    # Check cache
    if use_cache:
        cache_key = _get_cache_key("dns", domain=domain, record_types=sorted(record_types))
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    result = {
        "status": "success",
        "domain": domain,
        "dns_records": {},
        "ip_addresses": [],
        "mail_servers": [],
        "name_servers": []
    }
    
    if not DNS_AVAILABLE:
        return {
            "status": "error",
            "message": "dnspython not available. Install with: pip install dnspython"
        }
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 30
        
        for record_type in record_types:
            try:
                _rate_limit()
                answers = resolver.resolve(domain, record_type)
                
                records = []
                for rdata in answers:
                    record_data = {
                        "type": record_type,
                        "ttl": answers.ttl,
                        "data": str(rdata)
                    }
                    
                    # Extract additional information based on record type
                    if record_type == "MX":
                        record_data["priority"] = rdata.preference
                        record_data["exchange"] = str(rdata.exchange)
                        if str(rdata.exchange) not in result["mail_servers"]:
                            result["mail_servers"].append(str(rdata.exchange))
                    
                    elif record_type in ["A", "AAAA"]:
                        ip = str(rdata)
                        if ip not in result["ip_addresses"]:
                            result["ip_addresses"].append(ip)
                    
                    elif record_type == "NS":
                        ns = str(rdata)
                        if ns not in result["name_servers"]:
                            result["name_servers"].append(ns)
                    
                    records.append(record_data)
                
                result["dns_records"][record_type] = records
                
            except dns.resolver.NXDOMAIN:
                result["dns_records"][record_type] = {"error": "Domain does not exist"}
            except dns.resolver.NoAnswer:
                result["dns_records"][record_type] = {"error": "No records found"}
            except dns.exception.Timeout:
                result["dns_records"][record_type] = {"error": "DNS query timeout"}
            except Exception as e:
                result["dns_records"][record_type] = {"error": str(e)}
        
        # Try reverse DNS for IP addresses
        reverse_dns = {}
        for ip in result["ip_addresses"]:
            try:
                _rate_limit()
                reverse_name = dns.reversename.from_address(ip)
                reverse_answers = resolver.resolve(reverse_name, "PTR")
                reverse_dns[ip] = [str(rdata) for rdata in reverse_answers]
            except Exception:
                reverse_dns[ip] = []
        
        if reverse_dns:
            result["reverse_dns"] = reverse_dns
        
        # Cache successful results
        if use_cache:
            _save_to_cache(cache_key, result)
        
        return result
        
    except Exception as e:
        return {
            "status": "error",
            "domain": domain,
            "message": f"DNS enumeration failed: {str(e)}"
        }


@mcp.tool()
def subdomain_enumeration(
    domain: str,
    wordlist: Optional[List[str]] = None,
    use_common_subdomains: bool = True,
    timeout: int = 60,
    max_subdomains: int = 100
) -> Dict[str, Any]:
    """
    Enumerate subdomains for a domain.
    
    Args:
        domain: Domain name to enumerate subdomains for
        wordlist: List of subdomain names to try
        use_common_subdomains: Whether to use a built-in list of common subdomains
        timeout: Timeout for the entire operation
        max_subdomains: Maximum number of subdomains to check
        
    Returns:
        Dict with discovered subdomains
    """
    if not _validate_domain(domain):
        return {
            "status": "error",
            "message": "Invalid domain name format"
        }
    
    domain = domain.lower().strip()
    if "://" in domain:
        domain = urlparse(f"http://{domain}").netloc or urlparse(domain).netloc
    
    if not DNS_AVAILABLE:
        return {
            "status": "error",
            "message": "dnspython not available. Install with: pip install dnspython"
        }
    
    # Build subdomain list
    subdomains_to_check = []
    
    if use_common_subdomains:
        common_subs = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
            "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
            "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
            "ns3", "mail2", "new", "mysql", "old", "www1", "email", "img", "www3",
            "mail1", "shop", "sql", "secure", "beta", "team", "data", "demo"
        ]
        subdomains_to_check.extend(common_subs)
    
    if wordlist:
        subdomains_to_check.extend(wordlist)
    
    # Remove duplicates and limit
    subdomains_to_check = list(set(subdomains_to_check))[:max_subdomains]
    
    result = {
        "status": "success",
        "domain": domain,
        "subdomains_checked": len(subdomains_to_check),
        "subdomains_found": [],
        "failed_lookups": 0
    }
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 5
        
        start_time = time.time()
        
        for subdomain in subdomains_to_check:
            # Check timeout
            if time.time() - start_time > timeout:
                result["timeout_reached"] = True
                break
            
            full_domain = f"{subdomain}.{domain}"
            
            try:
                _rate_limit(2.0)  # Faster rate for subdomain enumeration
                
                # Try A record lookup
                answers = resolver.resolve(full_domain, "A")
                
                ips = [str(rdata) for rdata in answers]
                subdomain_data = {
                    "subdomain": full_domain,
                    "ips": ips,
                    "ttl": answers.ttl
                }
                
                # Try to get CNAME as well
                try:
                    cname_answers = resolver.resolve(full_domain, "CNAME")
                    subdomain_data["cname"] = [str(rdata) for rdata in cname_answers]
                except:
                    pass
                
                result["subdomains_found"].append(subdomain_data)
                
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                # Subdomain doesn't exist, which is expected
                continue
            except Exception as e:
                result["failed_lookups"] += 1
                if result["failed_lookups"] > 10:  # Too many failures, probably rate limited
                    break
        
        return result
        
    except Exception as e:
        return {
            "status": "error",
            "domain": domain,
            "message": f"Subdomain enumeration failed: {str(e)}"
        }


@mcp.tool()
def censys_domain_search(
    domain: str,
    api_id: Optional[str] = None,
    api_secret: Optional[str] = None,
    search_type: str = "hosts",
    max_results: int = 100
) -> Dict[str, Any]:
    """
    Search Censys for information about a domain.
    
    Args:
        domain: Domain to search for
        api_id: Censys API ID (overrides environment variable)
        api_secret: Censys API secret (overrides environment variable)
        search_type: Type of search ("hosts" or "certificates")
        max_results: Maximum number of results to return
        
    Returns:
        Dict with Censys search results
    """
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    if not _validate_domain(domain):
        return {
            "status": "error",
            "message": "Invalid domain name format"
        }
    
    # Use provided credentials or fall back to environment variables
    censys_id = api_id or CENSYS_API_ID
    censys_secret = api_secret or CENSYS_API_SECRET
    
    if not censys_id or not censys_secret:
        return {
            "status": "error",
            "message": "Censys API credentials not provided. Set CENSYS_API_ID and CENSYS_API_SECRET environment variables."
        }
    
    domain = domain.lower().strip()
    if "://" in domain:
        domain = urlparse(f"http://{domain}").netloc or urlparse(domain).netloc
    
    try:
        _rate_limit()
        
        # Build search query
        if search_type == "hosts":
            query = f"services.http.request.host:{domain} or services.tls.certificates.leaf_data.subject.common_name:{domain}"
            endpoint = f"{CENSYS_BASE_URL}/hosts/search"
        else:  # certificates
            query = f"names:{domain}"
            endpoint = f"{CENSYS_BASE_URL}/certificates/search"
        
        # Make API request
        params = {
            "q": query,
            "per_page": min(max_results, 100)
        }
        
        response = requests.get(
            endpoint,
            params=params,
            auth=(censys_id, censys_secret),
            timeout=30
        )
        response.raise_for_status()
        
        data = response.json()
        
        result = {
            "status": "success",
            "domain": domain,
            "search_type": search_type,
            "query": query,
            "results": data.get("result", {}).get("hits", []),
            "total": data.get("result", {}).get("total", 0),
            "result_count": len(data.get("result", {}).get("hits", []))
        }
        
        # Process results to extract key information
        processed_results = []
        for hit in result["results"]:
            if search_type == "hosts":
                processed_hit = {
                    "ip": hit.get("ip", ""),
                    "services": hit.get("services", []),
                    "location": hit.get("location", {}),
                    "autonomous_system": hit.get("autonomous_system", {}),
                    "last_updated": hit.get("last_updated_at", "")
                }
            else:  # certificates
                processed_hit = {
                    "fingerprint": hit.get("fingerprint_sha256", ""),
                    "names": hit.get("names", []),
                    "issuer": hit.get("parsed", {}).get("issuer", {}),
                    "subject": hit.get("parsed", {}).get("subject", {}),
                    "validity": hit.get("parsed", {}).get("validity", {}),
                    "signature_algorithm": hit.get("parsed", {}).get("signature_algorithm", {})
                }
            
            processed_results.append(processed_hit)
        
        result["processed_results"] = processed_results
        
        return result
        
    except requests.exceptions.HTTPError as e:
        if response.status_code == 401:
            return {
                "status": "error",
                "message": "Invalid Censys API credentials"
            }
        else:
            return {
                "status": "error",
                "message": f"Censys API error: {e}"
            }
    except Exception as e:
        return {
            "status": "error",
            "domain": domain,
            "message": f"Censys search failed: {str(e)}"
        }


@mcp.tool()
def domain_intelligence(
    domain: str,
    include_whois: bool = True,
    include_dns: bool = True,
    include_subdomains: bool = True,
    include_censys: bool = False,
    subdomain_wordlist: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Comprehensive domain intelligence gathering.
    
    Args:
        domain: Domain to investigate
        include_whois: Whether to include WHOIS data
        include_dns: Whether to include DNS enumeration
        include_subdomains: Whether to include subdomain enumeration
        include_censys: Whether to include Censys search
        subdomain_wordlist: Custom wordlist for subdomain enumeration
        
    Returns:
        Dict with comprehensive domain information
    """
    if not _validate_domain(domain):
        return {
            "status": "error",
            "message": "Invalid domain name format"
        }
    
    domain = domain.lower().strip()
    if "://" in domain:
        domain = urlparse(f"http://{domain}").netloc or urlparse(domain).netloc
    
    result = {
        "status": "success",
        "domain": domain,
        "timestamp": time.time(),
        "intelligence": {}
    }
    
    # WHOIS lookup
    if include_whois:
        logger.info(f"Performing WHOIS lookup for {domain}")
        whois_result = whois_lookup(domain)
        result["intelligence"]["whois"] = whois_result
    
    # DNS enumeration
    if include_dns:
        logger.info(f"Performing DNS enumeration for {domain}")
        dns_result = dns_enumeration(domain)
        result["intelligence"]["dns"] = dns_result
    
    # Subdomain enumeration
    if include_subdomains:
        logger.info(f"Performing subdomain enumeration for {domain}")
        subdomain_result = subdomain_enumeration(
            domain, 
            wordlist=subdomain_wordlist,
            max_subdomains=50  # Limit for comprehensive scan
        )
        result["intelligence"]["subdomains"] = subdomain_result
    
    # Censys search
    if include_censys and CENSYS_API_ID and CENSYS_API_SECRET:
        logger.info(f"Performing Censys search for {domain}")
        censys_result = censys_domain_search(domain)
        result["intelligence"]["censys"] = censys_result
    
    # Generate summary
    summary = {
        "domain": domain,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "ip_addresses": [],
        "mail_servers": [],
        "name_servers": [],
        "subdomains_found": 0,
        "censys_hosts": 0
    }
    
    # Extract key information from results
    if include_whois and result["intelligence"]["whois"]["status"] == "success":
        parsed_data = result["intelligence"]["whois"].get("parsed_data", {})
        summary["registrar"] = parsed_data.get("registrar")
        summary["creation_date"] = parsed_data.get("creation_date")
        summary["expiration_date"] = parsed_data.get("expiration_date")
    
    if include_dns and result["intelligence"]["dns"]["status"] == "success":
        dns_data = result["intelligence"]["dns"]
        summary["ip_addresses"] = dns_data.get("ip_addresses", [])
        summary["mail_servers"] = dns_data.get("mail_servers", [])
        summary["name_servers"] = dns_data.get("name_servers", [])
    
    if include_subdomains and result["intelligence"]["subdomains"]["status"] == "success":
        summary["subdomains_found"] = len(result["intelligence"]["subdomains"].get("subdomains_found", []))
    
    if include_censys and "censys" in result["intelligence"]:
        if result["intelligence"]["censys"]["status"] == "success":
            summary["censys_hosts"] = result["intelligence"]["censys"].get("result_count", 0)
    
    result["summary"] = summary
    
    return result


if __name__ == "__main__":
    mcp.run(transport="stdio")