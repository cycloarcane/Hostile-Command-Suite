#!/usr/bin/env python3
"""
certificate_osint.py — FastMCP tool for SSL/TLS certificate analysis and Certificate Transparency monitoring

FastMCP tools
────────────
    search_certificate_transparency(domain, ...)
    analyze_ssl_certificate(hostname, port=443, ...)
    monitor_certificate_changes(domain, ...)
    find_subdomains_from_certificates(domain, ...)

Returns
───────
    {
      "status": "success",
      "domain": "example.com",
      "certificates": [...],
      "subdomains": [...],
      "ssl_analysis": {...}
    }

Dependencies
────────────
    pip install requests ssl cryptography

Setup
─────
    Certificate Transparency APIs used:
    1. crt.sh (free)
    2. Censys certificates (requires API key)
    3. Google Certificate Transparency API
    
    For enhanced features, set:
    - CENSYS_API_ID and CENSYS_API_SECRET (for certificate search)
"""

import json
import os
import sys
import ssl
import socket
import time
import logging
import hashlib
import re
from typing import Any, Dict, List, Optional, Union, Tuple
from urllib.parse import urlparse
import datetime

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

from fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("certificate_osint")

mcp = FastMCP("certificate")  # MCP route → /certificate
_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
os.makedirs(_CACHE_DIR, exist_ok=True)

# API configuration
CENSYS_API_ID = os.environ.get("CENSYS_API_ID", "")
CENSYS_API_SECRET = os.environ.get("CENSYS_API_SECRET", "")

# Certificate Transparency log URLs
CT_LOGS = {
    "crt.sh": "https://crt.sh/",
    "google_argon": "https://ct.googleapis.com/logs/argon2021/",
    "cloudflare_nimbus": "https://ct.cloudflare.com/logs/nimbus2021/"
}

# Rate limiting
_LAST_CALL_AT: float = 0.0
DEFAULT_RATE_LIMIT = 0.5  # Requests per second


def _rate_limit(calls_per_second: float = DEFAULT_RATE_LIMIT) -> None:
    """Rate limiting for API calls"""
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
        if not part.replace("-", "").replace("*", "").isalnum():
            return False
        if part.startswith("-") or part.endswith("-"):
            return False
    
    return True


def _extract_domains_from_cert_names(names: List[str]) -> List[str]:
    """Extract unique domains from certificate subject alternative names"""
    domains = set()
    
    for name in names:
        # Clean up the name
        name = name.strip().lower()
        
        # Skip email addresses and IP addresses
        if "@" in name or re.match(r'^\d+\.\d+\.\d+\.\d+$', name):
            continue
        
        # Handle wildcard certificates
        if name.startswith("*."):
            # Add both wildcard and base domain
            domains.add(name)
            base_domain = name[2:]  # Remove *.
            if _validate_domain(base_domain):
                domains.add(base_domain)
        else:
            if _validate_domain(name):
                domains.add(name)
    
    return sorted(list(domains))


def _parse_certificate_dates(not_before: str, not_after: str) -> Dict[str, Any]:
    """Parse certificate validity dates"""
    try:
        # Handle different date formats
        date_formats = [
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ", 
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d"
        ]
        
        parsed_dates = {}
        
        for date_str, field_name in [(not_before, "not_before"), (not_after, "not_after")]:
            parsed_date = None
            for fmt in date_formats:
                try:
                    parsed_date = datetime.datetime.strptime(date_str, fmt)
                    break
                except ValueError:
                    continue
            
            if parsed_date:
                parsed_dates[field_name] = parsed_date.isoformat()
                parsed_dates[f"{field_name}_timestamp"] = parsed_date.timestamp()
        
        # Calculate validity period
        if "not_before_timestamp" in parsed_dates and "not_after_timestamp" in parsed_dates:
            validity_days = (parsed_dates["not_after_timestamp"] - parsed_dates["not_before_timestamp"]) / (24 * 60 * 60)
            parsed_dates["validity_period_days"] = round(validity_days)
            
            # Check if certificate is currently valid
            now = time.time()
            parsed_dates["is_valid"] = (parsed_dates["not_before_timestamp"] <= now <= parsed_dates["not_after_timestamp"])
            
            # Days until expiration
            if parsed_dates["not_after_timestamp"] > now:
                parsed_dates["days_until_expiry"] = round((parsed_dates["not_after_timestamp"] - now) / (24 * 60 * 60))
            else:
                parsed_dates["days_until_expiry"] = 0
                parsed_dates["expired"] = True
        
        return parsed_dates
        
    except Exception as e:
        logger.warning(f"Date parsing error: {e}")
        return {"error": "Failed to parse certificate dates"}


@mcp.tool()
def check_certificate_tools() -> Dict[str, Union[str, Dict[str, bool]]]:
    """
    Check which certificate analysis tools and dependencies are available.
    
    Returns:
        A dictionary with tool availability status
    """
    deps = {
        "requests": REQUESTS_AVAILABLE,
        "cryptography": CRYPTOGRAPHY_AVAILABLE,
        "ssl_socket": True,  # Built-in Python
        "censys_api": bool(CENSYS_API_ID and CENSYS_API_SECRET)
    }
    
    missing = []
    if not deps["requests"]:
        missing.append("requests: pip install requests")
    if not deps["cryptography"]:
        missing.append("cryptography: pip install cryptography")
    
    return {
        "status": "ok" if deps["requests"] else "missing_dependencies",
        "dependencies": deps,
        "installation_instructions": missing,
        "notes": {
            "ct_logs_free": "Certificate Transparency logs are freely accessible",
            "censys_optional": "Censys API provides enhanced certificate search capabilities"
        }
    }


@mcp.tool()
def search_certificate_transparency(
    domain: str,
    include_expired: bool = True,
    max_results: int = 100,
    use_cache: bool = True,
    cache_max_age: int = 3600  # 1 hour
) -> Dict[str, Any]:
    """
    Search Certificate Transparency logs for certificates issued for a domain.
    
    Args:
        domain: Domain to search for certificates
        include_expired: Whether to include expired certificates
        max_results: Maximum number of certificates to return
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with certificate transparency search results
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
    
    domain = domain.lower().strip()
    if "://" in domain:
        domain = urlparse(f"http://{domain}").netloc or urlparse(domain).netloc
    
    # Check cache
    if use_cache:
        cache_key = _get_cache_key("ct_search", domain=domain, include_expired=include_expired, max_results=max_results)
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    result = {
        "status": "success",
        "domain": domain,
        "certificates": [],
        "unique_subdomains": [],
        "certificate_authorities": {},
        "sources": []
    }
    
    # Method 1: crt.sh (most comprehensive free CT log search)
    try:
        _rate_limit()
        
        # Search for the domain and its subdomains
        url = "https://crt.sh/"
        params = {
            "q": f"%.{domain}",
            "output": "json"
        }
        
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        
        ct_data = response.json()
        
        all_domains = set()
        certificate_authorities = {}
        
        for cert in ct_data[:max_results]:
            cert_info = {
                "id": cert.get("id"),
                "logged_at": cert.get("entry_timestamp"),
                "not_before": cert.get("not_before"),
                "not_after": cert.get("not_after"),
                "common_name": cert.get("common_name"),
                "issuer_name": cert.get("issuer_name"),
                "serial_number": cert.get("serial_number")
            }
            
            # Parse certificate names to extract domains
            name_value = cert.get("name_value", "")
            if name_value:
                names = [name.strip() for name in name_value.split('\n') if name.strip()]
                cert_domains = _extract_domains_from_cert_names(names)
                cert_info["domains"] = cert_domains
                all_domains.update(cert_domains)
            
            # Parse validity dates
            if cert_info["not_before"] and cert_info["not_after"]:
                date_info = _parse_certificate_dates(cert_info["not_before"], cert_info["not_after"])
                cert_info.update(date_info)
                
                # Skip expired certificates if not requested
                if not include_expired and date_info.get("expired", False):
                    continue
            
            # Track certificate authorities
            issuer = cert_info["issuer_name"]
            if issuer:
                certificate_authorities[issuer] = certificate_authorities.get(issuer, 0) + 1
            
            result["certificates"].append(cert_info)
        
        # Extract unique subdomains
        target_subdomains = []
        for domain_name in all_domains:
            if domain_name.endswith(f".{domain}") or domain_name == domain:
                target_subdomains.append(domain_name)
        
        result["unique_subdomains"] = sorted(list(set(target_subdomains)))
        result["certificate_authorities"] = certificate_authorities
        result["sources"].append("crt.sh")
        
    except Exception as e:
        logger.warning(f"crt.sh search failed: {e}")
        result["sources"].append("crt.sh (failed)")
    
    # Method 2: Censys certificate search (if API key available)
    if CENSYS_API_ID and CENSYS_API_SECRET and not result["certificates"]:
        try:
            _rate_limit()
            
            # Search Censys certificate database
            censys_url = "https://search.censys.io/api/v2/certificates/search"
            headers = {
                "Content-Type": "application/json"
            }
            auth = (CENSYS_API_ID, CENSYS_API_SECRET)
            
            # Search for certificates containing the domain
            search_query = f"names: {domain} or names: *.{domain}"
            data = {
                "q": search_query,
                "per_page": min(max_results, 100)
            }
            
            response = requests.post(censys_url, json=data, headers=headers, auth=auth, timeout=30)
            response.raise_for_status()
            
            censys_data = response.json()
            
            for cert in censys_data.get("result", {}).get("hits", []):
                cert_info = {
                    "fingerprint_sha256": cert.get("fingerprint_sha256"),
                    "names": cert.get("names", []),
                    "issuer": cert.get("parsed", {}).get("issuer", {}),
                    "subject": cert.get("parsed", {}).get("subject", {}),
                    "validity": cert.get("parsed", {}).get("validity", {}),
                    "source": "censys"
                }
                
                # Extract validity information
                validity = cert_info["validity"]
                if validity.get("start") and validity.get("end"):
                    date_info = _parse_certificate_dates(validity["start"], validity["end"])
                    cert_info.update(date_info)
                
                result["certificates"].append(cert_info)
                
                # Add domains from this certificate
                for name in cert_info["names"]:
                    if name.endswith(f".{domain}") or name == domain:
                        if name not in result["unique_subdomains"]:
                            result["unique_subdomains"].append(name)
            
            result["sources"].append("Censys")
            
        except Exception as e:
            logger.warning(f"Censys certificate search failed: {e}")
            result["sources"].append("Censys (failed)")
    
    # Sort subdomains
    result["unique_subdomains"] = sorted(result["unique_subdomains"])
    
    # Generate summary statistics
    result["summary"] = {
        "total_certificates": len(result["certificates"]),
        "unique_subdomains_found": len(result["unique_subdomains"]),
        "certificate_authorities_count": len(result["certificate_authorities"]),
        "most_common_ca": max(result["certificate_authorities"].items(), key=lambda x: x[1])[0] if result["certificate_authorities"] else None
    }
    
    # Cache successful results
    if use_cache and result["certificates"]:
        _save_to_cache(cache_key, result)
    
    return result


@mcp.tool()
def analyze_ssl_certificate(
    hostname: str,
    port: int = 443,
    include_chain: bool = True,
    timeout: int = 10
) -> Dict[str, Any]:
    """
    Analyze the SSL/TLS certificate of a specific hostname and port.
    
    Args:
        hostname: Hostname to connect to
        port: Port number (default 443)
        include_chain: Whether to analyze the full certificate chain
        timeout: Connection timeout in seconds
        
    Returns:
        Dict with SSL certificate analysis
    """
    if not hostname:
        return {
            "status": "error",
            "message": "Hostname cannot be empty"
        }
    
    # Clean hostname
    hostname = hostname.strip().lower()
    if "://" in hostname:
        hostname = urlparse(f"http://{hostname}").netloc or urlparse(hostname).netloc
    if ":" in hostname and not hostname.startswith("["):  # Handle IPv6
        hostname = hostname.split(":")[0]
    
    result = {
        "status": "success",
        "hostname": hostname,
        "port": port,
        "certificate": {},
        "chain": [],
        "security_analysis": {},
        "connection_info": {}
    }
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # We want to analyze even invalid certs
        
        # Connect and get certificate
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get certificate in DER format
                cert_der = ssock.getpeercert(binary_form=True)
                cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                
                # Get certificate info
                cert_info = ssock.getpeercert()
                
                # Connection information
                result["connection_info"] = {
                    "cipher": ssock.cipher(),
                    "version": ssock.version(),
                    "compression": ssock.compression(),
                    "selected_alpn": ssock.selected_alpn_protocol(),
                    "selected_npn": ssock.selected_npn_protocol()
                }
                
                # Certificate chain
                if include_chain:
                    try:
                        chain = ssock.getpeercert_chain()
                        if chain:
                            result["chain"] = [
                                {
                                    "subject": dict(cert.get_subject().get_components()),
                                    "issuer": dict(cert.get_issuer().get_components()),
                                    "serial_number": str(cert.get_serial_number()),
                                    "version": cert.get_version(),
                                    "not_before": cert.get_notBefore().decode('utf-8'),
                                    "not_after": cert.get_notAfter().decode('utf-8')
                                }
                                for cert in chain
                            ]
                    except:
                        pass  # Chain analysis not critical
        
        # Parse certificate using cryptography library if available
        if CRYPTOGRAPHY_AVAILABLE:
            try:
                cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                
                # Extract detailed certificate information
                certificate_data = {
                    "version": cert.version.name,
                    "serial_number": str(cert.serial_number),
                    "signature_algorithm": cert.signature_algorithm_oid._name,
                    "issuer": cert.issuer.rfc4514_string(),
                    "subject": cert.subject.rfc4514_string(),
                    "not_valid_before": cert.not_valid_before.isoformat(),
                    "not_valid_after": cert.not_valid_after.isoformat(),
                    "public_key_algorithm": cert.public_key().__class__.__name__,
                }
                
                # Get Subject Alternative Names
                try:
                    san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    san_names = [name.value for name in san_ext.value]
                    certificate_data["subject_alt_names"] = san_names
                    certificate_data["domains"] = _extract_domains_from_cert_names(san_names)
                except x509.ExtensionNotFound:
                    certificate_data["subject_alt_names"] = []
                    certificate_data["domains"] = []
                
                # Calculate validity information
                now = datetime.datetime.now(datetime.timezone.utc)
                is_valid = cert.not_valid_before <= now <= cert.not_valid_after
                days_until_expiry = (cert.not_valid_after - now).days
                
                certificate_data.update({
                    "is_valid": is_valid,
                    "days_until_expiry": days_until_expiry,
                    "expired": days_until_expiry < 0,
                    "validity_period_days": (cert.not_valid_after - cert.not_valid_before).days
                })
                
                # Get public key details
                public_key = cert.public_key()
                if hasattr(public_key, 'key_size'):
                    certificate_data["key_size"] = public_key.key_size
                
                result["certificate"] = certificate_data
                
            except Exception as e:
                logger.warning(f"Detailed certificate parsing failed: {e}")
        
        # Fallback to basic certificate info if cryptography fails
        if not result["certificate"] and cert_info:
            result["certificate"] = {
                "subject": dict(x[0] for x in cert_info.get("subject", [])),
                "issuer": dict(x[0] for x in cert_info.get("issuer", [])),
                "version": cert_info.get("version"),
                "serial_number": cert_info.get("serialNumber"),
                "not_before": cert_info.get("notBefore"),
                "not_after": cert_info.get("notAfter"),
                "subject_alt_names": cert_info.get("subjectAltName", [])
            }
        
        # Security analysis
        security_issues = []
        recommendations = []
        
        # Check certificate validity
        if result["certificate"].get("expired"):
            security_issues.append("Certificate has expired")
            recommendations.append("Renew SSL certificate immediately")
        elif result["certificate"].get("days_until_expiry", 0) < 30:
            security_issues.append("Certificate expires soon")
            recommendations.append("Plan certificate renewal")
        
        # Check TLS version
        tls_version = result["connection_info"].get("version")
        if tls_version in ["TLSv1", "TLSv1.1"]:
            security_issues.append(f"Outdated TLS version: {tls_version}")
            recommendations.append("Upgrade to TLS 1.2 or higher")
        
        # Check key size
        key_size = result["certificate"].get("key_size")
        if key_size and key_size < 2048:
            security_issues.append(f"Weak key size: {key_size} bits")
            recommendations.append("Use at least 2048-bit RSA keys")
        
        # Check signature algorithm
        sig_alg = result["certificate"].get("signature_algorithm", "").lower()
        if "sha1" in sig_alg:
            security_issues.append("Weak signature algorithm (SHA-1)")
            recommendations.append("Use SHA-256 or stronger")
        
        result["security_analysis"] = {
            "security_issues": security_issues,
            "recommendations": recommendations,
            "overall_grade": "CRITICAL" if len(security_issues) >= 3 else "WARNING" if security_issues else "GOOD"
        }
        
        return result
        
    except socket.timeout:
        return {
            "status": "error",
            "message": f"Connection to {hostname}:{port} timed out"
        }
    except socket.gaierror as e:
        return {
            "status": "error",
            "message": f"DNS resolution failed for {hostname}: {str(e)}"
        }
    except ConnectionRefusedError:
        return {
            "status": "error",
            "message": f"Connection refused to {hostname}:{port}"
        }
    except ssl.SSLError as e:
        return {
            "status": "error",
            "message": f"SSL/TLS error: {str(e)}"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Certificate analysis failed: {str(e)}"
        }


@mcp.tool()
def find_subdomains_from_certificates(
    domain: str,
    min_certificate_age_days: int = 0,
    exclude_wildcards: bool = False,
    use_cache: bool = True
) -> Dict[str, Any]:
    """
    Discover subdomains by analyzing certificates from Certificate Transparency logs.
    
    Args:
        domain: Domain to find subdomains for
        min_certificate_age_days: Minimum age of certificates to consider
        exclude_wildcards: Whether to exclude wildcard certificates
        use_cache: Whether to use caching
        
    Returns:
        Dict with discovered subdomains from certificates
    """
    if not _validate_domain(domain):
        return {
            "status": "error",
            "message": "Invalid domain name format"
        }
    
    # Get certificates from CT logs
    ct_result = search_certificate_transparency(
        domain, 
        include_expired=True, 
        max_results=500,  # Get more results for comprehensive subdomain discovery
        use_cache=use_cache
    )
    
    if ct_result.get("status") != "success":
        return ct_result
    
    result = {
        "status": "success",
        "domain": domain,
        "subdomains": [],
        "wildcard_domains": [],
        "subdomain_sources": {},
        "statistics": {}
    }
    
    all_subdomains = set()
    wildcard_domains = set()
    subdomain_sources = {}
    
    # Process certificates to extract subdomains
    for cert in ct_result.get("certificates", []):
        # Check certificate age if specified
        if min_certificate_age_days > 0:
            logged_at = cert.get("logged_at")
            if logged_at:
                try:
                    cert_date = datetime.datetime.fromisoformat(logged_at.replace('Z', '+00:00'))
                    age_days = (datetime.datetime.now(datetime.timezone.utc) - cert_date).days
                    if age_days < min_certificate_age_days:
                        continue
                except:
                    pass
        
        # Extract domains from certificate
        cert_domains = cert.get("domains", [])
        if not cert_domains and cert.get("common_name"):
            cert_domains = [cert.get("common_name")]
        
        for subdomain in cert_domains:
            subdomain = subdomain.lower().strip()
            
            # Check if it's a wildcard
            if subdomain.startswith("*."):
                wildcard_domains.add(subdomain)
                if not exclude_wildcards:
                    # Also add the base domain without wildcard
                    base_domain = subdomain[2:]
                    if base_domain.endswith(f".{domain}") or base_domain == domain:
                        all_subdomains.add(base_domain)
            elif subdomain.endswith(f".{domain}") or subdomain == domain:
                all_subdomains.add(subdomain)
            
            # Track which certificate provided this subdomain
            if subdomain not in subdomain_sources:
                subdomain_sources[subdomain] = []
            
            cert_id = cert.get("id") or cert.get("fingerprint_sha256", "unknown")
            if cert_id not in subdomain_sources[subdomain]:
                subdomain_sources[subdomain].append(cert_id)
    
    # Sort and prepare results
    result["subdomains"] = sorted(list(all_subdomains))
    result["wildcard_domains"] = sorted(list(wildcard_domains))
    result["subdomain_sources"] = subdomain_sources
    
    # Generate statistics
    subdomain_levels = {}
    for subdomain in result["subdomains"]:
        level = subdomain.count('.') - domain.count('.')
        subdomain_levels[level] = subdomain_levels.get(level, 0) + 1
    
    result["statistics"] = {
        "total_subdomains": len(result["subdomains"]),
        "wildcard_certificates": len(result["wildcard_domains"]),
        "subdomain_levels": subdomain_levels,
        "most_common_level": max(subdomain_levels.items(), key=lambda x: x[1])[0] if subdomain_levels else 0
    }
    
    # Categorize subdomains by common patterns
    categories = {
        "mail": ["mail", "smtp", "pop", "imap", "webmail"],
        "web": ["www", "web", "portal", "app"],
        "dev": ["dev", "test", "staging", "beta", "alpha"],
        "admin": ["admin", "panel", "dashboard", "control"],
        "api": ["api", "rest", "graphql", "webhook"],
        "cdn": ["cdn", "static", "assets", "media"],
        "database": ["db", "mysql", "postgres", "mongo"],
        "other": []
    }
    
    categorized = {cat: [] for cat in categories.keys()}
    
    for subdomain in result["subdomains"]:
        parts = subdomain.split('.')
        subdomain_name = parts[0] if parts else subdomain
        
        categorized_flag = False
        for category, keywords in categories.items():
            if category == "other":
                continue
            if any(keyword in subdomain_name.lower() for keyword in keywords):
                categorized[category].append(subdomain)
                categorized_flag = True
                break
        
        if not categorized_flag:
            categorized["other"].append(subdomain)
    
    result["categorized_subdomains"] = {k: v for k, v in categorized.items() if v}
    
    return result


@mcp.tool()
def monitor_certificate_changes(
    domain: str,
    days_lookback: int = 30,
    alert_on_new_subdomains: bool = True,
    use_cache: bool = True
) -> Dict[str, Any]:
    """
    Monitor recent certificate changes for a domain to detect new issuances.
    
    Args:
        domain: Domain to monitor
        days_lookback: Number of days to look back for changes
        alert_on_new_subdomains: Whether to highlight new subdomains
        use_cache: Whether to use caching
        
    Returns:
        Dict with certificate monitoring results
    """
    if not _validate_domain(domain):
        return {
            "status": "error",
            "message": "Invalid domain name format"
        }
    
    # Get recent certificates
    ct_result = search_certificate_transparency(
        domain,
        include_expired=False,
        max_results=200,
        use_cache=use_cache
    )
    
    if ct_result.get("status") != "success":
        return ct_result
    
    result = {
        "status": "success",
        "domain": domain,
        "monitoring_period_days": days_lookback,
        "recent_certificates": [],
        "new_subdomains": [],
        "certificate_authorities": {},
        "alerts": []
    }
    
    # Filter certificates by date
    cutoff_time = time.time() - (days_lookback * 24 * 60 * 60)
    recent_certs = []
    all_recent_domains = set()
    
    for cert in ct_result.get("certificates", []):
        logged_at = cert.get("logged_at")
        if logged_at:
            try:
                # Handle different timestamp formats
                if isinstance(logged_at, str):
                    cert_timestamp = datetime.datetime.fromisoformat(logged_at.replace('Z', '+00:00')).timestamp()
                else:
                    cert_timestamp = float(logged_at) / 1000  # Assuming milliseconds
                
                if cert_timestamp >= cutoff_time:
                    recent_certs.append(cert)
                    
                    # Collect domains from recent certificates
                    cert_domains = cert.get("domains", [])
                    all_recent_domains.update(cert_domains)
                    
                    # Track certificate authorities
                    issuer = cert.get("issuer_name")
                    if issuer:
                        result["certificate_authorities"][issuer] = result["certificate_authorities"].get(issuer, 0) + 1
                        
            except Exception as e:
                logger.warning(f"Date parsing error for certificate: {e}")
                continue
    
    result["recent_certificates"] = recent_certs
    
    # If we want to alert on new subdomains, we need a baseline
    if alert_on_new_subdomains:
        # Get older certificates for comparison (past 90 days)
        baseline_result = search_certificate_transparency(
            domain,
            include_expired=True,
            max_results=500,
            use_cache=use_cache
        )
        
        baseline_domains = set()
        baseline_cutoff = time.time() - (90 * 24 * 60 * 60)  # 90 days ago
        
        for cert in baseline_result.get("certificates", []):
            logged_at = cert.get("logged_at")
            if logged_at:
                try:
                    if isinstance(logged_at, str):
                        cert_timestamp = datetime.datetime.fromisoformat(logged_at.replace('Z', '+00:00')).timestamp()
                    else:
                        cert_timestamp = float(logged_at) / 1000
                    
                    # Only include certificates older than our recent monitoring period
                    if cert_timestamp < cutoff_time and cert_timestamp >= baseline_cutoff:
                        cert_domains = cert.get("domains", [])
                        baseline_domains.update(cert_domains)
                        
                except:
                    continue
        
        # Find new subdomains that weren't in the baseline
        new_subdomains = all_recent_domains - baseline_domains
        result["new_subdomains"] = sorted(list(new_subdomains))
        
        if new_subdomains:
            result["alerts"].append({
                "type": "new_subdomains",
                "severity": "medium",
                "message": f"Found {len(new_subdomains)} new subdomains in the past {days_lookback} days",
                "details": list(new_subdomains)[:10]  # Limit to first 10 for display
            })
    
    # Check for suspicious patterns
    if len(recent_certs) > 10:  # Many certificates issued recently
        result["alerts"].append({
            "type": "high_certificate_volume",
            "severity": "low",
            "message": f"High certificate issuance activity: {len(recent_certs)} certificates in {days_lookback} days"
        })
    
    # Check for unusual certificate authorities
    if result["certificate_authorities"]:
        common_cas = ["Let's Encrypt", "DigiCert", "Sectigo", "GlobalSign", "GoDaddy"]
        unusual_cas = [ca for ca in result["certificate_authorities"].keys() 
                      if not any(common in ca for common in common_cas)]
        
        if unusual_cas:
            result["alerts"].append({
                "type": "unusual_certificate_authority",
                "severity": "low",
                "message": f"Certificates issued by uncommon CAs: {', '.join(unusual_cas[:3])}"
            })
    
    # Summary statistics
    result["summary"] = {
        "total_recent_certificates": len(recent_certs),
        "new_subdomains_count": len(result["new_subdomains"]),
        "certificate_authorities_count": len(result["certificate_authorities"]),
        "alerts_count": len(result["alerts"])
    }
    
    return result


if __name__ == "__main__":
    mcp.run(transport="stdio")