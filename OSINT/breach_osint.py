#!/usr/bin/env python3
"""
breach_osint.py — FastMCP tool for checking data breaches and exposed credentials

FastMCP tools
────────────
    check_hibp_breaches(email, ...)
    check_hibp_pastes(email, ...)
    check_dehashed(email, api_key=None, ...)
    search_leaked_passwords(password_hash, ...)

Returns
───────
    {
      "status": "success",
      "email": "user@example.com",
      "breaches": [...],
      "pastes": [...],
      "total_breaches": 5,
      "severity_analysis": {...}
    }

Dependencies
────────────
    pip install requests hashlib

Setup
─────
    For Have I Been Pwned API (recommended):
    1. Get API key from https://haveibeenpwned.com/API/Key
    2. Set HIBP_API_KEY environment variable
    
    For DeHashed API (optional):
    1. Get API key from https://dehashed.com/
    2. Set DEHASHED_API_KEY environment variable
"""

import json
import os
import sys
import time
import logging
import hashlib
from typing import Any, Dict, List, Optional, Union
import re

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
logger = logging.getLogger("breach_osint")

mcp = FastMCP("breach")  # MCP route → /breach
_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
os.makedirs(_CACHE_DIR, exist_ok=True)

# API configuration
HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "")
DEHASHED_API_KEY = os.environ.get("DEHASHED_API_KEY", "")
HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
DEHASHED_BASE_URL = "https://api.dehashed.com/search"

# Rate limiting
_LAST_CALL_AT: float = 0.0
DEFAULT_RATE_LIMIT = 0.1  # 10 requests per second (HIBP allows more with API key)


def _rate_limit(calls_per_second: float = DEFAULT_RATE_LIMIT) -> None:
    """Rate limiting for breach APIs"""
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


def _validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def _calculate_severity(breaches: List[Dict]) -> Dict[str, Any]:
    """Calculate severity analysis from breach data"""
    if not breaches:
        return {"level": "none", "score": 0, "description": "No breaches found"}
    
    severity_score = 0
    sensitive_categories = ["passwords", "payment cards", "social security numbers", "passports"]
    recent_threshold = time.time() - (365 * 24 * 60 * 60)  # 1 year ago
    
    recent_breaches = 0
    sensitive_breaches = 0
    total_records = 0
    
    for breach in breaches:
        # Add base score for each breach
        severity_score += 10
        
        # Check if breach is recent
        breach_date = breach.get("BreachDate", "")
        if breach_date:
            try:
                breach_timestamp = time.mktime(time.strptime(breach_date, "%Y-%m-%d"))
                if breach_timestamp > recent_threshold:
                    recent_breaches += 1
                    severity_score += 15
            except:
                pass
        
        # Check for sensitive data types
        data_classes = breach.get("DataClasses", [])
        for data_class in data_classes:
            if any(cat in data_class.lower() for cat in sensitive_categories):
                sensitive_breaches += 1
                severity_score += 20
                break
        
        # Add score based on breach size
        pwn_count = breach.get("PwnCount", 0)
        total_records += pwn_count
        if pwn_count > 1000000:  # Large breach
            severity_score += 25
        elif pwn_count > 100000:  # Medium breach
            severity_score += 15
    
    # Determine severity level
    if severity_score >= 100:
        level = "critical"
        description = "Multiple breaches with sensitive data and/or recent incidents"
    elif severity_score >= 60:
        level = "high"
        description = "Several breaches or breaches containing sensitive information"
    elif severity_score >= 30:
        level = "medium"
        description = "Some breaches found, monitor for credential reuse"
    elif severity_score > 0:
        level = "low"
        description = "Few breaches found, consider password changes"
    else:
        level = "none"
        description = "No breaches found"
    
    return {
        "level": level,
        "score": severity_score,
        "description": description,
        "recent_breaches": recent_breaches,
        "sensitive_breaches": sensitive_breaches,
        "total_breaches": len(breaches),
        "total_records": total_records
    }


@mcp.tool()
def check_breach_tools() -> Dict[str, Union[str, Dict[str, bool]]]:
    """
    Check which breach checking tools and dependencies are available.
    
    Returns:
        A dictionary with tool availability status
    """
    deps = {
        "requests": REQUESTS_AVAILABLE,
        "hibp_api_key": bool(HIBP_API_KEY),
        "dehashed_api_key": bool(DEHASHED_API_KEY)
    }
    
    missing = []
    if not deps["requests"]:
        missing.append("requests: pip install requests")
    if not deps["hibp_api_key"]:
        missing.append("HIBP API key: Get from https://haveibeenpwned.com/API/Key")
    
    return {
        "status": "ok" if deps["requests"] else "missing_dependencies",
        "dependencies": deps,
        "installation_instructions": missing,
        "notes": {
            "hibp_free": "HIBP can be used without API key but with rate limits",
            "dehashed_optional": "DeHashed API is optional for enhanced results"
        }
    }


@mcp.tool()
def check_hibp_breaches(
    email: str,
    api_key: Optional[str] = None,
    use_cache: bool = True,
    cache_max_age: int = 3600,  # 1 hour
    include_unverified: bool = False
) -> Dict[str, Any]:
    """
    Check Have I Been Pwned for breaches containing the email address.
    
    Args:
        email: Email address to check
        api_key: HIBP API key (overrides environment variable)
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        include_unverified: Whether to include unverified breaches
        
    Returns:
        Dict with breach information
    """
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    if not _validate_email(email):
        return {
            "status": "error",
            "message": "Invalid email address format"
        }
    
    # Check cache
    if use_cache:
        cache_key = _get_cache_key("hibp_breaches", email=email, include_unverified=include_unverified)
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    # Use provided API key or fall back to environment variable
    hibp_api_key = api_key or HIBP_API_KEY
    
    headers = {
        "User-Agent": "OSINT-Breach-Checker"
    }
    
    if hibp_api_key:
        headers["hibp-api-key"] = hibp_api_key
    
    try:
        _rate_limit(1.0 if hibp_api_key else 0.2)  # Higher rate limit with API key
        
        url = f"{HIBP_BASE_URL}/breachedaccount/{email}"
        params = {}
        if not include_unverified:
            params["truncateResponse"] = "false"
        
        response = requests.get(url, headers=headers, params=params, timeout=15)
        
        if response.status_code == 404:
            # No breaches found
            result = {
                "status": "success",
                "email": email,
                "breaches": [],
                "total_breaches": 0,
                "severity_analysis": _calculate_severity([])
            }
        elif response.status_code == 200:
            breaches = response.json()
            
            result = {
                "status": "success",
                "email": email,
                "breaches": breaches,
                "total_breaches": len(breaches),
                "severity_analysis": _calculate_severity(breaches)
            }
        elif response.status_code == 429:
            return {
                "status": "error",
                "message": "Rate limit exceeded. Consider getting an API key from HIBP."
            }
        elif response.status_code == 401:
            return {
                "status": "error",
                "message": "Invalid API key or API key required for this request."
            }
        else:
            return {
                "status": "error",
                "message": f"HIBP API error: HTTP {response.status_code}"
            }
        
        # Cache successful results
        if use_cache:
            _save_to_cache(cache_key, result)
        
        return result
        
    except requests.exceptions.RequestException as e:
        return {
            "status": "error",
            "message": f"Request failed: {str(e)}"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Unexpected error: {str(e)}"
        }


@mcp.tool()
def check_hibp_pastes(
    email: str,
    api_key: Optional[str] = None,
    use_cache: bool = True,
    cache_max_age: int = 3600
) -> Dict[str, Any]:
    """
    Check Have I Been Pwned for pastes containing the email address.
    
    Args:
        email: Email address to check
        api_key: HIBP API key (overrides environment variable)
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with paste information
    """
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    if not _validate_email(email):
        return {
            "status": "error",
            "message": "Invalid email address format"
        }
    
    # HIBP requires API key for paste searches
    hibp_api_key = api_key or HIBP_API_KEY
    if not hibp_api_key:
        return {
            "status": "error",
            "message": "HIBP API key required for paste searches. Get one from https://haveibeenpwned.com/API/Key"
        }
    
    # Check cache
    if use_cache:
        cache_key = _get_cache_key("hibp_pastes", email=email)
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    headers = {
        "User-Agent": "OSINT-Breach-Checker",
        "hibp-api-key": hibp_api_key
    }
    
    try:
        _rate_limit()
        
        url = f"{HIBP_BASE_URL}/pasteaccount/{email}"
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 404:
            # No pastes found
            result = {
                "status": "success",
                "email": email,
                "pastes": [],
                "total_pastes": 0
            }
        elif response.status_code == 200:
            pastes = response.json()
            
            # Process paste data
            processed_pastes = []
            for paste in pastes:
                processed_paste = {
                    "source": paste.get("Source"),
                    "id": paste.get("Id"),
                    "title": paste.get("Title"),
                    "date": paste.get("Date"),
                    "email_count": paste.get("EmailCount", 0)
                }
                processed_pastes.append(processed_paste)
            
            result = {
                "status": "success",
                "email": email,
                "pastes": processed_pastes,
                "total_pastes": len(processed_pastes)
            }
        elif response.status_code == 429:
            return {
                "status": "error",
                "message": "Rate limit exceeded."
            }
        elif response.status_code == 401:
            return {
                "status": "error",
                "message": "Invalid API key."
            }
        else:
            return {
                "status": "error",
                "message": f"HIBP API error: HTTP {response.status_code}"
            }
        
        # Cache successful results
        if use_cache:
            _save_to_cache(cache_key, result)
        
        return result
        
    except requests.exceptions.RequestException as e:
        return {
            "status": "error",
            "message": f"Request failed: {str(e)}"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Unexpected error: {str(e)}"
        }


@mcp.tool()
def check_password_pwned(
    password: str,
    use_k_anonymity: bool = True
) -> Dict[str, Any]:
    """
    Check if a password has been compromised using HIBP Pwned Passwords.
    Uses k-anonymity to protect the password being checked.
    
    Args:
        password: Password to check
        use_k_anonymity: Whether to use k-anonymity (recommended)
        
    Returns:
        Dict with password compromise information
    """
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    if not password or len(password) < 1:
        return {
            "status": "error",
            "message": "Password cannot be empty"
        }
    
    try:
        # Calculate SHA-1 hash of password
        password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        
        if use_k_anonymity:
            # Use k-anonymity: send only first 5 chars of hash
            hash_prefix = password_hash[:5]
            hash_suffix = password_hash[5:]
            
            _rate_limit()
            
            url = f"https://api.pwnedpasswords.com/range/{hash_prefix}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            # Parse response to find our hash
            found_count = 0
            for line in response.text.splitlines():
                suffix, count = line.split(':')
                if suffix == hash_suffix:
                    found_count = int(count)
                    break
            
            result = {
                "status": "success",
                "password_compromised": found_count > 0,
                "compromise_count": found_count,
                "hash_prefix": hash_prefix,
                "recommendation": "Change password immediately" if found_count > 0 else "Password appears safe"
            }
            
            if found_count > 0:
                if found_count > 100000:
                    result["severity"] = "critical"
                elif found_count > 10000:
                    result["severity"] = "high"
                elif found_count > 1000:
                    result["severity"] = "medium"
                else:
                    result["severity"] = "low"
            else:
                result["severity"] = "none"
            
            return result
        
        else:
            # Direct hash lookup (not recommended for production)
            logger.warning("Using direct hash lookup - k-anonymity is safer")
            
            _rate_limit()
            
            url = f"https://api.pwnedpasswords.com/pwnedpassword/{password_hash}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                count = int(response.text)
                return {
                    "status": "success",
                    "password_compromised": True,
                    "compromise_count": count,
                    "full_hash": password_hash,
                    "severity": "high" if count > 1000 else "medium",
                    "recommendation": "Change password immediately"
                }
            elif response.status_code == 404:
                return {
                    "status": "success",
                    "password_compromised": False,
                    "compromise_count": 0,
                    "full_hash": password_hash,
                    "severity": "none",
                    "recommendation": "Password appears safe"
                }
            else:
                return {
                    "status": "error",
                    "message": f"API error: HTTP {response.status_code}"
                }
        
    except requests.exceptions.RequestException as e:
        return {
            "status": "error",
            "message": f"Request failed: {str(e)}"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Unexpected error: {str(e)}"
        }


@mcp.tool()
def comprehensive_breach_check(
    email: str,
    check_pastes: bool = True,
    api_key: Optional[str] = None,
    use_cache: bool = True
) -> Dict[str, Any]:
    """
    Perform a comprehensive breach check including breaches and pastes.
    
    Args:
        email: Email address to check
        check_pastes: Whether to check for pastes (requires API key)
        api_key: HIBP API key (overrides environment variable)
        use_cache: Whether to use caching
        
    Returns:
        Dict with comprehensive breach information
    """
    if not _validate_email(email):
        return {
            "status": "error",
            "message": "Invalid email address format"
        }
    
    result = {
        "status": "success",
        "email": email,
        "timestamp": time.time(),
        "breach_check": {},
        "paste_check": {},
        "overall_assessment": {}
    }
    
    # Check breaches
    logger.info(f"Checking breaches for {email}")
    breach_result = check_hibp_breaches(email, api_key=api_key, use_cache=use_cache)
    result["breach_check"] = breach_result
    
    # Check pastes if requested and API key available
    if check_pastes and (api_key or HIBP_API_KEY):
        logger.info(f"Checking pastes for {email}")
        paste_result = check_hibp_pastes(email, api_key=api_key, use_cache=use_cache)
        result["paste_check"] = paste_result
    else:
        result["paste_check"] = {
            "status": "skipped",
            "message": "Paste check skipped (requires API key)" if not (api_key or HIBP_API_KEY) else "Paste check disabled"
        }
    
    # Generate overall assessment
    total_breaches = 0
    total_pastes = 0
    severity_score = 0
    
    if breach_result.get("status") == "success":
        total_breaches = breach_result.get("total_breaches", 0)
        severity_analysis = breach_result.get("severity_analysis", {})
        severity_score += severity_analysis.get("score", 0)
    
    if result["paste_check"].get("status") == "success":
        total_pastes = result["paste_check"].get("total_pastes", 0)
        # Add score for pastes
        severity_score += total_pastes * 5
    
    # Determine overall risk level
    if severity_score >= 100:
        risk_level = "critical"
        recommendations = [
            "Change all passwords immediately",
            "Enable 2FA on all accounts",
            "Monitor credit reports",
            "Consider identity protection services"
        ]
    elif severity_score >= 60:
        risk_level = "high"
        recommendations = [
            "Change passwords for affected services",
            "Enable 2FA where possible",
            "Monitor accounts for suspicious activity"
        ]
    elif severity_score >= 30:
        risk_level = "medium"
        recommendations = [
            "Consider changing passwords",
            "Enable 2FA for important accounts",
            "Regular account monitoring"
        ]
    elif severity_score > 0:
        risk_level = "low"
        recommendations = [
            "Consider password updates as precaution",
            "Enable 2FA for enhanced security"
        ]
    else:
        risk_level = "minimal"
        recommendations = [
            "Continue good security practices",
            "Regular password updates recommended"
        ]
    
    result["overall_assessment"] = {
        "risk_level": risk_level,
        "severity_score": severity_score,
        "total_breaches": total_breaches,
        "total_pastes": total_pastes,
        "recommendations": recommendations,
        "summary": f"Found in {total_breaches} breaches and {total_pastes} pastes"
    }
    
    return result


@mcp.tool()
def check_domain_breaches(
    domain: str,
    api_key: Optional[str] = None,
    use_cache: bool = True,
    cache_max_age: int = 86400  # 24 hours
) -> Dict[str, Any]:
    """
    Check for breaches affecting a specific domain.
    
    Args:
        domain: Domain to check for breaches
        api_key: HIBP API key (overrides environment variable)
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with domain breach information
    """
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    if not domain or "." not in domain:
        return {
            "status": "error",
            "message": "Invalid domain format"
        }
    
    # Clean domain
    domain = domain.lower().strip()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("//")[1]
    if "/" in domain:
        domain = domain.split("/")[0]
    
    # Check cache
    if use_cache:
        cache_key = _get_cache_key("domain_breaches", domain=domain)
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    hibp_api_key = api_key or HIBP_API_KEY
    if not hibp_api_key:
        return {
            "status": "error",
            "message": "HIBP API key required for domain searches. Get one from https://haveibeenpwned.com/API/Key"
        }
    
    headers = {
        "User-Agent": "OSINT-Breach-Checker",
        "hibp-api-key": hibp_api_key
    }
    
    try:
        _rate_limit()
        
        url = f"{HIBP_BASE_URL}/breaches"
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        all_breaches = response.json()
        
        # Filter breaches that affect the domain
        domain_breaches = []
        for breach in all_breaches:
            breach_domain = breach.get("Domain", "").lower()
            if domain in breach_domain or breach_domain in domain:
                domain_breaches.append(breach)
        
        result = {
            "status": "success",
            "domain": domain,
            "breaches": domain_breaches,
            "total_breaches": len(domain_breaches),
            "severity_analysis": _calculate_severity(domain_breaches)
        }
        
        # Cache successful results
        if use_cache:
            _save_to_cache(cache_key, result)
        
        return result
        
    except requests.exceptions.RequestException as e:
        return {
            "status": "error",
            "message": f"Request failed: {str(e)}"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Unexpected error: {str(e)}"
        }


if __name__ == "__main__":
    mcp.run(transport="stdio")