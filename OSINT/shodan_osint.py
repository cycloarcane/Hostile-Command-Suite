#!/usr/bin/env python3
"""
shodan_osint.py — FastMCP tool that performs IoT/device discovery using Shodan

FastMCP tools
────────────
    search_shodan(query, max_results=100, ...)
    get_host_info(ip_address, ...)
    search_facets(query, facets=["country", "org"], ...)

Returns
───────
    {
      "status": "success",
      "query": "...",
      "results": [...],
      "total": 12345,
      "facets": {...}
    }

Setup
─────
    1. Create a Shodan account at: https://www.shodan.io/
    2. Get your API key from: https://account.shodan.io/
    3. Set the SHODAN_API_KEY environment variable
       or pass via --api-key parameter
"""

import json
import os
import sys
import time
import hashlib
import logging
from typing import Any, Dict, List, Optional, Union
import requests
from fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("shodan_osint")

mcp = FastMCP("shodan")  # MCP route → /shodan
_LAST_CALL_AT: float = 0.0  # Global for rate throttle
_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
os.makedirs(_CACHE_DIR, exist_ok=True)

# Shodan API configuration
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
SHODAN_BASE_URL = "https://api.shodan.io"

# Default rate limit - Shodan allows 1 request per second for free accounts
DEFAULT_RATE_LIMIT = 1.0  # Requests per second


def _rate_limit(calls_per_second: float = DEFAULT_RATE_LIMIT) -> None:
    """
    Limit API calls to respect Shodan's rate limits
    
    Args:
        calls_per_second: Maximum calls per second allowed
    """
    global _LAST_CALL_AT
    
    # Calculate minimum time between calls
    min_interval = 1.0 / calls_per_second
    
    # Calculate wait time
    wait = _LAST_CALL_AT + min_interval - time.time()
    if wait > 0:
        logger.debug(f"Rate limiting: waiting {wait:.2f} seconds")
        time.sleep(wait)
    
    _LAST_CALL_AT = time.time()


def _get_cache_key(endpoint: str, **kwargs) -> str:
    """Generate a cache key from the endpoint and kwargs"""
    # Filter out non-serializable objects and sort for consistent keys
    serializable_kwargs = {
        k: v for k, v in kwargs.items() 
        if isinstance(v, (str, int, float, bool, type(None)))
    }
    cache_str = f"{endpoint}_{json.dumps(serializable_kwargs, sort_keys=True)}"
    return hashlib.md5(cache_str.encode()).hexdigest()


def _get_from_cache(cache_key: str, max_age: int = 3600) -> Optional[Dict[str, Any]]:
    """Try to get results from cache, return None if not found or expired"""
    cache_file = os.path.join(_CACHE_DIR, f"{cache_key}.json")
    
    if os.path.exists(cache_file):
        file_age = time.time() - os.path.getmtime(cache_file)
        if file_age < max_age:
            try:
                with open(cache_file, 'r') as f:
                    logger.info(f"Cache hit for {cache_key}")
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Cache read error: {e}")
    
    return None


def _save_to_cache(cache_key: str, data: Dict[str, Any]) -> None:
    """Save results to cache"""
    cache_file = os.path.join(_CACHE_DIR, f"{cache_key}.json")
    try:
        with open(cache_file, 'w') as f:
            json.dump(data, f)
        logger.debug(f"Saved to cache: {cache_key}")
    except IOError as e:
        logger.warning(f"Cache write error: {e}")


def _make_shodan_request(endpoint: str, params: Dict[str, Any], api_key: str) -> Dict[str, Any]:
    """
    Make a request to the Shodan API
    
    Args:
        endpoint: API endpoint to call
        params: Query parameters
        api_key: Shodan API key
        
    Returns:
        Dict with API response
    """
    _rate_limit()
    
    # Add API key to params
    params['key'] = api_key
    
    url = f"{SHODAN_BASE_URL}/{endpoint}"
    
    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        if response.status_code == 401:
            raise ValueError("Invalid Shodan API key or quota exceeded") from e
        elif response.status_code == 404:
            raise ValueError("Resource not found") from e
        else:
            logger.error(f"HTTP error: {e}")
            raise
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {e}")
        raise


@mcp.tool()
def check_shodan_installation() -> Dict[str, str]:
    """
    Check if Shodan API is configured and return information about it.
    
    Returns:
        A dictionary with configuration status and API info if available
    """
    if not SHODAN_API_KEY:
        return {
            "status": "not_configured",
            "message": "No Shodan API key found. Set SHODAN_API_KEY environment variable or pass api_key parameter."
        }
    
    try:
        # Test API key by getting account info
        response = _make_shodan_request("api-info", {}, SHODAN_API_KEY)
        
        return {
            "status": "configured",
            "plan": response.get("plan", "unknown"),
            "query_credits": response.get("query_credits", 0),
            "scan_credits": response.get("scan_credits", 0),
            "message": "Shodan API is configured and ready to use."
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error checking Shodan API: {str(e)}"
        }


@mcp.tool()
def search_shodan(
    query: str,
    max_results: int = 100,
    api_key: Optional[str] = None,
    use_cache: bool = True,
    cache_max_age: int = 3600,  # 1 hour in seconds
    facets: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Search Shodan for devices and services.
    
    Args:
        query: Shodan search query (e.g., "apache", "port:22", "country:US")
        max_results: Maximum number of results to return
        api_key: Shodan API key (overrides environment variable)
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        facets: List of facets to include (e.g., ["country", "org", "port"])
        
    Returns:
        Dict with search results and metadata
    """
    # Use provided API key or fall back to environment variable
    shodan_api_key = api_key or SHODAN_API_KEY
    
    if not shodan_api_key:
        return {
            "status": "error",
            "message": "No Shodan API key provided. Set SHODAN_API_KEY environment variable or pass api_key parameter."
        }
    
    # Check cache first if enabled
    if use_cache:
        cache_key = _get_cache_key(
            "search", 
            query=query,
            max_results=max_results,
            facets=facets
        )
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    try:
        # Prepare search parameters
        params = {
            "q": query,
            "limit": min(max_results, 100)  # Shodan API limit is 100 per request
        }
        
        # Add facets if provided
        if facets:
            params["facets"] = ",".join(facets)
        
        # Execute the search
        response = _make_shodan_request("shodan/host/search", params, shodan_api_key)
        
        # Extract results
        results = response.get("matches", [])
        
        # Process results to extract key information
        processed_results = []
        for result in results:
            processed_result = {
                "ip": result.get("ip_str", ""),
                "port": result.get("port", 0),
                "organization": result.get("org", ""),
                "location": {
                    "country": result.get("location", {}).get("country_name", ""),
                    "city": result.get("location", {}).get("city", ""),
                    "latitude": result.get("location", {}).get("latitude"),
                    "longitude": result.get("location", {}).get("longitude")
                },
                "hostnames": result.get("hostnames", []),
                "domains": result.get("domains", []),
                "timestamp": result.get("timestamp", ""),
                "product": result.get("product", ""),
                "version": result.get("version", ""),
                "os": result.get("os", ""),
                "banner": result.get("data", "")[:500],  # Truncate banner for display
                "vulnerabilities": result.get("vulns", []),
                "tags": result.get("tags", [])
            }
            processed_results.append(processed_result)
        
        # Build final result
        result = {
            "status": "success",
            "query": query,
            "results": processed_results,
            "total": response.get("total", 0),
            "facets": response.get("facets", {}),
            "result_count": len(processed_results)
        }
        
        # Cache the result if caching is enabled
        if use_cache:
            _save_to_cache(cache_key, result)
        
        return result
        
    except ValueError as e:
        # Handle API key and quota errors
        return {"status": "error", "query": query, "message": str(e)}
    
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return {"status": "error", "query": query, "message": f"unexpected: {e}"}


@mcp.tool()
def get_host_info(
    ip_address: str,
    api_key: Optional[str] = None,
    use_cache: bool = True,
    cache_max_age: int = 3600,
    history: bool = False
) -> Dict[str, Any]:
    """
    Get detailed information about a specific host/IP address.
    
    Args:
        ip_address: IP address to look up
        api_key: Shodan API key (overrides environment variable)
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        history: Whether to include historical data
        
    Returns:
        Dict with host information
    """
    # Use provided API key or fall back to environment variable
    shodan_api_key = api_key or SHODAN_API_KEY
    
    if not shodan_api_key:
        return {
            "status": "error",
            "message": "No Shodan API key provided. Set SHODAN_API_KEY environment variable or pass api_key parameter."
        }
    
    # Check cache first if enabled
    if use_cache:
        cache_key = _get_cache_key(
            "host", 
            ip_address=ip_address,
            history=history
        )
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    try:
        # Prepare parameters
        params = {}
        if history:
            params["history"] = "true"
        
        # Execute the lookup
        response = _make_shodan_request(f"shodan/host/{ip_address}", params, shodan_api_key)
        
        # Process the response
        result = {
            "status": "success",
            "ip_address": ip_address,
            "hostnames": response.get("hostnames", []),
            "organization": response.get("org", ""),
            "isp": response.get("isp", ""),
            "asn": response.get("asn", ""),
            "location": {
                "country": response.get("country_name", ""),
                "region": response.get("region_code", ""),
                "city": response.get("city", ""),
                "latitude": response.get("latitude"),
                "longitude": response.get("longitude"),
                "postal_code": response.get("postal_code", "")
            },
            "os": response.get("os", ""),
            "tags": response.get("tags", []),
            "vulnerabilities": list(response.get("vulns", [])),
            "last_update": response.get("last_update", ""),
            "ports": response.get("ports", []),
            "services": []
        }
        
        # Process service data
        for service in response.get("data", []):
            service_info = {
                "port": service.get("port", 0),
                "protocol": service.get("transport", ""),
                "product": service.get("product", ""),
                "version": service.get("version", ""),
                "timestamp": service.get("timestamp", ""),
                "banner": service.get("data", "")[:500],  # Truncate banner
                "ssl": service.get("ssl", {}),
                "http": service.get("http", {})
            }
            result["services"].append(service_info)
        
        # Cache the result if caching is enabled
        if use_cache:
            _save_to_cache(cache_key, result)
        
        return result
        
    except ValueError as e:
        # Handle API key and quota errors
        return {"status": "error", "ip_address": ip_address, "message": str(e)}
    
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return {"status": "error", "ip_address": ip_address, "message": f"unexpected: {e}"}


@mcp.tool()
def search_facets(
    query: str,
    facets: List[str] = ["country", "org", "port"],
    api_key: Optional[str] = None,
    use_cache: bool = True,
    cache_max_age: int = 3600
) -> Dict[str, Any]:
    """
    Get faceted search results from Shodan to understand data distribution.
    
    Args:
        query: Shodan search query
        facets: List of facets to analyze (e.g., ["country", "org", "port", "product"])
        api_key: Shodan API key (overrides environment variable)
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with faceted analysis results
    """
    # Use provided API key or fall back to environment variable
    shodan_api_key = api_key or SHODAN_API_KEY
    
    if not shodan_api_key:
        return {
            "status": "error",
            "message": "No Shodan API key provided. Set SHODAN_API_KEY environment variable or pass api_key parameter."
        }
    
    # Check cache first if enabled
    if use_cache:
        cache_key = _get_cache_key(
            "search_facets", 
            query=query,
            facets=facets
        )
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    try:
        # Prepare search parameters
        params = {
            "q": query,
            "facets": ",".join(facets),
            "limit": 1  # We only want facet data, not individual results
        }
        
        # Execute the search
        response = _make_shodan_request("shodan/host/search", params, shodan_api_key)
        
        # Build result focusing on facets
        result = {
            "status": "success",
            "query": query,
            "total": response.get("total", 0),
            "facets": response.get("facets", {}),
            "facet_analysis": {}
        }
        
        # Process facets for easier analysis
        for facet_name, facet_data in response.get("facets", {}).items():
            result["facet_analysis"][facet_name] = [
                {"value": item["value"], "count": item["count"]}
                for item in facet_data
            ]
        
        # Cache the result if caching is enabled
        if use_cache:
            _save_to_cache(cache_key, result)
        
        return result
        
    except ValueError as e:
        # Handle API key and quota errors
        return {"status": "error", "query": query, "message": str(e)}
    
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return {"status": "error", "query": query, "message": f"unexpected: {e}"}


@mcp.tool()
def get_my_ip() -> Dict[str, Any]:
    """
    Get your current public IP address as seen by Shodan.
    
    Returns:
        Dict with your public IP information
    """
    try:
        response = requests.get(f"{SHODAN_BASE_URL}/tools/myip", timeout=10)
        response.raise_for_status()
        ip_address = response.text.strip()
        
        return {
            "status": "success",
            "ip_address": ip_address,
            "message": f"Your public IP address is: {ip_address}"
        }
        
    except Exception as e:
        logger.error(f"Error getting IP: {e}")
        return {"status": "error", "message": f"Error getting IP: {e}"}


if __name__ == "__main__":
    mcp.run(transport="stdio")