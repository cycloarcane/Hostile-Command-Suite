#!/usr/bin/env python3
"""
duckduckgo_osint.py — DuckDuckGo wrapper with enhanced rate limit handling

FastMCP tool
────────────
    search_duckduckgo_text(query, max_results=20, delay=3, …)

Returns
───────
    {
      "status": "success",
      "backend": "html",
      "query": "...",
      "results": [ {title, href, snippet}, … ],
      "results_markdown": ["1. [Title](url) — snippet", …]
    }
"""

import json
import os
import random
import sys
import time
import hashlib
from typing import Any, Dict, List, Optional

from bs4 import BeautifulSoup
from duckduckgo_search import DDGS
from duckduckgo_search.exceptions import DuckDuckGoSearchException
from fastmcp import FastMCP
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception,
    RetryError,
    before_sleep_log
)

# Define our own rate limit exception in case it's not in the library
class RateLimitException(DuckDuckGoSearchException):
    """Custom exception for rate limiting"""
    pass
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("duckduckgo_osint")

mcp = FastMCP("duckduckgo")          # MCP route → /duckduckgo
_BACKEND = "html"
_LAST_CALL_AT: float = 0.0           # global for simple throttle
_CONSECUTIVE_FAILURES: int = 0       # track consecutive failures for adaptive delay
_MAX_CONSECUTIVE_FAILURES: int = 3   # threshold to increase delay
_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
os.makedirs(_CACHE_DIR, exist_ok=True)

# Create a list of proxy servers to rotate through (replace with your actual proxies)
_PROXY_LIST = [
    # Example format:
    # "socks5://user:pass@proxy1.example.com:1080",
    # "http://user:pass@proxy2.example.com:3128",
    # "tb"  # Alias for Tor Browser (socks5://127.0.0.1:9150)
]

def _adaptive_rate_limit(delay: float) -> None:
    """
    Adaptive rate limiting with progressive backoff based on failure history
    """
    global _LAST_CALL_AT, _CONSECUTIVE_FAILURES
    
    # Increase delay if we've had consecutive failures
    if _CONSECUTIVE_FAILURES >= _MAX_CONSECUTIVE_FAILURES:
        adaptive_delay = delay * (1.5 ** min(_CONSECUTIVE_FAILURES, 5))
        # Add jitter to prevent synchronized retries
        adaptive_delay += random.uniform(0, 1)
    else:
        adaptive_delay = delay
    
    # Calculate wait time
    wait = _LAST_CALL_AT + adaptive_delay - time.time()
    if wait > 0:
        logger.debug(f"Rate limiting: waiting {wait:.2f} seconds")
        time.sleep(wait)
    
    _LAST_CALL_AT = time.time()

def _clean(html_snippet: str) -> str:
    """Clean HTML from snippets"""
    return BeautifulSoup(html_snippet, "html.parser").get_text(" ", strip=True)

def _md(res: Dict[str, str], idx: int) -> str:
    """Format result as markdown"""
    return f"{idx}. [{res['title'] or '(no title)'}]({res['href']}) — {res['snippet']}"

def _get_cache_key(query: str, **kwargs) -> str:
    """Generate a cache key from the query and kwargs"""
    # Filter out non-serializable objects and sort for consistent keys
    serializable_kwargs = {
        k: v for k, v in kwargs.items() 
        if isinstance(v, (str, int, float, bool, type(None)))
    }
    cache_str = f"{query}_{json.dumps(serializable_kwargs, sort_keys=True)}"
    return hashlib.md5(cache_str.encode()).hexdigest()

def _get_from_cache(cache_key: str, max_age: int = 86400) -> Optional[Dict[str, Any]]:
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

def _get_next_proxy() -> Optional[str]:
    """Get the next proxy from rotation"""
    if not _PROXY_LIST:
        return None
    
    return random.choice(_PROXY_LIST)

def _is_rate_limit_error(exception):
    """Check if the exception is a rate limit error"""
    # Look for rate limit indicators in exception message
    error_msg = str(exception).lower()
    return (
        isinstance(exception, DuckDuckGoSearchException) and 
        ("rate" in error_msg or "limit" in error_msg or "429" in error_msg or 
         "202" in error_msg or "403" in error_msg)
    )

# Main search function with tenacity retry
@retry(
    retry=retry_if_exception(_is_rate_limit_error),
    wait=wait_exponential(multiplier=1, min=4, max=60),
    stop=stop_after_attempt(5),
    before_sleep=before_sleep_log(logger, logging.INFO)
)
def _execute_search(
    query: str,
    delay: float = 6.0,
    region: str = "wt-wt",
    safesearch: str = "off",
    timelimit: Optional[str] = None,
    max_results: int = 20,
    proxy: Optional[str] = None,
) -> List[Dict[str, str]]:
    """Execute the actual search with retries"""
    global _CONSECUTIVE_FAILURES
    
    _adaptive_rate_limit(delay)
    
    try:
        with DDGS(proxy=proxy) as ddgs:
            hits_iter = ddgs.text(
                query,
                region=region,
                safesearch=safesearch,
                timelimit=timelimit,
                backend=_BACKEND,
                max_results=max_results,
            )
            raw = list(hits_iter)
        
        # Reset consecutive failures on success
        _CONSECUTIVE_FAILURES = 0
        
        # Clean the results
        cleaned = [
            {
                "title": h.get("title", ""),
                "href": h.get("href", ""),
                "snippet": _clean(h.get("body", "")),
            }
            for h in raw
        ]
        
        return cleaned
        
    except DuckDuckGoSearchException as e:
        # Increment consecutive failures to increase backoff
        _CONSECUTIVE_FAILURES += 1
        error_msg = str(e).lower()
        
        # Check if this is likely a rate limit error
        if "rate" in error_msg or "limit" in error_msg or "202" in error_msg or "403" in error_msg:
            logger.warning(f"Rate limit hit (failure #{_CONSECUTIVE_FAILURES}): {e}")
            # Wrap in our custom exception for the retry mechanism
            raise RateLimitException(f"Rate limit detected: {e}")
        else:
            logger.error(f"DuckDuckGo search error: {e}")
            raise
    
    except Exception as e:
        _CONSECUTIVE_FAILURES += 1
        logger.error(f"Unexpected error: {e}")
        raise

@mcp.tool()
def search_duckduckgo_text(
    query: str,
    max_results: int = 20,
    delay: float = 3.0,  # Increased from 2.0 to 3.0
    region: str = "wt-wt",
    safesearch: str = "moderate",
    timelimit: Optional[str] = None,
    use_cache: bool = True,
    cache_max_age: int = 86400,  # 24 hours in seconds
    use_proxies: bool = False,
) -> Dict[str, Any]:
    """
    Enhanced DuckDuckGo search with caching, proxy rotation, and rate limit handling.
    
    Args:
        query: Search query string
        max_results: Maximum number of results to return
        delay: Minimum delay between requests (seconds)
        region: Region for search results (e.g., "wt-wt", "us-en")
        safesearch: SafeSearch setting ("on", "moderate", "off")
        timelimit: Time limit for results (e.g. "d" for day, "w" for week)
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        use_proxies: Whether to use proxy rotation
    
    Returns:
        Dict with search results and metadata
    """
    # Check cache first if enabled
    if use_cache:
        cache_key = _get_cache_key(
            query, 
            max_results=max_results,
            region=region,
            safesearch=safesearch,
            timelimit=timelimit
        )
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    # Get a proxy if proxy rotation is enabled
    proxy = _get_next_proxy() if use_proxies and _PROXY_LIST else None
    
    try:
        # Attempt the search with retries
        cleaned_results = _execute_search(
            query,
            delay=delay,
            region=region,
            safesearch=safesearch,
            timelimit=timelimit,
            max_results=max_results,
            proxy=proxy,
        )
        
        # Format results
        md_results = [_md(r, i) for i, r in enumerate(cleaned_results, 1)]
        
        result = {
            "status": "success",
            "backend": _BACKEND,
            "query": query,
            "results": cleaned_results,
            "results_markdown": md_results,
        }
        
        # Cache the result if caching is enabled
        if use_cache:
            _save_to_cache(cache_key, result)
        
        return result
        
    except RetryError:
        logger.error(f"All retries failed for query: {query}")
        return {
            "status": "error", 
            "query": query, 
            "message": "Exceeded retry attempts due to rate limiting"
        }
    
    except DuckDuckGoSearchException as e:
        logger.error(f"DuckDuckGo error: {e}")
        return {"status": "error", "query": query, "message": str(e)}
    
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return {"status": "error", "query": query, "message": f"unexpected: {e}"}


# ───────────── CLI helper (optional) ─────────────
def _cli() -> None:
    import argparse

    p = argparse.ArgumentParser(description="DDG HTML search (rate-limited)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("search")
    s.add_argument("query")
    s.add_argument("--max", type=int, default=20)
    s.add_argument("--delay", type=float, default=3.0)
    s.add_argument("--region", default="wt-wt")
    s.add_argument("--safesearch", choices=["off", "moderate", "on"], default="moderate")
    s.add_argument("--timelimit", choices=["d", "w", "m", "y"], default=None)
    s.add_argument("--no-cache", action="store_true", help="Disable caching")
    s.add_argument("--use-proxies", action="store_true", help="Enable proxy rotation")

    sub.add_parser("check")

    args = p.parse_args()
    if args.cmd == "check":
        out = {"status": "ok", "message": "duckduckgo_osint ready"}
    else:
        out = search_duckduckgo_text(
            args.query,
            max_results=args.max,
            delay=args.delay,
            region=args.region,
            safesearch=args.safesearch,
            timelimit=args.timelimit,
            use_cache=not args.no_cache,
            use_proxies=args.use_proxies,
        )

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in {"search", "check"}:
        _cli()
    else:
        mcp.run(transport="stdio")