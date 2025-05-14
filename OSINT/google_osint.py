#!/usr/bin/env python3
"""
google_osint.py — Google Custom Search API wrapper with caching, pagination,
and relevance ranking

FastMCP tools
────────────
    search_google_text(query, max_results=50, …)
    search_with_relevance(query, max_results=50, relevance_keywords=None, …)

Returns
───────
    {
      "status": "success",
      "query": "...",
      "results": [ {title, url, snippet}, … ],
      "results_markdown": ["1. [Title](url) — snippet", …]
    }

Setup
─────
    1. Create a Google Custom Search Engine at: https://programmablesearchengine.google.com/
    2. Create a Google API key at: https://console.developers.google.com/
    3. Set the GOOGLE_SEARCH_API_KEY and GOOGLE_SEARCH_CX environment variables
       or pass via --api-key and --cx parameters
"""

import json
import os
import sys
import time
import hashlib
import argparse
import re
from typing import Any, Dict, List, Optional
import logging
import requests
from fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("google_osint")

mcp = FastMCP("google")  # MCP route → /google
_LAST_CALL_AT: float = 0.0  # Global for rate throttle
_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
os.makedirs(_CACHE_DIR, exist_ok=True)

# Google Custom Search API configuration
GOOGLE_API_KEY = os.environ.get("GOOGLE_SEARCH_API_KEY", "")
GOOGLE_SEARCH_CX = os.environ.get("GOOGLE_SEARCH_CX", "")
GOOGLE_ENDPOINT = "https://www.googleapis.com/customsearch/v1"

# Default rate limit - Google allows 100 search queries per day for free
# This translates to roughly 1 request per 15 minutes if evenly distributed
# However, we'll use a more reasonable limit for bursts of activity
DEFAULT_RATE_LIMIT = 0.2  # Requests per second (1 every 5 seconds)


def _rate_limit(calls_per_second: float = DEFAULT_RATE_LIMIT) -> None:
    """
    Limit API calls to respect Google's rate limits
    
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


def _md(res: Dict[str, str], idx: int) -> str:
    """Format result as markdown"""
    return f"{idx}. [{res['title']}]({res['url']}) — {res['snippet']}"


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


def _execute_google_search(
    query: str,
    api_key: str,
    cx: str,
    start: int = 1,
    num: int = 10,
    safe: str = "off",
    date_restrict: Optional[str] = None,
    filter: str = "1",
    gl: Optional[str] = None,
    lr: Optional[str] = None,
    rights: Optional[str] = None,
    site_search: Optional[str] = None,
    file_type: Optional[str] = None,
    search_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute a Google Custom Search API call
    
    Args:
        query: Search query
        api_key: Google API key
        cx: Google Custom Search Engine ID
        start: Start index for pagination (1-based)
        num: Number of results to return (max 10)
        safe: SafeSearch setting (off, medium, high)
        date_restrict: Date restriction (e.g., "d7" for last week)
        filter: Enable/disable duplicate content filter (0=off, 1=on)
        gl: Geolocation - country code (e.g., "us")
        lr: Language restriction (e.g., "lang_en")
        rights: Filter by license (e.g., "cc_publicdomain")
        site_search: Restrict to specific site (e.g., "example.com")
        file_type: Filter by file type (e.g., "pdf")
        search_type: Type of search (e.g., "image")
    
    Returns:
        Dict with search results
    """
    # Apply rate limiting
    _rate_limit()
    
    # Build parameters
    params = {
        "key": api_key,
        "cx": cx,
        "q": query,
        "start": start,
        "num": min(num, 10),  # API limit is 10 results per page
        "safe": safe,
        "filter": filter,
    }
    
    # Add optional parameters if provided
    if date_restrict:
        params["dateRestrict"] = date_restrict
    if gl:
        params["gl"] = gl
    if lr:
        params["lr"] = lr
    if rights:
        params["rights"] = rights
    if site_search:
        params["siteSearch"] = site_search
    if file_type:
        params["fileType"] = file_type
    if search_type:
        params["searchType"] = search_type
    
    # Make the request
    try:
        response = requests.get(GOOGLE_ENDPOINT, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        if response.status_code == 403:
            logger.error("Authentication error: Invalid API key or quota exceeded")
            raise ValueError("Invalid Google API key or quota exceeded") from e
        else:
            logger.error(f"HTTP error: {e}")
            raise
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {e}")
        raise


def score_relevance(result: Dict[str, str], keywords: List[str]) -> float:
    """
    Score a search result based on relevance to keywords.
    
    Args:
        result: Search result dictionary
        keywords: List of keywords to score against
        
    Returns:
        Relevance score (higher is more relevant)
    """
    score = 0.0
    
    # Get the text content to score
    title = result.get("title", "").lower()
    snippet = result.get("snippet", "").lower()
    url = result.get("url", "").lower()
    
    # Score based on keyword presence
    for keyword in keywords:
        # Title matches are most important
        if keyword in title:
            score += 3.0
        
        # Snippet matches are next
        if keyword in snippet:
            score += 1.5
        
        # URL matches suggest relevance too
        if keyword in url:
            score += 1.0
    
    # Bonus for https (security)
    if url.startswith("https"):
        score += 0.5
    
    # Penalty for very generic or too short snippets
    if len(snippet) < 20:
        score -= 1.0
    
    # Bonus for specific file types that might have more complete information
    if url.endswith(('.pdf', '.doc', '.docx', '.ppt', '.pptx')):
        score += 0.5
        
    # Bonus for likely high-authority domains
    if url.endswith(('.edu', '.gov', '.org')):
        score += 1.0
    
    return score


@mcp.tool()
def search_google_text(
    query: str,
    max_results: int = 50,
    safe: str = "off",
    date_restrict: Optional[str] = None,
    gl: Optional[str] = None,
    lr: Optional[str] = None,
    site_search: Optional[str] = None,
    file_type: Optional[str] = None,
    api_key: Optional[str] = None,
    cx: Optional[str] = None,
    use_cache: bool = True,
    cache_max_age: int = 86400,  # 24 hours in seconds
) -> Dict[str, Any]:
    """
    Search Google using the official Google Custom Search API.
    
    Args:
        query: Search query string
        max_results: Maximum number of results to return
        safe: SafeSearch setting ("off", "medium", "high")
        date_restrict: Time limit for results (e.g. "d7" for past week)
        gl: Country code for geo-location (e.g., "us", "uk")
        lr: Language restriction (e.g., "lang_en", "lang_fr")
        site_search: Restrict search to a specific site
        file_type: Filter results by file type (e.g., "pdf", "doc")
        api_key: Google API key (overrides environment variable)
        cx: Google Custom Search Engine ID (overrides environment variable)
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
    
    Returns:
        Dict with search results and metadata
    """
    # Use provided API key/CX or fall back to environment variables
    google_api_key = api_key or GOOGLE_API_KEY
    google_cx = cx or GOOGLE_SEARCH_CX
    
    if not google_api_key:
        return {
            "status": "error",
            "message": "No Google API key provided. Set GOOGLE_SEARCH_API_KEY environment variable or pass api_key parameter."
        }
    
    if not google_cx:
        return {
            "status": "error",
            "message": "No Google Custom Search Engine ID provided. Set GOOGLE_SEARCH_CX environment variable or pass cx parameter."
        }
    
    # Check cache first if enabled
    if use_cache:
        cache_key = _get_cache_key(
            query, 
            max_results=max_results,
            safe=safe,
            date_restrict=date_restrict,
            gl=gl,
            lr=lr,
            site_search=site_search,
            file_type=file_type
        )
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    try:
        # Calculate how many API calls we need based on max_results
        # Google Custom Search API returns max 10 results per call
        results = []
        pages_needed = (max_results + 9) // 10  # Ceiling division
        
        for page in range(pages_needed):
            start_index = page * 10 + 1  # Google uses 1-based indexing
            
            logger.info(f"Fetching page {page+1} with start index {start_index}")
            
            # Execute the search
            response = _execute_google_search(
                query=query,
                api_key=google_api_key,
                cx=google_cx,
                start=start_index,
                num=min(10, max_results - len(results)),
                safe=safe,
                date_restrict=date_restrict,
                gl=gl,
                lr=lr,
                site_search=site_search,
                file_type=file_type
            )
            
            # Extract search results
            if "items" in response:
                for item in response["items"]:
                    results.append({
                        "title": item.get("title", ""),
                        "url": item.get("link", ""),
                        "snippet": item.get("snippet", ""),
                        "mime_type": item.get("mime", ""),
                        "file_format": item.get("fileFormat", ""),
                    })
                    
                    # Stop if we have enough results
                    if len(results) >= max_results:
                        break
            
            # Stop if we got fewer than 10 results (last page)
            if "items" not in response or len(response["items"]) < 10:
                break
                
            # Stop if we have enough results
            if len(results) >= max_results:
                break
                
            # Respect rate limits between pagination calls
            if page < pages_needed - 1:
                time.sleep(5)  # Additional delay between pagination requests to avoid quota issues
        
        # Format results in markdown
        md_results = [_md(r, i) for i, r in enumerate(results, 1)]
        
        # Build final result
        result = {
            "status": "success",
            "query": query,
            "results": results[:max_results],  # Ensure we don't exceed max_results
            "results_markdown": md_results[:max_results],
            "result_count": len(results),
            "search_information": {
                "total_results": response.get("searchInformation", {}).get("totalResults", "0"),
                "time_taken": response.get("searchInformation", {}).get("searchTime", 0)
            }
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
def search_with_relevance(
    query: str,
    max_results: int = 50,
    relevance_keywords: Optional[List[str]] = None,
    safe: str = "off",
    date_restrict: Optional[str] = None,
    gl: Optional[str] = None,
    lr: Optional[str] = None,
    site_search: Optional[str] = None,
    file_type: Optional[str] = None,
    api_key: Optional[str] = None,
    cx: Optional[str] = None,
    use_cache: bool = True,
) -> Dict[str, Any]:
    """
    Enhanced search that scores and ranks results by relevance to keywords.
    
    Args:
        query: Search query string
        max_results: Maximum number of results to return
        relevance_keywords: Keywords for relevance scoring (defaults to query terms)
        safe: SafeSearch setting ("off", "medium", "high")
        date_restrict: Time limit for results (e.g. "d7" for past week)
        gl: Country code for geo-location (e.g., "us", "uk")
        lr: Language restriction (e.g., "lang_en", "lang_fr")
        site_search: Restrict search to a specific site
        file_type: Filter results by file type (e.g., "pdf", "doc")
        api_key: Google API key (overrides environment variable)
        cx: Google Custom Search Engine ID (overrides environment variable)
        use_cache: Whether to use caching
    
    Returns:
        Dict with search results ranked by relevance
    """
    # Default keywords are from the query if none provided
    if not relevance_keywords:
        relevance_keywords = [word.lower() for word in query.split() if len(word) > 2]
    
    # Check cache first if enabled - with different key for relevance search
    if use_cache:
        cache_key = _get_cache_key(
            f"relevance_{query}", 
            max_results=max_results,
            relevance_keywords=relevance_keywords,
            safe=safe,
            date_restrict=date_restrict,
            gl=gl,
            lr=lr,
            site_search=site_search,
            file_type=file_type
        )
        cached_result = _get_from_cache(cache_key, 86400)  # 24 hours cache
        if cached_result:
            return cached_result
    
    # Perform the search
    search_results = search_google_text(
        query=query,
        max_results=max_results,
        safe=safe,
        date_restrict=date_restrict,
        gl=gl,
        lr=lr,
        site_search=site_search,
        file_type=file_type,
        api_key=api_key,
        cx=cx,
        use_cache=use_cache
    )
    
    if search_results.get("status") != "success":
        return search_results
    
    # Score and rank the results
    results = search_results.get("results", [])
    scored_results = []
    
    for result in results:
        score = score_relevance(result, relevance_keywords)
        scored_results.append({
            "result": result,
            "score": score
        })
    
    # Sort by relevance score (highest first)
    scored_results.sort(key=lambda x: x["score"], reverse=True)
    
    # Create a new list with just the ranked results (no scores)
    ranked_results = [item["result"] for item in scored_results]
    
    # Format results as markdown
    md_results = [_md(r, i) for i, r in enumerate(ranked_results, 1)]
    
    # Return the ranked results
    result = {
        "status": "success",
        "query": query,
        "keywords_used": relevance_keywords,
        "results": ranked_results,
        "results_markdown": md_results,
        "scored_results": scored_results,  # Include scores for transparency
        "result_count": len(results),
        "search_information": search_results.get("search_information", {})
    }
    
    # Cache the relevance result if enabled
    if use_cache:
        _save_to_cache(cache_key, result)
    
    return result


# ───────────── CLI helper (optional) ─────────────
def _cli() -> None:
    p = argparse.ArgumentParser(description="Google Custom Search API wrapper")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("search")
    s.add_argument("query")
    s.add_argument("--max", type=int, default=50, help="Maximum number of results")
    s.add_argument("--api-key", default=None, help="Google API key (overrides env var)")
    s.add_argument("--cx", default=None, help="Google Custom Search Engine ID (overrides env var)")
    s.add_argument("--safe", choices=["off", "medium", "high"], default="off", help="SafeSearch setting")
    s.add_argument("--date", default=None, help="Date restrict (e.g., d7, m3)")
    s.add_argument("--gl", default=None, help="Geolocation country code (e.g., us)")
    s.add_argument("--lr", default=None, help="Language restrict (e.g., lang_en)")
    s.add_argument("--site", default=None, help="Site search restriction")
    s.add_argument("--filetype", default=None, help="File type filter (e.g., pdf)")
    s.add_argument("--no-cache", action="store_true", help="Disable caching")
    s.add_argument("--with-relevance", action="store_true", help="Use relevance scoring")
    s.add_argument("--keywords", nargs="+", help="Relevance keywords")

    sub.add_parser("check")

    args = p.parse_args()
    if args.cmd == "check":
        api_key_status = "configured" if GOOGLE_API_KEY else "not configured"
        cx_status = "configured" if GOOGLE_SEARCH_CX else "not configured"
        out = {
            "status": "ok", 
            "message": f"google_osint ready. API key: {api_key_status}, Search Engine ID: {cx_status}"
        }
    else:
        if args.with_relevance:
            out = search_with_relevance(
                args.query,
                max_results=args.max,
                relevance_keywords=args.keywords,
                safe=args.safe,
                date_restrict=args.date,
                gl=args.gl,
                lr=args.lr,
                site_search=args.site,
                file_type=args.filetype,
                api_key=args.api_key,
                cx=args.cx,
                use_cache=not args.no_cache,
            )
        else:
            out = search_google_text(
                args.query,
                max_results=args.max,
                safe=args.safe,
                date_restrict=args.date,
                gl=args.gl,
                lr=args.lr,
                site_search=args.site,
                file_type=args.filetype,
                api_key=args.api_key,
                cx=args.cx,
                use_cache=not args.no_cache,
            )

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    # Check if being run directly with command-line arguments
    if len(sys.argv) > 1 and sys.argv[1] in {"search", "check"}:
        _cli()
    else:
        # Otherwise, run as an MCP service
        mcp.run(transport="stdio")