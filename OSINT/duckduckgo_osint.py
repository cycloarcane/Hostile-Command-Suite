#!/usr/bin/env python3
"""
duckduckgo_osint.py — Direct HTTP requests version to bypass rate limiting
"""

import json
import os
import sys
import time
import hashlib
import logging
import random
import re
import requests
from typing import Dict, List, Any, Optional
from bs4 import BeautifulSoup
from fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("duckduckgo_osint")

mcp = FastMCP("duckduckgo")  # MCP route → /duckduckgo
_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
os.makedirs(_CACHE_DIR, exist_ok=True)

# Global timestamp of last successful search
_LAST_SUCCESSFUL_SEARCH = 0
_MIN_SEARCH_INTERVAL = 60  # Increased to 60 seconds

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

def format_boolean_search(query, boolean_mode="default"):
    """
    Format a search query with boolean operators for better results.
    
    Args:
        query: The original search query
        boolean_mode: The boolean formatting mode to use:
            - "default": Add quotes around multi-word terms
            - "strict": Use AND between all terms
            - "site": Add site: operators if domain patterns are detected
            - "none": No formatting, use raw query
    
    Returns:
        Formatted boolean search query
    """
    if boolean_mode == "none":
        return query
        
    # Split query into terms, preserving existing quotes and operators
    terms = []
    in_quotes = False
    current_term = ""
    
    for char in query + " ":  # Add space to process the last term
        if char == '"':
            in_quotes = not in_quotes
            current_term += char
        elif char.isspace() and not in_quotes:
            if current_term:
                terms.append(current_term)
                current_term = ""
        else:
            current_term += char
    
    # Process each term according to the boolean mode
    processed_terms = []
    
    for term in terms:
        # Skip if term is already a boolean operator
        if term.upper() in ("AND", "OR", "NOT") or term.startswith("site:"):
            processed_terms.append(term)
            continue
            
        # Handle existing quoted terms
        if term.startswith('"') and term.endswith('"'):
            processed_terms.append(term)
            continue
            
        # Apply boolean formatting based on mode
        if " " in term and not term.startswith('"') and boolean_mode != "none":
            # Add quotes around multi-word terms
            processed_terms.append(f'"{term}"')
        elif boolean_mode == "site" and "." in term and not any(op in term for op in (":", "@")):
            # Convert potential domains to site: operators
            if re.match(r'^[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+', term):
                processed_terms.append(f'site:{term}')
            else:
                processed_terms.append(term)
        else:
            processed_terms.append(term)
    
    # Join terms with proper connectors
    if boolean_mode == "strict":
        result = " AND ".join(processed_terms)
    else:
        result = " ".join(processed_terms)
        
    return result

def score_relevance(result: Dict[str, str], keywords: List[str]) -> float:
    """Score a search result based on relevance to keywords."""
    score = 0.0
    
    # Get the text content to score
    title = result.get("title", "").lower()
    snippet = result.get("snippet", "").lower()
    url = result.get("href", "").lower()
    
    # Score based on keyword presence
    for keyword in keywords:
        if keyword in title:
            score += 3.0
        if keyword in snippet:
            score += 1.5
        if keyword in url:
            score += 1.0
    
    # Bonus for https
    if url.startswith("https"):
        score += 0.5
    
    # Penalty for short snippets
    if len(snippet) < 20:
        score -= 1.0
    
    return score

def direct_search(query, max_results=20):
    """
    Perform a search using direct HTTP requests instead of DDGS
    """
    # User agents list
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
    ]
    
    # Pick a random user agent
    user_agent = random.choice(user_agents)
    
    # Set up a session with appropriate headers
    session = requests.Session()
    session.headers.update({
        'User-Agent': user_agent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': 'https://duckduckgo.com/',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0'
    })
    
    # Attempt to get the search page first (to set cookies)
    try:
        logger.info("Fetching DuckDuckGo homepage to set cookies")
        response = session.get('https://duckduckgo.com/')
        
        # Now perform the actual search using the lite version
        logger.info(f"Performing lite search for: {query}")
        search_url = 'https://lite.duckduckgo.com/lite/'
        params = {
            'q': query,
            'kl': 'wt-wt'  # Region parameter
        }
        
        response = session.get(search_url, params=params)
        
        if response.status_code == 200:
            logger.info("Successfully received search results")
            # Parse results with BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract results - this is specific to the lite version structure
            results = []
            
            # Find all search result pairs (title/link and snippet)
            result_links = soup.select('.result-link')
            result_snippets = soup.select('.result-snippet')
            
            # Process the results - lite version has a simpler structure
            for i, (link, snippet) in enumerate(zip(result_links, result_snippets)):
                if i >= max_results:
                    break
                
                title = link.get_text(strip=True)
                href = link.get('href')
                
                # Extract and clean snippet text
                snippet_text = snippet.get_text(strip=True)
                
                results.append({
                    'title': title,
                    'href': href,
                    'snippet': snippet_text
                })
            
            return results
        else:
            logger.error(f"Search request failed with status code: {response.status_code}")
            return []
            
    except Exception as e:
        logger.error(f"Error during direct search: {e}")
        return []

@mcp.tool()
def search_duckduckgo_text(
    query: str,
    max_results: int = 20,
    delay: float = 8.0,
    region: str = "wt-wt",
    safesearch: str = "moderate",
    timelimit: Optional[str] = None,
    use_cache: bool = True,
    cache_max_age: int = 86400,  # 24 hours in seconds
    use_proxies: bool = False,
    boolean_mode: str = "default"
) -> Dict[str, Any]:
    """
    DuckDuckGo search with direct HTTP requests to prevent rate limiting.
    
    Args:
        query: Search query string
        max_results: Maximum number of results to return
        delay: Minimum delay between requests (seconds)
        region: Region for search results (e.g., "wt-wt", "us-en")
        safesearch: SafeSearch setting ("on", "moderate", "off")
        timelimit: Time limit for results (e.g. "d" for day, "w" for week)
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        use_proxies: Whether to use proxy rotation (kept for compatibility)
        boolean_mode: Boolean search mode (default, strict, site, none)
    
    Returns:
        Dict with search results and metadata
    """
    global _LAST_SUCCESSFUL_SEARCH
    
    # Format query with boolean operators if enabled
    formatted_query = format_boolean_search(query, boolean_mode)
    logger.info(f"Original query: {query}")
    logger.info(f"Formatted query: {formatted_query}")
    
    # Check cache first if enabled
    if use_cache:
        cache_key = _get_cache_key(
            query, 
            max_results=max_results,
            region=region,
            safesearch=safesearch,
            timelimit=timelimit,
            boolean_mode=boolean_mode
        )
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    # CRUCIAL: Always enforce a significant delay to avoid rate limiting
    forced_delay = random.uniform(5, 10)
    logger.info(f"Enforcing minimum delay of {forced_delay:.2f}s")
    time.sleep(forced_delay)
    
    # Wait for minimum interval since last successful search
    now = time.time()
    time_since_last = now - _LAST_SUCCESSFUL_SEARCH
    if time_since_last < _MIN_SEARCH_INTERVAL:
        wait_time = _MIN_SEARCH_INTERVAL - time_since_last
        logger.info(f"Waiting {wait_time:.2f}s for global search cooldown")
        time.sleep(wait_time)
    
    # Add a small random delay to make patterns less predictable
    random_delay = random.uniform(1.0, 3.0)
    time.sleep(random_delay)
    
    logger.info(f"Starting search: {formatted_query[:50]}... (max={max_results})")
    
    try:
        # Try the direct HTTP request approach instead of DDGS
        raw_results = direct_search(formatted_query, max_results=max_results)
        
        # If direct search fails or returns no results
        if not raw_results:
            logger.warning("Direct search returned no results, using fallback message")
            return {
                "status": "error",
                "message": "Direct search failed to return results. Try another query or wait longer.",
                "query": query,
                "formatted_query": formatted_query
            }
        
        # Format results
        md_results = [_md(r, i) for i, r in enumerate(raw_results, 1)]
        
        # Record successful search time
        _LAST_SUCCESSFUL_SEARCH = time.time()
        
        result = {
            "status": "success",
            "query": query,
            "formatted_query": formatted_query,
            "results": raw_results,
            "results_markdown": md_results,
            "result_count": len(raw_results),
            "boolean_mode": boolean_mode
        }
        
        # Cache the result if caching is enabled
        if use_cache:
            _save_to_cache(cache_key, result)
        
        return result
        
    except Exception as e:
        logger.error(f"Search error: {e}")
        return {
            "status": "error", 
            "query": query,
            "formatted_query": formatted_query,
            "message": str(e),
            "boolean_mode": boolean_mode
        }

@mcp.tool()
def search_with_relevance(
    query: str,
    max_results: int = 30,
    relevance_keywords: Optional[List[str]] = None, 
    delay: float = 8.0,
    region: str = "wt-wt",
    safesearch: str = "moderate",
    timelimit: Optional[str] = None,
    use_cache: bool = True,
    use_proxies: bool = False,
    boolean_mode: str = "default"
) -> Dict[str, Any]:
    """
    Enhanced search that scores and ranks results by relevance to keywords.
    
    Args:
        query: Search query string
        max_results: Maximum number of results to return
        relevance_keywords: Keywords for relevance scoring (defaults to query terms)
        delay: Minimum delay between requests (seconds)
        region: Region for search results (e.g., "wt-wt", "us-en")
        safesearch: SafeSearch setting ("on", "moderate", "off")
        timelimit: Time limit for results (e.g. "d" for day, "w" for week)
        use_cache: Whether to use caching
        use_proxies: Whether to use proxy rotation (kept for compatibility)
        boolean_mode: Boolean search mode (default, strict, site, none)
    
    Returns:
        Dict with search results ranked by relevance
    """
    # Default keywords are from the query if none provided
    if not relevance_keywords:
        relevance_keywords = [word.lower() for word in query.split() if len(word) > 2]
    
    # Perform the search
    search_results = search_duckduckgo_text(
        query=query,
        max_results=max_results,
        delay=delay,
        region=region,
        safesearch=safesearch,
        timelimit=timelimit,
        use_cache=use_cache,
        use_proxies=use_proxies,
        boolean_mode=boolean_mode
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
    return {
        "status": "success",
        "query": query,
        "formatted_query": search_results.get("formatted_query"),
        "keywords_used": relevance_keywords,
        "results": ranked_results,
        "results_markdown": md_results,
        "scored_results": scored_results,  # Include scores for transparency
        "boolean_mode": boolean_mode
    }

if __name__ == "__main__":
    mcp.run(transport="stdio")