#!/usr/bin/env python3
"""
link_follower_osint.py — Simple web content fetcher and parser for OSINT investigations

FastMCP tools
────────────
    fetch_url(url, ...)
    fetch_multiple_urls(urls, ...)

Returns
───────
    {
      "status": "success",
      "url": "https://example.com",
      "title": "Page Title",
      "text_content": "Extracted text content...",
      "links": [{"href": "...", "text": "..."}],
      "metadata": {...}
    }

Purpose
───────
This tool acts like an enhanced curl command for LLMs, allowing them to:
- Fetch web page content from URLs found in other investigations
- Extract clean text content from HTML pages
- Get basic page metadata (title, description, etc.)
- Extract all links from pages for further investigation
- Handle different content types appropriately

Use Cases
─────────
- Follow up on URLs discovered by search tools
- Extract content from company/personal websites
- Get text content from news articles or blog posts
- Download and analyze documents linked from web pages
- Basic reconnaissance of target websites
"""

import json
import os
import sys
import time
import re
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse, urljoin

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

from fastmcp import FastMCP

mcp = FastMCP("link_follower")       # MCP route → /link_follower
_LAST_CALL_AT: float = 0.0           # global for simple throttle
_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"


def _rate_limit(delay: float) -> None:
    """Implement a simple rate limiter to be respectful to websites."""
    global _LAST_CALL_AT
    wait = _LAST_CALL_AT + delay - time.time()
    if wait > 0:
        time.sleep(wait)
    _LAST_CALL_AT = time.time()


def _create_session() -> requests.Session:
    """Create a requests session with retry strategy and proper headers."""
    session = requests.Session()
    
    retry_strategy = Retry(
        total=3,
        status_forcelist=[429, 500, 502, 503, 504],
        method_whitelist=["HEAD", "GET", "OPTIONS"],
        backoff_factor=1
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    session.headers.update({
        'User-Agent': _USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    })
    
    return session


def _extract_metadata(soup: BeautifulSoup) -> Dict[str, str]:
    """Extract basic metadata from HTML head tags."""
    metadata = {}
    
    # Extract meta tags
    for meta in soup.find_all("meta"):
        if meta.get("name") and meta.get("content"):
            metadata[meta["name"]] = meta["content"]
        elif meta.get("property") and meta.get("content"):
            metadata[meta["property"]] = meta["content"]
    
    return metadata


def _extract_links(soup: BeautifulSoup, base_url: str) -> List[Dict[str, str]]:
    """Extract links from the page and normalize URLs."""
    links = []
    
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        
        # Normalize URL (handle relative URLs)
        try:
            full_url = urljoin(base_url, href)
        except:
            continue
        
        # Get link text (or use URL if no text)
        text = a_tag.get_text(strip=True) or href
        
        links.append({
            "href": full_url,
            "text": text[:200]  # Truncate long text
        })
    
    return links


def _clean_text(soup: BeautifulSoup) -> str:
    """Extract clean text content from HTML."""
    # Remove script and style elements
    for script in soup(["script", "style", "header", "footer", "nav"]):
        script.extract()
    
    # Get text
    text = soup.get_text(separator=" ", strip=True)
    
    # Clean up whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text


def _is_valid_url(url: str) -> bool:
    """Check if URL is valid and supported."""
    try:
        result = urlparse(url)
        return all([result.scheme in ("http", "https"), result.netloc])
    except Exception:
        return False


@mcp.tool()
def fetch_url(
    url: str,
    delay: float = 2.0,
    timeout: int = 30,
    max_content_length: int = 5000000,  # 5MB limit
    extract_text: bool = True,
    extract_links: bool = True,
    extract_metadata: bool = True,
) -> Dict[str, Any]:
    """
    Fetch and parse content from a single URL (like an enhanced curl command).
    
    This tool allows the LLM to follow links discovered during investigations and
    extract useful content from web pages for further analysis.
    
    Args:
        url: URL to fetch
        delay: Delay before request (seconds) 
        timeout: Request timeout (seconds)
        max_content_length: Maximum content size to download (~5MB)
        extract_text: Whether to extract clean text content
        extract_links: Whether to extract all links from the page
        extract_metadata: Whether to extract HTML metadata
        
    Returns:
        Dict with page content, links, and metadata
    """
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    if not _is_valid_url(url):
        return {
            "status": "error",
            "url": url,
            "message": "Invalid or unsupported URL format",
        }
    
    _rate_limit(delay)
    
    try:
        session = _create_session()
        response = session.get(url, timeout=timeout, stream=True)
        
        # Check content length if provided in headers
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > max_content_length:
            return {
                "status": "error",
                "url": url,
                "message": f"Content too large: {content_length} bytes (max: {max_content_length})",
            }
        
        # Check content type
        content_type = response.headers.get("Content-Type", "").lower()
        
        # Handle non-HTML content
        if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
            if "text/" in content_type:
                # For text content, just return the text
                return {
                    "status": "success",
                    "url": url,
                    "content_type": content_type,
                    "text_content": response.text[:max_content_length],
                    "file_size": len(response.text)
                }
            else:
                # For binary content, just return info
                return {
                    "status": "success",
                    "url": url,
                    "content_type": content_type,
                    "message": f"Binary content detected: {content_type}",
                    "file_size": len(response.content) if hasattr(response, 'content') else 0
                }
        
        # Raise for HTTP errors
        response.raise_for_status()
        
        # Parse HTML content
        if not BS4_AVAILABLE:
            # Fallback without BeautifulSoup
            return {
                "status": "success",
                "url": url,
                "content_type": content_type,
                "raw_html": response.text[:max_content_length],
                "message": "HTML returned but BeautifulSoup not available for parsing"
            }
        
        soup = BeautifulSoup(response.text, "html.parser")
        
        result = {
            "status": "success",
            "url": url,
            "content_type": content_type,
            "title": soup.title.string.strip() if soup.title else "",
            "file_size": len(response.text)
        }
        
        # Extract text content if requested
        if extract_text:
            result["text_content"] = _clean_text(soup)
        
        # Extract links if requested
        if extract_links:
            result["links"] = _extract_links(soup, url)
        
        # Extract metadata if requested
        if extract_metadata:
            result["metadata"] = _extract_metadata(soup)
        
        return result
        
    except requests.exceptions.Timeout:
        return {"status": "error", "url": url, "message": "Request timed out"}
    
    except requests.exceptions.TooManyRedirects:
        return {"status": "error", "url": url, "message": "Too many redirects"}
    
    except requests.exceptions.HTTPError as e:
        return {"status": "error", "url": url, "message": f"HTTP error: {e}"}
    
    except requests.exceptions.RequestException as e:
        return {"status": "error", "url": url, "message": f"Request failed: {e}"}
    
    except Exception as e:
        return {"status": "error", "url": url, "message": f"Unexpected error: {e}"}


@mcp.tool()
def fetch_multiple_urls(
    urls: List[str],
    max_urls: int = 10,
    delay: float = 2.0,
    timeout: int = 30,
    max_content_length: int = 5000000,
    extract_text: bool = True,
    extract_links: bool = True,
    extract_metadata: bool = True,
) -> Dict[str, Any]:
    """
    Fetch and parse content from multiple URLs in sequence.
    
    Useful when you have a list of URLs from search results or other investigations
    that need to be analyzed for content.
    
    Args:
        urls: List of URLs to fetch
        max_urls: Maximum number of URLs to process
        delay: Delay between requests (seconds)
        timeout: Request timeout per URL (seconds)
        max_content_length: Maximum content size per URL
        extract_text: Whether to extract text content
        extract_links: Whether to extract links
        extract_metadata: Whether to extract metadata
        
    Returns:
        Dict with results for each URL processed
    """
    if not urls:
        return {"status": "error", "message": "No URLs provided"}
    
    # Limit the number of URLs to process
    urls_to_process = urls[:max_urls]
    
    results = {}
    successful = 0
    failed = 0
    
    for i, url in enumerate(urls_to_process):
        print(f"Fetching URL {i+1}/{len(urls_to_process)}: {url}")
        
        result = fetch_url(
            url=url,
            delay=delay,
            timeout=timeout,
            max_content_length=max_content_length,
            extract_text=extract_text,
            extract_links=extract_links,
            extract_metadata=extract_metadata,
        )
        
        results[url] = result
        
        if result.get("status") == "success":
            successful += 1
        else:
            failed += 1
    
    return {
        "status": "success",
        "total_urls": len(urls),
        "processed_urls": len(urls_to_process),
        "successful": successful,
        "failed": failed,
        "results": results
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")