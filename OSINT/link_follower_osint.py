#!/usr/bin/env python3
"""
link_follower_osint.py — Web page content fetcher and parser

FastMCP tool
────────────
    fetch_url(url, delay=3, timeout=30, ...)
    fetch_multiple_urls(urls, max_urls=10, delay=3, timeout=30, ...)

Returns
───────
    {
      "status": "success",
      "url": "...",
      "content_type": "text/html",
      "title": "Page Title",
      "text_content": "Extracted text from the page...",
      "links": [{"href": "...", "text": "..."}, ...],
      "metadata": {"description": "...", ...}
    }
"""

import json
import sys
import time
import re
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup
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


def _extract_metadata(soup: BeautifulSoup) -> Dict[str, str]:
    """Extract metadata from HTML head tags."""
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
        full_url = urljoin(base_url, href)
        
        # Get link text (or use URL if no text)
        text = a_tag.get_text(strip=True) or href
        
        links.append({"href": full_url, "text": text})
    
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
    delay: float = 3.0,
    timeout: int = 30,
    max_content_length: int = 1000000,  # ~1MB
    extract_text: bool = True,
    extract_links: bool = True,
    extract_metadata: bool = True,
) -> Dict[str, Any]:
    """Fetch and parse content from a single URL."""
    if not _is_valid_url(url):
        return {
            "status": "error",
            "url": url,
            "message": "Invalid or unsupported URL format",
        }
    
    _rate_limit(delay)
    
    try:
        headers = {"User-Agent": _USER_AGENT}
        response = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            stream=True,
        )
        
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
                }
            else:
                # For binary content, just return info
                return {
                    "status": "success",
                    "url": url,
                    "content_type": content_type,
                    "message": f"Non-HTML content: {content_type}",
                }
        
        # Raise for HTTP errors
        response.raise_for_status()
        
        # Parse HTML
        soup = BeautifulSoup(response.text, "html.parser")
        
        result = {
            "status": "success",
            "url": url,
            "content_type": content_type,
            "title": soup.title.string.strip() if soup.title else "",
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
    delay: float = 3.0,
    timeout: int = 30,
    max_content_length: int = 1000000,
    extract_text: bool = True,
    extract_links: bool = True,
    extract_metadata: bool = True,
) -> Dict[str, Any]:
    """Fetch and parse content from multiple URLs."""
    if not urls:
        return {"status": "error", "message": "No URLs provided"}
    
    # Limit the number of URLs to process
    urls_to_process = urls[:max_urls]
    
    results = []
    for url in urls_to_process:
        result = fetch_url(
            url=url,
            delay=delay,
            timeout=timeout,
            max_content_length=max_content_length,
            extract_text=extract_text,
            extract_links=extract_links,
            extract_metadata=extract_metadata,
        )
        results.append(result)
    
    return {
        "status": "success",
        "total_urls": len(urls),
        "processed_urls": len(urls_to_process),
        "results": results,
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")