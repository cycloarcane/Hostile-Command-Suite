#!/usr/bin/env python3
"""
search_orchestrator.py — Combined DuckDuckGo search, link processing, and database storage

This microservice coordinates between:
1. duckduckgo_osint.py - For search queries
2. link_follower_osint.py - For processing links
3. database_osint.py - For storing and retrieving results
"""

import os
import sys
import json
import time
import re
import uuid
import random
from datetime import datetime
from typing import List, Dict, Any, Optional

# Import FastMCP for tool access
from fastmcp import FastMCP

# Initialize FastMCP for this service and dependencies
mcp = FastMCP("search_orchestrator")
duckduckgo = FastMCP("duckduckgo")
link_follower = FastMCP("link_follower")
database = FastMCP("database")

# Constants
DEFAULT_MAX_RESULTS = 30
DEFAULT_LINKS_TO_PROCESS = 10
DEFAULT_SEARCH_DELAY = 5.0
DEFAULT_LINK_DELAY = 3.0
DEFAULT_CONFIDENCE = 0.9

# Helper Functions
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
    url = result.get("href", "").lower()
    
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
    
    return score

def extract_insights(processed_links: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract insights from processed links.
    
    Args:
        processed_links: Result from link_follower
        
    Returns:
        Dictionary with insights
    """
    insights = {
        "common_terms": [],
        "content_summary": "",
        "metadata_summary": {}
    }
    
    # Only process if we have successful results
    if processed_links.get("status") != "success":
        return insights
    
    # Extract text from all links
    all_text = ""
    metadata_counts = {}
    
    for result in processed_links.get("results", []):
        if result.get("status") == "success":
            # Add text content
            if "text_content" in result:
                all_text += " " + result.get("text_content", "")
            
            # Collect metadata
            if "metadata" in result:
                for key, value in result.get("metadata", {}).items():
                    if key not in metadata_counts:
                        metadata_counts[key] = {}
                    
                    if value not in metadata_counts[key]:
                        metadata_counts[key][value] = 0
                    
                    metadata_counts[key][value] += 1
    
    # Find common terms (simple approach - could be improved)
    if all_text:
        # Clean and tokenize
        words = re.findall(r'\b[a-z]{4,}\b', all_text.lower())
        
        # Count frequencies
        from collections import Counter
        word_counts = Counter(words)
        
        # Get top terms
        insights["common_terms"] = [word for word, count in word_counts.most_common(10)]
    
    # Summarize metadata
    for key, values in metadata_counts.items():
        if key in ["description", "keywords", "author"]:
            insights["metadata_summary"][key] = list(values.keys())
    
    return insights

def generate_search_id() -> str:
    """Generate a unique search ID"""
    return f"search_{int(time.time())}_{str(uuid.uuid4())[:8]}"

def search_with_retry(query: str, max_results: int, search_delay: float, retries: int = 3):
    """
    Attempt a search with multiple retries and exponential backoff.
    
    Args:
        query: The search query
        max_results: Maximum results to return
        search_delay: Initial delay between requests
        retries: Maximum number of retry attempts
        
    Returns:
        Search results or error dictionary
    """
    attempt = 0
    current_delay = search_delay
    
    while attempt < retries:
        try:
            # Add jitter to delay to prevent synchronized retries
            actual_delay = current_delay * (0.8 + random.random() * 0.4)  # ±20% jitter
            
            print(f"Search attempt {attempt+1} with delay {actual_delay:.2f}s")
            
            search_results = duckduckgo.search_duckduckgo_text(
                query=query,
                max_results=max_results,
                delay=actual_delay,
                use_cache=True,
                cache_max_age=86400  # 24-hour cache
            )
            
            # If successful, return the results
            if search_results.get("status") == "success":
                return search_results
                
            # If rate limited, try again with increased delay
            if "rate limit" in search_results.get("message", "").lower():
                print(f"Rate limited on attempt {attempt+1}. Retrying...")
                attempt += 1
                current_delay = current_delay * 2  # Exponential backoff
                time.sleep(current_delay)  # Wait before retry
                continue
                
            # If other error, return it
            return search_results
            
        except Exception as e:
            print(f"Search error on attempt {attempt+1}: {str(e)}")
            attempt += 1
            current_delay = current_delay * 2  # Exponential backoff
            time.sleep(current_delay)  # Wait before retry
    
    # All retries failed
    return {
        "status": "error",
        "message": f"Failed after {retries} attempts. Last delay: {current_delay:.2f}s",
        "query": query
    }

# MCP Endpoints
@mcp.tool()
def search_and_store(
    query: str, 
    max_results: int = DEFAULT_MAX_RESULTS, 
    links_to_process: int = DEFAULT_LINKS_TO_PROCESS,
    relevance_keywords: Optional[List[str]] = None,
    search_delay: float = DEFAULT_SEARCH_DELAY,
    link_delay: float = DEFAULT_LINK_DELAY,
    notes: Optional[str] = None,
    use_google_fallback: bool = False
) -> Dict[str, Any]:
    """
    Performs the full search workflow:
    1. Search DuckDuckGo (with retry logic)
    2. Process and score results
    3. Fetch content from most relevant links
    4. Store everything in the database
    
    Args:
        query: Search query
        max_results: Maximum results to get from search
        links_to_process: How many links to process
        relevance_keywords: Keywords for relevance scoring (defaults to query terms)
        search_delay: Delay for search requests
        link_delay: Delay between link requests
        notes: Optional notes about this search
        use_google_fallback: Whether to try Google if DuckDuckGo fails
        
    Returns:
        Dictionary with search results, processed links, insights and storage info
    """
    search_id = generate_search_id()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 1. Make a search with retries
    print(f"Searching for: {query}")
    search_results = search_with_retry(
        query=query,
        max_results=max_results,
        search_delay=search_delay
    )
    
    # If DuckDuckGo fails and Google fallback is enabled, try Google
    if search_results.get("status") != "success" and use_google_fallback:
        print("DuckDuckGo search failed. Trying Google fallback...")
        try:
            google = FastMCP("google")
            search_results = google.search_google_text(
                query=query,
                max_results=max_results,
                use_cache=True
            )
        except Exception as e:
            print(f"Google fallback also failed: {str(e)}")
            # Continue with DuckDuckGo results even if they failed
    
    if search_results.get("status") != "success":
        return {
            "status": "error",
            "message": search_results.get("message", "Search failed"),
            "original_response": search_results
        }
    
    # 2. Score and rank the results by relevance
    results = search_results.get("results", [])
    
    # Default keywords are from the query if none provided
    if not relevance_keywords:
        relevance_keywords = [word.lower() for word in query.split() if len(word) > 2]
    
    # Score each result
    scored_results = []
    for result in results:
        score = score_relevance(result, relevance_keywords)
        scored_results.append({
            "result": result,
            "score": score
        })
    
    # Sort by relevance score
    scored_results.sort(key=lambda x: x["score"], reverse=True)
    
    # Get the top links to process
    top_links = [item["result"]["href"] for item in scored_results[:links_to_process]]
    
    # 3. Process the top links
    processed_links = {"status": "not_processed", "results": []}
    if top_links:
        print(f"Processing {len(top_links)} most relevant links...")
        try:
            processed_links = link_follower.fetch_multiple_urls(
                urls=top_links,
                max_urls=len(top_links),
                delay=link_delay,
                extract_text=True,
                extract_links=False,
                extract_metadata=True
            )
        except Exception as e:
            print(f"Error processing links: {str(e)}")
            processed_links = {
                "status": "error",
                "message": f"Link processing failed: {str(e)}",
                "results": []
            }
    
    # 4. Extract insights
    insights = extract_insights(processed_links)
    
    # 5. Store in database
    # First, store the search query as a target
    try:
        storage_result = database.store_osint_data(
            target_type="search_query",
            target_value=query,
            source_name="search_orchestrator",
            source_type="combined_search",
            data_type="search_results",
            data_value={
                "search_id": search_id,
                "timestamp": timestamp,
                "query": query,
                "keywords": relevance_keywords,
                "search_results_count": len(results),
                "processed_links_count": len(top_links),
                "search_results": search_results,
                "scored_results": scored_results,
                "insights": insights,
                "processed_links": processed_links
            },
            confidence=DEFAULT_CONFIDENCE,
            notes=notes
        )
    except Exception as e:
        print(f"Database storage error: {str(e)}")
        storage_result = {
            "status": "error",
            "message": f"Failed to store in database: {str(e)}"
        }
    
    # 6. Return combined results
    return {
        "status": "success",
        "search_id": search_id,
        "timestamp": timestamp,
        "query": query,
        "search_results_count": len(results),
        "processed_links_count": len(top_links),
        "top_links": top_links,
        "insights": insights,
        "storage_info": storage_result,
        "data_id": storage_result.get("data_id") if storage_result.get("status") == "success" else None
    }

@mcp.tool()
def retrieve_search_results(
    data_id: Optional[int] = None, 
    query: Optional[str] = None
) -> Dict[str, Any]:
    """
    Retrieve stored search results from the database.
    
    Args:
        data_id: The database ID of the specific search result
        query: The original search query
        
    Returns:
        Dictionary with the stored search results
    """
    try:
        if data_id:
            # Get specific search by ID
            return database.get_osint_data_by_id(data_id=data_id)
        elif query:
            # Get all searches for a query
            return database.get_osint_data_by_target(
                target_type="search_query",
                target_value=query,
                data_type="search_results"
            )
        else:
            return {
                "status": "error",
                "message": "Either data_id or query must be provided"
            }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to retrieve search results: {str(e)}"
        }

@mcp.tool()
def get_recent_searches(limit: int = 10, offset: int = 0) -> Dict[str, Any]:
    """
    Get a list of recent searches from the database.
    
    Args:
        limit: Maximum number of recent searches to return
        offset: Number of records to skip (for pagination)
        
    Returns:
        Dictionary with recent search information
    """
    try:
        # Use the new endpoint directly in database_osint.py
        return database.get_recent_searches(limit=limit, offset=offset)
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to retrieve recent searches: {str(e)}"
        }

@mcp.tool()
def update_search_note(data_id: int, notes: str) -> Dict[str, Any]:
    """
    Update the notes for a stored search.
    
    Args:
        data_id: The database ID of the search result
        notes: New notes to store
        
    Returns:
        Dictionary with update status
    """
    try:
        # Use the new endpoint directly in database_osint.py
        return database.update_osint_data_notes(data_id=data_id, notes=notes)
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to update search notes: {str(e)}"
        }

@mcp.tool()
def delete_search_results(data_id: int) -> Dict[str, Any]:
    """
    Delete stored search results from the database.
    
    Args:
        data_id: The database ID of the search result to delete
        
    Returns:
        Dictionary with deletion status
    """
    try:
        return database.delete_osint_data(data_id=data_id)
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to delete search results: {str(e)}"
        }

@mcp.tool()
def check_service_status() -> Dict[str, Any]:
    """
    Check if all required services are available and working.
    
    Returns:
        Dictionary with service status information
    """
    services = {}
    
    # Check DuckDuckGo service
    try:
        ddg_result = duckduckgo.search_duckduckgo_text(
            query="test query",
            max_results=1,
            use_cache=True
        )
        services["duckduckgo"] = {
            "status": "ok" if ddg_result.get("status") == "success" else "error",
            "details": ddg_result.get("message", "")
        }
    except Exception as e:
        services["duckduckgo"] = {
            "status": "error",
            "details": str(e)
        }
    
    # Check link follower service
    try:
        lf_result = link_follower.fetch_url(
            url="https://example.com",
            delay=0.1,
            timeout=5
        )
        services["link_follower"] = {
            "status": "ok" if lf_result.get("status") == "success" else "error",
            "details": lf_result.get("message", "")
        }
    except Exception as e:
        services["link_follower"] = {
            "status": "error",
            "details": str(e)
        }
    
    # Check database service
    try:
        db_result = database.check_database_connection()
        services["database"] = {
            "status": "ok" if db_result.get("status") == "connected" else "error",
            "details": db_result
        }
    except Exception as e:
        services["database"] = {
            "status": "error",
            "details": str(e)
        }
    
    # Determine overall status
    overall_status = "ok"
    for service, status in services.items():
        if status["status"] != "ok":
            overall_status = "degraded"
            break
    
    return {
        "status": overall_status,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "services": services
    }

if __name__ == "__main__":
    mcp.run(transport="stdio")