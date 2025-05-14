#!/usr/bin/env python3
"""
search_orchestrator.py — Combined DuckDuckGo search, link processing, and database storage

This microservice coordinates between:
1. duckduckgo_osint.py - For search queries
2. link_follower_osint.py - For processing links
3. database_osint.py - For storing and retrieving results

Endpoints:
- search_and_store - Main workflow
- retrieve_search_results - Get stored results from database
- get_recent_searches - List recent searches
- update_search_note - Update notes for a stored search
- delete_search_results - Remove stored results
- check_service_status - Verify that all services are working
"""

import os
import sys
import json
import time
import re
import uuid
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

# MCP Endpoints
@mcp.tool()
def search_and_store(
    query: str, 
    max_results: int = DEFAULT_MAX_RESULTS, 
    links_to_process: int = DEFAULT_LINKS_TO_PROCESS,
    relevance_keywords: Optional[List[str]] = None,
    search_delay: float = DEFAULT_SEARCH_DELAY,
    link_delay: float = DEFAULT_LINK_DELAY,
    notes: Optional[str] = None
) -> Dict[str, Any]:
    """
    Performs the full search workflow:
    1. Search DuckDuckGo
    2. Process and score results
    3. Fetch content from most relevant links
    4. Store everything in the database
    
    Args:
        query: Search query
        max_results: Maximum results to get from DuckDuckGo
        links_to_process: How many links to process
        relevance_keywords: Keywords for relevance scoring (defaults to query terms)
        search_delay: Delay for search requests
        link_delay: Delay between link requests
        notes: Optional notes about this search
        
    Returns:
        Dictionary with search results, processed links, insights and storage info
    """
    search_id = generate_search_id()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 1. Make a single search with maximum results
    print(f"Searching for: {query}")
    search_results = duckduckgo.search_duckduckgo_text(
        query=query,
        max_results=max_results,
        delay=search_delay,
        use_cache=True,
        cache_max_age=86400  # 24-hour cache
    )
    
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
        processed_links = link_follower.fetch_multiple_urls(
            urls=top_links,
            max_urls=len(top_links),
            delay=link_delay,
            extract_text=True,
            extract_links=False,
            extract_metadata=True
        )
    
    # 4. Extract insights
    insights = extract_insights(processed_links)
    
    # 5. Store in database
    # First, store the search query as a target
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
        "data_id": storage_result.get("data_id")
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

@mcp.tool()
def get_recent_searches(limit: int = 10) -> Dict[str, Any]:
    """
    Get a list of recent searches from the database.
    
    Args:
        limit: Maximum number of recent searches to return
        
    Returns:
        Dictionary with recent search information
    """
    # This requires a custom query that the current database_osint.py doesn't support
    # We'll simulate it by getting all targets of type search_query
    # In a real implementation, we would add a specific endpoint for this
    
    # Check database connection
    db_status = database.check_database_connection()
    
    if db_status.get("status") != "connected":
        return {
            "status": "error",
            "message": "Database connection failed",
            "details": db_status
        }
    
    # For now, return a message explaining the limitation
    return {
        "status": "not_implemented",
        "message": "This feature requires a custom database query not currently supported.",
        "suggestion": "To implement this feature, add a new endpoint to database_osint.py that retrieves recent targets by type with a LIMIT clause."
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
    # First, get the current data
    current_data = database.get_osint_data_by_id(data_id=data_id)
    
    if current_data.get("status") != "success":
        return current_data
    
    # Check if this is a search_query target
    data = current_data.get("data", {})
    if data.get("target_type") != "search_query":
        return {
            "status": "error",
            "message": "The specified ID does not correspond to a search query"
        }
    
    # Update verification status as a way to mark that we've reviewed the search
    update_result = database.update_osint_data_verification(
        data_id=data_id,
        verified=True
    )
    
    # The database_osint.py doesn't have a way to update just the notes
    # In a real implementation, we would add a specific endpoint for this
    
    return {
        "status": "partial_success",
        "message": "Marked search as verified. Note update not implemented.",
        "details": update_result,
        "suggestion": "To implement note updates, add a new endpoint to database_osint.py that allows updating the data_value field."
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
    return database.delete_osint_data(data_id=data_id)

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