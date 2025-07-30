#!/usr/bin/env python3
"""
DuckDuckGo Web Search MCP Server - Web Search OSINT Tool
Part of Hostile Command Suite OSINT Package
"""

import json
import asyncio
from typing import Dict, List, Any
from mcp.server import Server
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

# Create MCP server instance
server = Server("duckduckgo-search")

def check_duckduckgo_available() -> bool:
    """Check if duckduckgo_search is installed and available"""
    try:
        import duckduckgo_search
        return True
    except ImportError:
        return False

@server.list_tools()
async def handle_list_tools() -> List[types.Tool]:
    """List available DuckDuckGo search tools"""
    return [
        types.Tool(
            name="web_search",
            description="Search the web using DuckDuckGo for OSINT intelligence gathering",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query to execute"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default: 10)",
                        "default": 10
                    },
                    "region": {
                        "type": "string", 
                        "description": "Region for search results (default: us-en)",
                        "default": "us-en"
                    },
                    "safesearch": {
                        "type": "string",
                        "description": "Safe search setting: on, moderate, off (default: moderate)",
                        "default": "moderate"
                    }
                },
                "required": ["query"]
            }
        ),
        types.Tool(
            name="news_search",
            description="Search for news articles using DuckDuckGo",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "News search query"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default: 10)",
                        "default": 10
                    },
                    "region": {
                        "type": "string",
                        "description": "Region for search results (default: us-en)",
                        "default": "us-en"
                    }
                },
                "required": ["query"]
            }
        ),
        types.Tool(
            name="check_duckduckgo_status",
            description="Check if DuckDuckGo search tool is available",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> List[types.TextContent]:
    """Handle tool calls"""
    
    if name == "check_duckduckgo_status":
        available = check_duckduckgo_available()
        status = "available" if available else "not installed"
        return [
            types.TextContent(
                type="text",
                text=json.dumps({
                    "tool": "duckduckgo_search",
                    "status": status,
                    "available": available,
                    "description": "Web search for OSINT intelligence gathering"
                }, indent=2)
            )
        ]
    
    elif name == "web_search":
        query = arguments.get("query")
        max_results = arguments.get("max_results", 10)
        region = arguments.get("region", "us-en")
        safesearch = arguments.get("safesearch", "moderate")
        
        if not query:
            return [types.TextContent(type="text", text=json.dumps({"error": "Query is required"}))]
        
        if not check_duckduckgo_available():
            return [types.TextContent(type="text", text=json.dumps({
                "error": "duckduckgo_search not installed. Install with: pip install duckduckgo-search"
            }))]
        
        try:
            from duckduckgo_search import DDGS
            
            with DDGS() as ddgs:
                results = list(ddgs.text(
                    keywords=query,
                    region=region,
                    safesearch=safesearch,
                    max_results=max_results
                ))
            
            # Extract key information for OSINT analysis
            processed_results = []
            for result in results:
                processed_results.append({
                    "title": result.get("title", ""),
                    "body": result.get("body", ""),
                    "href": result.get("href", ""),
                    "source": result.get("source", "")
                })
            
            search_result = {
                "tool": "duckduckgo_search",
                "search_type": "web",
                "query": query,
                "status": "success",
                "results_count": len(processed_results),
                "results": processed_results,
                "search_params": {
                    "max_results": max_results,
                    "region": region,
                    "safesearch": safesearch
                },
                "investigation_summary": f"Found {len(processed_results)} web results for '{query}'"
            }
            
            return [types.TextContent(type="text", text=json.dumps(search_result, indent=2))]
            
        except Exception as e:
            return [types.TextContent(type="text", text=json.dumps({
                "tool": "duckduckgo_search",
                "query": query,
                "status": "error",
                "error": f"Search error: {str(e)}"
            }))]
    
    elif name == "news_search":
        query = arguments.get("query")
        max_results = arguments.get("max_results", 10)
        region = arguments.get("region", "us-en")
        
        if not query:
            return [types.TextContent(type="text", text=json.dumps({"error": "Query is required"}))]
        
        if not check_duckduckgo_available():
            return [types.TextContent(type="text", text=json.dumps({
                "error": "duckduckgo_search not installed. Install with: pip install duckduckgo-search"
            }))]
        
        try:
            from duckduckgo_search import DDGS
            
            with DDGS() as ddgs:
                results = list(ddgs.news(
                    keywords=query,
                    region=region,
                    max_results=max_results
                ))
            
            # Extract key information
            processed_results = []
            for result in results:
                processed_results.append({
                    "title": result.get("title", ""),
                    "body": result.get("body", ""),
                    "url": result.get("url", ""),
                    "date": result.get("date", ""),
                    "source": result.get("source", "")
                })
            
            news_result = {
                "tool": "duckduckgo_search",
                "search_type": "news",
                "query": query,
                "status": "success",
                "results_count": len(processed_results),
                "results": processed_results,
                "search_params": {
                    "max_results": max_results,
                    "region": region
                },
                "investigation_summary": f"Found {len(processed_results)} news results for '{query}'"
            }
            
            return [types.TextContent(type="text", text=json.dumps(news_result, indent=2))]
            
        except Exception as e:
            return [types.TextContent(type="text", text=json.dumps({
                "tool": "duckduckgo_search",
                "query": query,
                "status": "error",
                "error": f"News search error: {str(e)}"
            }))]
    
    else:
        return [types.TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]

async def main():
    # Run the server using stdin/stdout streams
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="duckduckgo-search",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=None,
                    experimental_capabilities=None,
                ),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())