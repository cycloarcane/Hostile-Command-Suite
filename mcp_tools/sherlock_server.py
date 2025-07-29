#!/usr/bin/env python3
"""
Sherlock MCP Server - Username OSINT Tool
Part of Hostile Command Suite OSINT Package
"""

import subprocess
import json
import shutil
from typing import Dict, List, Any
from mcp.server import Server
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

# Create MCP server instance
server = Server("sherlock-osint")

def check_sherlock_available() -> bool:
    """Check if sherlock is installed and available"""
    return shutil.which("sherlock") is not None

@server.list_tools()
async def handle_list_tools() -> List[types.Tool]:
    """List available sherlock tools"""
    return [
        types.Tool(
            name="investigate_username",
            description="Search for username across 400+ social media platforms using Sherlock",
            inputSchema={
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username to investigate"
                    },
                    "timeout": {
                        "type": "integer", 
                        "description": "Timeout in seconds (default: 10)",
                        "default": 10
                    }
                },
                "required": ["username"]
            }
        ),
        types.Tool(
            name="check_sherlock_status",
            description="Check if Sherlock tool is available and working",
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
    
    if name == "check_sherlock_status":
        available = check_sherlock_available()
        status = "available" if available else "not found"
        return [
            types.TextContent(
                type="text",
                text=json.dumps({
                    "tool": "sherlock",
                    "status": status,
                    "available": available,
                    "description": "Username investigation across 400+ platforms"
                }, indent=2)
            )
        ]
    
    elif name == "investigate_username":
        username = arguments.get("username")
        timeout = arguments.get("timeout", 10)
        
        if not username:
            return [types.TextContent(type="text", text=json.dumps({"error": "Username is required"}))]
        
        if not check_sherlock_available():
            return [types.TextContent(type="text", text=json.dumps({"error": "Sherlock not installed or not in PATH"}))]
        
        try:
            # Run sherlock with simple text output
            cmd = ['sherlock', username, '--timeout', str(timeout), '--print-found']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # Parse accounts found
                accounts = []
                for line in result.stdout.split('\n'):
                    if 'http' in line and username in line:
                        accounts.append(line.strip())
                
                investigation_result = {
                    "tool": "sherlock",
                    "target": username,
                    "target_type": "username", 
                    "status": "success",
                    "accounts_found": len(accounts),
                    "platforms": accounts,
                    "raw_output": result.stdout,
                    "investigation_summary": f"Found {len(accounts)} potential accounts for username '{username}' across social media platforms"
                }
            else:
                investigation_result = {
                    "tool": "sherlock",
                    "target": username,
                    "status": "error",
                    "error": f"Sherlock failed: {result.stderr}"
                }
            
            return [types.TextContent(type="text", text=json.dumps(investigation_result, indent=2))]
            
        except subprocess.TimeoutExpired:
            return [types.TextContent(type="text", text=json.dumps({
                "tool": "sherlock",
                "target": username,
                "status": "error", 
                "error": "Investigation timed out"
            }))]
        except Exception as e:
            return [types.TextContent(type="text", text=json.dumps({
                "tool": "sherlock",
                "target": username,
                "status": "error",
                "error": f"Sherlock error: {str(e)}"
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
                server_name="sherlock-osint",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=None,
                    experimental_capabilities=None,
                ),
            ),
        )

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())