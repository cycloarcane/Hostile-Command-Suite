#!/usr/bin/env python3
"""
Mosint MCP Server - Email OSINT Tool
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
server = Server("mosint-osint")

def check_mosint_available() -> bool:
    """Check if mosint is installed and available"""
    return shutil.which("mosint") is not None

@server.list_tools()
async def handle_list_tools() -> List[types.Tool]:
    """List available mosint tools"""
    return [
        types.Tool(
            name="investigate_email",
            description="Investigate email address for breaches, social accounts, and intelligence using Mosint",
            inputSchema={
                "type": "object",
                "properties": {
                    "email": {
                        "type": "string",
                        "description": "Email address to investigate"
                    },
                    "verbose": {
                        "type": "boolean",
                        "description": "Enable verbose output (default: true)",
                        "default": True
                    }
                },
                "required": ["email"]
            }
        ),
        types.Tool(
            name="check_mosint_status",
            description="Check if Mosint tool is available and working",
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
    
    if name == "check_mosint_status":
        available = check_mosint_available()
        status = "available" if available else "not found"
        return [
            types.TextContent(
                type="text",
                text=json.dumps({
                    "tool": "mosint",
                    "status": status,
                    "available": available,
                    "description": "Email OSINT and breach investigation"
                }, indent=2)
            )
        ]
    
    elif name == "investigate_email":
        email = arguments.get("email")
        verbose = arguments.get("verbose", True)
        
        if not email:
            return [types.TextContent(type="text", text=json.dumps({"error": "Email is required"}))]
        
        # Basic email validation
        if "@" not in email or "." not in email:
            return [types.TextContent(type="text", text=json.dumps({"error": "Invalid email format"}))]
        
        if not check_mosint_available():
            return [types.TextContent(type="text", text=json.dumps({"error": "Mosint not installed or not in PATH"}))]
        
        try:
            # Run mosint with verbose output
            cmd = ['mosint', email]
            if verbose:
                cmd.append('-v')
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                investigation_result = {
                    "tool": "mosint",
                    "target": email,
                    "target_type": "email",
                    "status": "success",
                    "domain": email.split("@")[1],
                    "raw_output": result.stdout,
                    "investigation_summary": f"Completed email intelligence gathering for '{email}'"
                }
                
                # Try to extract useful information from output
                output_lines = result.stdout.lower()
                if "breach" in output_lines or "compromised" in output_lines:
                    investigation_result["potential_breach"] = True
                if "social" in output_lines or "account" in output_lines:
                    investigation_result["social_accounts_found"] = True
                    
            else:
                investigation_result = {
                    "tool": "mosint",
                    "target": email,
                    "status": "error",
                    "error": f"Mosint failed: {result.stderr}"
                }
            
            return [types.TextContent(type="text", text=json.dumps(investigation_result, indent=2))]
            
        except subprocess.TimeoutExpired:
            return [types.TextContent(type="text", text=json.dumps({
                "tool": "mosint",
                "target": email,
                "status": "error",
                "error": "Investigation timed out"
            }))]
        except Exception as e:
            return [types.TextContent(type="text", text=json.dumps({
                "tool": "mosint",
                "target": email,
                "status": "error",
                "error": f"Mosint error: {str(e)}"
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
                server_name="mosint-osint",
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