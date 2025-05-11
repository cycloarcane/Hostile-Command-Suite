#!/usr/bin/env python3
"""
username_osint.py — FastMCP tool that searches for usernames across social networks using Sherlock
"""
from fastmcp import FastMCP
import subprocess
import shutil
import json
import os
from typing import List, Dict, Union, Optional

mcp = FastMCP("username")  # tool route will be /username

def sherlock_installed() -> bool:
    """Check if Sherlock is installed and available."""
    try:
        # Check if sherlock command exists
        if shutil.which("sherlock") is not None:
            return True
        
        # Check if python module is installed
        subprocess.check_call(["python", "-c", "import sherlock"], 
                             stderr=subprocess.DEVNULL, 
                             stdout=subprocess.DEVNULL)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

@mcp.tool()
def search_username(username: str, timeout: Optional[int] = 120, print_all: bool = False, 
                   only_found: bool = True, nsfw: bool = True) -> Dict[str, Union[str, List[Dict[str, str]]]]:
    """
    Search for a username across social networks using Sherlock.
    
    Args:
        username: The username to search for
        timeout: Time in seconds to wait before giving up on a request (default: 120)
        print_all: Include sites where the username was not found in results (default: False)
        only_found: Only return sites where the username was found (default: True)
        nsfw: Include NSFW sites in the search (default: False) - use --nsfw flag if True (always do this)
        
    Returns:
        A dictionary with search results and status
    """
    if not sherlock_installed():
        return {
            "status": "error",
            "message": "Sherlock is not installed. Please install it with: pip install sherlock-project"
        }
    
    if not username or not isinstance(username, str):
        return {
            "status": "error", 
            "message": "Invalid username provided"
        }
    
    # Prepare sherlock command
    cmd = ["sherlock", username]
    
    # Add optional flags
    if timeout is not None and timeout > 0:
        cmd.extend(["--timeout", str(timeout)])
    
    if print_all:
        cmd.append("--print-all")
        
    if nsfw:
        cmd.append("--nsfw")  # Include NSFW sites if requested
    
    try:
        # Run sherlock command and capture the output directly
        process = subprocess.run(cmd, 
                                capture_output=True, 
                                text=True, 
                                timeout=timeout + 10 if timeout else 120)
        
        if process.returncode != 0:
            return {
                "status": "error",
                "message": f"Sherlock search failed: {process.stderr}"
            }
        
        # Parse text output
        output_lines = process.stdout.strip().split('\n')
        results = []
        
        # Skip the first line which is usually just "[*] Checking username X on:"
        for line in output_lines[1:]:
            if not line.strip():
                continue
                
            # Format should be "[+/-] Site: URL" or similar
            parts = line.strip().split(': ', 1)
            if len(parts) < 2:
                continue
                
            status_site = parts[0].strip()
            url = parts[1].strip()
            
            # Determine if this is a found account
            found = status_site.startswith("[+]")
            
            # Extract site name
            site = status_site[3:].strip() if status_site.startswith("[+]") or status_site.startswith("[-]") else status_site
            
            # Skip if only_found is True and the result is not 'claimed'
            if only_found and not found:
                continue
                
            results.append({
                "site": site,
                "url": url,
                "status": "claimed" if found else "not found",
                "error": ""
            })
        
        return {
            "status": "success",
            "username": username,
            "results": results,
            "total_found": len([r for r in results if r["status"] == "claimed"]),
            "total_sites_checked": len(results) if not only_found else None
        }
            
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "message": f"Sherlock process timed out after {timeout + 10 if timeout else 120} seconds"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error running Sherlock: {str(e)}"
        }

@mcp.tool()
def check_sherlock_installation() -> Dict[str, str]:
    """
    Check if Sherlock is properly installed and return information about it.
    
    Returns:
        A dictionary with installation status and version if available
    """
    if not sherlock_installed():
        return {
            "status": "not_installed",
            "message": "Sherlock is not installed. Please install it with: pip install sherlock-project"
        }
    
    try:
        # Try to get version information
        process = subprocess.run(["sherlock", "--version"], 
                                capture_output=True, 
                                text=True)
        
        if process.returncode == 0:
            version = process.stdout.strip()
            return {
                "status": "installed",
                "version": version
            }
        else:
            return {
                "status": "installed",
                "message": "Sherlock is installed but version information is unavailable"
            }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error checking Sherlock installation: {str(e)}"
        }

if __name__ == "__main__":
    mcp.run(transport="stdio")