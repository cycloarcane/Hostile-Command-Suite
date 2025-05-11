#!/usr/bin/env python3
"""
nmap_ptest.py — FastMCP tool that performs network scanning using Nmap
"""
from fastmcp import FastMCP
import subprocess
import shutil
import json
import os
import re
from typing import List, Dict, Union, Optional, Any

mcp = FastMCP("nmap")  # tool route will be /nmap

def nmap_installed() -> bool:
    """Check if Nmap is installed and available."""
    return shutil.which("nmap") is not None

def parse_nmap_output(output: str) -> Dict[str, Any]:
    """Parse the nmap text output into a structured format."""
    result = {
        "hosts": [],
        "summary": "",
        "scan_stats": {}
    }
    
    # Extract scan summary from last line
    summary_match = re.search(r'# Nmap done at .* -- (.*)', output)
    if summary_match:
        result["summary"] = summary_match.group(1)
    
    # Extract scan stats
    stats_match = re.search(r'(\d+) IP address(?:es)? \((\d+) host(?:s)? up\) scanned in ([\d.]+) seconds', output)
    if stats_match:
        result["scan_stats"] = {
            "total_ips": int(stats_match.group(1)),
            "hosts_up": int(stats_match.group(2)),
            "scan_time": float(stats_match.group(3))
        }
    
    # Find hosts with open ports
    host_blocks = re.finditer(r'Nmap scan report for ([^\n]+)(?:\n[^\n]+)*?(?:^PORT\s+STATE\s+SERVICE(?:\s+VERSION)?)(.*?)(?=(?:^Nmap scan report|\Z))', 
                              output, re.MULTILINE | re.DOTALL)
    
    for host_block in host_blocks:
        host_info = {
            "target": host_block.group(1).strip(),
            "ports": []
        }
        
        # Parse ip and hostname
        if "(" in host_info["target"] and ")" in host_info["target"]:
            match = re.search(r'(.*) \(([^)]+)\)', host_info["target"])
            if match:
                host_info["hostname"] = match.group(1).strip()
                host_info["ip"] = match.group(2).strip()
        else:
            # It's just an IP
            host_info["ip"] = host_info["target"]
            host_info["hostname"] = ""
        
        # Extract OS detection info
        os_match = re.search(r'OS details: (.*)', host_block.group(0))
        if os_match:
            host_info["os"] = os_match.group(1).strip()
        
        # Extract port information
        port_lines = re.finditer(r'^(\d+)\/(\w+)\s+(\w+)\s+(\S+)(?:\s+(.*))?$', 
                                host_block.group(2), 
                                re.MULTILINE)
        
        for port_line in port_lines:
            port_info = {
                "port": int(port_line.group(1)),
                "protocol": port_line.group(2),
                "state": port_line.group(3),
                "service": port_line.group(4),
                "version": port_line.group(5) if port_line.group(5) else ""
            }
            host_info["ports"].append(port_info)
        
        result["hosts"].append(host_info)
    
    return result

@mcp.tool()
def scan_target(target: str, scan_type: str = "basic", ports: Optional[str] = None, 
               timeout: Optional[int] = 300, service_detection: bool = False,
               os_detection: bool = False, script_scan: bool = False) -> Dict[str, Any]:
    """
    Scan a network target using Nmap.
    
    Args:
        target: The target to scan (IP, hostname, CIDR notation)
        scan_type: Type of scan to perform: "basic" (SYN), "connect" (full TCP), "quick" (fewer ports), "comprehensive" (more thorough)
        ports: Specific ports to scan (e.g., "22,80,443" or "1-1000")
        timeout: Timeout in seconds for the scan to complete
        service_detection: Enable service version detection (slower)
        os_detection: Enable OS detection (requires privileged access)
        script_scan: Run default scripts for additional information
        
    Returns:
        A dictionary with scan results and status
    """
    if not nmap_installed():
        return {
            "status": "error",
            "message": "Nmap is not installed. Please install it first."
        }
    
    if not target:
        return {
            "status": "error", 
            "message": "Invalid target provided"
        }
    
    # Build nmap command based on options
    cmd = ["nmap"]
    
    # Set scan type
    if scan_type == "basic":
        cmd.append("-sT")       # TCP connect scan instead of SYN scan to avoid root requirement
    elif scan_type == "connect":
        cmd.append("-sT")       # TCP connect scan
    elif scan_type == "quick":
        cmd.extend(["-T4", "-F"])  # Fast timing, fewer ports
    elif scan_type == "comprehensive":
        cmd.extend(["-sT", "-T4", "-A"])  # Using connect scan instead of SYN scan
    
    # Add optional features
    if service_detection:
        cmd.append("-sV")
    
    if os_detection:
        cmd.append("-O")
    
    if script_scan:
        cmd.append("-sC")
    
    # Add port specification if provided
    if ports:
        cmd.extend(["-p", ports])
    
    # Add target
    cmd.append(target)
    
    try:
        # Run nmap command and capture the output
        process = subprocess.run(cmd, 
                                capture_output=True, 
                                text=True, 
                                timeout=timeout)
        
        if process.returncode != 0 and not "Warning" in process.stderr:
            return {
                "status": "error",
                "message": f"Nmap scan failed: {process.stderr}",
                "command": " ".join(cmd)
            }
        
        # Parse output into structured format
        result = parse_nmap_output(process.stdout)
        
        return {
            "status": "success",
            "target": target,
            "scan_type": scan_type,
            "command": " ".join(cmd),
            "results": result,
            "raw_output": process.stdout,  # Include raw nmap output
            "warnings": process.stderr if process.stderr else None
        }
            
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "message": f"Nmap process timed out after {timeout} seconds",
            "command": " ".join(cmd)
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error running Nmap: {str(e)}",
            "command": " ".join(cmd)
        }

@mcp.tool()
def check_nmap_installation() -> Dict[str, str]:
    """
    Check if Nmap is properly installed and return information about it.
    
    Returns:
        A dictionary with installation status and version if available
    """
    if not nmap_installed():
        return {
            "status": "not_installed",
            "message": "Nmap is not installed. Please install it first."
        }
    
    try:
        # Try to get version information
        process = subprocess.run(["nmap", "--version"], 
                                capture_output=True, 
                                text=True)
        
        if process.returncode == 0:
            # Extract version from first line
            version_match = re.search(r'Nmap version ([^\s]+)', process.stdout)
            version = version_match.group(1) if version_match else "unknown"
            
            return {
                "status": "installed",
                "version": version,
                "details": process.stdout.strip()
            }
        else:
            return {
                "status": "installed",
                "message": "Nmap is installed but version information is unavailable"
            }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error checking Nmap installation: {str(e)}"
        }

@mcp.tool()
def scan_network(network: str, scan_speed: str = "normal", 
                top_ports: int = 100, ping_scan: bool = False,
                timeout: Optional[int] = 600) -> Dict[str, Any]:
    """
    Scan an entire network to discover hosts and open ports.
    
    Args:
        network: The network to scan in CIDR notation (e.g., "192.168.1.0/24")
        scan_speed: Speed of the scan: "slow", "normal", "fast", "insane"
        top_ports: Number of most common ports to scan (e.g., 100, 1000)
        ping_scan: Only perform ping scan (faster, but less info)
        timeout: Timeout in seconds for the scan to complete
        
    Returns:
        A dictionary with scan results and status
    """
    if not nmap_installed():
        return {
            "status": "error",
            "message": "Nmap is not installed. Please install it first."
        }
    
    if not network or not re.match(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$', network):
        return {
            "status": "error", 
            "message": "Invalid network provided. Please use CIDR notation (e.g., 192.168.1.0/24)."
        }
    
    # Build nmap command based on options
    cmd = ["nmap"]
    
    # Set scan speed
    if scan_speed == "slow":
        cmd.append("-T2")
    elif scan_speed == "normal":
        cmd.append("-T3")
    elif scan_speed == "fast":
        cmd.append("-T4")
    elif scan_speed == "insane":
        cmd.append("-T5")
    
    # Set port options
    if ping_scan:
        cmd.append("-sn")  # Ping scan only, no port scan
    else:
        cmd.extend(["--top-ports", str(top_ports)])
    
    # Add target network
    cmd.append(network)
    
    try:
        # Run nmap command and capture the output
        process = subprocess.run(cmd, 
                                capture_output=True, 
                                text=True, 
                                timeout=timeout)
        
        if process.returncode != 0 and not "Warning" in process.stderr:
            return {
                "status": "error",
                "message": f"Network scan failed: {process.stderr}",
                "command": " ".join(cmd)
            }
        
        # Parse output into structured format
        result = parse_nmap_output(process.stdout)
        
        return {
            "status": "success",
            "network": network,
            "scan_type": "ping_only" if ping_scan else f"top_{top_ports}_ports",
            "command": " ".join(cmd),
            "results": result,
            "raw_output": process.stdout,  # Include raw nmap output
            "hosts_found": len(result["hosts"]),
            "warnings": process.stderr if process.stderr else None
        }
            
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "message": f"Network scan timed out after {timeout} seconds",
            "command": " ".join(cmd)
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error scanning network: {str(e)}",
            "command": " ".join(cmd)
        }

if __name__ == "__main__":
    mcp.run(transport="stdio")