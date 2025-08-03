#!/usr/bin/env python3
"""
Google Search MCP Server - Advanced Google Search OSINT Tool with Browser Automation
Part of Hostile Command Suite OSINT Package
"""

import json
import asyncio
import os
import time
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional
from mcp.server import Server
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from bs4 import BeautifulSoup
import urllib.parse

# Create MCP server instance
server = Server("google-search")

def check_selenium_available() -> bool:
    """Check if selenium and chromedriver are available"""
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        return True
    except ImportError:
        return False

def setup_chrome_driver(headless: bool = False) -> webdriver.Chrome:
    """Setup Chrome driver with appropriate options for OSINT work"""
    options = Options()
    if headless:
        options.add_argument("--headless")
    
    # Standard privacy and security options
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-plugins")
    options.add_argument("--disable-images")  # Speed up loading
    options.add_argument("--disable-javascript")  # Basic scraping doesn't need JS
    
    # User agent rotation for stealth
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ]
    options.add_argument(f"--user-agent={user_agents[int(time.time()) % len(user_agents)]}")
    
    return webdriver.Chrome(options=options)

def save_target_data(target: str, data_type: str, content: str, metadata: Dict[str, Any] = None) -> str:
    """Save investigation data to organized folders"""
    # Create target-specific directory
    safe_target = "".join(c for c in target if c.isalnum() or c in (' ', '-', '_')).rstrip()
    target_dir = Path(f"investigations/{safe_target}")
    target_dir.mkdir(parents=True, exist_ok=True)
    
    # Create subdirectories
    (target_dir / "text").mkdir(exist_ok=True)
    (target_dir / "images").mkdir(exist_ok=True)
    (target_dir / "metadata").mkdir(exist_ok=True)
    
    timestamp = int(time.time())
    
    if data_type == "text":
        file_path = target_dir / "text" / f"search_results_{timestamp}.txt"
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
    elif data_type == "image":
        file_path = target_dir / "images" / f"image_{timestamp}.jpg"
        # For images, content should be image data
        with open(file_path, 'wb') as f:
            f.write(content)
    elif data_type == "metadata":
        file_path = target_dir / "metadata" / f"metadata_{timestamp}.json"
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(metadata or {}, f, indent=2)
    
    return str(file_path)

def download_image(url: str, target_dir: Path) -> Optional[str]:
    """Download image from URL"""
    try:
        response = requests.get(url, timeout=10, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        if response.status_code == 200:
            timestamp = int(time.time())
            filename = f"image_{timestamp}.jpg"
            file_path = target_dir / "images" / filename
            with open(file_path, 'wb') as f:
                f.write(response.content)
            return str(file_path)
    except Exception as e:
        print(f"Failed to download image from {url}: {e}")
    return None

@server.list_tools()
async def handle_list_tools() -> List[types.Tool]:
    """List available Google search tools"""
    return [
        types.Tool(
            name="google_search",
            description="Advanced Google search with browser automation for comprehensive OSINT intelligence gathering",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query to execute on Google"
                    },
                    "target": {
                        "type": "string", 
                        "description": "Target identifier for organizing saved data"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default: 10)",
                        "default": 10
                    },
                    "include_images": {
                        "type": "boolean",
                        "description": "Whether to also search for and download images (default: true)",
                        "default": True
                    },
                    "save_data": {
                        "type": "boolean",
                        "description": "Whether to save results to target folders (default: true)",
                        "default": True
                    },
                    "search_type": {
                        "type": "string",
                        "description": "Type of Google search (web, images, news)",
                        "enum": ["web", "images", "news"],
                        "default": "web"
                    }
                },
                "required": ["query", "target"]
            }
        ),
        types.Tool(
            name="google_image_search",
            description="Specialized Google Images search for visual OSINT intelligence",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Image search query"
                    },
                    "target": {
                        "type": "string",
                        "description": "Target identifier for organizing saved data"
                    },
                    "max_images": {
                        "type": "integer", 
                        "description": "Maximum number of images to download (default: 5)",
                        "default": 5
                    },
                    "save_images": {
                        "type": "boolean",
                        "description": "Whether to download and save images (default: true)",
                        "default": True
                    }
                },
                "required": ["query", "target"]
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> List[types.TextContent]:
    """Handle tool calls for Google search operations"""
    
    if not check_selenium_available():
        return [types.TextContent(
            type="text",
            text="Error: Selenium not available. Please install selenium and chromedriver."
        )]
    
    if name == "google_search":
        return await google_search(arguments)
    elif name == "google_image_search":
        return await google_image_search(arguments)
    else:
        return [types.TextContent(
            type="text", 
            text=f"Unknown tool: {name}"
        )]

async def google_search(args: Dict[str, Any]) -> List[types.TextContent]:
    """Perform Google web search with browser automation"""
    query = args["query"]
    target = args["target"]
    max_results = args.get("max_results", 10)
    include_images = args.get("include_images", True)
    save_data = args.get("save_data", True)
    search_type = args.get("search_type", "web")
    
    driver = None
    results = []
    
    try:
        driver = setup_chrome_driver(headless=False)
        
        # Construct Google search URL
        if search_type == "images":
            search_url = f"https://www.google.com/search?tbm=isch&q={urllib.parse.quote(query)}"
        elif search_type == "news":
            search_url = f"https://www.google.com/search?tbm=nws&q={urllib.parse.quote(query)}"
        else:
            search_url = f"https://www.google.com/search?q={urllib.parse.quote(query)}"
        
        print(f"🌐 Opening Google search for: {query}")
        driver.get(search_url)
        print("⏳ Waiting for page to load...")
        time.sleep(3)  # Let page load
        
        # Accept cookies if prompted (common anti-bot measure)
        try:
            accept_button = WebDriverWait(driver, 3).until(
                EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Accept') or contains(text(), 'I agree')]"))
            )
            accept_button.click()
            time.sleep(1)
        except TimeoutException:
            pass  # No cookie banner
        
        # Extract search results
        if search_type == "images":
            results = extract_image_results(driver, max_results)
        else:
            results = extract_web_results(driver, max_results)
        
        # Save data if requested
        saved_files = []
        if save_data and results:
            # Save text results
            text_content = format_results_for_saving(results, query, search_type)
            text_file = save_target_data(target, "text", text_content)
            saved_files.append(text_file)
            
            # Save metadata
            metadata = {
                "query": query,
                "search_type": search_type,
                "timestamp": int(time.time()),
                "results_count": len(results),
                "target": target
            }
            metadata_file = save_target_data(target, "metadata", "", metadata)
            saved_files.append(metadata_file)
            
            # Download images if requested and results contain image URLs
            if include_images and search_type != "images":  # For web/news results
                target_dir = Path(f"investigations/{target.replace(' ', '_')}")
                target_dir.mkdir(parents=True, exist_ok=True)
                (target_dir / "images").mkdir(exist_ok=True)
                
                for result in results[:3]:  # Limit to first 3 results
                    if "image_url" in result:
                        img_file = download_image(result["image_url"], target_dir)
                        if img_file:
                            saved_files.append(img_file)
        
        # Format response
        response_text = f"Google {search_type.title()} Search Results for: {query}\n"
        response_text += f"Target: {target}\n"
        response_text += f"Results found: {len(results)}\n\n"
        
        for i, result in enumerate(results, 1):
            response_text += f"{i}. {result.get('title', 'No title')}\n"
            response_text += f"   URL: {result.get('url', 'No URL')}\n"
            if result.get('snippet'):
                response_text += f"   Description: {result['snippet']}\n"
            response_text += "\n"
        
        if saved_files:
            response_text += f"\nData saved to files:\n"
            for file_path in saved_files:
                response_text += f"- {file_path}\n"
        
        return [types.TextContent(type="text", text=response_text)]
        
    except Exception as e:
        return [types.TextContent(
            type="text",
            text=f"Error performing Google search: {str(e)}"
        )]
    finally:
        if driver:
            driver.quit()

async def google_image_search(args: Dict[str, Any]) -> List[types.TextContent]:
    """Perform specialized Google Images search"""
    query = args["query"]
    target = args["target"] 
    max_images = args.get("max_images", 5)
    save_images = args.get("save_images", True)
    
    driver = None
    
    try:
        driver = setup_chrome_driver(headless=False)
        
        # Navigate to Google Images
        search_url = f"https://www.google.com/search?tbm=isch&q={urllib.parse.quote(query)}"
        print(f"🌐 Opening Google search for: {query}")
        driver.get(search_url)
        print("⏳ Waiting for page to load...")
        time.sleep(3)
        
        # Extract image results
        image_results = extract_image_results(driver, max_images)
        
        # Download images if requested
        downloaded_files = []
        if save_images and image_results:
            target_dir = Path(f"investigations/{target.replace(' ', '_')}")
            target_dir.mkdir(parents=True, exist_ok=True)
            (target_dir / "images").mkdir(exist_ok=True)
            
            for result in image_results:
                if result.get("image_url"):
                    img_file = download_image(result["image_url"], target_dir)
                    if img_file:
                        downloaded_files.append(img_file)
        
        # Format response
        response_text = f"Google Images Search Results for: {query}\n"
        response_text += f"Target: {target}\n"
        response_text += f"Images found: {len(image_results)}\n\n"
        
        for i, result in enumerate(image_results, 1):
            response_text += f"{i}. {result.get('title', 'No title')}\n"
            response_text += f"   Source: {result.get('source_url', 'No source')}\n"
            response_text += f"   Image URL: {result.get('image_url', 'No image URL')}\n\n"
        
        if downloaded_files:
            response_text += f"\nImages downloaded:\n"
            for file_path in downloaded_files:
                response_text += f"- {file_path}\n"
        
        return [types.TextContent(type="text", text=response_text)]
        
    except Exception as e:
        return [types.TextContent(
            type="text",
            text=f"Error performing Google image search: {str(e)}"
        )]
    finally:
        if driver:
            driver.quit()

def extract_web_results(driver: webdriver.Chrome, max_results: int) -> List[Dict[str, Any]]:
    """Extract web search results from Google search page"""
    results = []
    
    try:
        # Find search result containers
        search_results = driver.find_elements(By.CSS_SELECTOR, "div.g")
        
        for result in search_results[:max_results]:
            try:
                # Extract title
                title_elem = result.find_element(By.CSS_SELECTOR, "h3")
                title = title_elem.text if title_elem else "No title"
                
                # Extract URL
                link_elem = result.find_element(By.CSS_SELECTOR, "a")
                url = link_elem.get_attribute("href") if link_elem else "No URL"
                
                # Extract snippet/description
                snippet_elem = result.find_elements(By.CSS_SELECTOR, "span, div")
                snippet = ""
                for elem in snippet_elem:
                    text = elem.text.strip()
                    if text and len(text) > 20:  # Get first substantial text
                        snippet = text
                        break
                
                results.append({
                    "title": title,
                    "url": url,
                    "snippet": snippet[:300] if snippet else "No description"
                })
                
            except NoSuchElementException:
                continue
    
    except Exception as e:
        print(f"Error extracting web results: {e}")
    
    return results

def extract_image_results(driver: webdriver.Chrome, max_images: int) -> List[Dict[str, Any]]:
    """Extract image search results from Google Images"""
    results = []
    
    try:
        # Find image containers
        image_elements = driver.find_elements(By.CSS_SELECTOR, "img[src]")
        
        for img in image_elements[:max_images * 2]:  # Get more than needed to filter
            try:
                src = img.get_attribute("src")
                alt = img.get_attribute("alt") or "No description"
                
                # Skip small/icon images and data URLs
                if (src and 
                    not src.startswith("data:") and 
                    "google" not in src.lower() and
                    len(alt) > 3):
                    
                    # Try to find source website
                    parent = img.find_element(By.XPATH, "./../..")
                    source_link = None
                    try:
                        source_elem = parent.find_element(By.CSS_SELECTOR, "a")
                        source_link = source_elem.get_attribute("href")
                    except NoSuchElementException:
                        source_link = "Unknown source"
                    
                    results.append({
                        "title": alt,
                        "image_url": src,
                        "source_url": source_link
                    })
                    
                    if len(results) >= max_images:
                        break
                        
            except Exception as e:
                continue
    
    except Exception as e:
        print(f"Error extracting image results: {e}")
    
    return results

def format_results_for_saving(results: List[Dict[str, Any]], query: str, search_type: str) -> str:
    """Format search results for saving to file"""
    content = f"Google {search_type.title()} Search Results\n"
    content += f"Query: {query}\n"
    content += f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
    content += f"Results: {len(results)}\n"
    content += "=" * 50 + "\n\n"
    
    for i, result in enumerate(results, 1):
        content += f"{i}. {result.get('title', 'No title')}\n"
        content += f"URL: {result.get('url', result.get('source_url', 'No URL'))}\n"
        if result.get('snippet'):
            content += f"Description: {result['snippet']}\n"
        if result.get('image_url'):
            content += f"Image URL: {result['image_url']}\n"
        content += "-" * 30 + "\n\n"
    
    return content

async def main():
    """Main entry point for the MCP server"""
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="google-search",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=None,
                    experimental_capabilities={}
                )
            )
        )

if __name__ == "__main__":
    asyncio.run(main())