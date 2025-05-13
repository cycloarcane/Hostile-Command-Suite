#!/usr/bin/env python3
"""
tiktok_comments.py — FastMCP tool that searches for comments made by a specific TikTok user
using the unofficial TikTok API by David Teather.
"""
from fastmcp import FastMCP
import subprocess
import shutil
import asyncio
import json
import os
from typing import List, Dict, Union, Optional, Any

mcp = FastMCP("tiktok")  # tool route will be /tiktok

def tiktok_api_installed() -> bool:
    """Check if unofficial TikTok API and its dependencies are installed and available."""
    try:
        # Check if TikTokApi module is installed
        subprocess.check_call(["python", "-c", "import TikTokApi"], 
                             stderr=subprocess.DEVNULL, 
                             stdout=subprocess.DEVNULL)
        
        # Check if playwright is installed
        subprocess.check_call(["python", "-c", "import playwright"], 
                             stderr=subprocess.DEVNULL, 
                             stdout=subprocess.DEVNULL)
                             
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

def check_playwright_browser_installed() -> bool:
    """Check if playwright browsers are installed."""
    try:
        # Check if playwright browsers are installed
        result = subprocess.run(["python", "-m", "playwright", "install", "--help"], 
                               stderr=subprocess.PIPE, 
                               stdout=subprocess.PIPE,
                               text=True)
        return "Usage: install [options] [browser...]" in result.stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

@mcp.tool()
def check_tiktok_installation() -> Dict[str, str]:
    """
    Check if the unofficial TikTok API is properly installed and return information about it.
    
    Returns:
        A dictionary with installation status and installation instructions if needed
    """
    if not tiktok_api_installed():
        return {
            "status": "not_installed",
            "message": "The unofficial TikTok API is not installed. Please install it with: pip install TikTokApi"
        }
    
    if not check_playwright_browser_installed():
        return {
            "status": "missing_browsers",
            "message": "Playwright browsers are not installed. Please install them with: python -m playwright install"
        }
    
    try:
        # Try to get version information
        import TikTokApi
        version = TikTokApi.__version__
        return {
            "status": "installed",
            "version": version,
            "message": "TikTok API is installed and ready to use."
        }
    except (ImportError, AttributeError):
        return {
            "status": "installed",
            "message": "TikTok API is installed but version information is unavailable."
        }

@mcp.tool()
async def get_user_comments(username: str, target_username: str, 
                           max_videos: Optional[int] = 10,
                           max_comments_per_video: Optional[int] = 100,
                           use_proxy: bool = False,
                           proxy: Optional[str] = None,
                           ms_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Search for comments made by a specific user on another user's videos.
    
    Args:
        username: The TikTok username whose videos to search through
        target_username: The username whose comments we're looking for
        max_videos: Maximum number of videos to search through (default: 10)
        max_comments_per_video: Maximum number of comments to fetch per video (default: 100)
        use_proxy: Whether to use a proxy for the requests (default: False)
        proxy: Proxy URL in format http://user:pass@ip:port (default: None)
        ms_token: TikTok ms_token from browser cookies for authentication (default: None)
        
    Returns:
        A dictionary with search results and status
    """
    if not tiktok_api_installed():
        return {
            "status": "error",
            "message": "TikTok API is not installed. Please install it with: pip install TikTokApi"
        }
    
    if not check_playwright_browser_installed():
        return {
            "status": "error",
            "message": "Playwright browsers are not installed. Please install them with: python -m playwright install"
        }
    
    if not username or not target_username:
        return {
            "status": "error", 
            "message": "Both username and target_username must be provided"
        }
    
    # Import here to avoid issues if TikTokApi is not installed
    from TikTokApi import TikTokApi
    
    try:
        ms_token_list = [ms_token] if ms_token else None
        proxy_settings = {"http": proxy, "https": proxy} if use_proxy and proxy else None
        found_comments = []
        
        # Since the API is async, we need to run the async search function
        async with TikTokApi() as api:
            # Create session
            try:
                await api.create_sessions(
                    ms_tokens=ms_token_list, 
                    num_sessions=1,
                    sleep_after=3,
                    proxies=proxy_settings if proxy_settings else None
                )
            except Exception as e:
                return {
                    "status": "error",
                    "message": f"Failed to create TikTok session: {str(e)}"
                }
            
            # Step 1: Get user profile
            try:
                user = api.user(username=username)
                user_data = await user.info()
            except Exception as e:
                return {
                    "status": "error",
                    "message": f"Failed to fetch user information for {username}: {str(e)}"
                }
                
            # Step 2: Get videos from this user
            try:
                videos = []
                count = 0
                
                async for video in user.videos(count=max_videos):
                    videos.append(video)
                    count += 1
                    if count >= max_videos:
                        break
                        
                if not videos:
                    return {
                        "status": "error",
                        "message": f"No videos found for user {username}"
                    }
            except Exception as e:
                return {
                    "status": "error",
                    "message": f"Failed to fetch videos for {username}: {str(e)}"
                }
                
            # Step 3: Get comments for each video and filter by target_username
            total_comments_checked = 0
            for video in videos:
                try:
                    # Get video info to display in results
                    video_info = {
                        "id": video.id,
                        "description": getattr(video, "desc", "No description"),
                        "create_time": getattr(video, "create_time", "Unknown"),
                        "stats": getattr(video, "stats", {})
                    }
                    
                    # Get comments
                    comments_count = 0
                    async for comment in video.comments(count=max_comments_per_video):
                        total_comments_checked += 1
                        comment_author_username = getattr(comment.author, "username", None)
                        
                        # Check if this comment is from our target user
                        if comment_author_username and comment_author_username.lower() == target_username.lower():
                            # Get basic comment data
                            comment_data = {
                                "id": comment.id,
                                "text": comment.text,
                                "likes_count": comment.likes_count,
                                "create_time": comment.as_dict.get("create_time", "Unknown"),
                                "video_id": video.id,
                                "video_desc": video_info["description"],
                                "replied_to": comment.as_dict.get("reply_to_reply_id", "0") != "0",
                                "raw_data": comment.as_dict
                            }
                            found_comments.append(comment_data)
                            
                        comments_count += 1
                        if comments_count >= max_comments_per_video:
                            break
                            
                except Exception as e:
                    # Continue with next video if there's an error
                    continue
                    
        # Return the results
        return {
            "status": "success",
            "username": username,
            "target_username": target_username,
            "total_videos_searched": len(videos),
            "total_comments_checked": total_comments_checked,
            "total_comments_found": len(found_comments),
            "comments": found_comments
        }
            
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error running TikTok API: {str(e)}"
        }

@mcp.tool()
async def search_comments_by_keyword(username: str, keyword: str, 
                                   max_videos: Optional[int] = 10,
                                   max_comments_per_video: Optional[int] = 100,
                                   case_sensitive: bool = False,
                                   use_proxy: bool = False,
                                   proxy: Optional[str] = None,
                                   ms_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Search for comments containing a specific keyword on a user's videos.
    
    Args:
        username: The TikTok username whose videos to search through
        keyword: The keyword to search for in comments
        max_videos: Maximum number of videos to search through (default: 10)
        max_comments_per_video: Maximum number of comments to fetch per video (default: 100)
        case_sensitive: Whether to perform case-sensitive keyword matching (default: False)
        use_proxy: Whether to use a proxy for the requests (default: False)
        proxy: Proxy URL in format http://user:pass@ip:port (default: None)
        ms_token: TikTok ms_token from browser cookies for authentication (default: None)
        
    Returns:
        A dictionary with search results and status
    """
    if not tiktok_api_installed():
        return {
            "status": "error",
            "message": "TikTok API is not installed. Please install it with: pip install TikTokApi"
        }
    
    if not check_playwright_browser_installed():
        return {
            "status": "error",
            "message": "Playwright browsers are not installed. Please install them with: python -m playwright install"
        }
    
    if not username or not keyword:
        return {
            "status": "error", 
            "message": "Both username and keyword must be provided"
        }
    
    # Import here to avoid issues if TikTokApi is not installed
    from TikTokApi import TikTokApi
    
    try:
        ms_token_list = [ms_token] if ms_token else None
        proxy_settings = {"http": proxy, "https": proxy} if use_proxy and proxy else None
        found_comments = []
        
        # Since the API is async, we need to run the async search function
        async with TikTokApi() as api:
            # Create session
            try:
                await api.create_sessions(
                    ms_tokens=ms_token_list, 
                    num_sessions=1,
                    sleep_after=3,
                    proxies=proxy_settings if proxy_settings else None
                )
            except Exception as e:
                return {
                    "status": "error",
                    "message": f"Failed to create TikTok session: {str(e)}"
                }
            
            # Step 1: Get user profile
            try:
                user = api.user(username=username)
                user_data = await user.info()
            except Exception as e:
                return {
                    "status": "error",
                    "message": f"Failed to fetch user information for {username}: {str(e)}"
                }
                
            # Step 2: Get videos from this user
            try:
                videos = []
                count = 0
                
                async for video in user.videos(count=max_videos):
                    videos.append(video)
                    count += 1
                    if count >= max_videos:
                        break
                        
                if not videos:
                    return {
                        "status": "error",
                        "message": f"No videos found for user {username}"
                    }
            except Exception as e:
                return {
                    "status": "error",
                    "message": f"Failed to fetch videos for {username}: {str(e)}"
                }
                
            # Step 3: Get comments for each video and filter by keyword
            total_comments_checked = 0
            for video in videos:
                try:
                    # Get video info to display in results
                    video_info = {
                        "id": video.id,
                        "description": getattr(video, "desc", "No description"),
                        "create_time": getattr(video, "create_time", "Unknown"),
                        "stats": getattr(video, "stats", {})
                    }
                    
                    # Get comments
                    comments_count = 0
                    async for comment in video.comments(count=max_comments_per_video):
                        total_comments_checked += 1
                        
                        comment_text = comment.text or ""
                        
                        # Check if keyword is in the comment text
                        if ((case_sensitive and keyword in comment_text) or 
                            (not case_sensitive and keyword.lower() in comment_text.lower())):
                            # Get basic comment data
                            comment_data = {
                                "id": comment.id,
                                "text": comment.text,
                                "likes_count": comment.likes_count,
                                "create_time": comment.as_dict.get("create_time", "Unknown"),
                                "video_id": video.id,
                                "video_desc": video_info["description"],
                                "author_username": getattr(comment.author, "username", "Unknown"),
                                "raw_data": comment.as_dict
                            }
                            found_comments.append(comment_data)
                            
                        comments_count += 1
                        if comments_count >= max_comments_per_video:
                            break
                            
                except Exception as e:
                    # Continue with next video if there's an error
                    continue
                    
        # Return the results
        return {
            "status": "success",
            "username": username,
            "keyword": keyword,
            "total_videos_searched": len(videos),
            "total_comments_checked": total_comments_checked,
            "total_comments_found": len(found_comments),
            "comments": found_comments
        }
            
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error running TikTok API: {str(e)}"
        }

if __name__ == "__main__":
    mcp.run(transport="stdio")