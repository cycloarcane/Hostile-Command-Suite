#!/usr/bin/env python3
"""
social_osint.py — FastMCP tool for social media intelligence gathering and analysis

FastMCP tools
────────────
    search_social_profiles(username, platforms=None, ...)
    analyze_social_footprint(target, ...)
    find_social_connections(username, platform, ...)
    monitor_social_mentions(keywords, platforms, ...)

Returns
───────
    {
      "status": "success",
      "username": "johndoe",
      "profiles": [...],
      "connections": [...],
      "activity_analysis": {...}
    }

Dependencies
────────────
    pip install requests beautifulsoup4 python-dateutil

Setup
─────
    For enhanced features, get API keys from:
    1. Twitter API v2: https://developer.twitter.com/en/docs/twitter-api
    2. Reddit API: https://www.reddit.com/dev/api/
    3. GitHub API: https://docs.github.com/en/rest
    
    Set environment variables:
    - TWITTER_BEARER_TOKEN
    - REDDIT_CLIENT_ID, REDDIT_CLIENT_SECRET
    - GITHUB_TOKEN
"""

import json
import os
import sys
import time
import logging
import hashlib
import re
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urljoin, urlparse, quote
import base64

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    from dateutil import parser as date_parser
    DATEUTIL_AVAILABLE = True
except ImportError:
    DATEUTIL_AVAILABLE = False

from fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("social_osint")

mcp = FastMCP("social")  # MCP route → /social
_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
os.makedirs(_CACHE_DIR, exist_ok=True)

# API configuration
TWITTER_BEARER_TOKEN = os.environ.get("TWITTER_BEARER_TOKEN", "")
REDDIT_CLIENT_ID = os.environ.get("REDDIT_CLIENT_ID", "")
REDDIT_CLIENT_SECRET = os.environ.get("REDDIT_CLIENT_SECRET", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

# Platform configurations
SOCIAL_PLATFORMS = {
    "twitter": {
        "url_pattern": "https://twitter.com/{}",
        "api_endpoint": "https://api.twitter.com/2/users/by/username/{}",
        "requires_api": True
    },
    "github": {
        "url_pattern": "https://github.com/{}",
        "api_endpoint": "https://api.github.com/users/{}",
        "requires_api": False
    },
    "reddit": {
        "url_pattern": "https://reddit.com/user/{}",
        "api_endpoint": "https://www.reddit.com/user/{}/about.json",
        "requires_api": False
    },
    "instagram": {
        "url_pattern": "https://instagram.com/{}",
        "api_endpoint": None,
        "requires_api": False
    },
    "linkedin": {
        "url_pattern": "https://linkedin.com/in/{}",
        "api_endpoint": None,
        "requires_api": False
    },
    "facebook": {
        "url_pattern": "https://facebook.com/{}",
        "api_endpoint": None,
        "requires_api": False
    },
    "youtube": {
        "url_pattern": "https://youtube.com/@{}",
        "api_endpoint": None,
        "requires_api": False
    },
    "tiktok": {
        "url_pattern": "https://tiktok.com/@{}",
        "api_endpoint": None,
        "requires_api": False
    },
    "discord": {
        "url_pattern": "https://discord.com/users/{}",
        "api_endpoint": None,
        "requires_api": False
    },
    "telegram": {
        "url_pattern": "https://t.me/{}",
        "api_endpoint": None,
        "requires_api": False
    }
}

# Rate limiting
_LAST_CALL_AT: float = 0.0
DEFAULT_RATE_LIMIT = 0.5  # Requests per second


def _rate_limit(calls_per_second: float = DEFAULT_RATE_LIMIT) -> None:
    """Rate limiting for API calls"""
    global _LAST_CALL_AT
    
    min_interval = 1.0 / calls_per_second
    wait = _LAST_CALL_AT + min_interval - time.time()
    if wait > 0:
        time.sleep(wait)
    _LAST_CALL_AT = time.time()


def _get_cache_key(operation: str, **kwargs) -> str:
    """Generate a cache key"""
    serializable_kwargs = {
        k: v for k, v in kwargs.items() 
        if isinstance(v, (str, int, float, bool, type(None)))
    }
    cache_str = f"{operation}_{json.dumps(serializable_kwargs, sort_keys=True)}"
    return hashlib.md5(cache_str.encode()).hexdigest()


def _get_from_cache(cache_key: str, max_age: int = 3600) -> Optional[Dict[str, Any]]:
    """Try to get results from cache"""
    cache_file = os.path.join(_CACHE_DIR, f"{cache_key}.json")
    
    if os.path.exists(cache_file):
        file_age = time.time() - os.path.getmtime(cache_file)
        if file_age < max_age:
            try:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
    return None


def _save_to_cache(cache_key: str, data: Dict[str, Any]) -> None:
    """Save results to cache"""
    cache_file = os.path.join(_CACHE_DIR, f"{cache_key}.json")
    try:
        with open(cache_file, 'w') as f:
            json.dump(data, f)
    except IOError as e:
        logger.warning(f"Cache write error: {e}")


def _create_session() -> requests.Session:
    """Create a requests session with retry strategy"""
    session = requests.Session()
    
    retry_strategy = Retry(
        total=3,
        status_forcelist=[429, 500, 502, 503, 504],
        method_whitelist=["HEAD", "GET", "OPTIONS"],
        backoff_factor=1
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Common headers to appear more like a real browser
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    })
    
    return session


def _validate_username(username: str) -> bool:
    """Validate username format"""
    if not username or len(username) < 1 or len(username) > 50:
        return False
    
    # Basic username validation - alphanumeric, underscore, dash
    pattern = r'^[a-zA-Z0-9_.-]+$'
    return bool(re.match(pattern, username))


def _check_url_exists(session: requests.Session, url: str, timeout: int = 10) -> Dict[str, Any]:
    """Check if a URL exists and extract basic information"""
    try:
        _rate_limit()
        
        response = session.head(url, timeout=timeout, allow_redirects=True)
        
        if response.status_code == 200:
            return {
                "exists": True,
                "status_code": response.status_code,
                "final_url": response.url,
                "headers": dict(response.headers)
            }
        elif response.status_code == 405:  # Method not allowed, try GET
            response = session.get(url, timeout=timeout, allow_redirects=True)
            return {
                "exists": response.status_code == 200,
                "status_code": response.status_code,
                "final_url": response.url,
                "headers": dict(response.headers)
            }
        else:
            return {
                "exists": False,
                "status_code": response.status_code,
                "final_url": response.url
            }
            
    except requests.exceptions.RequestException as e:
        return {
            "exists": False,
            "error": str(e)
        }


def _extract_profile_data(session: requests.Session, url: str, platform: str) -> Dict[str, Any]:
    """Extract profile data from social media page"""
    if not BS4_AVAILABLE:
        return {"error": "BeautifulSoup4 not available for content parsing"}
    
    try:
        _rate_limit()
        
        response = session.get(url, timeout=15)
        if response.status_code != 200:
            return {"error": f"HTTP {response.status_code}"}
        
        soup = BeautifulSoup(response.content, 'html.parser')
        profile_data = {}
        
        # Extract common profile information
        # Title
        title = soup.find('title')
        if title:
            profile_data['page_title'] = title.get_text().strip()
        
        # Meta description
        meta_desc = soup.find('meta', attrs={'name': 'description'}) or soup.find('meta', attrs={'property': 'og:description'})
        if meta_desc:
            profile_data['description'] = meta_desc.get('content', '').strip()
        
        # Profile image
        og_image = soup.find('meta', attrs={'property': 'og:image'})
        if og_image:
            profile_data['profile_image'] = og_image.get('content', '').strip()
        
        # Platform-specific extraction
        if platform == "github":
            # GitHub specific extraction
            profile_name = soup.find('span', class_='p-name')
            if profile_name:
                profile_data['full_name'] = profile_name.get_text().strip()
            
            bio = soup.find('div', class_='p-note')
            if bio:
                profile_data['bio'] = bio.get_text().strip()
            
            # Repository count, followers, etc.
            stats = soup.find_all('span', class_='Counter')
            if len(stats) >= 2:
                profile_data['repositories'] = stats[0].get_text().strip()
                profile_data['followers'] = stats[1].get_text().strip() if len(stats) > 1 else None
        
        elif platform == "twitter":
            # Twitter/X specific extraction (limited due to login requirements)
            # Most Twitter data now requires authentication
            pass
        
        elif platform == "instagram":
            # Instagram specific extraction (limited due to login requirements)
            pass
        
        # Generic extraction for other platforms
        # Look for common profile indicators
        possible_names = soup.find_all(['h1', 'h2'], string=re.compile(r'[A-Za-z\s]+'))
        if possible_names:
            profile_data['possible_name'] = possible_names[0].get_text().strip()
        
        return profile_data
        
    except Exception as e:
        return {"error": f"Profile extraction failed: {str(e)}"}


@mcp.tool()
def check_social_tools() -> Dict[str, Union[str, Dict[str, bool]]]:
    """
    Check which social media analysis tools and dependencies are available.
    
    Returns:
        A dictionary with tool availability status
    """
    deps = {
        "requests": REQUESTS_AVAILABLE,
        "beautifulsoup4": BS4_AVAILABLE,
        "dateutil": DATEUTIL_AVAILABLE,
        "twitter_api": bool(TWITTER_BEARER_TOKEN),
        "reddit_api": bool(REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET),
        "github_api": bool(GITHUB_TOKEN)
    }
    
    missing = []
    if not deps["requests"]:
        missing.append("requests: pip install requests")
    if not deps["beautifulsoup4"]:
        missing.append("beautifulsoup4: pip install beautifulsoup4")
    if not deps["dateutil"]:
        missing.append("dateutil: pip install python-dateutil")
    
    return {
        "status": "ok" if deps["requests"] and deps["beautifulsoup4"] else "missing_dependencies",
        "dependencies": deps,
        "installation_instructions": missing,
        "supported_platforms": list(SOCIAL_PLATFORMS.keys()),
        "notes": {
            "api_keys_optional": "API keys improve data quality and rate limits",
            "some_platforms_limited": "Some platforms require login or have anti-scraping measures"
        }
    }


@mcp.tool()
def search_social_profiles(
    username: str,
    platforms: Optional[List[str]] = None,
    check_variations: bool = True,
    include_profile_data: bool = False,
    use_cache: bool = True,
    cache_max_age: int = 3600
) -> Dict[str, Any]:
    """
    Search for social media profiles across multiple platforms.
    
    Args:
        username: Username to search for
        platforms: List of platforms to check (default: all)
        check_variations: Whether to check common username variations
        include_profile_data: Whether to extract profile data from found profiles
        use_cache: Whether to use caching
        cache_max_age: Maximum age of cached results in seconds
        
    Returns:
        Dict with found social media profiles
    """
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    if not _validate_username(username):
        return {
            "status": "error",
            "message": "Invalid username format"
        }
    
    if platforms is None:
        platforms = list(SOCIAL_PLATFORMS.keys())
    
    # Validate platforms
    invalid_platforms = [p for p in platforms if p not in SOCIAL_PLATFORMS]
    if invalid_platforms:
        return {
            "status": "error",
            "message": f"Invalid platforms: {', '.join(invalid_platforms)}"
        }
    
    # Check cache
    if use_cache:
        cache_key = _get_cache_key(
            "social_profiles", 
            username=username, 
            platforms=sorted(platforms),
            check_variations=check_variations,
            include_profile_data=include_profile_data
        )
        cached_result = _get_from_cache(cache_key, cache_max_age)
        if cached_result:
            return cached_result
    
    result = {
        "status": "success",
        "username": username,
        "platforms_checked": platforms,
        "profiles_found": [],
        "profiles_not_found": [],
        "variations_checked": [],
        "summary": {}
    }
    
    session = _create_session()
    usernames_to_check = [username]
    
    # Generate username variations if requested
    if check_variations:
        variations = []
        
        # Common variations
        variations.extend([
            username.lower(),
            username.upper(),
            username.replace('_', ''),
            username.replace('-', ''),
            username.replace('.', ''),
            f"{username}1",
            f"{username}2",
            f"_{username}",
            f"{username}_",
            f"{username}.official"
        ])
        
        # Remove duplicates and original
        variations = list(set(variations) - {username})
        usernames_to_check.extend(variations[:5])  # Limit variations to avoid too many requests
        result["variations_checked"] = variations[:5]
    
    # Check each platform for each username variation
    for check_username in usernames_to_check:
        for platform in platforms:
            platform_config = SOCIAL_PLATFORMS[platform]
            profile_url = platform_config["url_pattern"].format(check_username)
            
            logger.info(f"Checking {platform} for username: {check_username}")
            
            # Check if profile exists
            url_check = _check_url_exists(session, profile_url)
            
            profile_info = {
                "platform": platform,
                "username": check_username,
                "url": profile_url,
                "exists": url_check.get("exists", False),
                "status_code": url_check.get("status_code"),
                "is_variation": check_username != username
            }
            
            if url_check.get("exists"):
                profile_info["final_url"] = url_check.get("final_url", profile_url)
                
                # Extract profile data if requested
                if include_profile_data:
                    profile_data = _extract_profile_data(session, profile_url, platform)
                    if profile_data and "error" not in profile_data:
                        profile_info["profile_data"] = profile_data
                
                result["profiles_found"].append(profile_info)
            else:
                result["profiles_not_found"].append(profile_info)
            
            # Add small delay between requests to be respectful
            time.sleep(0.5)
    
    # Generate summary
    platforms_with_profiles = set(p["platform"] for p in result["profiles_found"])
    result["summary"] = {
        "total_profiles_found": len(result["profiles_found"]),
        "platforms_with_profiles": list(platforms_with_profiles),
        "total_platforms_checked": len(platforms),
        "success_rate": len(platforms_with_profiles) / len(platforms) if platforms else 0,
        "variations_found": len([p for p in result["profiles_found"] if p["is_variation"]])
    }
    
    # Cache successful results
    if use_cache:
        _save_to_cache(cache_key, result)
    
    return result


@mcp.tool()
def analyze_github_profile(
    username: str,
    include_repositories: bool = True,
    include_activity: bool = True,
    max_repos: int = 20,
    use_cache: bool = True
) -> Dict[str, Any]:
    """
    Perform detailed analysis of a GitHub profile using GitHub API.
    
    Args:
        username: GitHub username to analyze
        include_repositories: Whether to analyze repositories
        include_activity: Whether to analyze recent activity
        max_repos: Maximum number of repositories to analyze
        use_cache: Whether to use caching
        
    Returns:
        Dict with detailed GitHub profile analysis
    """
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    if not _validate_username(username):
        return {
            "status": "error",
            "message": "Invalid username format"
        }
    
    # Check cache
    if use_cache:
        cache_key = _get_cache_key(
            "github_analysis", 
            username=username, 
            include_repositories=include_repositories,
            include_activity=include_activity,
            max_repos=max_repos
        )
        cached_result = _get_from_cache(cache_key, 3600)  # 1 hour cache
        if cached_result:
            return cached_result
    
    result = {
        "status": "success",
        "username": username,
        "profile": {},
        "repositories": [],
        "activity_analysis": {},
        "intelligence": {}
    }
    
    session = _create_session()
    
    # Add GitHub token if available
    if GITHUB_TOKEN:
        session.headers.update({"Authorization": f"token {GITHUB_TOKEN}"})
    
    try:
        # Get user profile
        _rate_limit()
        
        user_url = f"https://api.github.com/users/{username}"
        response = session.get(user_url, timeout=15)
        
        if response.status_code == 404:
            return {
                "status": "error",
                "message": f"GitHub user '{username}' not found"
            }
        elif response.status_code != 200:
            return {
                "status": "error",
                "message": f"GitHub API error: HTTP {response.status_code}"
            }
        
        user_data = response.json()
        
        # Extract profile information
        result["profile"] = {
            "login": user_data.get("login"),
            "name": user_data.get("name"),
            "bio": user_data.get("bio"),
            "company": user_data.get("company"),
            "location": user_data.get("location"),
            "email": user_data.get("email"),
            "blog": user_data.get("blog"),
            "twitter_username": user_data.get("twitter_username"),
            "public_repos": user_data.get("public_repos", 0),
            "public_gists": user_data.get("public_gists", 0),
            "followers": user_data.get("followers", 0),
            "following": user_data.get("following", 0),
            "created_at": user_data.get("created_at"),
            "updated_at": user_data.get("updated_at"),
            "avatar_url": user_data.get("avatar_url"),
            "html_url": user_data.get("html_url")
        }
        
        # Get repositories if requested
        if include_repositories and user_data.get("public_repos", 0) > 0:
            _rate_limit()
            
            repos_url = f"https://api.github.com/users/{username}/repos"
            params = {
                "sort": "updated",
                "per_page": min(max_repos, 100)
            }
            
            repos_response = session.get(repos_url, params=params, timeout=15)
            if repos_response.status_code == 200:
                repos_data = repos_response.json()
                
                for repo in repos_data:
                    repo_info = {
                        "name": repo.get("name"),
                        "full_name": repo.get("full_name"),
                        "description": repo.get("description"),
                        "language": repo.get("language"),
                        "stars": repo.get("stargazers_count", 0),
                        "forks": repo.get("forks_count", 0),
                        "watchers": repo.get("watchers_count", 0),
                        "size": repo.get("size", 0),
                        "created_at": repo.get("created_at"),
                        "updated_at": repo.get("updated_at"),
                        "pushed_at": repo.get("pushed_at"),
                        "html_url": repo.get("html_url"),
                        "clone_url": repo.get("clone_url"),
                        "topics": repo.get("topics", []),
                        "is_fork": repo.get("fork", False),
                        "has_issues": repo.get("has_issues", False),
                        "has_wiki": repo.get("has_wiki", False)
                    }
                    result["repositories"].append(repo_info)
        
        # Analyze activity and generate intelligence
        if include_activity:
            activity_analysis = {
                "account_age_days": 0,
                "recent_activity": False,
                "popular_languages": {},
                "total_stars_received": 0,
                "collaboration_score": 0,
                "activity_level": "unknown"
            }
            
            # Calculate account age
            if result["profile"]["created_at"]:
                try:
                    if DATEUTIL_AVAILABLE:
                        created_date = date_parser.parse(result["profile"]["created_at"])
                        account_age = (date_parser.parse("now") - created_date).days
                        activity_analysis["account_age_days"] = account_age
                except:
                    pass
            
            # Analyze repositories
            if result["repositories"]:
                languages = {}
                total_stars = 0
                total_forks = 0
                
                for repo in result["repositories"]:
                    # Count languages
                    lang = repo.get("language")
                    if lang:
                        languages[lang] = languages.get(lang, 0) + 1
                    
                    # Sum stars and forks
                    total_stars += repo.get("stars", 0)
                    total_forks += repo.get("forks", 0)
                
                activity_analysis["popular_languages"] = dict(sorted(languages.items(), key=lambda x: x[1], reverse=True)[:5])
                activity_analysis["total_stars_received"] = total_stars
                activity_analysis["total_forks_received"] = total_forks
                activity_analysis["collaboration_score"] = result["profile"]["followers"] + total_forks
                
                # Determine activity level
                repo_count = len(result["repositories"])
                if repo_count >= 20 and total_stars >= 50:
                    activity_analysis["activity_level"] = "very_high"
                elif repo_count >= 10 and total_stars >= 10:
                    activity_analysis["activity_level"] = "high"
                elif repo_count >= 5:
                    activity_analysis["activity_level"] = "medium"
                elif repo_count >= 1:
                    activity_analysis["activity_level"] = "low"
                else:
                    activity_analysis["activity_level"] = "minimal"
            
            result["activity_analysis"] = activity_analysis
        
        # Generate intelligence summary
        intelligence = {
            "developer_profile": True,
            "skill_indicators": [],
            "professional_indicators": [],
            "contact_methods": [],
            "risk_indicators": []
        }
        
        # Skill indicators
        if result["activity_analysis"].get("popular_languages"):
            intelligence["skill_indicators"].extend([
                f"Proficient in {lang}" for lang in list(result["activity_analysis"]["popular_languages"].keys())[:3]
            ])
        
        # Professional indicators
        if result["profile"].get("company"):
            intelligence["professional_indicators"].append(f"Works at {result['profile']['company']}")
        
        if result["profile"].get("location"):
            intelligence["professional_indicators"].append(f"Located in {result['profile']['location']}")
        
        # Contact methods
        if result["profile"].get("email"):
            intelligence["contact_methods"].append(f"Email: {result['profile']['email']}")
        
        if result["profile"].get("blog"):
            intelligence["contact_methods"].append(f"Blog/Website: {result['profile']['blog']}")
        
        if result["profile"].get("twitter_username"):
            intelligence["contact_methods"].append(f"Twitter: @{result['profile']['twitter_username']}")
        
        result["intelligence"] = intelligence
        
        # Cache successful results
        if use_cache:
            _save_to_cache(cache_key, result)
        
        return result
        
    except requests.exceptions.RequestException as e:
        return {
            "status": "error",
            "message": f"GitHub API request failed: {str(e)}"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"GitHub analysis failed: {str(e)}"
        }


@mcp.tool()
def find_social_connections(
    username: str,
    platform: str = "github",
    connection_types: List[str] = ["followers", "following"],
    max_connections: int = 50
) -> Dict[str, Any]:
    """
    Find social connections for a user on a specific platform.
    
    Args:
        username: Username to find connections for
        platform: Platform to search on
        connection_types: Types of connections to find
        max_connections: Maximum number of connections to return per type
        
    Returns:
        Dict with social connections information
    """
    if not REQUESTS_AVAILABLE:
        return {
            "status": "error",
            "message": "requests not available. Install with: pip install requests"
        }
    
    if platform not in SOCIAL_PLATFORMS:
        return {
            "status": "error",
            "message": f"Unsupported platform: {platform}"
        }
    
    if not _validate_username(username):
        return {
            "status": "error",
            "message": "Invalid username format"
        }
    
    result = {
        "status": "success",
        "username": username,
        "platform": platform,
        "connections": {},
        "analysis": {}
    }
    
    session = _create_session()
    
    # Add authentication if available
    if platform == "github" and GITHUB_TOKEN:
        session.headers.update({"Authorization": f"token {GITHUB_TOKEN}"})
    
    try:
        # Currently only GitHub connections are implemented
        if platform == "github":
            for connection_type in connection_types:
                if connection_type not in ["followers", "following"]:
                    continue
                
                _rate_limit()
                
                url = f"https://api.github.com/users/{username}/{connection_type}"
                params = {"per_page": min(max_connections, 100)}
                
                response = session.get(url, params=params, timeout=15)
                
                if response.status_code == 200:
                    connections_data = response.json()
                    
                    connections = []
                    for user in connections_data:
                        connection_info = {
                            "login": user.get("login"),
                            "html_url": user.get("html_url"),
                            "avatar_url": user.get("avatar_url"),
                            "type": user.get("type")  # User or Organization
                        }
                        connections.append(connection_info)
                    
                    result["connections"][connection_type] = connections
                
                elif response.status_code == 404:
                    return {
                        "status": "error",
                        "message": f"User '{username}' not found on {platform}"
                    }
                else:
                    result["connections"][connection_type] = {
                        "error": f"HTTP {response.status_code}"
                    }
        
        # Generate analysis
        analysis = {
            "total_connections": sum(len(conns) for conns in result["connections"].values() if isinstance(conns, list)),
            "connection_ratio": 0,
            "notable_connections": []
        }
        
        # Calculate follower/following ratio for GitHub
        if "followers" in result["connections"] and "following" in result["connections"]:
            followers = len(result["connections"]["followers"]) if isinstance(result["connections"]["followers"], list) else 0
            following = len(result["connections"]["following"]) if isinstance(result["connections"]["following"], list) else 0
            
            if following > 0:
                analysis["connection_ratio"] = followers / following
            
            # Look for notable connections (organizations, high-profile users)
            for connection_type, connections in result["connections"].items():
                if isinstance(connections, list):
                    for conn in connections:
                        if conn.get("type") == "Organization":
                            analysis["notable_connections"].append({
                                "username": conn["login"],
                                "type": "organization",
                                "connection_type": connection_type
                            })
        
        result["analysis"] = analysis
        
        return result
        
    except requests.exceptions.RequestException as e:
        return {
            "status": "error",
            "message": f"API request failed: {str(e)}"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Connection analysis failed: {str(e)}"
        }


@mcp.tool()
def comprehensive_social_analysis(
    target: str,
    include_profile_extraction: bool = True,
    include_connections: bool = False,
    max_platforms: int = 10
) -> Dict[str, Any]:
    """
    Perform comprehensive social media analysis for a target.
    
    Args:
        target: Username or identifier to analyze
        include_profile_extraction: Whether to extract detailed profile data
        include_connections: Whether to analyze social connections
        max_platforms: Maximum number of platforms to check
        
    Returns:
        Dict with comprehensive social media intelligence
    """
    if not _validate_username(target):
        return {
            "status": "error",
            "message": "Invalid target format"
        }
    
    result = {
        "status": "success",
        "target": target,
        "timestamp": time.time(),
        "profile_search": {},
        "detailed_analysis": {},
        "connections_analysis": {},
        "intelligence_summary": {}
    }
    
    # Step 1: Search for profiles across platforms
    logger.info(f"Searching for social profiles for: {target}")
    
    platforms_to_check = list(SOCIAL_PLATFORMS.keys())[:max_platforms]
    profile_search = search_social_profiles(
        target,
        platforms=platforms_to_check,
        check_variations=True,
        include_profile_data=include_profile_extraction,
        use_cache=True
    )
    
    result["profile_search"] = profile_search
    
    # Step 2: Detailed analysis for found profiles
    found_platforms = [p["platform"] for p in profile_search.get("profiles_found", [])]
    
    for platform in found_platforms:
        if platform == "github":
            logger.info(f"Performing detailed GitHub analysis for: {target}")
            github_analysis = analyze_github_profile(
                target,
                include_repositories=True,
                include_activity=True,
                use_cache=True
            )
            if github_analysis.get("status") == "success":
                result["detailed_analysis"]["github"] = github_analysis
        
        # Add other platform-specific detailed analysis here
        # For now, we'll use the basic profile data from the search
    
    # Step 3: Connections analysis (if requested)
    if include_connections:
        for platform in found_platforms:
            if platform == "github":
                logger.info(f"Analyzing GitHub connections for: {target}")
                connections = find_social_connections(
                    target,
                    platform="github",
                    connection_types=["followers", "following"],
                    max_connections=25
                )
                if connections.get("status") == "success":
                    result["connections_analysis"]["github"] = connections
    
    # Step 4: Generate intelligence summary
    intelligence = {
        "digital_footprint_score": 0,
        "professional_indicators": [],
        "personal_indicators": [],
        "technical_skills": [],
        "contact_information": [],
        "risk_assessment": {
            "privacy_level": "unknown",
            "information_exposure": "low"
        },
        "recommendations": []
    }
    
    # Calculate digital footprint score
    platforms_found = len(profile_search.get("profiles_found", []))
    intelligence["digital_footprint_score"] = min(platforms_found * 10, 100)
    
    # Extract indicators from detailed analysis
    if "github" in result["detailed_analysis"]:
        github_data = result["detailed_analysis"]["github"]
        
        # Professional indicators
        profile = github_data.get("profile", {})
        if profile.get("company"):
            intelligence["professional_indicators"].append(f"Company: {profile['company']}")
        if profile.get("location"):
            intelligence["personal_indicators"].append(f"Location: {profile['location']}")
        
        # Technical skills
        activity = github_data.get("activity_analysis", {})
        languages = activity.get("popular_languages", {})
        intelligence["technical_skills"] = [f"{lang} ({count} repos)" for lang, count in languages.items()]
        
        # Contact information
        github_intel = github_data.get("intelligence", {})
        intelligence["contact_information"].extend(github_intel.get("contact_methods", []))
    
    # Privacy assessment
    total_info_points = len(intelligence["professional_indicators"]) + len(intelligence["personal_indicators"]) + len(intelligence["contact_information"])
    
    if total_info_points >= 5:
        intelligence["risk_assessment"]["information_exposure"] = "high"
        intelligence["risk_assessment"]["privacy_level"] = "low"
        intelligence["recommendations"].append("Consider reviewing privacy settings across platforms")
    elif total_info_points >= 2:
        intelligence["risk_assessment"]["information_exposure"] = "medium"
        intelligence["risk_assessment"]["privacy_level"] = "medium"
    else:
        intelligence["risk_assessment"]["information_exposure"] = "low"
        intelligence["risk_assessment"]["privacy_level"] = "high"
    
    # General recommendations
    if platforms_found >= 5:
        intelligence["recommendations"].append("Strong digital presence - monitor for unauthorized use")
    if not intelligence["contact_information"]:
        intelligence["recommendations"].append("Limited contact information found - may indicate privacy-conscious user")
    
    result["intelligence_summary"] = intelligence
    
    return result


if __name__ == "__main__":
    mcp.run(transport="stdio")