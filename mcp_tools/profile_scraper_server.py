#!/usr/bin/env python3
"""
Profile Scraper MCP Server
Follows Sherlock links to extract profile information for OSINT investigations
"""

import asyncio
import json
import re
import urllib.parse
from typing import Dict, List, Any, Optional
import requests
from bs4 import BeautifulSoup
import time

class ProfileScraper:
    """Scrapes profile pages found by Sherlock for additional intelligence"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.timeout = 10
        self.max_retries = 2
    
    def extract_profile_data(self, url: str, html: str, platform: str) -> Dict[str, Any]:
        """Extract structured data from profile HTML"""
        soup = BeautifulSoup(html, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.decompose()
        
        profile_data = {
            "url": url,
            "platform": platform,
            "text_content": "",
            "bio": "",
            "display_name": "",
            "follower_count": None,
            "following_count": None,
            "post_count": None,
            "links": [],
            "images": [],
            "verified": False,
            "location": "",
            "joined_date": ""
        }
        
        # Get clean text content
        text = soup.get_text()
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        profile_data["text_content"] = ' '.join(chunk for chunk in chunks if chunk)[:2000]  # Limit to 2000 chars
        
        # Platform-specific extraction
        if "twitter.com" in url or "x.com" in url:
            profile_data.update(self._extract_twitter_data(soup))
        elif "instagram.com" in url:
            profile_data.update(self._extract_instagram_data(soup))
        elif "github.com" in url:
            profile_data.update(self._extract_github_data(soup))
        elif "linkedin.com" in url:
            profile_data.update(self._extract_linkedin_data(soup))
        elif "facebook.com" in url:
            profile_data.update(self._extract_facebook_data(soup))
        elif "reddit.com" in url:
            profile_data.update(self._extract_reddit_data(soup))
        else:
            profile_data.update(self._extract_generic_data(soup))
        
        # Extract links
        links = soup.find_all('a', href=True)
        for link in links[:10]:  # Limit to first 10 links
            href = link.get('href')
            if href and (href.startswith('http') or href.startswith('www')):
                profile_data["links"].append({
                    "url": href,
                    "text": link.get_text().strip()[:100]
                })
        
        return profile_data
    
    def _extract_twitter_data(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Extract Twitter/X specific data"""
        data = {}
        
        # Display name
        display_name_elem = soup.find(attrs={"data-testid": "UserName"})
        if display_name_elem:
            data["display_name"] = display_name_elem.get_text().strip()
        
        # Bio
        bio_elem = soup.find(attrs={"data-testid": "UserDescription"})
        if bio_elem:
            data["bio"] = bio_elem.get_text().strip()
        
        # Follower counts
        following_elem = soup.find(attrs={"data-testid": "UserFollowing"})
        if following_elem:
            text = following_elem.get_text()
            numbers = re.findall(r'[\d,]+', text)
            if numbers:
                data["following_count"] = numbers[0].replace(',', '')
        
        followers_elem = soup.find(attrs={"data-testid": "UserFollowers"})
        if followers_elem:
            text = followers_elem.get_text()
            numbers = re.findall(r'[\d,]+', text)
            if numbers:
                data["follower_count"] = numbers[0].replace(',', '')
        
        # Verified status
        verified_elem = soup.find(attrs={"data-testid": "icon-verified"})
        data["verified"] = verified_elem is not None
        
        return data
    
    def _extract_instagram_data(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Extract Instagram specific data"""
        data = {}
        
        # Look for JSON-LD data
        script_tags = soup.find_all('script', type='application/ld+json')
        for script in script_tags:
            try:
                json_data = json.loads(script.string)
                if isinstance(json_data, dict):
                    data["display_name"] = json_data.get("name", "")
                    data["bio"] = json_data.get("description", "")
            except:
                pass
        
        return data
    
    def _extract_github_data(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Extract GitHub specific data"""
        data = {}
        
        # Display name
        name_elem = soup.find("span", class_="p-name")
        if name_elem:
            data["display_name"] = name_elem.get_text().strip()
        
        # Bio
        bio_elem = soup.find("div", class_="p-note")
        if bio_elem:
            data["bio"] = bio_elem.get_text().strip()
        
        # Location
        location_elem = soup.find("span", class_="p-label")
        if location_elem:
            data["location"] = location_elem.get_text().strip()
        
        # Repository count
        repo_elem = soup.find("span", class_="Counter")
        if repo_elem:
            data["post_count"] = repo_elem.get_text().strip()
        
        return data
    
    def _extract_linkedin_data(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Extract LinkedIn specific data"""
        data = {}
        
        # Display name
        h1_tags = soup.find_all("h1")
        for h1 in h1_tags:
            text = h1.get_text().strip()
            if len(text) > 2 and len(text) < 100:
                data["display_name"] = text
                break
        
        return data
    
    def _extract_facebook_data(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Extract Facebook specific data"""
        data = {}
        
        # Facebook often blocks scrapers, so limited extraction
        title = soup.find("title")
        if title:
            data["display_name"] = title.get_text().strip()
        
        return data
    
    def _extract_reddit_data(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Extract Reddit specific data"""
        data = {}
        
        # Post karma
        karma_elements = soup.find_all(string=re.compile(r'\d+\s+karma'))
        if karma_elements:
            data["post_count"] = karma_elements[0].strip()
        
        return data
    
    def _extract_generic_data(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Extract generic profile data for unknown platforms"""
        data = {}
        
        # Try to find display name from title or h1
        title = soup.find("title")
        if title:
            data["display_name"] = title.get_text().strip()[:100]
        
        h1 = soup.find("h1")
        if h1 and not data.get("display_name"):
            data["display_name"] = h1.get_text().strip()[:100]
        
        # Look for bio in meta description
        meta_desc = soup.find("meta", attrs={"name": "description"})
        if meta_desc:
            data["bio"] = meta_desc.get("content", "")[:500]
        
        return data
    
    async def scrape_profile(self, url: str) -> Dict[str, Any]:
        """Scrape a single profile URL"""
        try:
            # Basic URL validation and cleanup
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Extract platform name
            parsed_url = urllib.parse.urlparse(url)
            platform = parsed_url.netloc.lower()
            if platform.startswith('www.'):
                platform = platform[4:]
            
            # Make request with retry logic
            for attempt in range(self.max_retries + 1):
                try:
                    response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                    if response.status_code == 200:
                        break
                    elif response.status_code in [429, 503]:  # Rate limited
                        if attempt < self.max_retries:
                            time.sleep(2 ** attempt)  # Exponential backoff
                            continue
                except requests.RequestException as e:
                    if attempt < self.max_retries:
                        time.sleep(1)
                        continue
                    raise e
            
            if response.status_code != 200:
                return {
                    "url": url,
                    "platform": platform,
                    "status": "error",
                    "error": f"HTTP {response.status_code}",
                    "accessible": False
                }
            
            # Extract profile data
            profile_data = self.extract_profile_data(url, response.text, platform)
            profile_data.update({
                "status": "success",
                "accessible": True,
                "response_size": len(response.text),
                "content_type": response.headers.get('content-type', '')
            })
            
            return profile_data
            
        except Exception as e:
            return {
                "url": url,
                "platform": platform if 'platform' in locals() else "unknown",
                "status": "error",
                "error": str(e),
                "accessible": False
            }
    
    async def scrape_multiple_profiles(self, urls: List[str], max_concurrent: int = 3) -> List[Dict[str, Any]]:
        """Scrape multiple profile URLs with concurrency control"""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scrape_with_semaphore(url):
            async with semaphore:
                return await self.scrape_profile(url)
        
        tasks = [scrape_with_semaphore(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append({
                    "url": urls[i],
                    "status": "error",
                    "error": str(result),
                    "accessible": False
                })
            else:
                processed_results.append(result)
        
        return processed_results

# MCP Server Implementation
class ProfileScraperMCPServer:
    """MCP Server for profile scraping functionality"""
    
    def __init__(self):
        self.scraper = ProfileScraper()
    
    async def scrape_sherlock_profiles(self, sherlock_results: List[str], max_profiles: int = 5) -> Dict[str, Any]:
        """
        Scrape profiles found by Sherlock
        
        Args:
            sherlock_results: List of URLs found by Sherlock
            max_profiles: Maximum number of profiles to scrape
        """
        try:
            # Limit number of profiles to scrape
            urls_to_scrape = sherlock_results[:max_profiles]
            
            if not urls_to_scrape:
                return {
                    "tool": "profile_scraper",
                    "status": "error",
                    "error": "No URLs provided to scrape"
                }
            
            # Scrape profiles
            profile_results = await self.scraper.scrape_multiple_profiles(urls_to_scrape)
            
            # Summarize results
            successful_scrapes = [p for p in profile_results if p.get("status") == "success"]
            failed_scrapes = [p for p in profile_results if p.get("status") == "error"]
            
            # Extract interesting findings
            interesting_profiles = []
            for profile in successful_scrapes:
                if (profile.get("bio") or 
                    profile.get("display_name") or 
                    profile.get("links") or
                    profile.get("location")):
                    interesting_profiles.append(profile)
            
            return {
                "tool": "profile_scraper",
                "status": "success",
                "total_scraped": len(profile_results),
                "successful_scrapes": len(successful_scrapes),
                "failed_scrapes": len(failed_scrapes),
                "interesting_profiles": len(interesting_profiles),
                "profiles": profile_results,
                "summary": f"Scraped {len(successful_scrapes)}/{len(urls_to_scrape)} profiles successfully, found {len(interesting_profiles)} with useful information"
            }
            
        except Exception as e:
            return {
                "tool": "profile_scraper",
                "status": "error",
                "error": str(e)
            }
    
    async def check_profile_scraper_status(self) -> Dict[str, Any]:
        """Check if profile scraper is working"""
        try:
            # Test with a simple request
            test_result = await self.scraper.scrape_profile("https://httpbin.org/get")
            return {
                "tool": "profile_scraper",
                "status": "operational",
                "test_result": test_result.get("status") == "success"
            }
        except Exception as e:
            return {
                "tool": "profile_scraper", 
                "status": "error",
                "error": str(e)
            }

# For direct testing
if __name__ == "__main__":
    async def test_scraper():
        server = ProfileScraperMCPServer()
        
        # Test with some example URLs
        test_urls = [
            "https://github.com/torvalds",
            "https://httpbin.org/get"
        ]
        
        result = await server.scrape_sherlock_profiles(test_urls, max_profiles=2)
        print(json.dumps(result, indent=2))
    
    asyncio.run(test_scraper())