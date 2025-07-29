#!/usr/bin/env python3
"""
Link Analyzer MCP Server
Deep analysis of URLs including GitHub profiles, social media, and generic web content
"""

import asyncio
import json
import re
import urllib.parse
from typing import Dict, List, Any, Optional
import requests
from bs4 import BeautifulSoup
import time

class LinkAnalyzer:
    """Analyzes URLs for detailed intelligence extraction"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.timeout = 15
        self.max_retries = 2
    
    def analyze_github_profile(self, soup: BeautifulSoup, url: str) -> Dict[str, Any]:
        """Deep analysis of GitHub profiles"""
        analysis = {
            "platform": "github",
            "profile_type": "developer",
            "technical_info": {},
            "repositories": [],
            "activity_metrics": {},
            "social_connections": [],
            "security_indicators": {}
        }
        
        try:
            # Extract comprehensive profile information
            
            # Bio and basic info
            bio_elem = soup.find("div", class_="p-note user-profile-bio")
            if bio_elem:
                analysis["bio"] = bio_elem.get_text().strip()
            
            # Location
            location_elem = soup.find("span", class_="p-label")
            if location_elem:
                analysis["location"] = location_elem.get_text().strip()
            
            # Company/Organization
            company_elem = soup.find("span", class_="p-org")
            if company_elem:
                analysis["organization"] = company_elem.get_text().strip()
            
            # Website/Blog
            website_elem = soup.find("a", class_="Link--primary")
            if website_elem and website_elem.get("href"):
                analysis["website"] = website_elem.get("href")
            
            # Repository information
            repo_elements = soup.find_all("div", class_="Box-row")
            for repo in repo_elements[:10]:  # Limit to top 10 repos
                repo_name_elem = repo.find("a", {"itemprop": "name codeRepository"})
                if repo_name_elem:
                    repo_info = {
                        "name": repo_name_elem.get_text().strip(),
                        "url": "https://github.com" + repo_name_elem.get("href", "")
                    }
                    
                    # Description
                    desc_elem = repo.find("p", {"itemprop": "description"})
                    if desc_elem:
                        repo_info["description"] = desc_elem.get_text().strip()
                    
                    # Language
                    lang_elem = repo.find("span", {"itemprop": "programmingLanguage"})
                    if lang_elem:
                        repo_info["language"] = lang_elem.get_text().strip()
                    
                    # Stars
                    star_elem = repo.find("a", href=re.compile(r"/stargazers"))
                    if star_elem:
                        star_text = star_elem.get_text().strip()
                        repo_info["stars"] = star_text
                    
                    analysis["repositories"].append(repo_info)
            
            # Activity metrics
            contrib_elem = soup.find("div", class_="js-yearly-contributions")
            if contrib_elem:
                contrib_text = contrib_elem.get_text()
                # Extract contribution count
                contrib_match = re.search(r'(\d+)\s+contributions', contrib_text)
                if contrib_match:
                    analysis["activity_metrics"]["yearly_contributions"] = contrib_match.group(1)
            
            # Follower/Following counts
            followers_elem = soup.find("a", href=re.compile(r"/followers"))
            if followers_elem:
                followers_text = followers_elem.get_text().strip()
                analysis["activity_metrics"]["followers"] = re.sub(r'[^\d.]', '', followers_text)
            
            following_elem = soup.find("a", href=re.compile(r"/following"))
            if following_elem:
                following_text = following_elem.get_text().strip()
                analysis["activity_metrics"]["following"] = re.sub(r'[^\d.]', '', following_text)
            
            # Organizations
            org_elements = soup.find_all("a", href=re.compile(r"^/orgs/"))
            for org in org_elements[:5]:  # Limit to 5 orgs
                org_name = org.get("aria-label", "").replace("@", "")
                if org_name:
                    analysis["social_connections"].append({
                        "type": "organization",
                        "name": org_name,
                        "url": "https://github.com" + org.get("href", "")
                    })
            
            # Security analysis
            analysis["security_indicators"] = self._analyze_github_security(analysis)
            
            # Technical analysis from repositories
            analysis["technical_info"] = self._analyze_technical_profile(analysis["repositories"])
            
        except Exception as e:
            analysis["extraction_error"] = str(e)
        
        return analysis
    
    def _analyze_github_security(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security aspects of GitHub profile"""
        security_analysis = {
            "risk_level": "LOW",
            "security_concerns": [],
            "positive_indicators": [],
            "recommendations": []
        }
        
        try:
            # Check for security-related keywords in bio
            bio = profile_data.get("bio", "").lower()
            security_keywords = ["security", "pentesting", "red team", "blue team", "cybersecurity", 
                               "vulnerability", "exploit", "hacking", "malware", "forensics"]
            
            found_security_keywords = [kw for kw in security_keywords if kw in bio]
            if found_security_keywords:
                security_analysis["security_focus"] = found_security_keywords
                security_analysis["positive_indicators"].append("Security professional background")
            
            # Analyze repository topics for security tools
            security_repos = []
            for repo in profile_data.get("repositories", []):
                repo_name = repo.get("name", "").lower()
                repo_desc = repo.get("description", "").lower()
                
                if any(kw in repo_name or kw in repo_desc for kw in security_keywords):
                    security_repos.append(repo["name"])
            
            if security_repos:
                security_analysis["security_repositories"] = security_repos
                security_analysis["positive_indicators"].append(f"Security-related repositories: {len(security_repos)}")
            
            # Check activity level
            yearly_contribs = profile_data.get("activity_metrics", {}).get("yearly_contributions", "0")
            try:
                contrib_count = int(yearly_contribs.replace(",", ""))
                if contrib_count > 1000:
                    security_analysis["positive_indicators"].append("High activity level (1000+ contributions)")
                elif contrib_count < 50:
                    security_analysis["security_concerns"].append("Low activity level")
            except:
                pass
            
            # Organization analysis
            orgs = profile_data.get("social_connections", [])
            if len(orgs) > 3:
                security_analysis["positive_indicators"].append("Active in multiple organizations")
            
            # Determine overall risk level
            if len(security_analysis["security_concerns"]) > len(security_analysis["positive_indicators"]):
                security_analysis["risk_level"] = "MEDIUM"
            elif found_security_keywords and security_repos:
                security_analysis["risk_level"] = "HIGH"  # High capability, not necessarily threat
            
        except Exception as e:
            security_analysis["analysis_error"] = str(e)
        
        return security_analysis
    
    def _analyze_technical_profile(self, repositories: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze technical capabilities from repositories"""
        tech_analysis = {
            "primary_languages": {},
            "technology_stack": [],
            "expertise_areas": [],
            "project_types": []
        }
        
        try:
            # Language frequency analysis
            languages = {}
            for repo in repositories:
                lang = repo.get("language")
                if lang:
                    languages[lang] = languages.get(lang, 0) + 1
            
            # Sort by frequency
            sorted_langs = sorted(languages.items(), key=lambda x: x[1], reverse=True)
            tech_analysis["primary_languages"] = dict(sorted_langs[:5])
            
            # Technology stack analysis
            tech_keywords = {
                "web": ["web", "html", "css", "javascript", "react", "vue", "angular", "django", "flask"],
                "mobile": ["android", "ios", "react-native", "flutter", "swift", "kotlin"],
                "ai/ml": ["machine-learning", "ai", "neural", "tensorflow", "pytorch", "sklearn"],
                "security": ["security", "pentest", "vulnerability", "exploit", "forensics"],
                "devops": ["docker", "kubernetes", "ci", "cd", "terraform", "ansible"],
                "blockchain": ["blockchain", "crypto", "bitcoin", "ethereum", "smart-contract"],
                "systems": ["system", "kernel", "driver", "embedded", "firmware"]
            }
            
            for category, keywords in tech_keywords.items():
                category_count = 0
                for repo in repositories:
                    repo_text = (repo.get("name", "") + " " + repo.get("description", "")).lower()
                    if any(kw in repo_text for kw in keywords):
                        category_count += 1
                
                if category_count > 0:
                    tech_analysis["expertise_areas"].append({
                        "area": category,
                        "projects": category_count
                    })
            
            # Project type analysis
            for repo in repositories:
                stars = repo.get("stars", "0")
                try:
                    star_count = int(re.sub(r'[^\d]', '', stars))
                    if star_count > 100:
                        tech_analysis["project_types"].append({
                            "name": repo.get("name"),
                            "type": "popular_project",
                            "stars": star_count
                        })
                except:
                    pass
                    
        except Exception as e:
            tech_analysis["analysis_error"] = str(e)
        
        return tech_analysis
    
    def analyze_social_media_profile(self, soup: BeautifulSoup, url: str, platform: str) -> Dict[str, Any]:
        """Analyze social media profiles"""
        analysis = {
            "platform": platform,
            "profile_type": "social_media",
            "content_analysis": {},
            "engagement_metrics": {},
            "behavioral_indicators": {},
            "connections": []
        }
        
        try:
            # Extract platform-specific data based on URL
            if "twitter.com" in url or "x.com" in url:
                analysis.update(self._analyze_twitter_profile(soup))
            elif "linkedin.com" in url:
                analysis.update(self._analyze_linkedin_profile(soup))
            elif "instagram.com" in url:
                analysis.update(self._analyze_instagram_profile(soup))
            elif "mastodon" in url:
                analysis.update(self._analyze_mastodon_profile(soup))
            else:
                analysis.update(self._analyze_generic_social_profile(soup))
                
        except Exception as e:
            analysis["extraction_error"] = str(e)
        
        return analysis
    
    def _analyze_twitter_profile(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Analyze Twitter/X profiles"""
        twitter_data = {}
        
        # Bio extraction
        bio_elem = soup.find(attrs={"data-testid": "UserDescription"})
        if bio_elem:
            twitter_data["bio"] = bio_elem.get_text().strip()
        
        # Follower metrics
        following_elem = soup.find(attrs={"data-testid": "UserFollowing"})
        if following_elem:
            twitter_data["following"] = following_elem.get_text().strip()
        
        followers_elem = soup.find(attrs={"data-testid": "UserFollowers"})
        if followers_elem:
            twitter_data["followers"] = followers_elem.get_text().strip()
        
        # Location
        location_elem = soup.find(attrs={"data-testid": "UserLocation"})
        if location_elem:
            twitter_data["location"] = location_elem.get_text().strip()
        
        # Website
        website_elem = soup.find(attrs={"data-testid": "UserUrl"})
        if website_elem:
            link = website_elem.find("a")
            if link:
                twitter_data["website"] = link.get("href", "")
        
        return twitter_data
    
    def _analyze_linkedin_profile(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Analyze LinkedIn profiles"""
        linkedin_data = {}
        
        # Professional title
        title_elem = soup.find("div", class_="text-body-medium")
        if title_elem:
            linkedin_data["professional_title"] = title_elem.get_text().strip()
        
        # Experience section
        experience_section = soup.find("section", id="experience-section")
        if experience_section:
            positions = []
            position_elems = experience_section.find_all("div", class_="pv-entity__summary-info")
            for pos in position_elems[:5]:  # Limit to 5 positions
                position_data = {}
                title_elem = pos.find("h3")
                if title_elem:
                    position_data["title"] = title_elem.get_text().strip()
                
                company_elem = pos.find("p", class_="pv-entity__secondary-title")
                if company_elem:
                    position_data["company"] = company_elem.get_text().strip()
                
                if position_data:
                    positions.append(position_data)
            
            linkedin_data["experience"] = positions
        
        return linkedin_data
    
    def _analyze_instagram_profile(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Analyze Instagram profiles"""
        instagram_data = {}
        
        # Look for JSON-LD data
        script_tags = soup.find_all('script', type='application/ld+json')
        for script in script_tags:
            try:
                json_data = json.loads(script.string)
                if isinstance(json_data, dict):
                    instagram_data["display_name"] = json_data.get("name", "")
                    instagram_data["bio"] = json_data.get("description", "")
                    instagram_data["follower_count"] = json_data.get("interactionStatistic", {}).get("userInteractionCount", "")
            except:
                pass
        
        return instagram_data
    
    def _analyze_mastodon_profile(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Analyze Mastodon profiles"""
        mastodon_data = {}
        
        # Display name
        name_elem = soup.find("span", class_="p-name")
        if name_elem:
            mastodon_data["display_name"] = name_elem.get_text().strip()
        
        # Bio/Note
        note_elem = soup.find("div", class_="account__header__content")
        if note_elem:
            mastodon_data["bio"] = note_elem.get_text().strip()
        
        # Stats
        stats_elems = soup.find_all("div", class_="counter")
        for stat in stats_elems:
            label_elem = stat.find("small")
            value_elem = stat.find("span")
            if label_elem and value_elem:
                label = label_elem.get_text().strip().lower()
                value = value_elem.get_text().strip()
                mastodon_data[f"{label}_count"] = value
        
        return mastodon_data
    
    def _analyze_generic_social_profile(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Analyze generic social media profiles"""
        generic_data = {}
        
        # Try to extract common elements
        title = soup.find("title")
        if title:
            generic_data["page_title"] = title.get_text().strip()
        
        # Look for meta description
        meta_desc = soup.find("meta", attrs={"name": "description"})
        if meta_desc:
            generic_data["description"] = meta_desc.get("content", "")
        
        # Look for profile-like structures
        profile_imgs = soup.find_all("img", class_=re.compile(r"profile|avatar|user"))
        if profile_imgs:
            generic_data["has_profile_image"] = True
        
        return generic_data
    
    def analyze_generic_website(self, soup: BeautifulSoup, url: str) -> Dict[str, Any]:
        """Analyze generic websites for intelligence"""
        analysis = {
            "platform": "generic_website",
            "site_type": "unknown",
            "content_analysis": {},
            "technical_indicators": {},
            "intelligence_value": "low"
        }
        
        try:
            # Basic site information
            title = soup.find("title")
            if title:
                analysis["title"] = title.get_text().strip()
            
            # Meta information
            meta_desc = soup.find("meta", attrs={"name": "description"})
            if meta_desc:
                analysis["description"] = meta_desc.get("content", "")
            
            # Determine site type
            analysis["site_type"] = self._determine_site_type(soup, url)
            
            # Extract key content
            content_analysis = self._analyze_website_content(soup)
            analysis["content_analysis"] = content_analysis
            
            # Technical indicators
            tech_indicators = self._analyze_technical_indicators(soup)
            analysis["technical_indicators"] = tech_indicators
            
            # Determine intelligence value
            analysis["intelligence_value"] = self._assess_intelligence_value(analysis)
            
        except Exception as e:
            analysis["extraction_error"] = str(e)
        
        return analysis
    
    def _determine_site_type(self, soup: BeautifulSoup, url: str) -> str:
        """Determine the type of website"""
        
        # Check for common patterns
        if "blog" in url.lower() or soup.find("article") or soup.find(class_=re.compile(r"blog|post")):
            return "blog"
        elif soup.find("form", attrs={"action": re.compile(r"login|signin")}) or "login" in url:
            return "login_page"
        elif soup.find(class_=re.compile(r"portfolio|resume|cv")):
            return "portfolio"
        elif soup.find(class_=re.compile(r"shop|cart|buy|price")):
            return "ecommerce"
        elif soup.find("form") and soup.find("input", type="email"):
            return "contact_form"
        elif len(soup.find_all("a")) > 50:  # Lots of links
            return "directory_listing"
        else:
            return "informational"
    
    def _analyze_website_content(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Analyze website content for intelligence"""
        content_analysis = {}
        
        # Extract text content
        text_content = soup.get_text()
        content_analysis["word_count"] = len(text_content.split())
        
        # Look for contact information
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, text_content)
        if emails:
            content_analysis["email_addresses"] = list(set(emails))
        
        # Look for phone numbers
        phone_pattern = r'(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
        phones = re.findall(phone_pattern, text_content)
        if phones:
            content_analysis["phone_numbers"] = list(set(phones))
        
        # Extract links
        external_links = []
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            if href and (href.startswith('http') and 'github.com' not in href):
                external_links.append(href)
        
        if external_links:
            content_analysis["external_links"] = external_links[:10]  # Limit to 10
        
        return content_analysis
    
    def _analyze_technical_indicators(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Analyze technical aspects of the website"""
        tech_indicators = {}
        
        # Check for common frameworks/CMS
        if soup.find(attrs={"name": "generator"}):
            generator = soup.find(attrs={"name": "generator"}).get("content", "")
            tech_indicators["cms_framework"] = generator
        
        # Look for JavaScript frameworks
        scripts = soup.find_all('script')
        frameworks = []
        for script in scripts:
            script_content = str(script)
            if 'react' in script_content.lower():
                frameworks.append('React')
            elif 'vue' in script_content.lower():
                frameworks.append('Vue.js')
            elif 'angular' in script_content.lower():
                frameworks.append('Angular')
        
        if frameworks:
            tech_indicators["javascript_frameworks"] = list(set(frameworks))
        
        # Check for analytics/tracking
        tracking_services = []
        if soup.find(string=re.compile(r'google-analytics|gtag|ga\(')):
            tracking_services.append('Google Analytics')
        if soup.find(string=re.compile(r'facebook\.com/tr')):
            tracking_services.append('Facebook Pixel')
        
        if tracking_services:
            tech_indicators["tracking_services"] = tracking_services
        
        return tech_indicators
    
    def _assess_intelligence_value(self, analysis: Dict[str, Any]) -> str:
        """Assess the intelligence value of the analyzed content"""
        score = 0
        
        # Check for contact information
        if analysis.get("content_analysis", {}).get("email_addresses"):
            score += 3
        if analysis.get("content_analysis", {}).get("phone_numbers"):
            score += 2
        
        # Check for external links
        if analysis.get("content_analysis", {}).get("external_links"):
            score += 1
        
        # Check site type
        valuable_types = ["portfolio", "blog", "contact_form"]
        if analysis.get("site_type") in valuable_types:
            score += 2
        
        # Determine value
        if score >= 5:
            return "high"
        elif score >= 3:
            return "medium"
        else:
            return "low"
    
    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """Main method to analyze any URL"""
        try:
            # Basic URL validation and cleanup
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Make request with retry logic
            for attempt in range(self.max_retries + 1):
                try:
                    response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                    if response.status_code == 200:
                        break
                    elif response.status_code in [429, 503]:  # Rate limited
                        if attempt < self.max_retries:
                            time.sleep(2 ** attempt)
                            continue
                except requests.RequestException as e:
                    if attempt < self.max_retries:
                        time.sleep(1)
                        continue
                    raise e
            
            if response.status_code != 200:
                return {
                    "url": url,
                    "status": "error",
                    "error": f"HTTP {response.status_code}",
                    "accessible": False
                }
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Determine analysis type based on URL
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc.lower()
            
            if "github.com" in domain:
                analysis = self.analyze_github_profile(soup, url)
            elif any(social in domain for social in ["twitter.com", "x.com", "linkedin.com", "instagram.com", "mastodon"]):
                platform = domain.replace("www.", "").split(".")[0]
                analysis = self.analyze_social_media_profile(soup, url, platform)
            else:
                analysis = self.analyze_generic_website(soup, url)
            
            # Add common metadata
            analysis.update({
                "url": url,
                "domain": domain,
                "status": "success",
                "accessible": True,
                "response_size": len(response.text),
                "content_type": response.headers.get('content-type', ''),
                "analysis_timestamp": time.time()
            })
            
            return analysis
            
        except Exception as e:
            return {
                "url": url,
                "status": "error",
                "error": str(e),
                "accessible": False
            }

# MCP Server Implementation
class LinkAnalyzerMCPServer:
    """MCP Server for link analysis functionality"""
    
    def __init__(self):
        self.analyzer = LinkAnalyzer()
    
    async def analyze_link(self, url: str) -> Dict[str, Any]:
        """
        Analyze a single URL for intelligence gathering
        
        Args:
            url: URL to analyze
        """
        try:
            result = await self.analyzer.analyze_url(url)
            
            return {
                "tool": "link_analyzer",
                "status": result.get("status", "error"),
                "url": url,
                "analysis": result,
                "intelligence_summary": self._generate_intelligence_summary(result)
            }
            
        except Exception as e:
            return {
                "tool": "link_analyzer",
                "status": "error",
                "url": url,
                "error": str(e)
            }
    
    async def analyze_multiple_links(self, urls: List[str], max_concurrent: int = 3) -> Dict[str, Any]:
        """
        Analyze multiple URLs with concurrency control
        
        Args:
            urls: List of URLs to analyze
            max_concurrent: Maximum concurrent requests
        """
        try:
            semaphore = asyncio.Semaphore(max_concurrent)
            
            async def analyze_with_semaphore(url):
                async with semaphore:
                    return await self.analyzer.analyze_url(url)
            
            tasks = [analyze_with_semaphore(url) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
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
            
            # Generate summary
            successful_analyses = [r for r in processed_results if r.get("status") == "success"]
            high_value_analyses = [r for r in successful_analyses 
                                 if r.get("intelligence_value") in ["high", "medium"]]
            
            return {
                "tool": "link_analyzer",
                "status": "success",
                "total_analyzed": len(processed_results),
                "successful_analyses": len(successful_analyses),
                "high_value_findings": len(high_value_analyses),
                "analyses": processed_results,
                "summary": f"Analyzed {len(successful_analyses)}/{len(urls)} URLs successfully, found {len(high_value_analyses)} high-value targets"
            }
            
        except Exception as e:
            return {
                "tool": "link_analyzer",
                "status": "error",
                "error": str(e)
            }
    
    def _generate_intelligence_summary(self, analysis: Dict[str, Any]) -> str:
        """Generate a human-readable intelligence summary"""
        if analysis.get("status") != "success":
            return f"Analysis failed: {analysis.get('error', 'Unknown error')}"
        
        platform = analysis.get("platform", "unknown")
        summary_parts = []
        
        if platform == "github":
            # GitHub-specific summary
            repos = analysis.get("repositories", [])
            activity = analysis.get("activity_metrics", {})
            security = analysis.get("security_indicators", {})
            
            summary_parts.append(f"GitHub profile with {len(repos)} repositories")
            
            if activity.get("yearly_contributions"):
                summary_parts.append(f"{activity['yearly_contributions']} yearly contributions")
            
            if security.get("security_focus"):
                summary_parts.append(f"Security focus: {', '.join(security['security_focus'])}")
            
            if analysis.get("organization"):
                summary_parts.append(f"Works at: {analysis['organization']}")
        
        elif platform in ["twitter", "linkedin", "instagram", "mastodon"]:
            # Social media summary
            summary_parts.append(f"{platform.title()} profile")
            
            if analysis.get("bio"):
                summary_parts.append(f"Bio: {analysis['bio'][:100]}...")
            
            if analysis.get("followers"):
                summary_parts.append(f"Followers: {analysis['followers']}")
        
        else:
            # Generic website summary
            site_type = analysis.get("site_type", "unknown")
            intelligence_value = analysis.get("intelligence_value", "low")
            
            summary_parts.append(f"{site_type} website")
            summary_parts.append(f"Intelligence value: {intelligence_value}")
            
            content = analysis.get("content_analysis", {})
            if content.get("email_addresses"):
                summary_parts.append(f"Found {len(content['email_addresses'])} email addresses")
        
        return "; ".join(summary_parts) if summary_parts else "Basic website analysis completed"
    
    async def check_link_analyzer_status(self) -> Dict[str, Any]:
        """Check if link analyzer is working"""
        try:
            # Test with a simple request
            test_result = await self.analyzer.analyze_url("https://httpbin.org/get")
            return {
                "tool": "link_analyzer",
                "status": "operational",
                "test_result": test_result.get("status") == "success"
            }
        except Exception as e:
            return {
                "tool": "link_analyzer",
                "status": "error",
                "error": str(e)
            }

# For direct testing
if __name__ == "__main__":
    async def test_analyzer():
        server = LinkAnalyzerMCPServer()
        
        # Test with GitHub profile
        github_result = await server.analyze_link("https://github.com/torvalds")
        print("GitHub Analysis:")
        print(json.dumps(github_result, indent=2))
        
        print("\n" + "="*50 + "\n")
        
        # Test with generic website
        generic_result = await server.analyze_link("https://httpbin.org/get")
        print("Generic Website Analysis:")
        print(json.dumps(generic_result, indent=2))
    
    asyncio.run(test_analyzer())