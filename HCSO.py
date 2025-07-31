#!/usr/bin/env python3
"""
HCSO.py - Hostile Command Suite OSINT Agent
An intelligent OSINT investigation system with local AI decision-making

Part of the Hostile Command Suite OSINT Package
"""

import argparse
import asyncio
import json
import os
import sys
import yaml
import signal
import readline
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path
import subprocess
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm
from rich import print as rprint

# ASCII Banner
BANNER = """
  ╔═════════════════════════════════════════════════════════════════════════╗
  ║  ██   ██ ███████ ██████         ███████ ███████  ██ ███    ██ ████████  ║
  ║  ██   ██ ██      ██             ██   ██ ██       ██ ████   ██    ██     ║
  ║  ███████ ███████ ██      █████  ██   ██ ███████  ██ ██ ██  ██    ██     ║
  ║  ██   ██      ██ ██             ██   ██      ██  ██ ██  ██ ██    ██     ║
  ║  ██   ██ ███████ ██████         ███████ ███████  ██ ██   ████    ██     ║
  ╚═════════════════════════════════════════════════════════════════════════╝

      Hostile Command Suite - OSINT Package
      Intelligent Open Source Intelligence Investigation System
      
"""

@dataclass
class InvestigationState:
    """Track investigation progress and findings"""
    target: str
    target_type: str
    findings: List[Dict[str, Any]]
    investigation_chain: List[str]
    risk_level: str = "UNKNOWN"
    next_recommended_action: Optional[str] = None
    
    def add_finding(self, tool: str, result: Dict[str, Any]):
        """Add investigation finding"""
        self.findings.append({
            "tool": tool,
            "timestamp": None,  # Could add proper timestamp
            "result": result
        })
        self.investigation_chain.append(f"{tool}:{self.target}")

class PromptManager:
    """Manage configurable system prompts"""
    
    def __init__(self, prompts_dir: str = "prompts"):
        self.prompts_dir = Path(prompts_dir)
        self.prompts = {}
        self.load_prompts()
    
    def load_prompts(self):
        """Load all prompt files"""
        try:
            # Load agent system prompts
            agent_file = self.prompts_dir / "agent_system.yaml"
            if agent_file.exists():
                with open(agent_file, 'r') as f:
                    self.prompts['agent'] = yaml.safe_load(f)
            
            # Load tool prompts
            tool_file = self.prompts_dir / "tool_prompts.yaml"
            if tool_file.exists():
                with open(tool_file, 'r') as f:
                    self.prompts['tools'] = yaml.safe_load(f)
                    
        except Exception as e:
            print(f"Warning: Could not load prompts - {e}")
            self.prompts = {}
    
    def get_agent_prompt(self) -> str:
        """Get main agent system prompt"""
        if 'agent' in self.prompts and 'osint_agent' in self.prompts['agent']:
            agent_config = self.prompts['agent']['osint_agent']
            return agent_config.get('core_instructions', '')
        return "You are an OSINT investigation agent."
    
    def get_tool_prompt(self, tool_name: str, **kwargs) -> str:
        """Get tool-specific analysis prompt"""
        if 'tools' in self.prompts and f"{tool_name}_analysis" in self.prompts['tools']:
            template = self.prompts['tools'][f"{tool_name}_analysis"]
            try:
                return template.format(**kwargs)
            except KeyError as e:
                return f"Analysis template error: missing {e}"
        return f"Analyze the {tool_name} results."

class MCPToolManager:
    """Manage MCP-based OSINT tools"""
    
    def __init__(self):
        self.available_tools = {}
        self.tool_processes = {}
        self.check_available_tools()
    
    def check_available_tools(self):
        """Check which MCP tools are available"""
        tools_dir = Path("mcp_tools")
        
        # Check for sherlock server
        sherlock_server = tools_dir / "sherlock_server.py"
        if sherlock_server.exists():
            self.available_tools['sherlock'] = {
                'server_path': str(sherlock_server),
                'description': 'Username investigation across 400+ platforms',
                'target_types': ['username']
            }
        
        # Check for mosint server  
        mosint_server = tools_dir / "mosint_server.py"
        if mosint_server.exists():
            self.available_tools['mosint'] = {
                'server_path': str(mosint_server),
                'description': 'Email OSINT and breach investigation',
                'target_types': ['email']
            }
        
        # Check for profile scraper server
        profile_scraper_server = tools_dir / "profile_scraper_server.py"
        if profile_scraper_server.exists():
            self.available_tools['profile_scraper'] = {
                'server_path': str(profile_scraper_server),
                'description': 'Scrape profiles from Sherlock results for additional intelligence',
                'target_types': ['urls']
            }
        
        # Check for link analyzer server
        link_analyzer_server = tools_dir / "link_analyzer_server.py"
        if link_analyzer_server.exists():
            self.available_tools['link_analyzer'] = {
                'server_path': str(link_analyzer_server),
                'description': 'Deep analysis of URLs including GitHub profiles and web content',
                'target_types': ['urls']
            }
        
        # Check for DuckDuckGo search server
        duckduckgo_server = tools_dir / "duckduckgo_server.py"
        if duckduckgo_server.exists():
            self.available_tools['duckduckgo_search'] = {
                'server_path': str(duckduckgo_server),
                'description': 'Web search for OSINT intelligence gathering',
                'target_types': ['any']
            }
    
    async def call_tool(self, tool_name: str, method: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call an MCP tool method"""
        if tool_name not in self.available_tools:
            return {"error": f"Tool {tool_name} not available"}
        
        try:
            # For now, simulate MCP calls by running the tools directly
            # In a full implementation, this would use proper MCP protocol
            server_path = self.available_tools[tool_name]['server_path']
            
            if tool_name == 'sherlock' and method == 'investigate_username':
                return await self._call_sherlock(arguments.get('username'))
            elif tool_name == 'mosint' and method == 'investigate_email':
                return await self._call_mosint(arguments.get('email'))
            elif tool_name == 'profile_scraper' and method == 'scrape_sherlock_profiles':
                return await self._call_profile_scraper(arguments.get('sherlock_results', []), arguments.get('max_profiles', 5))
            elif tool_name == 'link_analyzer' and method == 'analyze_link':
                return await self._call_link_analyzer(arguments.get('url'))
            elif tool_name == 'duckduckgo_search' and method == 'web_search':
                return await self._call_duckduckgo_search(arguments.get('query'), arguments.get('max_results', 10))
            elif tool_name == 'duckduckgo_search' and method == 'news_search':
                return await self._call_duckduckgo_news(arguments.get('query'), arguments.get('max_results', 10))
            else:
                return {"error": f"Unknown method {method} for tool {tool_name}"}
                
        except Exception as e:
            return {"error": f"Tool call failed: {str(e)}"}
    
    async def _call_sherlock(self, username: str) -> Dict[str, Any]:
        """Call sherlock tool directly"""
        try:
            cmd = ['sherlock', username, '--timeout', '10', '--print-found']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # Parse results and extract URLs
                accounts = []
                profile_urls = []
                
                for line in result.stdout.split('\n'):
                    if 'http' in line and username in line:
                        accounts.append(line.strip())
                        # Extract URL from the line
                        import re
                        url_match = re.search(r'https?://[^\s]+', line)
                        if url_match:
                            profile_urls.append(url_match.group())
                
                return {
                    "tool": "sherlock",
                    "target": username,
                    "target_type": "username",
                    "status": "success", 
                    "accounts_found": len(accounts),
                    "platforms": accounts,
                    "profile_urls": profile_urls,
                    "investigation_summary": f"Found {len(accounts)} accounts for '{username}'"
                }
            else:
                return {"tool": "sherlock", "status": "error", "error": result.stderr}
                
        except Exception as e:
            return {"tool": "sherlock", "status": "error", "error": str(e)}
    
    async def _call_mosint(self, email: str) -> Dict[str, Any]:
        """Call mosint tool directly"""
        try:
            cmd = ['mosint', email, '-v']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            return {
                "tool": "mosint",
                "target": email,
                "target_type": "email",
                "status": "success" if result.returncode == 0 else "error",
                "domain": email.split("@")[1] if "@" in email else None,
                "raw_output": result.stdout,
                "investigation_summary": f"Email intelligence completed for '{email}'"
            }
            
        except Exception as e:
            return {"tool": "mosint", "status": "error", "error": str(e)}
    
    async def _call_profile_scraper(self, sherlock_results: List[str], max_profiles: int = 5) -> Dict[str, Any]:
        """Call profile scraper tool directly"""
        try:
            # Import the profile scraper server
            import sys
            sys.path.append('mcp_tools')
            from profile_scraper_server import ProfileScraperMCPServer
            
            # Initialize and call the scraper
            scraper_server = ProfileScraperMCPServer()
            result = await scraper_server.scrape_sherlock_profiles(sherlock_results, max_profiles)
            
            return result
            
        except Exception as e:
            return {"tool": "profile_scraper", "status": "error", "error": str(e)}
    
    async def _call_link_analyzer(self, url: str) -> Dict[str, Any]:
        """Call link analyzer tool directly"""
        try:
            # Import the link analyzer server
            import sys
            sys.path.append('mcp_tools')
            from link_analyzer_server import LinkAnalyzerMCPServer
            
            # Initialize and call the analyzer
            analyzer_server = LinkAnalyzerMCPServer()
            result = await analyzer_server.analyze_link(url)
            
            return result
            
        except Exception as e:
            return {"tool": "link_analyzer", "status": "error", "error": str(e)}
    
    async def _call_duckduckgo_search(self, query: str, max_results: int = 10) -> Dict[str, Any]:
        """Call DuckDuckGo web search tool directly"""
        try:
            # Import the DuckDuckGo search server
            import sys
            sys.path.append('mcp_tools')
            from duckduckgo_server import check_duckduckgo_available
            
            if not check_duckduckgo_available():
                return {"tool": "duckduckgo_search", "status": "error", "error": "duckduckgo_search not installed"}
            
            from duckduckgo_search import DDGS
            
            with DDGS() as ddgs:
                results = list(ddgs.text(
                    keywords=query,
                    region="us-en",
                    safesearch="moderate",
                    max_results=max_results
                ))
            
            # Process results for OSINT analysis
            processed_results = []
            for result in results:
                processed_results.append({
                    "title": result.get("title", ""),
                    "body": result.get("body", ""),
                    "href": result.get("href", ""),
                    "source": result.get("source", "")
                })
            
            return {
                "tool": "duckduckgo_search",
                "search_type": "web",
                "query": query,
                "status": "success",
                "results_count": len(processed_results),
                "results": processed_results,
                "investigation_summary": f"Found {len(processed_results)} web results for '{query}'"
            }
            
        except Exception as e:
            return {"tool": "duckduckgo_search", "status": "error", "error": str(e)}
    
    async def _call_duckduckgo_news(self, query: str, max_results: int = 10) -> Dict[str, Any]:
        """Call DuckDuckGo news search tool directly"""
        try:
            # Import the DuckDuckGo search server
            import sys
            sys.path.append('mcp_tools')
            from duckduckgo_server import check_duckduckgo_available
            
            if not check_duckduckgo_available():
                return {"tool": "duckduckgo_search", "status": "error", "error": "duckduckgo_search not installed"}
            
            from duckduckgo_search import DDGS
            
            with DDGS() as ddgs:
                results = list(ddgs.news(
                    keywords=query,
                    region="us-en",
                    max_results=max_results
                ))
            
            # Process results for OSINT analysis
            processed_results = []
            for result in results:
                processed_results.append({
                    "title": result.get("title", ""),
                    "body": result.get("body", ""),
                    "url": result.get("url", ""),
                    "date": result.get("date", ""),
                    "source": result.get("source", "")
                })
            
            return {
                "tool": "duckduckgo_search",
                "search_type": "news", 
                "query": query,
                "status": "success",
                "results_count": len(processed_results),
                "results": processed_results,
                "investigation_summary": f"Found {len(processed_results)} news results for '{query}'"
            }
            
        except Exception as e:
            return {"tool": "duckduckgo_search", "status": "error", "error": str(e)}

class OllamaAgent:
    """Intelligent OSINT agent powered by local ollama"""
    
    def __init__(self, model: str = "qwen3:8b", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url
        self.console = Console()
        self.prompt_manager = PromptManager()
        self.interrupted = False
        
        # Set up interrupt handler
        signal.signal(signal.SIGINT, self._handle_interrupt)
    
    def _handle_interrupt(self, signum, frame):
        """Handle interruption gracefully"""
        self.interrupted = True
        self.console.print("\n[red]Investigation interrupted by user[/red]")
    
    def is_available(self) -> bool:
        """Check if ollama is running"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    async def analyze_and_decide(self, investigation: InvestigationState, tools: MCPToolManager) -> str:
        """Use AI to analyze findings and decide next steps"""
        if not self.is_available():
            return "Ollama not available for intelligent analysis"
        
        # Build comprehensive context for AI decision making
        context = {
            "target": investigation.target,
            "target_type": investigation.target_type,
            "findings_count": len(investigation.findings),
            "investigation_chain": investigation.investigation_chain,
            "available_tools": list(tools.available_tools.keys()),
            "recent_findings": investigation.findings[-3:] if investigation.findings else []
        }
        
        # Extract intelligence from all findings for better decision making
        discovered_data = self._extract_discovered_intelligence(investigation.findings)
        
        # Get agent system prompt
        system_prompt = self.prompt_manager.get_agent_prompt()
        
        decision_prompt = f"""
{system_prompt}

COMPREHENSIVE TOOL CAPABILITIES:
- sherlock: Username investigation across 400+ social platforms
- mosint: Email OSINT, breach data, domain analysis
- profile_scraper: Automatically runs after sherlock (don't suggest manually)
- link_analyzer: Deep analysis of URLs, GitHub profiles, websites
- duckduckgo_search: Web search for additional intelligence, news search

INTELLIGENT TOOL SELECTION STRATEGY:
1. Analyze ALL available information about the target
2. Consider what intelligence gaps remain
3. Select tools that will provide the most valuable new information
4. Don't repeat the same type of search unless new data warrants it

CURRENT INVESTIGATION STATE:
Target: {context['target']} (Type: {context['target_type']})
Investigation Chain: {' -> '.join(context['investigation_chain'])}
Findings So Far: {context['findings_count']} results
Available Tools: {', '.join(context['available_tools'])}

DISCOVERED INTELLIGENCE:
{json.dumps(discovered_data, indent=2)}

RECENT FINDINGS DETAIL:
{json.dumps(context['recent_findings'], indent=2)}

INTELLIGENT DECISION MATRIX:
Based on discovered intelligence, consider these strategies:

1. EMAIL ADDRESSES found → Use mosint for breach/domain analysis
2. NEW USERNAMES found → Use sherlock for additional platform discovery  
3. INTERESTING URLs found → Use link_analyzer for deep content analysis
4. NAMES/ORGANIZATIONS found → Use duckduckgo_search for web intelligence
5. SOCIAL MEDIA PROFILES found → Check if worth deeper analysis
6. TECHNICAL INDICATORS → Search for additional context
7. If comprehensive intelligence gathered → Mark COMPLETE

SEARCH INTELLIGENCE OPPORTUNITIES:
- Target name + location for news/records
- Target + associated organizations
- Technical details + context
- Associated usernames/emails + breach data
- Profile information + additional context

Analyze the current intelligence state and recommend the MOST VALUABLE next step:

ANALYSIS: [detailed analysis of current intelligence gaps]
RECOMMENDATION: [specific next step or COMPLETE]
TOOL: [tool to use or NONE if complete]
TARGET: [specific query/target for the tool]
REASONING: [why this provides maximum additional intelligence value]
"""

        try:
            response = requests.post(f"{self.base_url}/api/generate",
                                   json={
                                       "model": self.model,
                                       "prompt": decision_prompt,
                                       "stream": False
                                   }, timeout=30)
            
            if response.status_code == 200:
                result = response.json().get("response", "No analysis available")
                # Clean up reasoning model artifacts
                import re
                result = re.sub(r'<think>.*?</think>', '', result, flags=re.DOTALL)
                return result.strip()
            else:
                return f"AI analysis failed: HTTP {response.status_code}"
                
        except Exception as e:
            return f"AI analysis error: {str(e)}"
    
    def _extract_discovered_intelligence(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract key intelligence from investigation findings"""
        intelligence = {
            "emails": [],
            "usernames": [],
            "urls": [],
            "names": [],
            "organizations": [],
            "technical_info": [],
            "platforms": [],
            "locations": []
        }
        
        for finding in findings:
            result = finding.get("result", {})
            tool = finding.get("tool", "")
            
            if tool == "sherlock":
                # Extract platforms and URLs from sherlock results
                platforms = result.get("platforms", [])
                profile_urls = result.get("profile_urls", [])
                intelligence["platforms"].extend(platforms)
                intelligence["urls"].extend(profile_urls)
                
            elif tool == "mosint":
                # Extract email domain and breach info
                domain = result.get("domain", "")
                if domain:
                    intelligence["organizations"].append(domain)
                
            elif tool == "profile_scraper":
                # Extract additional information from scraped profiles
                scraped_data = result.get("scraped_profiles", [])
                for profile in scraped_data:
                    content = profile.get("content", "")
                    # Simple extraction - could be enhanced with NLP
                    if "@" in content:
                        import re
                        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)
                        intelligence["emails"].extend(emails)
                        
            elif tool == "link_analyzer":
                # Extract analyzed information
                analysis = result.get("analysis", {})
                platform = analysis.get("platform", "")
                if platform:
                    intelligence["platforms"].append(platform)
                    
            elif tool == "duckduckgo_search":
                # Extract search results context
                search_results = result.get("results", [])
                for search_result in search_results:
                    title = search_result.get("title", "")
                    body = search_result.get("body", "")
                    # Could extract entities, organizations, etc. from search results
                    intelligence["technical_info"].append(f"{title}: {body[:100]}...")
        
        # Remove duplicates and empty values
        for key in intelligence:
            intelligence[key] = list(set([item for item in intelligence[key] if item]))
            
        return intelligence

class HCSOAgent:
    """Main OSINT Agent Controller"""
    
    def __init__(self, model: str = "qwen3:8b"):
        self.console = Console()
        self.model = model
        self.tools = MCPToolManager()
        self.agent = OllamaAgent(model=model)
        self.current_investigation: Optional[InvestigationState] = None
    
    def print_with_padding(self, content, padding="  "):
        """Print content with consistent left padding"""
        # For Rich objects, render to buffer first then add padding
        if hasattr(content, '__rich__') or hasattr(content, '__rich_console__'):
            from rich.console import Console
            from io import StringIO
            buffer = StringIO()
            temp_console = Console(file=buffer, width=self.console.size.width - len(padding))
            temp_console.print(content)
            content_output = buffer.getvalue()
            
            for line in content_output.split('\n'):
                if line.strip():  # Only print non-empty lines
                    self.console.print(f"{padding}{line}")
        else:
            # For simple text content
            lines = str(content).split('\n') if hasattr(content, 'split') else [str(content)]
            for line in lines:
                self.console.print(f"{padding}{line}")
    
    def get_user_input(self, prompt: str) -> str:
        """Get user input with proper readline support for backspace handling"""
        # Configure readline for better input handling
        readline.parse_and_bind('tab: complete')
        readline.parse_and_bind('set editing-mode emacs')
        
        # Print the prompt using Rich formatting
        self.console.print(prompt, end="")
        
        try:
            # Use raw input with readline support
            return input().strip()
        except (EOFError, KeyboardInterrupt):
            return 'quit'
    
    def display_banner(self):
        """Display the HCSO banner"""
        self.console.print(BANNER, style="bold red")
        self.console.print(f"  [bright_red]Using AI Model:[/bright_red] [bold white]{self.model}[/bold white]")
        self.console.print(f"  [bright_red]Available Tools:[/bright_red] [bold white]{', '.join(self.tools.available_tools.keys())}[/bold white]")
        self.console.print("\n" + "  " + "─" * 78)
    
    def detect_target_type(self, target: str) -> str:
        """Detect the type of target"""
        if "@" in target and "." in target:
            return "email"
        elif "." in target and not "@" in target:
            return "domain"  
        else:
            return "username"
    
    async def start_investigation(self, target: str) -> InvestigationState:
        """Begin new investigation"""
        target_type = self.detect_target_type(target)
        investigation = InvestigationState(
            target=target,
            target_type=target_type,
            findings=[],
            investigation_chain=[]
        )
        
        self.console.print(f"\n  [bold red]Starting Investigation[/bold red]")
        self.console.print(f"  [bright_red]Target:[/bright_red] [white]{target}[/white]")
        self.console.print(f"  [bright_red]Type:[/bright_red] [white]{target_type}[/white]")
        self.console.print()
        
        return investigation
    
    async def execute_investigation_step(self, investigation: InvestigationState, tool: str, method: str, args: Dict[str, Any]):
        """Execute a single investigation step"""
        # Show animated dots progress indicator
        with Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn(f"[dim]Running {tool}...[/dim]"),
            console=self.console,
            transient=True
        ) as progress:
            task = progress.add_task("", total=None)
            # Add padding to progress display
            progress.columns[0].style = "dim"
            progress.columns[1].style = "dim"
            
            result = await self.tools.call_tool(tool, method, args)
            investigation.add_finding(tool, result)
        
        # Display results
        self.display_investigation_result(tool, result)
    
    def display_investigation_result(self, tool: str, result: Dict[str, Any]):
        """Display results from an investigation tool"""
        if result.get("status") == "success":
            # Create summary table
            table = Table(title=f"{tool.upper()} Investigation Results", title_style="bold red")
            table.add_column("Metric", style="bright_red")
            table.add_column("Value", style="white")
            
            if tool == "sherlock":
                table.add_row("Target", result.get("target", ""))
                table.add_row("Accounts Found", str(result.get("accounts_found", 0)))
                table.add_row("Status", "[green]Success[/green]")
            elif tool == "mosint":
                table.add_row("Target", result.get("target", ""))
                table.add_row("Domain", result.get("domain", ""))
                table.add_row("Status", "[green]Success[/green]")
            elif tool == "profile_scraper":
                table.add_row("Total Scraped", str(result.get("total_scraped", 0)))
                table.add_row("Successful", str(result.get("successful_scrapes", 0)))
                table.add_row("With Useful Info", str(result.get("interesting_profiles", 0)))
                table.add_row("Status", "[green]Success[/green]")
            elif tool == "link_analyzer":
                analysis = result.get("analysis", {})
                table.add_row("URL", result.get("url", ""))
                table.add_row("Platform", analysis.get("platform", "unknown"))
                table.add_row("Intelligence Value", analysis.get("intelligence_value", "unknown"))
                table.add_row("Status", "[green]Success[/green]")
            elif tool == "duckduckgo_search":
                table.add_row("Query", result.get("query", ""))
                table.add_row("Search Type", result.get("search_type", ""))
                table.add_row("Results Found", str(result.get("results_count", 0)))
                table.add_row("Status", "[green]Success[/green]")
            
            # Render table with manual padding
            from rich.console import Console
            from io import StringIO
            buffer = StringIO()
            temp_console = Console(file=buffer, width=self.console.size.width - 2)
            temp_console.print(table)
            table_output = buffer.getvalue()
            
            for line in table_output.split('\n'):
                if line.strip():  # Only print non-empty lines
                    self.console.print(f"  {line}")
            
            self.console.print("  " + "─" * 60)
        else:
            # Display error
            error_panel = Panel(
                result.get("error", "Unknown error"),
                title=f"{tool.upper()} Error",
                border_style="red"
            )
            
            # Render panel with manual padding
            from rich.console import Console
            from io import StringIO
            buffer = StringIO()
            temp_console = Console(file=buffer, width=self.console.size.width - 2)
            temp_console.print(error_panel)
            panel_output = buffer.getvalue()
            
            for line in panel_output.split('\n'):
                if line.strip():  # Only print non-empty lines
                    self.console.print(f"  {line}")
            
            self.console.print("  " + "─" * 60)
    
    async def run_agent_loop(self, target: str):
        """Main intelligent agent investigation loop"""
        investigation = await self.start_investigation(target)
        self.current_investigation = investigation
        
        # Initial tool selection based on target type
        if investigation.target_type == "username" and "sherlock" in self.tools.available_tools:
            await self.execute_investigation_step(
                investigation, 
                "sherlock", 
                "investigate_username", 
                {"username": target}
            )
            
            # If sherlock found profiles and profile scraper is available, automatically scrape them
            if (investigation.findings and 
                investigation.findings[-1]["result"].get("profile_urls") and
                "profile_scraper" in self.tools.available_tools):
                
                profile_urls = investigation.findings[-1]["result"]["profile_urls"]
                if profile_urls:
                    self.console.print(f"\n  [bold red]Found {len(profile_urls)} profiles, scraping for additional intelligence...[/bold red]")
                    await self.execute_investigation_step(
                        investigation,
                        "profile_scraper",
                        "scrape_sherlock_profiles",
                        {"sherlock_results": profile_urls, "max_profiles": min(5, len(profile_urls))}
                    )
            
        elif investigation.target_type == "email" and "mosint" in self.tools.available_tools:
            await self.execute_investigation_step(
                investigation,
                "mosint", 
                "investigate_email",
                {"email": target}
            )
        
        # Agent decision loop
        max_iterations = 5
        iteration = 0
        
        while iteration < max_iterations and not self.agent.interrupted:
            self.console.print(f"\n  [bold red]AI Agent Analyzing...[/bold red]")
            
            # Get AI recommendation for next step
            decision = await self.agent.analyze_and_decide(investigation, self.tools)
            
            # Display AI analysis with padding
            analysis_panel = Panel(decision, title="AI Investigation Analysis", border_style="red")
            
            # Render panel with manual padding like other sections
            from rich.console import Console
            from io import StringIO
            buffer = StringIO()
            temp_console = Console(file=buffer, width=self.console.size.width - 2)
            temp_console.print(analysis_panel)
            panel_output = buffer.getvalue()
            
            for line in panel_output.split('\n'):
                if line.strip():  # Only print non-empty lines
                    self.console.print(f"  {line}")
            
            self.console.print("  " + "─" * 60)
            
            # Check if investigation should continue
            if "complete" in decision.lower() or "finished" in decision.lower():
                break
            
            # Ask user if they want to continue with AI recommendation
            if not Confirm.ask("\n  Continue with AI recommendation?"):
                break
            
            # Parse AI decision for next action
            recommendation_executed = await self._execute_ai_recommendation(decision, investigation)
            
            if not recommendation_executed:
                self.console.print("  [yellow]Could not parse AI recommendation or tool not available[/yellow]")
            
            iteration += 1
        
        # Final summary
        self.display_final_summary(investigation)
    
    async def _execute_ai_recommendation(self, decision: str, investigation: InvestigationState) -> bool:
        """Parse and execute AI recommendation"""
        try:
            import re
            
            # Extract tool and target from AI decision using regex
            tool_match = re.search(r'TOOL:\s*[`"]?(\w+)[`"]?', decision, re.IGNORECASE)
            target_match = re.search(r'TARGET:\s*[`"]?([^`"\n]+)[`"]?', decision, re.IGNORECASE)
            
            if not tool_match:
                return False
            
            tool = tool_match.group(1).lower().strip()
            target = target_match.group(1).strip() if target_match else None
            
            # Check if tool is available
            if tool not in self.tools.available_tools:
                self.console.print(f"  [red]Tool '{tool}' not available[/red]")
                return False
            
            # Execute based on tool type
            if tool == "sherlock" and target:
                await self.execute_investigation_step(
                    investigation,
                    "sherlock",
                    "investigate_username",
                    {"username": target}
                )
                return True
                
            elif tool == "mosint" and target:
                await self.execute_investigation_step(
                    investigation,
                    "mosint",
                    "investigate_email",
                    {"email": target}
                )
                return True
                
            elif tool == "link_analyzer" and target:
                await self.execute_investigation_step(
                    investigation,
                    "link_analyzer",
                    "analyze_link",
                    {"url": target}
                )
                return True
                
            elif tool == "duckduckgo_search" and target:
                # Determine if it should be web search or news search based on context
                search_type = "web_search"  # Default to web search
                if "news" in target.lower() or "recent" in target.lower():
                    search_type = "news_search"
                    
                await self.execute_investigation_step(
                    investigation,
                    "duckduckgo_search",
                    search_type,
                    {"query": target, "max_results": 10}
                )
                return True
            
            elif tool.lower() in ["none", "complete"]:
                self.console.print("  [green]AI recommends investigation is complete[/green]")
                return True
            
            else:
                self.console.print(f"  [yellow]Unknown tool recommendation: {tool}[/yellow]")
                return False
                
        except Exception as e:
            self.console.print(f"  [red]Error parsing AI recommendation: {str(e)}[/red]")
            return False
    
    def display_final_summary(self, investigation: InvestigationState):
        """Display final investigation summary"""
        self.console.print(f"\n  [bold red]Investigation Summary[/bold red]")
        self.console.print("  " + "═" * 80)
        
        summary_table = Table(title_style="bold red")
        summary_table.add_column("Investigation Details", style="bright_red")
        summary_table.add_column("Results", style="white")
        
        summary_table.add_row("Target", investigation.target)
        summary_table.add_row("Target Type", investigation.target_type)
        summary_table.add_row("Tools Used", " → ".join(investigation.investigation_chain))
        summary_table.add_row("Total Findings", str(len(investigation.findings)))
        
        self.print_with_padding(summary_table)
        self.console.print("  " + "─" * 60)
        
        # Display each finding with padding
        for i, finding in enumerate(investigation.findings, 1):
            tool = finding["tool"]
            result = finding["result"]
            
            self.console.print(f"\n  [bold red]Finding {i}: {tool.upper()}[/bold red]")
            finding_panel = Panel(
                json.dumps(result, indent=2),
                title=f"Finding {i}: {tool.upper()}",
                border_style="red"
            )
            self.print_with_padding(finding_panel)
            self.console.print("  " + "─" * 60)
    
    async def run_interactive_mode(self):
        """Run in interactive investigation mode"""
        self.display_banner()
        
        while True:
            try:
                self.console.print("\n  [bold red]═══ COMPREHENSIVE TARGET INFORMATION ═══[/bold red]")
                self.console.print("  [dim]Provide ALL available information about your target for intelligent analysis[/dim]")
                self.console.print("  [dim]Include: names, usernames, emails, addresses, organizations, social profiles, etc.[/dim]")
                
                target_info = self.get_user_input("\n  [bold red]Enter ALL target information (or 'quit')[/bold red] (): ")
                
                if target_info.lower() in ['quit', 'exit', 'q']:
                    self.console.print("  [red]Goodbye![/red]")
                    break
                
                if not target_info:
                    continue
                
                await self.run_comprehensive_investigation(target_info)
                
            except KeyboardInterrupt:
                self.console.print("\n  [red]Investigation interrupted[/red]")
                if self.current_investigation:
                    self.display_final_summary(self.current_investigation)
                break
            except Exception as e:
                self.console.print(f"  [bright_red]Error: {str(e)}[/bright_red]")
    
    async def run_comprehensive_investigation(self, target_info: str):
        """Run comprehensive investigation based on all provided target information"""
        self.console.print(f"\n  [bold red]Analyzing Provided Information[/bold red]")
        self.console.print("  " + "─" * 78)
        
        # Extract structured data from the provided information using AI
        extracted_data = await self.extract_target_data(target_info)
        
        if not extracted_data:
            self.console.print("  [yellow]Could not extract actionable intelligence from provided information[/yellow]")
            return
            
        # Display extracted intelligence
        self.display_extracted_intelligence(extracted_data)
        
        # Create investigation state with comprehensive data
        investigation = InvestigationState(
            target=target_info[:50] + "..." if len(target_info) > 50 else target_info,
            target_type="comprehensive",
            findings=[],
            investigation_chain=[]
        )
        self.current_investigation = investigation
        
        # Execute investigations based on extracted data
        await self.execute_comprehensive_investigations(investigation, extracted_data)
        
        # AI agent loop for additional analysis
        max_iterations = 3
        iteration = 0
        
        while iteration < max_iterations and not self.agent.interrupted:
            self.console.print(f"\n  [bold red]AI Agent Analyzing Comprehensive Results...[/bold red]")
            
            decision = await self.agent.analyze_and_decide(investigation, self.tools)
            
            # Display AI analysis
            analysis_panel = Panel(decision, title="AI Investigation Analysis", border_style="red")
            from rich.console import Console
            from io import StringIO
            buffer = StringIO()
            temp_console = Console(file=buffer, width=self.console.size.width - 2)
            temp_console.print(analysis_panel)
            panel_output = buffer.getvalue()
            
            for line in panel_output.split('\n'):
                if line.strip():
                    self.console.print(f"  {line}")
            
            self.console.print("  " + "─" * 60)
            
            if "complete" in decision.lower() or "finished" in decision.lower():
                break
            
            if not Confirm.ask("\n  Continue with AI recommendation?"):
                break
            
            recommendation_executed = await self._execute_ai_recommendation(decision, investigation)
            
            if not recommendation_executed:
                self.console.print("  [yellow]Could not parse AI recommendation or tool not available[/yellow]")
            
            iteration += 1
        
        # Final comprehensive summary
        self.display_final_summary(investigation)
    
    async def extract_target_data(self, target_info: str) -> Dict[str, List[str]]:
        """Use AI to extract structured data from provided target information"""
        if not self.agent.is_available():
            # Fallback to simple regex extraction if AI unavailable
            return self._simple_data_extraction(target_info)
        
        extraction_prompt = f"""
Analyze the following target information and extract structured data for OSINT investigation.

TARGET INFORMATION: {target_info}

Extract and categorize the following types of information:

1. REAL NAMES (first name, last name, full names - NOT usernames)
2. USERNAMES (social media handles, online identities)  
3. EMAIL ADDRESSES
4. PHYSICAL ADDRESSES (street addresses, cities, states, countries)
5. PHONE NUMBERS
6. ORGANIZATIONS (companies, schools, groups)
7. URLS/SOCIAL PROFILES
8. OTHER IDENTIFIERS (employee IDs, account numbers, etc.)

Return ONLY a JSON object in this exact format:
{{
  "names": ["John Smith", "Jane Doe"],
  "usernames": ["johnsmith123", "j_doe"],
  "emails": ["john@example.com"],
  "addresses": ["123 Main St, City, State"],
  "phones": ["+1-555-123-4567"],
  "organizations": ["Acme Corp", "State University"],
  "urls": ["https://linkedin.com/in/johnsmith"],
  "identifiers": ["Employee ID: 12345"]
}}

Be precise and only extract clear, identifiable information. Do not speculate or infer.
"""
        
        try:
            response = requests.post(f"{self.agent.base_url}/api/generate",
                                   json={
                                       "model": self.agent.model,
                                       "prompt": extraction_prompt,
                                       "stream": False
                                   }, timeout=30)
            
            if response.status_code == 200:
                result = response.json().get("response", "")
                # Extract JSON from response
                import re
                json_match = re.search(r'\{.*\}', result, re.DOTALL)
                if json_match:
                    try:
                        return json.loads(json_match.group())
                    except json.JSONDecodeError:
                        pass
            
            # Fallback to simple extraction
            return self._simple_data_extraction(target_info)
            
        except Exception as e:
            self.console.print(f"  [yellow]AI extraction failed, using fallback: {str(e)}[/yellow]")
            return self._simple_data_extraction(target_info)
    
    def _simple_data_extraction(self, target_info: str) -> Dict[str, List[str]]:
        """Simple regex-based data extraction as fallback"""
        import re
        
        extracted = {
            "names": [],
            "usernames": [],
            "emails": [],
            "addresses": [],
            "phones": [],
            "organizations": [],
            "urls": [],
            "identifiers": []
        }
        
        # Extract emails
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', target_info)
        extracted["emails"] = emails
        
        # Extract URLs
        urls = re.findall(r'https?://[^\s]+', target_info)
        extracted["urls"] = urls
        
        # Extract phone numbers (basic patterns)
        phones = re.findall(r'[\+]?[1-9]?[0-9]{7,15}', target_info)
        extracted["phones"] = [p for p in phones if len(p) >= 7]
        
        # Simple name extraction (words that might be names)
        words = target_info.split()
        potential_names = []
        for i in range(len(words) - 1):
            if words[i][0].isupper() and words[i+1][0].isupper() and len(words[i]) > 2 and len(words[i+1]) > 2:
                potential_names.append(f"{words[i]} {words[i+1]}")
        extracted["names"] = potential_names[:3]  # Limit to 3 potential names
        
        return extracted
    
    def display_extracted_intelligence(self, extracted_data: Dict[str, List[str]]):
        """Display the extracted intelligence in a formatted table"""
        from rich.table import Table
        
        table = Table(title="Extracted Target Intelligence", title_style="bold red")
        table.add_column("Data Type", style="bright_red", width=15)
        table.add_column("Extracted Values", style="white")
        
        for data_type, values in extracted_data.items():
            if values:  # Only show categories with data
                display_name = data_type.replace("_", " ").title()
                values_str = "\n".join(values) if len(values) <= 3 else "\n".join(values[:3]) + f"\n... and {len(values)-3} more"
                table.add_row(display_name, values_str)
        
        self.print_with_padding(table)
        self.console.print("  " + "─" * 60)
    
    async def execute_comprehensive_investigations(self, investigation: InvestigationState, extracted_data: Dict[str, List[str]]):
        """Execute investigations based on all extracted data types"""
        
        # Investigate names with web search
        for name in extracted_data.get("names", []):
            if name.strip():
                self.console.print(f"\n  [bold red]Investigating Name: {name}[/bold red]")
                await self.execute_investigation_step(
                    investigation,
                    "duckduckgo_search",
                    "web_search",
                    {"query": f'"{name}"', "max_results": 10}
                )
        
        # Investigate usernames with Sherlock
        for username in extracted_data.get("usernames", []):
            if username.strip() and "sherlock" in self.tools.available_tools:
                self.console.print(f"\n  [bold red]Investigating Username: {username}[/bold red]")
                await self.execute_investigation_step(
                    investigation,
                    "sherlock",
                    "investigate_username",
                    {"username": username}
                )
                
                # Auto-scrape profiles if found
                if (investigation.findings and 
                    investigation.findings[-1]["result"].get("profile_urls") and
                    "profile_scraper" in self.tools.available_tools):
                    
                    profile_urls = investigation.findings[-1]["result"]["profile_urls"]
                    if profile_urls:
                        self.console.print(f"\n  [bold red]Found {len(profile_urls)} profiles, scraping...[/bold red]")
                        await self.execute_investigation_step(
                            investigation,
                            "profile_scraper",
                            "scrape_sherlock_profiles",
                            {"sherlock_results": profile_urls, "max_profiles": min(5, len(profile_urls))}
                        )
        
        # Investigate emails with Mosint
        for email in extracted_data.get("emails", []):
            if email.strip() and "mosint" in self.tools.available_tools:
                self.console.print(f"\n  [bold red]Investigating Email: {email}[/bold red]")
                await self.execute_investigation_step(
                    investigation,
                    "mosint",
                    "investigate_email",
                    {"email": email}
                )
        
        # Investigate organizations with web search
        for org in extracted_data.get("organizations", []):
            if org.strip():
                self.console.print(f"\n  [bold red]Investigating Organization: {org}[/bold red]")
                await self.execute_investigation_step(
                    investigation,
                    "duckduckgo_search",
                    "web_search",
                    {"query": f'"{org}"', "max_results": 8}
                )
        
        # Analyze URLs with link analyzer
        for url in extracted_data.get("urls", []):
            if url.strip() and "link_analyzer" in self.tools.available_tools:
                self.console.print(f"\n  [bold red]Analyzing URL: {url}[/bold red]")
                await self.execute_investigation_step(
                    investigation,
                    "link_analyzer",
                    "analyze_link",
                    {"url": url}
                )

async def main():
    parser = argparse.ArgumentParser(description="HCSO - Hostile Command Suite OSINT Agent")
    parser.add_argument("target", nargs="?", help="Target to investigate")
    parser.add_argument("--interactive", "-i", action="store_true", help="Run in interactive mode")
    parser.add_argument("--model", "-m", default="qwen3:8b", help="Ollama model to use (default: qwen3:8b)")
    
    args = parser.parse_args()
    
    # Create agent
    agent = HCSOAgent(model=args.model)
    
    if args.interactive or not args.target:
        await agent.run_interactive_mode()
    else:
        agent.display_banner()
        # For command line usage, use comprehensive investigation if target contains multiple types of info
        if " " in args.target or "@" in args.target or "http" in args.target:
            await agent.run_comprehensive_investigation(args.target)
        else:
            # Simple single target investigation (backward compatibility)
            await agent.run_agent_loop(args.target)

if __name__ == "__main__":
    asyncio.run(main())