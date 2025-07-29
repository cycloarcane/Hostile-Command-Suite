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
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path
import subprocess
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
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
                # Parse results
                accounts = []
                for line in result.stdout.split('\n'):
                    if 'http' in line and username in line:
                        accounts.append(line.strip())
                
                return {
                    "tool": "sherlock",
                    "target": username,
                    "target_type": "username",
                    "status": "success", 
                    "accounts_found": len(accounts),
                    "platforms": accounts,
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
        
        # Build context for AI decision making
        context = {
            "target": investigation.target,
            "target_type": investigation.target_type,
            "findings_count": len(investigation.findings),
            "investigation_chain": investigation.investigation_chain,
            "available_tools": list(tools.available_tools.keys()),
            "recent_findings": investigation.findings[-3:] if investigation.findings else []
        }
        
        # Get agent system prompt
        system_prompt = self.prompt_manager.get_agent_prompt()
        
        decision_prompt = f"""
{system_prompt}

CURRENT INVESTIGATION STATUS:
Target: {context['target']} (Type: {context['target_type']})
Investigation Chain: {' -> '.join(context['investigation_chain'])}
Findings So Far: {context['findings_count']} results
Available Tools: {', '.join(context['available_tools'])}

RECENT FINDINGS:
{json.dumps(context['recent_findings'], indent=2)}

Based on the current investigation state and findings, what should be the next step?
Consider:
1. Are there new leads to follow up on?
2. Should we pivot to a different investigation angle?
3. Is the current investigation complete?
4. What additional intelligence would be most valuable?

Respond with your analysis and recommended next action in the format:
ANALYSIS: [your analysis]
RECOMMENDATION: [specific next step]
TOOL: [tool to use] 
TARGET: [what to investigate next]
REASONING: [why this is the best next step]
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
        # Add manual progress indication with proper padding
        self.console.print(f"  [dim]Running {tool}...[/dim]")
        
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
            if not Confirm.ask("\nContinue with AI recommendation?"):
                break
            
            # Parse AI decision for next action (simplified)
            # In a full implementation, this would be more sophisticated
            if "sherlock" in decision.lower() and "sherlock" in self.tools.available_tools:
                # Extract username from decision if possible
                continue_investigation = Confirm.ask("Run additional sherlock investigation?")
                if continue_investigation:
                    username = Prompt.ask("Enter username to investigate")
                    await self.execute_investigation_step(
                        investigation,
                        "sherlock",
                        "investigate_username", 
                        {"username": username}
                    )
            
            iteration += 1
        
        # Final summary
        self.display_final_summary(investigation)
    
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
                target = Prompt.ask("\n  [bold red]Enter investigation target (or 'quit')[/bold red]").strip()
                
                if target.lower() in ['quit', 'exit', 'q']:
                    self.console.print("  [red]Goodbye![/red]")
                    break
                
                if not target:
                    continue
                
                await self.run_agent_loop(target)
                
            except KeyboardInterrupt:
                self.console.print("\n  [red]Investigation interrupted[/red]")
                if self.current_investigation:
                    self.display_final_summary(self.current_investigation)
                break
            except Exception as e:
                self.console.print(f"  [bright_red]Error: {str(e)}[/bright_red]")

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
        await agent.run_agent_loop(args.target)

if __name__ == "__main__":
    asyncio.run(main())