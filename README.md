# OSINT CLI

*Author:* **cycloarcane**  
*Contact:* [cycloarkane@gmail.com](mailto:cycloarkane@gmail.com)  
*License:* PolyForm Noncommercial License 1.0.0

**A minimal, terminal-based OSINT investigation toolkit with local LLM analysis**

Inspired by [CAI](https://github.com/aliasrobotics/cai)'s modular agent architecture, this tool provides a streamlined terminal interface for OSINT investigations using local ollama for intelligent analysis.

---

## 🚀 Quick Start

### Prerequisites

1. **Install ollama** (for AI analysis):
```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.2  # or your preferred model
```

2. **Install OSINT tools**:
```bash
# Arch Linux
yay -S sherlock-git mosint

# Ubuntu/Debian
pip install sherlock-project
# For mosint, download from: https://github.com/alpkeskin/mosint
```

### Installation

```bash
git clone https://github.com/cycloarcane/Hostile-Command-Suite.git
cd Hostile-Command-Suite
pip install -r requirements-minimal.txt
chmod +x osint_cli.py
```

### Usage

**Interactive mode:**
```bash
./osint_cli.py --interactive
```

**Single target:**
```bash
./osint_cli.py username123
./osint_cli.py user@example.com
```

---

## 🛠️ Features

### Core Capabilities

- **Username Investigation**: Sherlock integration for social media account discovery
- **Email Investigation**: Mosint integration for email intelligence gathering  
- **AI Analysis**: Local ollama integration for intelligent findings analysis
- **Terminal Interface**: Clean, rich terminal output with progress indicators
- **Modular Design**: Easy to extend with additional OSINT tools

### Supported Targets

| Target Type | Tool Used | Description |
|-------------|-----------|-------------|
| **Username** | Sherlock | Search 400+ social media platforms |
| **Email** | Mosint | Email OSINT and breach checking |

### AI Integration

The tool integrates with local ollama to provide:
- Intelligent analysis of OSINT findings
- Security-focused risk assessment
- Actionable recommendations
- Pattern recognition across tools

---

## 🏗️ Architecture

### Design Philosophy

Inspired by CAI's approach, the tool follows these principles:

- **Agent-Centric**: Modular tool integration
- **Terminal-First**: Clean CLI experience  
- **Local LLM**: No cloud dependencies for analysis
- **Minimal Dependencies**: Only essential packages
- **Extensible**: Easy to add new OSINT tools

### Tool Integration Pattern

```python
class NewTool:
    def __init__(self):
        self.name = "newtool"
        self.available = self._check_availability()
    
    def investigate(self, target: str) -> Dict[str, Any]:
        # Tool-specific investigation logic
        return results
```

---

## 📊 Example Output

```
OSINT Investigation: username123
┏━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Tool     ┃ Status  ┃ Key Findings                                   ┃
┡━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ SHERLOCK │ Success │ Found 15 potential accounts across platforms  │
└──────────┴─────────┴────────────────────────────────────────────────┘

AI Analysis:
╭─ Security Analysis ─────────────────────────────────────────────────────╮
│ The investigation revealed significant digital footprint for username123 │
│ across multiple platforms. Key security concerns:                        │
│                                                                           │
│ 1. High visibility across social media platforms                         │
│ 2. Consistent username usage indicates poor OPSEC                        │
│ 3. Recommend further investigation of identified accounts                 │
│                                                                           │
│ Risk Level: MEDIUM - Target has extensive online presence                │
╰───────────────────────────────────────────────────────────────────────────╯
```

---

## 🔧 Configuration

### Ollama Setup

Default configuration connects to `http://localhost:11434` with `llama3.2` model.

Customize via command line:
```bash
./osint_cli.py --model llama3.1 target_username
```

### Tool Dependencies

The application automatically detects available tools:

- ✅ **Green**: Tool available and functional
- ⚠️ **Yellow**: Tool not found or not working
- Install missing tools for full functionality

---

## 🛡️ Security & Ethics

### Responsible Use

- **Legal Compliance**: Ensure all investigations comply with local laws
- **Authorization**: Only investigate targets you have permission to research
- **Rate Limiting**: Tools respect platform rate limits automatically
- **Local Processing**: All AI analysis happens locally via ollama

### Privacy Considerations

- **No Cloud Dependencies**: All processing happens locally
- **No Data Storage**: Investigation results are not persistently stored
- **Tool Isolation**: Each OSINT tool runs in isolation

---

## 🚧 Development

### Adding New Tools

1. Create a new tool class following the pattern in `osint_cli.py`
2. Add tool availability checking
3. Implement the `investigate()` method
4. Register in the `OSINTCli` tools dictionary

### Architecture Comparison

**Previous (Complex MCP):**
- 15+ FastMCP microservices
- PostgreSQL database requirement  
- Web UI integration
- API key management complexity

**Current (Minimal Terminal):**
- Single Python script
- No database required
- Pure terminal interface
- Local ollama for intelligence

---

## 📈 Roadmap

### Phase 1: Core Tools ✅
- [x] Sherlock username investigation
- [x] Mosint email investigation  
- [x] Ollama AI analysis integration
- [x] Rich terminal interface

### Phase 2: Enhanced Intelligence 🚧
- [ ] Domain investigation tools
- [ ] Phone number OSINT
- [ ] Social media deep dive
- [ ] Export functionality

### Phase 3: Advanced Features 📋
- [ ] Investigation session saving
- [ ] Custom tool integration
- [ ] Automated workflows
- [ ] Result correlation engine

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add your OSINT tool integration
4. Test with both available and unavailable tools
5. Submit a pull request

---

## 📄 License

This project is licensed under the PolyForm Noncommercial License 1.0.0 - see the LICENSE.txt file for details.

---

**Minimal. Terminal. Effective.**

*For questions or feature requests, contact [cycloarkane@gmail.com](mailto:cycloarkane@gmail.com)*