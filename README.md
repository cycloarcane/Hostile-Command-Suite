```
██╗  ██╗ ██████╗███████╗
██║  ██║██╔════╝██╔════╝
███████║██║     ███████╗
██╔══██║██║     ╚════██║
██║  ██║╚██████╗███████║
╚═╝  ╚═╝ ╚═════╝╚══════╝
```

# Hostile‑Command‑Suite

*Author:* **cycloarcane**
*Contact:* [cycloarkane@gmail.com](mailto:cycloarkane@gmail.com)
*License:* PolyForm Noncommercial License 1.0.0

**Hostile‑Command‑Suite (HCS)** is an extensible set of command‑line micro‑services (MCP servers) for open‑source intelligence and—soon—penetration‑testing workflows.  Each tool is wrapped in a fastMCP façade so a chatbot (or any JSON‑RPC client) can drive it securely and receive structured JSON back.  Postgres stores every result so no clue is lost.

---

## Repo Layout

```
Hostile-Command-Suite/
├── OSINT/                 # finished micro‑services + config
│   ├── config.json        # MCP server manifest
│   ├── db_schema.sql      # CREATE TABLE osint_results ...
│   ├── email_osint.py     # Mosint / Holehe / h8mail aggregator
│   ├── phone_osint.py     # PhoneInfoga wrapper
│   └── username_osint.py  # Sherlock wrapper
├── PEN-TEST/              # ✨ reserved: coming soon
└── README.md              # you are here
```

---

## Quick‑start

```bash
# 0. Arch prerequisites (base + yay assumed)
sudo pacman -Syu --needed base-devel git python python-pip python-virtualenv postgresql

# 1. Clone + create virtualenv
 git clone https://github.com/cycloarcane/Hostile-Command-Suite.git
 cd Hostile-Command-Suite
 python -m venv .venv && source .venv/bin/activate && pip install --upgrade pip

# 2. Install Postgres + schema
 sudo -iu postgres initdb -D /var/lib/postgres/data
 sudo systemctl enable --now postgresql
 sudo -iu postgres psql -c "CREATE ROLE osint_user LOGIN PASSWORD 'changeme';"
 sudo -iu postgres createdb -O osint_user osint_db
 psql -U osint_user -d osint_db -f OSINT/db_schema.sql

# 3. Grab toolchain (AUR helpers shown; swap for paru/pikaur if you like)
 yay -S spiderfoot recon-ng-git phoneinfoga-bin theharvester mosint holehe sherlock-git osintgram twint
 pip install h8mail instaloader social-analyzer
 git clone https://github.com/mxrch/GHunt ~/GHunt && pip install -r ~/GHunt/requirements.txt

# 4. Export DSN (or use .pgpass / peer auth)
 export OSINT_PG_DSN="dbname=osint_db user=osint_user password=changeme host=/var/run/postgresql"

# 5. Launch a tool (stdin JSON‑RPC)
echo '{"method":"mosint","params":["alice@example.com"]}' | \
      .venv/bin/python OSINT/email_osint.py
```

---

## API‑Key Matrix

| Tool                | Key **required** to run? | Key file / env var                        | What you miss without it |
| ------------------- | ------------------------ | ----------------------------------------- | ------------------------ |
| **Twint**           | No                       | —                                         | Nothing; full scrape     |
| **SpiderFoot**      | Optional per‑module      | `~/.spiderfoot.conf`                      | Extra data sources       |
| **Recon‑ng**        | Optional per‑module      | `keys add <module> <key>`                 | Extra data modules       |
| **PhoneInfoga**     | Optional                 | `~/.config/phoneinfoga/config.yaml`       | Carrier & spam enrich    |
| **theHarvester**    | Optional                 | `~/.theHarvester/api-keys.yaml`           | Bing/Hunter results      |
| **Mosint**          | **Yes** (full run)       | `~/.mosint.yaml`                          | Breach/social lookups    |
| **Holehe**          | No                       | —                                         | —                        |
| **h8mail**          | Optional                 | `h8mail_config.ini` or `-k` env           | Deep breach content      |
| **Sherlock**        | No                       | —                                         | —                        |
| **Social‑Analyzer** | Optional                 | `--google_key` / REST settings endpoint   | OCR + AI ranking         |
| **Instaloader**     | No                       | Instagram login only for private profiles | —                        |
| **Osintgram**       | IG creds (no API key)    | `credentials.ini`                         | Needs login at all       |
| **GHunt**           | Google cookies           | `config` file with SID, LSID, HSID        | Script won’t run         |

> **Tip:** keep secrets in 600‑perm dot‑files or systemd `LoadCredential=` so wrappers never embed them in code.

---

## Implemented vs TODO

| Wrapper script       | Status                                           |
| -------------------- | ------------------------------------------------ |
| `email_osint.py`     | ✅ ready (Mosint + Holehe + h8mail)               |
| `username_osint.py`  | ✅ ready (Sherlock)                               |
| `phone_osint.py`     | ✅ ready (PhoneInfoga)                            |
| `twitter_osint.py`   | ❌ *planned* (Twint timeline + followers)         |
| `social_osint.py`    | ❌ *planned* (Osintgram + Instaloader)            |
| `google_osint.py`    | ❌ *planned* (GHunt wrapper)                      |
| `footprint_osint.py` | ❌ *planned* (SpiderFoot / Recon‑ng orchestrator) |
| `PEN-TEST/*`         | 🚧 (Metasploit, Nuclei, etc. to be added)        |

PRs welcome—*especially* if you add a new wrapper with tests + DB storage!

---

## Contributing

1. Fork  ▸ hack ▸ **pull request**.
2. Stick to [`pre-commit`](https://pre-commit.com/) lint rules (`black`, `isort`, `flake8`).
3. Add a unit‑test in `tests/` if you add logic.
4. Sign off your commits (`git commit -s`).

Bug reports or feature ideas?  Open an issue or mail [cycloarkane@gmail.com](mailto:cycloarkane@gmail.com).

---

## Roadmap

* [ ] Finish wrappers marked ❌ and wire them into `OSINT/config.json`.
* [ ] Add `PEN-TEST` micro‑services (nmap, nuclei, feroxbuster, etc.).
* [ ] Docker‑compose for one‑command bring‑up.
* [ ] Web dashboard (React + FastAPI) to browse stored OSINT artefacts.

---

**weaponise knowledge** - *ethically, of course.*
