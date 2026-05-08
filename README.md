# iStrix

Penetration testing orchestration toolkit with AI-assisted planning and analysis.

**iStrix** combines nmap-based network scanning, tiered scan profiles, CVE enrichment,
professional reporting (HTML/PDF/MD), AI-assisted planning via OpenRouter, a job pipeline,
PostgreSQL-backed REST API, dark-theme GUI dashboard, vector-based CVE semantic search,
DNS-based Active Directory forest discovery, and a plugin system.

> **AI is not used during scans.** iStrix calls nmap and other tools directly via
> subprocess. AI (OpenRouter/Ollama) is only used for pre-scan planning (`istrix plan`)
> and post-scan analysis (`istrix consult`). No targets, packets, or scan data are
> ever sent to external AI services.

## Quick Start

```bash
pip install -e ".[all]"
istrix --help
```

> **Data Protection:** All scan output, reports, and test data default to `private/` which
> is gitignored. Never commit scan data. A CI data-leak check runs on every push.

## Commands

| Command | Purpose |
|---------|---------|
| `istrix scan <targets> --tier <tier> --parallel N --resume --forest --adaptive` | Run tiered nmap scan (parallel workers, incremental save/resume, AD forest discovery, auto-tuning) |
| `istrix plan <target>` | AI scan planning |
| `istrix consult <results.json>` | AI result analysis |
| `istrix report <file(s)> --level <lvl> --format <fmt> --parallel N [--per-host]` | Generate reports (parallel workers) |
| `istrix config status` | Tool availability check |
| `istrix job create\|run\|list\|show` | Job pipeline |
| `istrix --agent-help` | Concise agent-optimized reference |
| `istrix-server` | Start FastAPI backend + GUI dashboard on port 8443 |

## Scan Tiers

| Tier | Intensity | Description |
|------|-----------|-------------|
| `quick` | Passive | Top 100 TCP ports, ~30s |
| `stealth` | Passive | Slow, evasive, fragment packets |
| `normal` | Active | Top 10k ports, service detection, web probing, CVE enrichment |
| `full` | Active | All ports, OS detection, SSL checks, printer probe, DNS discovery |
| `aggressive` | Intrusive | Full ports + vuln NSE scripts + full module suite |

## Report Levels

| Level | Content |
|-------|---------|
| `brief` | Threat score + severity + risk profile + host overview |
| `detail` | Brief + full port/service findings table |
| `threat` | Detail + CVE cards with paragraphs + CVSS + exploitation narrative + vector matches |
| `remediation` | Detail + priority-sorted OS-aware actions with version-specific terminal commands |

Each level available in HTML, PDF, and Markdown. Auto-generated `index.html` with format selector.

## Key Features

- **DNS-based AD forest discovery** — single scan reveals all subnets via DNS SRV + PTR; forest-wide coverage from one entry CIDR
- **OS-aware remediation** — 7 OS families: Debian/Ubuntu (apt), RHEL/Oracle/Rocky/Alma (dnf), Windows (winget), Cisco (IOS), printer vendors (HP, Canon, Brother, Epson, Xerox firmware), embedded/IoT (firmware)
- **Vector CVE semantic search** — embedding-based cosine similarity finds known CVEs when regex fails (76% match on regreSSHion)
- **Printer probe** — PJL INFO ID on 9100 + IPP on 631 extracts exact model: "HP Color LaserJet Pro M479"
- **Windows OS detection** — LDAP RootDSE (functional level), IIS httpd version, NetBIOS name service; overrides nmap's incorrect SMB guessing
- **Adaptive worker tuning** — `--adaptive` benchmarks sample hosts to find optimal parallel count; monitors socket/CPU limits
- **Incremental save/resume** — partial results saved after each host; `--resume` skips already-scanned hosts
- **Parallel scan + report generation** — ThreadPoolExecutor for both phases; HTML+MD in parallel, PDF separately
- **PostgreSQL + pgvector** — 10 tables, vector embeddings for semantic CVE search
- **Plugin system** — BaseTool/BaseKnowledge with auto-discovery; CVE RSS feed poller included
- **Dark-theme GUI dashboard** — stat cards, jobs panel, CVE feed, per-host links with numeric IP sorting
- **68 tests** (16 unit + 52 integration) — all passing

## Subnet Scanning

```bash
# Parallel scanning
istrix scan 10.0.0.0/24 --tier aggressive --parallel 12 -o scan.json

# Adaptive auto-tuning — benchmarks sample hosts to determine optimal workers
istrix scan 10.0.0.0/24 --tier aggressive --adaptive -o scan.json

# Full forest scan — auto-discovers AD topology, scans all subnets
istrix scan 10.0.0.0/24 --tier aggressive --adaptive --forest -o scan.json

# Resume after disconnect
istrix scan 10.0.0.0/24 --tier full --parallel 8 --resume -o scan.json

# Per-host reports, parallel generation
istrix report scan.json --per-host --all --all-formats -o reports/ --parallel 20
```

### Adaptive Scaling

`--adaptive` automatically determines the safest parallel worker count before scanning:

- Samples **10 hosts** at each candidate worker count (tier-dependent: 4–12 for aggressive, 15–30 for quick)
- Monitors **socket count** (`ss -s`) and **CPU usage** (`top`) every 1.5s for 20s
- Safety limits: 30,000 sockets, 85% CPU
- Picks the highest count that stays within limits
- Only engages when targets > 5 (fewer targets use `--parallel` directly)

### Forest Scan

`--forest` discovers and scans an entire Active Directory forest from a single entry
subnet. After the initial scan completes, DNS SRV queries (`_ldap._tcp`,
`_kerberos._tcp`, `_gc._tcp`) locate all domain controllers, derive subnets,
and scan each one incrementally with full resume support.

```bash
# Discover all DC subnets from one /24 and scan every one
istrix scan 10.0.0.0/24 --tier aggressive --adaptive --forest -o forest.json
```

## API Server + Dashboard

```bash
export ISTRIX_DB_URL=postgresql+asyncpg://istrix:istrix@localhost/istrix
istrix-server
# → API: http://localhost:8443/api/
# → GUI: http://localhost:8443/
```

## AI Setup (Optional — planning and analysis only)

```bash
pip install istrix[ai]

# OpenRouter (embeddings + chat)
export STRIX_AI_PROVIDER=openrouter
export STRIX_AI_API_KEY=sk-or-v1-...
export STRIX_AI_MODEL=openai/gpt-4o

# OpenAI
export STRIX_AI_PROVIDER=openai
export STRIX_AI_API_KEY=sk-...

# Local (Ollama)
export STRIX_AI_PROVIDER=ollama
export STRIX_AI_API_BASE=http://localhost:11434/v1
export STRIX_AI_MODEL=llama3
```

## Requirements

- Python 3.11+
- nmap (subprocess, not bundled)
- PostgreSQL 16 (for API/dashboard, optional)
- whatweb, nikto, dig (optional — graceful fallback)

## License

Apache 2.0 — see [LICENSE](LICENSE).
External tools (nmap, etc.) are called via subprocess and retain their own licenses.
