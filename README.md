# API Vulnerability Analyzer — SOAR Dashboard

## Design Document

*Project: AI-driven Security Orchestration and Response dashboard for authorized pentest-lab targets (TryHackMe, PortSwigger Web Security Academy)*

---

## 1. Purpose & Scope

This project is a local dashboard that automates the repetitive parts of web/API penetration testing against **authorized lab environments**: discovering what a target application does, scanning its network services for known vulnerabilities, and drafting a findings report — all driven by small, independent AI agents that share one data store instead of passing data to each other directly.

The original design relied on manually browsing a target through Burp Suite and a Kali VM, with traffic mirrored to a host machine via `mitmdump`. That approach only captured traffic the operator personally triggered. The current design replaces that with **active automation**: a headless browser crawls the target and captures its own traffic, and a fuzzing agent actively probes for undocumented endpoints — no manual browsing required, and no second VM in the loop.

## 2. High-Level Architecture

Every agent reads from and writes to one shared SQLite database (`soar.db`). No agent calls another agent directly; none of them know the others exist. This means any single agent can be re-run in isolation as long as the data it needs already exists in the store.

```
 ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
 │ Recon Crawler │ │ API Hunter │ │ Nmap + CVE │
 │ (Playwright) │ │ (fuzzer) │ │ Matcher │
 └────────┬────────┘ └────────┬────────┘ └────────┬────────┘
 │ write │ write │ write
 ▼ ▼ ▼
 ┌─────────────────────────────────────────────────┐
 │ soar.db — unified findings store │
 │ (findings / config / cve_cache tables) │
 └─────────────────────────────────────────────────┘
 ▲ ▲ ▲
 │ read │ read │ read (all findings)
 ┌────────┴────────┐ ┌────────┴────────┐ ┌────────┴────────┐
 │ API Mapper │ │ Streamlit UI │ │ Reporter │
 │ (Ollama) │ │ (app.py) │ │ (Ollama) │
 └─────────────────┘ └─────────────────┘ └─────────────────┘
```

The Streamlit dashboard (`app.py`) is the control surface: one tab per agent, a sidebar to set the active **session**, and a raw-findings browser for debugging. Two local Ollama models do the language-generation work — `qwen2.5-coder:7b` for structured/technical output (API maps, candidate paths) and `llama3.2:latest` for the final prose report.

## 3. Tech Stack Summary

| Layer | Technology | Role |
| --- | --- | --- |
| UI / dashboard | Streamlit | Tabbed control panel, triggers agents, renders results |
| Shared state | SQLite (`soar.db`) | Single source of truth all agents read/write |
| Automated recon | Playwright (headless Chromium) | Crawls the target, captures its own network traffic |
| Active fuzzing | `requests` + Ollama | Probes guessed/mined/known-doc paths |
| Network scanning | `python-nmap` (wraps the `nmap` binary) | Service/version discovery on a target IP |
| Vulnerability data | CIRCL Vulnerability-Lookup API | Keyless CVE search by vendor/product |
| Language generation | Ollama (local LLM runtime) — `qwen2.5-coder:7b`, `llama3.2:latest` | API-doc generation, path guessing, report drafting |
| Legacy ingestion (optional) | Flask (`receiver.py`) + `mitmdump` | Manual capture fallback — no longer the primary path |

## 4. Data Model

All agent output lands in one table:

```sql
findings (
 id INTEGER PRIMARY KEY,
 session_id TEXT, -- groups one engagement together
 target TEXT, -- domain or IP this finding is about
 agent TEXT, -- which agent wrote it
 finding_type TEXT, -- what kind of record this is
 data TEXT, -- JSON blob, shape depends on finding_type
 created_at TEXT
)
```

**`finding_type` values in use:**

| finding\_type | Written by | Contains |
| --- | --- | --- |
| `raw_traffic` | recon\_crawler (or legacy receiver.py) | One captured HTTP request/response pair |
| `js_endpoint_candidate` | recon\_crawler | A path string mined out of a loaded `.js` file, plus which file it came from |
| `api_endpoint` | api\_hunter, api\_mapper | A responsive probed path, or a generated OpenAPI YAML document |
| `cve_match` | nmap\_cve | One open port/service plus any CVEs matched against it |
| `report` | reporter | The final generated Markdown report |

Two supporting tables: `config` (key/value — currently just `active_session`) and `cve_cache` (caches CIRCL lookups for 7 days so repeat report generation doesn't re-hit the network).

## 5. Agents

### 5.1 Recon Crawler (`recon_crawler.py`)

Launches headless Chromium, visits the start URL, and automatically follows same-origin links up to a page budget. Captures every XHR/fetch/document response the page makes on its own — no manual clicking. Additionally, every loaded `.js` file is scanned with a regex for quoted path-like strings; these are stored separately as `js_endpoint_candidate` findings, since lab "hidden endpoint" challenges typically reference a path in client-side code without ever calling it from a visible button.

### 5.2 API Hunter (`api_hunter.py`)

Active fuzzing agent. Combines three path sources before probing: (1) a fixed list of common API-documentation URLs (`/swagger.json`, `/api-docs`, etc.), (2) paths an LLM guesses from a short app-context description, (3) paths mined by the Recon Crawler. Each candidate gets a real GET request; anything other than a flat non-response (404/timeout/connection failure) is logged as a finding, with full visibility into status-code counts and failures for debugging.

### 5.3 API Mapper (`api_mapper.py`)

Reads all `raw_traffic` findings for a target and asks `qwen2.5-coder:7b` to synthesize them into an OpenAPI 3.0 YAML document — a structured map of the API surface actually observed.

### 5.4 Nmap + CVE Matcher (`nmap_cve.py`)

Runs `nmap -sV` against a target IP to enumerate open ports, services, and versions. Each open service is matched against CIRCL's CVE database by guessing a CPE vendor/product pair (a small lookup table covers common services; unmapped products fall back to a vendor==product guess). Version filtering against the returned CVE list is a text-match heuristic, not a structured version-range check — CIRCL's public search doesn't expose one.

### 5.5 Reporter (`reporter.py`)

Reads **every** finding stored for the active session, regardless of which agent produced it or in what order, and asks `llama3.2:latest` to draft a structured Markdown report (Executive Summary / Scope / Findings / Recommendations). This is the one-click, no-pipeline behavior the project was redesigned around: generating a report never requires re-running any other agent.

## 6. Session Model

A **session** is just a string tag (e.g. `thm-vulnbox-1`) set from the sidebar and stored in the `config` table as `active_session`. Every agent writes findings tagged with whatever session is currently active, and every read is scoped to it. This is what lets multiple engagements coexist in one database without their findings bleeding into each other — and what lets the legacy `receiver.py` tag incoming manual captures correctly without needing any direct link to the dashboard process.

## 7. Project Structure

```
api-vuln-analyzer/
├── app.py # Streamlit dashboard — one tab per agent
├── db.py # Unified findings store (SQLite)
├── receiver.py # Optional legacy manual-capture ingestion
├── requirements.txt
├── .gitignore
├── soar.db # created automatically on first run
└── agents/
 ├── recon_crawler.py # Automated crawl + JS endpoint mining
 ├── api_hunter.py # Active fuzzing (LLM + JS-mined + doc-path probes)
 ├── api_mapper.py # raw_traffic → OpenAPI YAML
 ├── nmap_cve.py # nmap -sV → CIRCL CVE matching
 └── reporter.py # All findings → Markdown report
```

## 8. Known Limitations & Next Steps

- **CVE matching is heuristic.** CIRCL's keyless search returns CVEs for a vendor/product pair; version applicability is approximated by text-matching the version string against each CVE's description, not a real version-range check.
- **CPE guessing is incomplete.** Services outside the built-in mapping fall back to a vendor==product guess, which is wrong for a meaningful fraction of software. The map should grow as gaps are found.
- **Crawler coverage is same-origin, link-based only.** It won't exercise functionality gated behind a login flow, a specific user role, or a multi-step form unless the crawl logic is extended to handle those.
- **No authentication-aware crawling yet.** Session cookies / login flows are not currently automated — a target requiring login needs that step added to `recon_crawler.py`.
- **Natural next addition:** a single "run everything" action chaining Recon → Hunter → Nmap/CVE → Report for one target, rather than clicking each tab in sequence.

## 9. Running the Project

```bash
pip install -r requirements.txt
playwright install chromium && playwright install-deps
streamlit run app.py
```

Set a session name in the sidebar, then work through the tabs in order: **Auto Recon → API Hunter → API Mapper → Nmap + CVE Scan → Reporter**. `nmap` must be installed on whatever host runs the scan, and that host needs network/VPN reach to the target IP.
