# ⚡ CyberAgent X — Architecture & Developer Reference

> **Platform**: Offline GPU Multi-Agent Cybersecurity Intelligence  
> **Hardware**: NVIDIA RTX 3050 6 GB (CUDA, all layers offloaded)  
> **Inference**: [Ollama](https://ollama.com) — 100 % local, zero cloud, zero API keys  
> **Version**: 2.0 — NVIDIA Nemotron + Dual-Engine Hybrid Search

---

## How to Run (3 steps)

```bat
:: Step 1 – First-time only
python run.py setup

:: Step 2 – Every subsequent launch (pick a mode)
python run.py            ← interactive menu
python run.py web        ← Web Studio  →  http://127.0.0.1:8000
python run.py cli        ← Terminal CLI
python run.py check      ← System health check
python run.py test       ← Full test suite (30 tests)
python run.py query "CVE-2021-44228"   ← One-shot pipeline
```

Or use `run.bat` on Windows (same arguments, loads `.env` automatically).

---

## Project Map

```
d:\ai agents\
│
│  ── Entry Points ──────────────────────────────────────────────────────────
├── run.py                ★ PRIMARY LAUNCHER  (start here)
├── run.bat               Windows wrapper for run.py  (loads .env)
├── main.py               Low-level CLI entry (used by run.py internally)
├── start.bat             Legacy launcher (still works)
├── setup.bat             Legacy setup (still works)
│
│  ── Configuration ─────────────────────────────────────────────────────────
├── .env                  Runtime config  (copy from .env.example, git-ignored)
├── .env.example          Template with all overridable settings
├── requirements.txt      Python dependencies
│
│  ── Documentation ─────────────────────────────────────────────────────────
├── ARCHITECTURE.md       ★ This file
├── GEMINI.md             AI rules: evidence-first, zero hallucination
├── walkthrough.md        Change log of recent features
├── implementation_plan.md Feature backlog and planning
│
│  ── Core System ────────────────────────────────────────────────────────────
├── core/
│   ├── config.py         Global config, model names, GPU locks, prompts
│   ├── pipeline.py       DAG orchestrator — runs the 10-agent swarm
│   ├── mission_state.py  Shared mission data model (Pydantic dataclasses)
│   ├── model_manager.py  VRAM tracker, model load/unload, GPU health
│   └── message_bus.py    Pub/sub event bus → SSE/WebSocket streaming
│
│  ── AI Agents ──────────────────────────────────────────────────────────────
├── agents/
│   ├── base_agent.py         Abstract base: Ollama streaming + GPU + tools
│   ├── orchestrator_agent.py APEX-0     👑  qwen3:8b        (DAG planner)
│   ├── osint_agent.py        RECON-1    🕵️  qwen3:4b        (web recon)
│   ├── threat_intel_agent.py AEGIS-2    🧠  deepseek-r1:8b  (CVE analysis)
│   ├── coding_agent.py       FORGE-3    💻  qwen2.5-coder:7b (PoC/patch)
│   ├── malware_agent.py      DISSECT-4  🔬  qwen3:8b        (binary/YARA)
│   ├── network_agent.py      VANGUARD-5 📡  gemma3:4b       (PCAP/IDS)
│   ├── report_agent.py       SCRIBE-6   📝  gemma3:4b       (executive report)
│   ├── redteam_agent.py      SHADOW-7   ⚔️  phi4-mini:3.8b  (red team/CTF)
│   ├── nemotron_agent.py     NEMO-8     🟢  nemotron-mini:4b (neural reasoning)
│   └── swarm_agent.py        NEXUS-8    🌐  gemma3:4b       (3-round swarm)
│
│  ── Intelligence Tools ──────────────────────────────────────────────────────
├── tools/
│   ├── vuln_correlator.py    8-step CVE pipeline + 100+ CPE product map
│   ├── hybrid_search.py      BM25 + Dense Semantic + RRF fusion engine
│   ├── threat_intel_fetcher.py  8 live feeds: NVD/CISA/Exploit-DB/Vulners…
│   ├── exploit_finder.py     Metasploit + Exploit-DB + GitHub PoC search
│   ├── nmap_scanner.py       Nmap wrapper → structured ServiceRecord output
│   ├── security_kb.py        7-layer local CVE vector DB + Nemotron synthesis
│   ├── document_rag.py       Document chunking + hybrid vector retrieval
│   ├── search_engine.py      DuckDuckGo + Crawl4AI OSINT web search
│   └── code_sandbox.py       Safe subprocess code execution
│
│  ── REST API ────────────────────────────────────────────────────────────────
├── api/
│   └── server.py             FastAPI: all endpoints, SSE, WebSockets, file upload
│
│  ── Web UI (React + Vite) ──────────────────────────────────────────────────
├── web/
│   ├── index.html
│   ├── vite.config.js        Dev proxy → localhost:8000
│   ├── package.json
│   └── src/
│       ├── App.jsx            Tab router
│       ├── index.css          Cyber theme (glassmorphism, CSS vars, animations)
│       └── components/
│           ├── SwarmVisualizer.jsx     Live DAG execution graph + streaming
│           ├── ThreatIntelHub.jsx      7-tab intel hub (HYBRID/NEMOTRON/CISA…)
│           ├── NmapScannerHub.jsx      Nmap UI + CPE/CVE service grid
│           ├── AgentCardGrid.jsx       10 agent cards + oscilloscope animation
│           ├── AgentPlayground.jsx     Direct per-agent chat
│           ├── GpuDashboard.jsx        Live GPU telemetry charts
│           ├── RagIngestor.jsx         Document upload + hybrid search
│           ├── SearchHub.jsx           OSINT web search
│           ├── Navbar.jsx              Navigation + GPU live meter
│           ├── GpuMeter.jsx            Inline VRAM bar
│           └── CanvasBackground.jsx    Animated particle canvas
│
│  ── Terminal UI ────────────────────────────────────────────────────────────
├── ui/
│   └── terminal_ui.py        Rich-library banner + styled CLI output
│
│  ── Persistent Data (auto-created) ─────────────────────────────────────────
├── data/
│   ├── security_kb/          Serialized CVE vector DB (JSON, survives restarts)
│   └── documents/            Uploaded RAG documents
│
│  ── Mission Reports (auto-created) ─────────────────────────────────────────
├── reports/
│   └── missions/             Final intelligence reports (Markdown/PDF, timestamped)
│
│  ── Code Sandbox ────────────────────────────────────────────────────────────
├── sandbox/                  Temporary agent-generated code execution area
│
│  ── Automated Tests ─────────────────────────────────────────────────────────
└── tests/
    ├── test_cpe_and_validation.py    CPE banner extraction + validation rules
    ├── test_hybrid_search.py         BM25, vectorizer, RRF, KB hybrid retrieval
    ├── test_nemotron_ai.py           Nemotron agent + pipeline + synthesis
    └── test_swarm_stage.py           Swarm 3-round loop + IDS rule parsing
```

---

## System Architecture Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                         CYBERAGENT X  v2.0                             │
│                                                                        │
│   Browser  ──── React/Vite UI (web/src/) ──── FastAPI (api/server.py) │
│                        ↕  SSE / WebSocket                              │
│                    ┌───────────────────┐                               │
│                    │   MESSAGE BUS     │  core/message_bus.py          │
│                    │  (pub/sub events) │                               │
│                    └────────┬──────────┘                               │
│                             │                                          │
│                    ┌────────▼──────────┐                               │
│                    │   DAG PIPELINE    │  core/pipeline.py             │
│                    │   AgentPipeline   │                               │
│                    └────────┬──────────┘                               │
│                             │                                          │
│      ┌──────────────────────┼──────────────────────┐                  │
│      │                      │                      │                   │
│  Phase 1 (Intel)       Phase 2 (Analysis)     Phase 3+               │
│  ┌─────────┐          ┌───────────┐           ┌──────────┐            │
│  │ RECON-1 │          │ DISSECT-4 │           │Validation│            │
│  │ AEGIS-2 │          │VANGUARD-5 │           │ SCRIBE-6 │            │
│  │ FORGE-3 │          │ SHADOW-7  │           └──────────┘            │
│  └────┬────┘          │  NEMO-8   │                                    │
│       │               │ NEXUS-8(Swarm)│                               │
│       │               └─────┬─────┘                                   │
│       │                     │                                          │
│       └──────────┬──────────┘                                         │
│                  │                                                     │
│         ┌────────▼─────────┐                                          │
│         │ EVIDENCE          │  tools/vuln_correlator.py               │
│         │ CORRELATOR        │  8-step: Scan→CPE→CVE→CVSS→KEV→Exploit  │
│         │ (Phase 2 gate)    │                                          │
│         └───────────────────┘                                          │
│                  │                                                     │
│         ┌────────▼─────────────────────────────────┐                  │
│         │         TOOLS LAYER                      │                  │
│         │                                          │                  │
│         │  hybrid_search   security_kb             │                  │
│         │  threat_intel_fetcher  nmap_scanner      │                  │
│         │  exploit_finder  document_rag            │                  │
│         │  search_engine   code_sandbox            │                  │
│         └────────┬─────────────────────────────────┘                  │
│                  │                                                     │
│         ┌────────▼───────────────────────┐                            │
│         │      OLLAMA  (localhost:11434) │                            │
│         │      NVIDIA RTX 3050 CUDA:0    │                            │
│         │      6 GB VRAM, all layers GPU │                            │
│         └────────────────────────────────┘                            │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 10-Agent Roster

| # | Callsign | Model | VRAM | Phase | Core Job |
|---|----------|-------|------|-------|----------|
| 0 | APEX-0 👑 | qwen3:8b | 5.0 GB | Orchestrator | Decomposes objective into a DAG task plan |
| 1 | RECON-1 🕵️ | qwen3:4b | 2.5 GB | Phase 1 | OSINT: web recon, DNS, subdomains, social |
| 2 | AEGIS-2 🧠 | deepseek-r1:8b | 5.0 GB | Phase 1 | CVE deep-dive, chain-of-thought, MITRE ATT&CK |
| 3 | FORGE-3 💻 | qwen2.5-coder:7b | 4.5 GB | Phase 1 | Exploit PoCs, patches, automation scripts |
| 4 | DISSECT-4 🔬 | qwen3:8b | 5.0 GB | Phase 2 | Malware, PE/ELF binary, shellcode, YARA |
| 5 | VANGUARD-5 📡 | gemma3:4b | 2.5 GB | Phase 2 | PCAP, protocol anomalies, Snort/Suricata IDS |
| 6 | SCRIBE-6 📝 | gemma3:4b | 2.5 GB | Phase 4 | Executive report, remediation guide |
| 7 | SHADOW-7 ⚔️ | phi4-mini:3.8b | 2.3 GB | Phase 2 | Red team, privilege escalation, AD attacks, CTF |
| 8 | NEMO-8 🟢 | nemotron-mini:4b | 2.8 GB | Phase 2 | NVIDIA hardware-accelerated neural threat modeling |
| — | NEXUS-8 🌐 | gemma3:4b | 2.5 GB | Phase 2 | Swarm coordinator (3-round: Network→Intel→Network) |

---

## DAG Execution Flow

```
User Objective
      │
      ▼
 [APEX-0]  ─── Orchestrator plans the DAG
      │
  ┌───┴────────────────────────┐
  ▼           ▼               ▼
[RECON-1]  [AEGIS-2]       [FORGE-3]          ← Phase 1 (parallel)
  OSINT    Threat Intel     Coder/RAG
  └───────────┴───────────────┘
                │
      ┌─────────▼──────────────────────────┐
      │   EVIDENCE CORRELATOR              │  ← Phase 2 Gate
      │   8-Step Vulnerability Pipeline    │
      │   Nmap → CPE → CVE → CVSS → KEV   │
      └────────┬──────────────────────────┘
               │
  ┌────────────┼────────────┬────────────┐
  ▼            ▼            ▼            ▼
[VANGUARD-5] [DISSECT-4] [SHADOW-7]  [NEMO-8]   ← Phase 2 (parallel)
  Network     Malware     Red Team    Nemotron AI
      └────────────────────────────────┘
               │
      ┌────────▼──────────────────┐
      │   VALIDATION ENGINE        │  ← Phase 3
      │   Confidence + Dedup       │
      └────────┬───────────────────┘
               │
      ┌────────▼──────────────────┐
      │   SCRIBE-6 (Report)        │  ← Phase 4
      │   Executive Deliverable    │
      └────────────────────────────┘
```

---

## Intelligence Tool Internals

### `vuln_correlator.py` — 8-Step Pipeline

```
[1] Ingest      ← Nmap XML/JSON or raw banner text
[2] Normalize   ← Clean version strings: "Apache/2.4.49-1" → "2.4.49"
[3] CPE Map     ← 100+ product entries + 36+ banner regexes
                   → cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
[4] CVE Fetch   ← NVD + Vulners + GHSA + Rapid7 + Exploit-DB (parallel)
[5] CVSS Score  ← v3.1 preferred, v3.0 fallback, v2.0 last resort
[6] CISA KEV    ← Cross-reference known-exploited catalog
[7] Exploits    ← Exploit-DB IDs + Metasploit modules + GitHub PoCs
[8] Confidence  ← 0–100% evidence score + tier label
                   CRITICAL (90%) / HIGH (75%) / MEDIUM (50%) / LOW (25%)
```

### `hybrid_search.py` — Dual-Engine Search

```
Query ─┬─→ BM25 (Okapi k₁=1.5, b=0.75)   exact tokens: CVE-IDs, ports, versions
       └─→ Dense Embeddings                conceptual similarity
              ├─ Ollama /api/embeddings     (when Ollama is online)
              └─ Offline 256-dim vectorizer (always available, zero deps)

Both ranked lists → Reciprocal Rank Fusion (RRF k=60)
                  + Domain boosters:  CISA KEV +0.25 / Exploit-DB +0.15

Result: { score, bm25_score, semantic_score, entry }
Modes:  "hybrid" | "bm25" | "semantic"
```

### `security_kb.py` — 7-Layer Local Intelligence

```
Layer 1  NVD + CISA KEV + OSV          live API fetch
Layer 2  Exploit-DB                    exploit code references
Layer 3  GitHub GHSA                   advisory database
Layer 4  Vendor Advisories             RedHat / Ubuntu / MSRC
Layer 5  Vector DB                     BM25 + semantic index
Layer 6  Hybrid Search                 ranked retrieval
Layer 7  Neural Synthesis              NEMO-8 (Nemotron) or Qwen
         query_with_nemotron()
         query_with_qwen()
         query_with_llm(model=...)      ← generic, auto-detects engine
```

---

## API Reference (key endpoints)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/query` | Full pipeline execution |
| `GET`  | `/api/stream` | SSE live token stream |
| `GET`  | `/api/status` | Ollama + GPU health |
| `POST` | `/api/nmap/scan` | Network scan |
| `POST` | `/api/tools/exploits/find-all` | Multi-source exploit search |
| `POST` | `/api/security-kb/query` | 7-layer KB synthesis |
| `POST` | `/api/security-kb/search` | Hybrid KB search |
| `POST` | `/api/nemotron/query` | NVIDIA Nemotron AI |
| `GET`  | `/api/models/nemotron` | Nemotron model info |
| `POST` | `/api/documents/upload` | Upload for RAG |
| `POST` | `/api/documents/search` | Hybrid document search |
| `GET`  | `/api/threat-intel/cisa-kev` | Live CISA KEV catalog |
| `GET`  | `/api/gpu/status` | VRAM + temp + utilization |

Full interactive docs: **http://127.0.0.1:8000/docs**

---

## GPU & VRAM Budget

| Model | Agent | VRAM |
|-------|-------|------|
| qwen3:8b | APEX-0 / DISSECT-4 | ~5.0 GB |
| deepseek-r1:8b | AEGIS-2 | ~5.0 GB |
| qwen2.5-coder:7b | FORGE-3 | ~4.5 GB |
| nemotron-mini:4b | NEMO-8 | ~2.8 GB |
| gemma3:4b | VANGUARD-5 / SCRIBE-6 / NEXUS-8 | ~2.5 GB |
| phi4-mini:3.8b | SHADOW-7 | ~2.3 GB |
| qwen3:4b | RECON-1 | ~2.5 GB |

> Only **one model runs at a time**. `model_manager.py` unloads the previous model before loading the next. Safe VRAM limit is set to **5,300 MB** (from 6,144 MB total).

---

## Configuration

**All settings are in `.env`** (copy from `.env.example`):

```ini
OLLAMA_HOST=http://localhost:11434
SERVER_HOST=127.0.0.1
SERVER_PORT=8000

# Override any agent model:
MODEL_NEMOTRON=nemotron-mini:4b
MODEL_THREAT_INTEL=deepseek-r1:8b
```

`core/config.py` auto-reads `.env` on import, so no extra library is needed.

---

## Running Tests

```bat
python run.py test
:: or:
python -m unittest discover -s tests -v
```

**30 / 30 tests pass** covering:
- CPE banner extraction (Apache, Nginx, IIS, OpenSSH)
- Validation engine (grounded vs ungrounded CVE detection)
- BM25 scoring and RRF fusion
- Offline 256-dim dense vectorizer
- Security KB hybrid retrieval
- NVIDIA Nemotron agent instantiation + pipeline registration
- Swarm agent 3-round context parsing

---

## First-Time Setup Checklist

```
□ Install Python 3.11+
□ Install Ollama  →  https://ollama.com/download
□ Run: python run.py setup
     installs Python deps + npm deps + builds React UI
□ Pull models:
     ollama pull qwen3:8b
     ollama pull qwen3:4b
     ollama pull deepseek-r1:8b
     ollama pull qwen2.5-coder:7b
     ollama pull gemma3:4b
     ollama pull phi4-mini:3.8b
     ollama pull nemotron-mini:4b
□ Run: python run.py check    ← verify everything is green
□ Run: python run.py web      ← launch
□ Open: http://127.0.0.1:8000
```

---

## Zero-Hallucination Policy

All 10 agents operate under strict rules defined in [`GEMINI.md`](file:///d:/ai%20agents/GEMINI.md):

- **Never fabricate** CVEs, ports, exploits, versions, or banners
- **Every claim** must trace to tool output or a verified threat database
- **Evidence classification**: CONFIRMED / LIKELY / POSSIBLE / UNKNOWN
- **CVE mapping requires**: product + exact version + affected range + prerequisites
- **Confidence is evidence-based** — not model certainty
