# Walkthrough: CyberAgent X (Offline GPU Unrestricted Multi-Agent System)

CyberAgent X is a 100% offline, NVIDIA GPU-accelerated multi-agent cybersecurity swarm platform designed specifically for the **NVIDIA GeForce RTX 3050 (6GB VRAM)**, running local **Ollama** models with dynamic VRAM swapping, zero content refusals, and multi-source threat intelligence correlation.

---

## 🎯 1. Exploit, CVE & Metasploit Intelligence Radar

A multi-source exploit and vulnerability search suite integrating:
- **Metasploit Framework Integration**: Fast module discovery, Ruby header & ranking inspection, author attribution, CVE references, default port resolution, and automated `.rc` Resource Script generation for safe authorized lab verification.
- **Exploit-DB Integration**: Instant lookup of weaponized public exploits, verified status, target platform tags, and raw exploit PoC code extractor (Python, C, Ruby).
- **GitHub CVE PoC Repositories**: Real-time integration with the `nomi-sec/PoC-in-GitHub` database and GitHub Repositories Search API for public PoC implementations with live star counts and forks.
- **GitHub Security Advisories (GHSA)**: Ecosystem vulnerability bulletins, affected package version ranges, and patched release tracking.

```
                  UNIFIED EXPLOIT RADAR
                            │
       ┌────────────────────┼────────────────────┐
       ↓                    ↓                    ↓
  METASPLOIT           EXPLOIT-DB           GITHUB POCS
Modules & .RC gen    Public PoCs & code   nomi-sec & repos
       │                    │                    │
       └────────────────────┼────────────────────┘
                            ↓
               [RAW CODE / .RC SCRIPT VIEWER]
```

### Available Endpoints:
- `POST /api/tools/exploits/find-all`: Unified 4-source parallel search across Metasploit, Exploit-DB, GitHub PoCs, and GHSA.
- `POST /api/tools/metasploit/search`: Metasploit module search by CVE, product, or keyword.
- `POST /api/tools/metasploit/details`: Inspect full Ruby source code, targets, and options.
- `POST /api/tools/metasploit/generate-rc`: Generates automated msfconsole `.rc` resource scripts.
- `POST /api/tools/exploitdb/search`: Exploit-DB search by CVE or keyword.
- `GET /api/tools/exploitdb/code/{edb_id}`: Raw PoC download and viewer.
- `POST /api/tools/github-pocs/search`: GitHub CVE PoC search.

---

## 🏛️ 2. Local Security Knowledge Base (KB) Architecture

```
                    LOCAL SECURITY KB
                           │
        ┌──────────────────┼──────────────────┐
        ↓                  ↓                  ↓
      NVD/CVE            CISA KEV          OSV
   CVE + CVSS/CPE      Exploited in wild   Packages
        │                  │                  │
        └──────────────────┼──────────────────┘
                           ↓
                     Exploit-DB
                  Public exploit references
                           │
                           ↓
                   GitHub Advisories
                           │
                           ↓
                    Vendor Advisories (RedHat, Ubuntu, MSRC, Debian)
                           │
                           ↓
                    Vector Database (Local Hybrid BM25 & Semantic Store)
                           │
                           ↓
                    Ollama + Qwen (Local Neural Intelligence Synthesis)
```

| Layer | Engine Component | Data Streams & Functionality |
|---|---|---|
| **Layer 1** | **Tri-Feed Ingestion (Parallel)** | **NVD/CVE** (CVSS metrics, CPEs), **CISA KEV** (actively exploited in wild, ransomware use), **OSV** (PyPI, npm, Go, Rust, Maven open-source packages) |
| **Layer 2** | **Exploit-DB Layer** | Public exploit references, PoC codes, EDB-IDs, verified weaponization flags |
| **Layer 3** | **GitHub Advisories (GHSA)** | GitHub security advisories, affected ecosystem ranges, patched versions |
| **Layer 4** | **Vendor Advisories** | **Red Hat Security Data API**, **Ubuntu CVE Tracker**, **MSRC**, **Debian Security Tracker** |
| **Layer 5** | **Vector Database** | Local persistent Vector & BM25 hybrid index (`data/security_kb/index.json`) for sub-millisecond semantic retrieval |
| **Layer 6** | **Ollama + Qwen** | Local neural synthesis via `qwen3:8b`, `qwen3:4b`, or `qwen2.5-coder:7b` for root-cause analysis, PoC generation & remediation code |

---

## 🏗️ 3. Multi-Agent DAG Execution Architecture

```
                    USER MISSION
                         ↓
                  ORCHESTRATOR
                         ↓
              ┌──────────┼──────────┐
              ↓          ↓          ↓
            OSINT    THREAT INTEL   RAG
              │          │          │
              └──────────┼──────────┘
                         ↓
                  EVIDENCE CORRELATOR
                         ↓
          ┌──────────────┼──────────────┐
          ↓              ↓              ↓
       NETWORK         MALWARE        CODING
          │              │              │
          └──────────────┼──────────────┘
                         ↓
                   VALIDATION
                         ↓
                     REPORT
```

* **Phase 1 (Intel Gathering)**: [OSINT, Threat Intel, RAG/Coder] gather external intelligence, footprints, and initial context.
* **Evidence Correlator**: Synthesizes Phase 1 outputs and executes the 8-step vulnerability risk and enrichment engine.
* **Phase 2 (Deep Specialist Analysis)**: [Network, Malware, Red Team] perform binary inspection, packet analysis, and tactical exploit mapping.
* **Validation Engine**: Cross-verifies evidence across specialist agents and computes overall mission confidence ratings.
* **Report Agent**: Synthesizes the executive and technical intelligence report deliverable.

---

## 🎯 4. 8-Stage Vulnerability Risk & Enrichment Pipeline

```
  [1] Nmap / Scan Ingestion
          ↓
  [2] Product + Version Normalization
          ↓
  [3] CPE 2.3 Generation & Validation
          ↓
  [4] Multi-Source CVE Matching (NVD, GHSA, Vulners, Rapid7, ExploitDB)
          ↓
  [5] CVSS v3.1 / v3.0 / v2.0 Scoring & Vector Extraction
          ↓
  [6] CISA KEV (Known Exploited Vulnerabilities) Verification
          ↓
  [7] Exploit Availability Assessment (ExploitDB, Metasploit, PoCs)
          ↓
  [8] Explainable Confidence Scoring (0-100% & Tier Rating)
```

---

## 📁 5. 10-Node Mission State Architecture (`mission/`)

```
mission/
├── target              # Target domain, IP address, CIDR, or system identifier
├── scope               # Authorized boundaries, port constraints, and test modes
├── discovered_assets   # Active hosts, IPs, MAC addresses, and OS fingerprints
├── services            # Open ports, protocols, detected products, and raw banners
├── vulnerabilities     # 8-step enriched CVE records, CVSS scores, vectors, and remediations
├── evidence            # Raw outputs, scan XMLs, tool executions, and artifact traces
├── agent_results       # Specialist agent responses, thinking traces, and timings
├── confidence          # Overall mission confidence score, rating, and validated checks
├── decisions           # Tactical decisions, triage recommendations, and prioritization
└── final_report        # Complete executive intelligence deliverable in Markdown
```

---

## 🤖 6. Multi-Agent Roster & Model Allocations

| # | Agent Role | Assigned Model | VRAM | Status | Specialty |
|---|---|---|---|---|---|
| 1 | 👑 **Master Orchestrator (Apex-0)** | `qwen3:8b` | ~5.0 GB | **READY** | Dynamic DAG planning & swarm routing |
| 2 | 🕵️ **OSINT & Deep Search (Recon-1)** | `qwen3:4b` | ~2.5 GB | **READY** | Multi-source web recon & document RAG |
| 3 | 🧠 **Threat Intelligence (Aegis-2)** | `deepseek-r1:8b` | ~5.0 GB | **READY** | Deep `<think>` CoT reasoning & CVE mapping |
| 4 | 💻 **Offensive/Defensive Coder (Forge-3)** | `qwen2.5-coder:7b` | ~4.5 GB | **READY** | Full-scale exploit PoCs, patches & tools |
| 5 | 🔬 **Malware & Reverse Eng (Dissect-4)** | `qwen3:8b` | ~5.0 GB | **READY** | Binary disassembly, shellcode & YARA rules |
| 6 | 📡 **Network & Packet Analyst (Vanguard-5)** | `gemma3:4b` | ~2.5 GB | **READY** | PCAP dissection & Suricata IDS signatures |
| 7 | 📝 **Executive Report Generator (Scribe-6)** | `gemma3:4b` | ~2.5 GB | **READY** | Technical deliverables & remediation matrices |
| 8 | ⚔️ **Red Team & CTF Simulator (Shadow-7)** | `phi4-mini:3.8b` | ~2.3 GB | **READY** | Privilege escalation & tactical CTF playbooks |

---

### ⚙️ 6.1 Model Sampling & Factual Accuracy Parameters

To eliminate hallucination, prevent creative token branching, and enforce strict evidence adherence across all 8 agents (adhering to the 20 Evidence & CVE Rules), model inference parameters are configured as follows:

| Parameter | Configured Value | Recommended Range | Reason & Operational Impact |
|---|---|---|---|
| `temperature` | `0.1` | `0.0 to 0.2` | Eliminates creative token branching on factual and analytical cybersecurity queries. |
| `top_p` | `0.2` | `0.1 to 0.3` | Restricts token selection strictly to high-probability tokens. |
| `repeat_penalty` | `1.15` | `1.1 to 1.2` | Prevents repetitive phrasing and reasoning loops in smaller models. |
| `num_ctx` | `8192` | `4096 to 8192` | Prevents VRAM exhaustion on RTX 3050 (6GB) while retaining complete context windows. |
| `num_gpu` | `99` | `99` | Offloads all model layers directly to NVIDIA Discrete GPU with CUDA. |

---

## 🚀 7. How to Run

### Quick Launch:
```powershell
.\start.bat
```

### Direct Python Execution:
```powershell
python main.py --web --port 8000
```
Open **`http://localhost:8000`** in any web browser.
