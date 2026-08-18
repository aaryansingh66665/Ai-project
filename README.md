# ⚡ CyberAgent X: 100% Offline NVIDIA GPU Unrestricted Multi-Agent AI System

An autonomous, 100% local, NVIDIA GPU-accelerated cybersecurity and deep intelligence multi-agent framework built for the **NVIDIA GeForce RTX 3050 (6GB VRAM)** running on local **Ollama (CUDA 13.2)** with zero cloud dependencies, zero search limits, and zero content restrictions.

---

## 🚀 Key Capabilities

1. **100% Offline & GPU Accelerated (CUDA)**:
   - Zero telemetry, zero cloud API keys, zero token bills.
   - Dynamic VRAM Lifecycle Manager automatically swops and unloads models between pipeline stages to fit 7B/8B reasoning models inside 6GB VRAM.

2. **Autonomous Multi-Agent Swarm (8 Specialized Agents)**:
   - 👑 **Master Orchestrator (Apex-0)** (`qwen3:8b`): Autonomous task planner & DAG router.
   - 🕵️ **OSINT & Deep Search (Recon-1)** (`qwen3:4b`): Limitless multi-source search across web & local RAG.
   - 🧠 **Threat Intelligence (Aegis-2)** (`deepseek-r1:8b`): Deep `<think>` chain-of-thought analysis & CVE mapping.
   - 💻 **Offensive & Defensive Coder (Forge-3)** (`qwen2.5-coder:7b`): Full-scale exploit PoCs, patches, and tooling.
   - 🔬 **Malware & Reverse Eng (Dissect-4)** (`qwen3:8b`): Binary disassembly, shellcode, and YARA rules.
   - 📡 **Network & Packet Analyst (Vanguard-5)** (`gemma3:4b`): PCAP traffic dissection & Suricata IDS rules.
   - 📝 **Executive Report Generator (Scribe-6)** (`gemma3:4b`): Technical deliverables, threat matrices, and remediation.
   - ⚔️ **Red Team & CTF Simulator (Shadow-7)** (`phi4-mini:3.8b`): Tactical penetration testing & privilege escalation.

3. **Unrestricted Search & Zero Refusal Personas**:
   - Direct, objective, technical research instructions without ethical disclaimers or refusal loops.
   - Multi-source search (DuckDuckGo, Wikipedia, ArXiv, raw web scrapers) and local document RAG.

4. **Dual Interface**:
   - **Modern Cyber Studio Web UI**: Live DAG pipeline visualizer, real-time token streaming, `<think>` reasoning view, live GPU/VRAM HUD, document drag-and-drop.
   - **Interactive Terminal CLI**: Resilient Rich console for quick command-line execution.

---

## ⚡ Quick Start

### 1. Launch via Menu
Double click `start.bat` or run:
```powershell
.\start.bat
```

### 2. Launch Web Studio Directly
```powershell
python main.py --web
```
Open **`http://127.0.0.1:8000`** in your web browser.

### 3. Launch Interactive Terminal CLI
```powershell
python main.py
```

### 4. Run System Diagnostics
```powershell
python main.py --check
```

### 5. Direct Headless CLI Execution
```powershell
python main.py --query "Analyze Log4j CVE-2021-44228 exploit mechanics and generate patch"
```
