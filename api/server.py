"""
FastAPI Server for CyberAgent X with Real-Time WebSockets, GPU Monitoring,
Unrestricted Search API, Offline Document RAG, and Swarm Execution.
"""

import os
import asyncio
import logging
from typing import List, Optional, Dict, Any
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Form, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel

from core.config import WORKSPACE_ROOT, AGENT_MODELS, DOCUMENTS_DIR
from core.model_manager import model_manager
from core.message_bus import message_bus, AgentEvent
from core.pipeline import pipeline
from core.mission_state import (
    active_mission,
    MissionState,
    DiscoveredAsset,
    ServiceRecord,
    VulnerabilityRecord,
    EvidenceItem,
    DecisionItem,
)
from tools.vuln_correlator import vuln_correlator
from tools.search_engine import search_engine
from tools.document_rag import document_rag
from tools.code_sandbox import code_sandbox
from tools.nmap_scanner import nmap_scanner
from tools.threat_intel_fetcher import threat_intel_fetcher

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("CyberAgent.Server")

# Global pipeline abort flag
_pipeline_stop_requested = False

app = FastAPI(
    title="CyberAgent X - Local GPU Multi-Agent System",
    description="Offline NVIDIA GPU-accelerated cybersecurity and research multi-agent platform.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------- REQUEST MODELS ---------------- #

class QueryRequest(BaseModel):
    query: str
    custom_agents: Optional[List[str]] = None


class SearchRequest(BaseModel):
    query: str
    max_results: Optional[int] = 6


class CodeRequest(BaseModel):
    code: str
    timeout_seconds: Optional[int] = 15


class NmapScanRequest(BaseModel):
    target: str
    profile: Optional[str] = "standard"
    custom_args: Optional[str] = None
    timeout_seconds: Optional[int] = 180


class NmapParseRequest(BaseModel):
    content: Optional[str] = None
    filename: Optional[str] = None


class NmapSwarmRequest(BaseModel):
    target: str
    scan_data: Optional[Dict[str, Any]] = None
    custom_agents: Optional[List[str]] = None


class ThreatIntelRequest(BaseModel):
    query: str
    max_per_source: Optional[int] = 5


class CorrelateVulnsRequest(BaseModel):
    target: Optional[str] = "127.0.0.1"
    scan_data: Optional[Dict[str, Any]] = None
    ports: Optional[List[Dict[str, Any]]] = None


class SecurityKBQueryRequest(BaseModel):
    query: str
    model: Optional[str] = "qwen3:8b"


class SecurityKBSearchRequest(BaseModel):
    query: str
    top_k: Optional[int] = 5
    mode: Optional[str] = "hybrid"  # "hybrid" | "bm25" | "semantic"
    alpha: Optional[float] = 0.5


class RAGSearchRequest(BaseModel):
    query: str
    top_k: Optional[int] = 5
    mode: Optional[str] = "hybrid"  # "hybrid" | "bm25" | "semantic"
    alpha: Optional[float] = 0.5


# ---------------- MISSION STATE & CORRELATION ENDPOINTS ---------------- #

@app.get("/api/mission/current")
async def get_current_mission():
    """Returns the active mission state and full 10-node hierarchy."""
    from core.mission_state import active_mission
    return {
        "mission": active_mission.to_dict()["mission"],
        "summary": active_mission.to_tree_summary(),
        "mission_id": active_mission.mission_id,
        "created_at": active_mission.created_at,
        "updated_at": active_mission.updated_at,
    }


@app.get("/api/mission/tree")
async def get_mission_tree():
    """Returns the 10-node directory tree summary of the current mission."""
    from core.mission_state import active_mission
    return active_mission.to_tree_summary()


@app.post("/api/mission/correlate")
async def correlate_vulnerabilities(req: CorrelateVulnsRequest):
    """
    Executes the complete 8-step vulnerability risk and enrichment pipeline:
      [1] Nmap / Scan Ingestion
      [2] Product + Version Normalization
      [3] CPE 2.3 Generation & Validation
      [4] Multi-Source CVE Matching
      [5] CVSS Scoring & Vector Extraction
      [6] CISA KEV Verification
      [7] Exploit Availability (ExploitDB, Metasploit, PoCs)
      [8] Explainable Confidence Scoring (0-100%)
    """
    from core.mission_state import active_mission
    loop = asyncio.get_running_loop()
    
    input_data = req.ports if req.ports else (req.scan_data if req.scan_data else [{"ip": req.target, "port": 80, "service": "http"}])
    result = await loop.run_in_executor(None, vuln_correlator.run_full_pipeline, input_data)
    
    for v in result.get("vulnerabilities", []):
        rec = VulnerabilityRecord(**v)
        active_mission.add_vulnerability(rec)
    
    for s in result.get("services", []):
        srec = ServiceRecord(**s)
        active_mission.add_service(srec)

    message_bus.emit_sync(
        AgentEvent(
            event_type="mission_update",
            agent_id="correlator",
            agent_name="Evidence Correlator",
            payload={
                "phase": "8-Step Vulnerability Enrichment",
                "mission_summary": active_mission.to_tree_summary(),
                "enriched_count": len(result.get("vulnerabilities", [])),
            },
            step_index=0,
            total_steps=1,
        )
    )

    return result


# ---------------- LOCAL SECURITY KB ENDPOINTS ---------------- #

@app.get("/api/security-kb/status")
async def get_security_kb_status():
    """Returns Local Security KB statistics and indexed vector records."""
    from tools.security_kb import local_security_kb
    return {
        "total_entries": len(local_security_kb.entries),
        "storage_path": str(local_security_kb.storage_dir),
        "layers": [
            "NVD/CVE + CISA KEV + OSV",
            "Exploit-DB",
            "GitHub Advisories",
            "Vendor Advisories (RedHat, Ubuntu, MSRC)",
            "Vector Database (Local BM25 + Embeddings)",
            "Ollama + Qwen (qwen3:8b / qwen3:4b / qwen2.5-coder)",
        ],
    }


@app.post("/api/security-kb/search")
async def search_security_kb(req: SecurityKBSearchRequest):
    """Performs Dual-Engine Hybrid search (BM25 + Semantic Embeddings) over the Local Security KB Vector DB."""
    from tools.security_kb import local_security_kb
    loop = asyncio.get_running_loop()
    matches = await loop.run_in_executor(
        None,
        local_security_kb.search_hybrid,
        req.query,
        req.top_k or 5,
        req.mode or "hybrid",
        req.alpha if req.alpha is not None else 0.5,
    )
    return {
        "query": req.query,
        "mode": req.mode or "hybrid",
        "alpha": req.alpha if req.alpha is not None else 0.5,
        "total_matches": len(matches),
        "matches": matches,
    }


@app.post("/api/security-kb/ingest")
async def ingest_to_security_kb(req: SecurityKBQueryRequest):
    """Ingests a target vulnerability across the 4 threat layers into the local Vector DB."""
    from tools.security_kb import local_security_kb
    loop = asyncio.get_running_loop()
    entry = await loop.run_in_executor(None, local_security_kb.ingest_to_vector_db, req.query)
    return {"success": True, "entry": entry.to_dict()}


@app.post("/api/security-kb/query")
async def query_security_kb_with_llm(req: SecurityKBQueryRequest):
    """
    Executes the full 7-tier pipeline:
      [1] Tri-Feed (NVD/CVE + CISA KEV + OSV)
      [2] Exploit-DB
      [3] GitHub Advisories
      [4] Vendor Advisories
      [5] Local Vector Database
      [6] Neural Synthesis (NVIDIA Nemotron / Qwen)
    """
    from tools.security_kb import local_security_kb
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        local_security_kb.query_with_llm,
        req.query,
        req.model or "nemotron-mini:4b",
    )
    return result


@app.get("/api/models/nemotron")
async def get_nemotron_info():
    """Returns NVIDIA Nemotron AI family models, acceleration details, and available variants."""
    from core.config import SUPPORTED_NEMOTRON_MODELS, AGENT_MODELS
    from core.model_manager import model_manager
    installed = model_manager.list_installed_models()
    installed_names = [m.get("name", "") for m in installed]
    nemotron_installed = [m for m in installed_names if "nemotron" in m.lower()]
    
    return {
        "engine": "NVIDIA Nemotron AI",
        "family": "NVIDIA Open Reasoning & Threat Modeling Models",
        "default_model": AGENT_MODELS.get("nemotron", "nemotron-mini:4b"),
        "supported_models": SUPPORTED_NEMOTRON_MODELS,
        "installed_nemotron_models": nemotron_installed,
        "hardware_acceleration": "NVIDIA CUDA / Tensor Core Accelerated",
        "capabilities": [
            "Hardware-accelerated analytical reasoning",
            "Multi-step threat modeling & attack tree decomposition",
            "Deterministic CVSS metrics validation",
            "Zero-hallucination exploit evaluation",
            "Code-level remediation synthesis",
        ],
    }


@app.post("/api/nemotron/query")
async def query_with_nemotron_ai(req: SecurityKBQueryRequest):
    """Executes full threat modeling and remediation synthesis using NVIDIA Nemotron AI."""
    from tools.security_kb import local_security_kb
    target_model = req.model if (req.model and "nemotron" in req.model) else "nemotron-mini:4b"
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        local_security_kb.query_with_nemotron,
        req.query,
        target_model,
    )
    return result


# ---------------- METASPLOIT & EXPLOIT FINDER MODELS ---------------- #

class MetasploitSearchRequest(BaseModel):
    query: str
    max_results: Optional[int] = 6


class MetasploitDetailsRequest(BaseModel):
    module_path_or_url: str


class MetasploitGenerateRCRequest(BaseModel):
    module_fullname: str
    rhosts: Optional[str] = "127.0.0.1"
    rport: Optional[int] = None
    lhost: Optional[str] = "127.0.0.1"
    lport: Optional[int] = 4444
    payload: Optional[str] = None
    extra_options: Optional[Dict[str, str]] = None


class ExploitDBSearchRequest(BaseModel):
    query: str
    max_results: Optional[int] = 8


class GitHubPoCSearchRequest(BaseModel):
    query: str
    max_results: Optional[int] = 8


class GitHubPoCReadmeRequest(BaseModel):
    repo_full_name: str


class UnifiedExploitSearchRequest(BaseModel):
    query: str


# ---------------- METASPLOIT, EXPLOIT-DB & GITHUB POC ENDPOINTS ---------------- #

@app.post("/api/tools/metasploit/search")
async def search_metasploit_modules(req: MetasploitSearchRequest):
    """Searches Metasploit Framework modules across canonical catalog, Rapid7, and GitHub."""
    from tools.exploit_finder import exploit_finder
    loop = asyncio.get_running_loop()
    modules = await loop.run_in_executor(None, exploit_finder.search_metasploit, req.query, req.max_results or 6)
    return {"query": req.query, "total": len(modules), "modules": [m.to_dict() for m in modules]}


@app.post("/api/tools/metasploit/details")
async def get_metasploit_module_details(req: MetasploitDetailsRequest):
    """Fetches full Ruby source code, targets, options, and metadata for a Metasploit module."""
    from tools.exploit_finder import exploit_finder
    loop = asyncio.get_running_loop()
    details = await loop.run_in_executor(None, exploit_finder.get_metasploit_module_details, req.module_path_or_url)
    if not details:
        raise HTTPException(status_code=404, detail="Metasploit module not found or source unreachable")
    return details.to_dict()


@app.post("/api/tools/metasploit/generate-rc")
async def generate_metasploit_rc_script(req: MetasploitGenerateRCRequest):
    """Generates an automated Metasploit Resource Script (.rc) for safe lab verification."""
    from tools.exploit_finder import exploit_finder
    rc_script = exploit_finder.generate_msf_resource_script(
        module_fullname=req.module_fullname,
        rhosts=req.rhosts or "127.0.0.1",
        rport=req.rport,
        lhost=req.lhost or "127.0.0.1",
        lport=req.lport or 4444,
        payload=req.payload,
        extra_options=req.extra_options,
    )
    return {
        "module_fullname": req.module_fullname,
        "rc_script": rc_script,
        "filename": f"{req.module_fullname.split('/')[-1]}.rc",
    }


@app.post("/api/tools/exploitdb/search")
async def search_exploitdb_entries(req: ExploitDBSearchRequest):
    """Searches Exploit-DB for weaponized exploits, platforms, and EDB-IDs."""
    from tools.exploit_finder import exploit_finder
    loop = asyncio.get_running_loop()
    entries = await loop.run_in_executor(None, exploit_finder.search_exploitdb, req.query, req.max_results or 8)
    return {"query": req.query, "total": len(entries), "entries": [e.to_dict() for e in entries]}


@app.get("/api/tools/exploitdb/code/{edb_id}")
async def get_exploitdb_raw_code(edb_id: str):
    """Downloads the raw exploit PoC / C / Python code from Exploit-DB."""
    from tools.exploit_finder import exploit_finder
    loop = asyncio.get_running_loop()
    raw_code = await loop.run_in_executor(None, exploit_finder.get_exploitdb_raw_code, edb_id)
    if not raw_code:
        raise HTTPException(status_code=404, detail=f"Exploit code for EDB-{edb_id} not found")
    return {"edb_id": edb_id, "raw_code": raw_code, "length": len(raw_code)}


@app.post("/api/tools/github-pocs/search")
async def search_github_cve_pocs(req: GitHubPoCSearchRequest):
    """Searches GitHub for public CVE PoC repositories and exploit implementations."""
    from tools.exploit_finder import exploit_finder
    loop = asyncio.get_running_loop()
    pocs = await loop.run_in_executor(None, exploit_finder.search_github_cve_pocs, req.query, req.max_results or 8)
    return {"query": req.query, "total": len(pocs), "pocs": [p.to_dict() for p in pocs]}


@app.post("/api/tools/github-pocs/readme")
async def get_github_poc_readme(req: GitHubPoCReadmeRequest):
    """Fetches the README or primary documentation of a GitHub PoC repository."""
    from tools.exploit_finder import exploit_finder
    loop = asyncio.get_running_loop()
    readme = await loop.run_in_executor(None, exploit_finder.get_github_poc_readme, req.repo_full_name)
    if not readme:
        raise HTTPException(status_code=404, detail="README not found")
    return {"repo_full_name": req.repo_full_name, "readme": readme}


@app.post("/api/tools/exploits/find-all")
async def find_all_exploits_and_vulns(req: UnifiedExploitSearchRequest):
    """
    Unified multi-source search across:
      [1] Metasploit Framework Modules
      [2] Exploit-DB Public Codes
      [3] GitHub CVE PoC Repositories
      [4] GitHub Security Advisories (GHSA)
    """
    from tools.exploit_finder import exploit_finder
    loop = asyncio.get_running_loop()
    results = await loop.run_in_executor(None, exploit_finder.find_all_exploits_and_vulns, req.query)
    return results


# ---------------- REST ENDPOINTS ---------------- #

@app.get("/api/status")
async def get_system_status():
    """Returns GPU metrics, loaded models, and Ollama connectivity."""
    loop = asyncio.get_running_loop()
    health = await loop.run_in_executor(None, model_manager.check_health)
    return {
        "status": "online",
        "gpu": health["gpu"],
        "ollama_online": health["ollama_online"],
        "running_models": health["running_models"],
        "installed_models": health["installed_models"],
        "agent_roster": AGENT_MODELS,
    }


@app.get("/api/gpu-status")
async def get_gpu_status():
    """Returns live GPU metrics (VRAM, temperature, utilisation)."""
    loop = asyncio.get_running_loop()
    gpu = await loop.run_in_executor(None, model_manager.get_gpu_stats)
    return gpu.to_dict()


@app.get("/api/models")
async def get_models():
    """Lists all Ollama models installed locally."""
    loop = asyncio.get_running_loop()
    installed = await loop.run_in_executor(None, model_manager.list_installed_models)
    running = await loop.run_in_executor(None, model_manager.list_running_models)
    return {
        "installed": installed,
        "running": running,
    }


@app.get("/api/messages")
async def get_recent_messages():
    """Returns the last 50 agent events emitted on the message bus."""
    return {"messages": message_bus.get_history(limit=50)}


@app.get("/api/agents")
async def get_agent_roster():
    """Returns detailed roster of all 8 specialized agents."""
    roster = []
    for agent_id, agent in pipeline.agents.items():
        roster.append({
            "id": agent.agent_id,
            "name": agent.name,
            "role": agent.role,
            "model": agent.model,
            "emoji": agent.emoji,
        })
    return {"agents": roster}


@app.post("/api/query")
async def execute_query(req: QueryRequest, background_tasks: BackgroundTasks):
    """Trigger multi-agent swarm pipeline execution."""
    pipeline.stop_requested = False
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, pipeline.execute, req.query, req.custom_agents)
    return result


@app.post("/api/pipeline/stop")
async def stop_pipeline():
    """Signal the running pipeline to abort after the current agent stage."""
    pipeline.request_stop()
    logger.info("Pipeline stop requested via API.")
    return {"success": True, "message": "Stop signal sent. Current agent will finish then pipeline halts."}


@app.post("/api/search")
async def search_endpoint(req: SearchRequest):
    """Direct unrestricted multi-source search."""
    results = search_engine.search(req.query, max_results=req.max_results or 6)
    return {"query": req.query, "count": len(results), "results": results}


@app.post("/api/threat-intel/search")
async def threat_intel_search(req: ThreatIntelRequest):
    """
    Fan-out search across all 8 threat intelligence databases:
    NVD, CISA KEV, GitHub Advisory, ExploitDB, Vulners, Rapid7, Metasploit, Crawl4AI.
    Returns severity-sorted, deduplicated results.
    """
    loop = asyncio.get_running_loop()
    results = await loop.run_in_executor(
        None,
        threat_intel_fetcher.search_all,
        req.query,
        req.max_per_source or 5,
    )
    return {
        "query": req.query,
        "total": len(results),
        "sources_queried": ["NVD", "CISA_KEV", "GitHub_Advisory", "ExploitDB", "Vulners", "Rapid7", "Metasploit"],
        "results": [r.to_dict() for r in results],
    }


@app.get("/api/threat-intel/cisa-kev")
async def get_cisa_kev():
    """Return the full CISA Known Exploited Vulnerabilities feed (cached 1h)."""
    loop = asyncio.get_running_loop()
    feed = await loop.run_in_executor(None, threat_intel_fetcher._get_cisa_kev_feed)
    return {"total": len(feed), "vulnerabilities": feed}


@app.get("/api/documents")
async def list_documents():
    """List all indexed files in local offline RAG."""
    docs = document_rag.list_documents()
    return {"total": len(docs), "documents": docs}


@app.post("/api/documents/upload")
async def upload_document(file: UploadFile = File(...)):
    """Upload and index a text/code/markdown/PDF document."""
    try:
        content_bytes = await file.read()
        try:
            content_text = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            content_text = content_bytes.decode("latin-1", errors="ignore")

        # Save to documents dir
        file_path = DOCUMENTS_DIR / file.filename
        with open(file_path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(content_text)

        chunks_count = document_rag.add_document(file.filename, content_text)
        return {"success": True, "filename": file.filename, "chunks": chunks_count}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})


@app.post("/api/documents/search")
async def search_documents(req: RAGSearchRequest):
    """Performs Dual-Engine Hybrid search (BM25 + Semantic Embeddings) over indexed documents."""
    loop = asyncio.get_running_loop()
    results = await loop.run_in_executor(
        None,
        document_rag.search_hybrid,
        req.query,
        req.top_k or 5,
        req.mode or "hybrid",
        req.alpha if req.alpha is not None else 0.5,
    )
    return {
        "query": req.query,
        "mode": req.mode or "hybrid",
        "alpha": req.alpha if req.alpha is not None else 0.5,
        "total_matches": len(results),
        "results": results,
    }


@app.post("/api/execute-code")
async def execute_code_endpoint(req: CodeRequest):
    """Execute Python code in local sandbox."""
    res = code_sandbox.execute_python(req.code, timeout_seconds=req.timeout_seconds or 15)
    return res


@app.post("/api/gpu/unload")
async def unload_gpu():
    """Unload all active models to free GPU VRAM."""
    loop = asyncio.get_running_loop()
    count = await loop.run_in_executor(None, model_manager.unload_all_models)
    gpu = await loop.run_in_executor(None, model_manager.get_gpu_stats)
    return {"success": True, "unloaded_models": count, "gpu": gpu.to_dict()}


# ---------------- NMAP NETWORK RECON ENDPOINTS ---------------- #

@app.get("/api/tools/nmap/profiles")
async def get_nmap_profiles():
    """Returns available Nmap scan profile presets."""
    profiles = {
        "quick": "-T4 -F",
        "standard": "-T4 -sV -sC",
        "aggressive": "-T4 -A -sV -sC",
        "stealth": "-T2 -sS",
        "udp": "-sU -T4 --top-ports 100",
        "vuln": "-sV --script=vuln",
        "full": "-T4 -sV -sC -p-",
    }
    return {"profiles": profiles}


@app.get("/api/tools/nmap/status")
async def get_nmap_status():
    """Returns local Nmap installation status and binary version."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, nmap_scanner.get_binary_info)


@app.post("/api/tools/nmap/scan")
async def run_nmap_scan(req: NmapScanRequest):
    """Executes a live Nmap network scan against target."""
    loop = asyncio.get_running_loop()
    res = await loop.run_in_executor(
        None,
        nmap_scanner.scan,
        req.target,
        req.profile,
        req.custom_args,
        req.timeout_seconds,
    )
    return res


@app.post("/api/tools/nmap/parse")
async def parse_nmap_log_endpoint(req: NmapParseRequest):
    """Parses raw Nmap XML or terminal text into structured JSON."""
    content = req.content or ""
    if "<nmaprun" in content:
        res = nmap_scanner.parse_nmap_xml(content)
    else:
        res = nmap_scanner.parse_nmap_text(content)
    res["success"] = True
    return res


@app.post("/api/tools/nmap/upload")
async def upload_nmap_file(file: UploadFile = File(...)):
    """Uploads and parses an Nmap .xml or .nmap scan log file."""
    try:
        content_bytes = await file.read()
        try:
            content_text = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            content_text = content_bytes.decode("latin-1", errors="ignore")

        if file.filename.endswith(".xml") or "<nmaprun" in content_text:
            res = nmap_scanner.parse_nmap_xml(content_text)
        else:
            res = nmap_scanner.parse_nmap_text(content_text)

        res["success"] = True
        res["filename"] = file.filename
        return res
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})


@app.post("/api/tools/nmap/analyze-with-swarm")
async def analyze_nmap_with_swarm(req: NmapSwarmRequest):
    """Feeds Nmap scan findings directly into the multi-agent swarm pipeline."""
    target = req.target
    scan_data = req.scan_data or {}

    # Format initial context from scan findings
    hosts_summary = []
    for host in scan_data.get("hosts", []):
        ip = host.get("ip", target)
        hostnames = ", ".join(host.get("hostnames", [])) or "None"
        ports = host.get("ports", [])
        port_lines = []
        for p in ports:
            port_lines.append(
                f"  - Port {p.get('port')}/{p.get('protocol')} [{p.get('service')}] "
                f"Product: {p.get('product')} Version: {p.get('version')} "
                f"Scripts: {p.get('scripts', {})}"
            )
        hosts_summary.append(f"Target Host: {ip} ({hostnames})\n" + "\n".join(port_lines))

    scan_context = "\n\n".join(hosts_summary) if hosts_summary else f"Target: {target} (No open ports discovered)"
    query = f"Analyze Nmap reconnaissance scan results and audit vulnerabilities for: {target}"

    agents = req.custom_agents or ["network", "threat_intel", "coder", "redteam", "report"]
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        pipeline.execute,
        query,
        agents,
        None,
        scan_context,
    )
    return result



# ---------------- WEBSOCKET STREAMING ---------------- #

@app.websocket("/ws/pipeline")
async def websocket_pipeline(websocket: WebSocket):
    """
    WebSocket endpoint streaming live agent tokens, <think> reasoning traces,
    DAG progression, and GPU metrics in real-time.
    """
    await websocket.accept()
    queue = message_bus.subscribe()
    logger.info("WebSocket client connected to /ws/pipeline")

    # Periodic background task to send GPU metrics
    async def send_gpu_heartbeat():
        while True:
            try:
                stats = model_manager.get_gpu_stats().to_dict()
                await websocket.send_json({"type": "gpu_update", "gpu": stats})
                await asyncio.sleep(2.0)
            except Exception:
                break

    heartbeat_task = asyncio.create_task(send_gpu_heartbeat())

    try:
        while True:
            # Receive event from message bus queue and forward to client
            event: AgentEvent = await queue.get()
            await websocket.send_json(event.to_dict())
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    except asyncio.CancelledError:
        logger.info("WebSocket pipeline cancelled during shutdown")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        heartbeat_task.cancel()
        message_bus.unsubscribe(queue)


# Serve built web static files if they exist
WEB_DIST = WORKSPACE_ROOT / "web" / "dist"
if WEB_DIST.exists():
    app.mount("/", StaticFiles(directory=str(WEB_DIST), html=True), name="web")


def start_server(host: str = "127.0.0.1", port: int = 8000):
    import uvicorn
    uvicorn.run("api.server:app", host=host, port=port, log_level="info", reload=False)


if __name__ == "__main__":
    start_server()
