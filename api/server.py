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
from tools.search_engine import search_engine
from tools.document_rag import document_rag
from tools.code_sandbox import code_sandbox
from tools.nmap_scanner import nmap_scanner

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("CyberAgent.Server")

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


# Request & Response Schemas
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
    loop = asyncio.get_running_loop()
    # Run pipeline in background executor to prevent blocking async event loop
    result = await loop.run_in_executor(None, pipeline.execute, req.query, req.custom_agents)
    return result


@app.post("/api/search")
async def search_endpoint(req: SearchRequest):
    """Direct unrestricted multi-source search."""
    results = search_engine.search(req.query, max_results=req.max_results or 6)
    return {"query": req.query, "count": len(results), "results": results}


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
