"""
Base Agent framework for CyberAgent X with streaming Ollama execution,
<think> reasoning block extraction, dynamic GPU management, and tool routing.
"""

import os
import json
import time
import httpx
import logging
from typing import Dict, List, Any, Optional, Generator, Callable
from core.config import OLLAMA_HOST, OLLAMA_TIMEOUT, DEFAULT_MODEL_OPTIONS
from core.model_manager import model_manager
from core.message_bus import message_bus, AgentEvent
from tools.search_engine import search_engine
from tools.document_rag import document_rag
from tools.code_sandbox import code_sandbox
from tools.nmap_scanner import nmap_scanner
from tools.threat_intel_fetcher import threat_intel_fetcher

logger = logging.getLogger("CyberAgent.BaseAgent")


class BaseAgent:
    """Base autonomous agent executing locally via Ollama with NVIDIA GPU acceleration."""

    def __init__(
        self,
        agent_id: str,
        name: str,
        role: str,
        model: str,
        system_prompt: str,
        emoji: str = "🤖",
    ):
        self.agent_id = agent_id
        self.name = name
        self.role = role
        self.model = model
        self.system_prompt = system_prompt
        self.emoji = emoji
        self.host = OLLAMA_HOST.rstrip("/")
        self.conversation_history: List[Dict[str, str]] = []

    def prepare_hardware(self):
        """Ensure GPU VRAM is cleared and target model is primed."""
        model_manager.prepare_model_for_agent(self.model)

    def run(
        self,
        prompt: str,
        context: Optional[str] = None,
        step_index: int = 1,
        total_steps: int = 1,
        on_token: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        """
        Synchronously execute agent with real-time token streaming and GPU tracking.
        """
        self.prepare_hardware()

        # Build full prompt with contextual attachments
        full_user_content = prompt
        if context:
            full_user_content = f"--- [PRIOR AGENT INTELLIGENCE & CONTEXT] ---\n{context}\n\n--- [PRIMARY TASK OBJECTIVE] ---\n{prompt}"

        # Emit Agent Start Event
        message_bus.emit_sync(
            AgentEvent(
                event_type="start",
                agent_id=self.agent_id,
                agent_name=self.name,
                payload={"model": self.model, "prompt": prompt[:200]},
                step_index=step_index,
                total_steps=total_steps,
            )
        )

        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": full_user_content},
        ]

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            "options": DEFAULT_MODEL_OPTIONS,
        }

        full_response = []
        thinking_blocks = []
        in_thinking = False
        current_think = []
        start_time = time.time()

        try:
            with httpx.Client(timeout=OLLAMA_TIMEOUT) as client:
                with client.stream("POST", f"{self.host}/api/chat", json=payload) as response:
                    if response.status_code != 200:
                        err_msg = f"Ollama HTTP error {response.status_code}: {response.read().decode('utf-8')}"
                        logger.error(err_msg)
                        raise RuntimeError(err_msg)

                    for line in response.iter_lines():
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            delta = data.get("message", {}).get("content", "")
                            if not delta:
                                continue

                            # Handle <think> reasoning tags (for DeepSeek-R1 and Qwen3)
                            if "<think>" in delta:
                                in_thinking = True
                                delta = delta.replace("<think>", "")
                            if "</think>" in delta:
                                in_thinking = False
                                parts = delta.split("</think>")
                                current_think.append(parts[0])
                                thinking_blocks.append("".join(current_think))
                                current_think = []
                                delta = parts[1] if len(parts) > 1 else ""

                            if in_thinking:
                                current_think.append(delta)
                                message_bus.emit_sync(
                                    AgentEvent(
                                        event_type="thinking",
                                        agent_id=self.agent_id,
                                        agent_name=self.name,
                                        payload={"chunk": delta, "accumulated": "".join(current_think)},
                                        step_index=step_index,
                                        total_steps=total_steps,
                                    )
                                )
                            else:
                                full_response.append(delta)
                                if on_token:
                                    on_token(delta)
                                message_bus.emit_sync(
                                    AgentEvent(
                                        event_type="stream",
                                        agent_id=self.agent_id,
                                        agent_name=self.name,
                                        payload={"chunk": delta, "accumulated_len": sum(len(x) for x in full_response)},
                                        step_index=step_index,
                                        total_steps=total_steps,
                                    )
                                )

                        except json.JSONDecodeError:
                            continue

        except Exception as e:
            logger.error(f"Agent '{self.name}' execution failed: {e}")
            message_bus.emit_sync(
                AgentEvent(
                    event_type="error",
                    agent_id=self.agent_id,
                    agent_name=self.name,
                    payload={"error": str(e)},
                    step_index=step_index,
                    total_steps=total_steps,
                )
            )
            return {
                "success": False,
                "agent_id": self.agent_id,
                "agent_name": self.name,
                "error": str(e),
                "duration_s": round(time.time() - start_time, 2),
                "output": "",
                "thinking": "",
            }

        duration = round(time.time() - start_time, 2)
        final_text = "".join(full_response).strip()
        thinking_text = "".join(thinking_blocks).strip()

        # Emit completion event
        message_bus.emit_sync(
            AgentEvent(
                event_type="complete",
                agent_id=self.agent_id,
                agent_name=self.name,
                payload={
                    "duration_s": duration,
                    "output_preview": final_text[:300],
                    "tokens_approx": (len(final_text) + len(thinking_text)) // 4,
                },
                step_index=step_index,
                total_steps=total_steps,
            )
        )

        return {
            "success": True,
            "agent_id": self.agent_id,
            "agent_name": self.name,
            "model": self.model,
            "output": final_text,
            "thinking": thinking_text,
            "duration_s": duration,
            "tokens_approx": (len(final_text) + len(thinking_text)) // 4,
        }

    # Tool invocation helpers for autonomous agents
    def search_web(self, query: str, max_results: int = 5) -> List[Dict[str, str]]:
        """Run unrestricted search."""
        message_bus.emit_sync(
            AgentEvent(
                event_type="tool_call",
                agent_id=self.agent_id,
                agent_name=self.name,
                payload={"tool": "search_web", "query": query},
            )
        )
        return search_engine.search(query, max_results=max_results)

    def query_rag(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """Search local documents."""
        message_bus.emit_sync(
            AgentEvent(
                event_type="tool_call",
                agent_id=self.agent_id,
                agent_name=self.name,
                payload={"tool": "query_rag", "query": query},
            )
        )
        return document_rag.search(query, top_k=top_k)

    def run_python(self, code: str) -> Dict[str, Any]:
        """Execute sandbox Python code."""
        message_bus.emit_sync(
            AgentEvent(
                event_type="tool_call",
                agent_id=self.agent_id,
                agent_name=self.name,
                payload={"tool": "run_python", "code_preview": code[:200]},
            )
        )
        return code_sandbox.execute_python(code)

    def scan_nmap(self, target: str, profile: str = "standard", custom_args: Optional[str] = None) -> Dict[str, Any]:
        """Execute Nmap scan on a target host or subnet."""
        message_bus.emit_sync(
            AgentEvent(
                event_type="tool_call",
                agent_id=self.agent_id,
                agent_name=self.name,
                payload={"tool": "scan_nmap", "target": target, "profile": profile},
            )
        )
        return nmap_scanner.scan(target, profile=profile, custom_args=custom_args)

    def parse_nmap_log(self, file_content_or_path: str) -> Dict[str, Any]:
        """Parse Nmap scan XML or text output."""
        message_bus.emit_sync(
            AgentEvent(
                event_type="tool_call",
                agent_id=self.agent_id,
                agent_name=self.name,
                payload={"tool": "parse_nmap_log", "preview": file_content_or_path[:100]},
            )
        )
        if os.path.exists(file_content_or_path):
            return nmap_scanner.parse_file(file_content_or_path)
        if "<nmaprun" in file_content_or_path:
            return nmap_scanner.parse_nmap_xml(file_content_or_path)
        return nmap_scanner.parse_nmap_text(file_content_or_path)

    def query_threat_dbs(self, query: str, max_per_source: int = 5) -> str:
        """Fan-out search across all 8 threat intelligence databases (NVD, CISA KEV, GitHub, ExploitDB, Vulners, Rapid7, Metasploit, Crawl4AI). Returns formatted context block."""
        message_bus.emit_sync(
            AgentEvent(
                event_type="tool_call",
                agent_id=self.agent_id,
                agent_name=self.name,
                payload={"tool": "query_threat_dbs", "query": query},
            )
        )
        results = threat_intel_fetcher.search_all(query, max_per_source=max_per_source)
        return threat_intel_fetcher.build_context_block(results)
