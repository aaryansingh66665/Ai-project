"""
Terminal UI and Rich Display Engine for CyberAgent X.
Includes real-time GPU HUD, DAG pipeline visualizer, and resilient input prompt.
"""

import sys
import os
import time
import warnings
from typing import List, Dict, Any, Optional

# Force UTF-8 on Windows stdout/stderr
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from core.config import AGENT_MODELS
from core.model_manager import model_manager
from core.message_bus import message_bus, AgentEvent

console = Console(force_terminal=True, legacy_windows=False)


def render_banner():
    """Print ASCII cyber banner and system metadata."""
    gpu = model_manager.get_gpu_stats()
    banner_text = Text()
    banner_text.append("╔══════════════════════════════════════════════════════════════════════════════╗\n", style="bright_cyan")
    banner_text.append("║                           ⚡  C Y B E R A G E N T  X                        ║\n", style="bold bright_cyan")
    banner_text.append("║           Offline Local NVIDIA GPU Unrestricted Multi-Agent Swarm           ║\n", style="dim white")
    banner_text.append("╠══════════════════════════════════════════════════════════════════════════════╣\n", style="bright_cyan")
    banner_text.append(f"║  GPU: {gpu.name[:36]:<36} VRAM: {gpu.used_mb}/{gpu.total_mb}MB ({gpu.used_pct}%)  ║\n", style="bright_green")
    banner_text.append(f"║  Engine: Ollama Local (CUDA)         Status: [ACTIVE / UNRESTRICTED]        ║\n", style="bright_yellow")
    banner_text.append("╚══════════════════════════════════════════════════════════════════════════════╝", style="bright_cyan")
    console.print(banner_text)


def render_system_status():
    """Print status table of GPU and all 8 local agents."""
    gpu = model_manager.get_gpu_stats()
    health = model_manager.check_health()

    table = Table(title="🤖 Active Multi-Agent Swarm Roster", box=box.ROUNDED, header_style="bold bright_cyan")
    table.add_column("#", justify="center", style="dim")
    table.add_column("Agent Role", style="bold white")
    table.add_column("Assigned Local Model", style="bright_green")
    table.add_column("Est. VRAM", justify="right", style="cyan")
    table.add_column("Status", justify="center", style="bold")

    roster_info = [
        ("1", "👑 Master Orchestrator (Apex-0)", AGENT_MODELS["orchestrator"], "~5.0 GB"),
        ("2", "🕵️ OSINT & Deep Search (Recon-1)", AGENT_MODELS["osint"], "~2.5 GB"),
        ("3", "🧠 Threat Intelligence (Aegis-2)", AGENT_MODELS["threat_intel"], "~5.0 GB"),
        ("4", "💻 Offensive/Defensive Coder (Forge-3)", AGENT_MODELS["coder"], "~4.5 GB"),
        ("5", "🔬 Malware & Reverse Eng (Dissect-4)", AGENT_MODELS["malware"], "~5.0 GB"),
        ("6", "📡 Network & Packet Analyst (Vanguard-5)", AGENT_MODELS["network"], "~2.5 GB"),
        ("7", "📝 Executive Report Generator (Scribe-6)", AGENT_MODELS["report"], "~2.5 GB"),
        ("8", "⚔️ Red Team & CTF Simulator (Shadow-7)", AGENT_MODELS["redteam"], "~2.3 GB"),
    ]

    for num, role, model, vram in roster_info:
        is_installed = any(model in m for m in health.get("installed_models", []))
        status_str = "[green]READY[/green]" if is_installed else "[red]MISSING[/red]"
        table.add_row(num, role, model, vram, status_str)

    console.print(table)


def get_user_input(prompt_text: str = "Enter your cybersecurity / research objective") -> str:
    """Resilient input helper handling both interactive consoles and standard terminals."""
    try:
        import questionary
        ans = questionary.text(f"⚡ {prompt_text}:").ask()
        if ans is not None and ans.strip():
            return ans.strip()
    except Exception:
        pass

    # Standard fallback
    try:
        console.print(f"\n[bold bright_cyan]⚡ {prompt_text}:[/bold bright_cyan] ", end="")
        line = sys.stdin.readline()
        if line:
            return line.strip()
    except Exception:
        pass

    return ""


class TerminalStreamingObserver:
    """Streams live token output and thinking blocks to terminal."""

    def __init__(self):
        self.current_agent = ""

    def on_event(self, event: AgentEvent):
        if event.event_type == "start":
            self.current_agent = event.agent_name
            console.print(f"\n[bold bright_cyan]────────────────────────────────────────────────────────────────────────[/bold bright_cyan]")
            console.print(f"🚀 [bold bright_yellow][Stage {event.step_index}/{event.total_steps}][/bold bright_yellow] [bold bright_green]{event.agent_name}[/bold bright_green] ({event.payload.get('model')}) [dim]Loaded in VRAM...[/dim]")
            console.print(f"[bold bright_cyan]────────────────────────────────────────────────────────────────────────[/bold bright_cyan]\n")

        elif event.event_type == "thinking":
            chunk = event.payload.get("chunk", "")
            # Print thinking chunks in dim italic
            sys.stdout.write(f"\033[90m\033[3m{chunk}\033[0m")
            sys.stdout.flush()

        elif event.event_type == "stream":
            chunk = event.payload.get("chunk", "")
            sys.stdout.write(chunk)
            sys.stdout.flush()

        elif event.event_type == "tool_call":
            tool_name = event.payload.get("tool")
            query = event.payload.get("query") or event.payload.get("target") or event.payload.get("code_preview") or event.payload.get("preview", "")
            console.print(f"\n[yellow]⚙️ Tool Invoked: [bold]{tool_name}[/bold] -> {str(query)[:90]}[/yellow]")

        elif event.event_type == "complete":
            dur = event.payload.get("duration_s", 0)
            tokens = event.payload.get("tokens_approx", 0)
            tps = round(tokens / max(dur, 0.1), 1)
            console.print(f"\n\n[dim cyan]✔ {self.current_agent} Completed in {dur}s ({tokens} tokens, ~{tps} tk/s)[/dim cyan]\n")


def attach_terminal_streamer() -> TerminalStreamingObserver:
    observer = TerminalStreamingObserver()
    message_bus.register_callback(observer.on_event)
    return observer
