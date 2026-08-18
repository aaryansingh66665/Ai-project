"""
CyberAgent X - Main Entrypoint & CLI Controller.
Supports CLI interactive mode, automated health check, direct query execution, and Web Studio launcher.
"""

import sys
import argparse
import logging
from core.config import AGENT_MODELS
from core.model_manager import model_manager
from core.pipeline import pipeline
from ui.terminal_ui import render_banner, render_system_status, get_user_input, attach_terminal_streamer

logging.basicConfig(level=logging.WARNING)


def run_health_check() -> bool:
    """Check GPU, Ollama, and local models."""
    render_banner()
    render_system_status()
    health = model_manager.check_health()

    print("\n--- System Diagnostics ---")
    if health["ollama_online"]:
        print("✔ Ollama Service: ONLINE (http://localhost:11434)")
    else:
        print("❌ Ollama Service: OFFLINE! Please start Ollama before proceeding.")

    gpu = health["gpu"]
    print(f"✔ GPU Device: {gpu['name']}")
    print(f"✔ GPU VRAM: {gpu['free_mb']}MB Free / {gpu['total_mb']}MB Total ({gpu['used_pct']}% used)")
    print(f"✔ GPU Temperature: {gpu['temp_c']}°C")

    missing = []
    for role, model in AGENT_MODELS.items():
        if not any(model in m for m in health["installed_models"]):
            missing.append(f"{role} ({model})")

    if missing:
        print(f"⚠️ Warning: Missing local models: {', '.join(missing)}")
        print("Run: ollama pull <model_name>")
    else:
        print("✔ All 6 local agent models are installed & ready.")

    return health["ollama_online"]


def run_interactive_cli():
    """Interactive loop in terminal."""
    render_banner()
    render_system_status()
    attach_terminal_streamer()

    while True:
        try:
            query = get_user_input("Enter Objective (or 'exit' / 'status' / 'web')")
            if not query:
                continue
            if query.lower() in ["exit", "quit", "q"]:
                print("Exiting CyberAgent X. Goodbye!")
                break
            if query.lower() == "status":
                render_system_status()
                continue
            if query.lower() == "web":
                print("Starting Web Studio Server...")
                from api.server import start_server
                start_server()
                break

            print(f"\n[Executing Multi-Agent Swarm for: '{query}']")
            pipeline.execute(query)

        except KeyboardInterrupt:
            print("\nOperation interrupted by user.")
            break
        except Exception as e:
            print(f"\nError: {e}")


def main():
    parser = argparse.ArgumentParser(description="CyberAgent X - Offline GPU Multi-Agent Intelligence System")
    parser.add_argument("--check", action="store_true", help="Run system diagnostics and verify GPU/Ollama/Models")
    parser.add_argument("--web", action="store_true", help="Start FastAPI Backend Server and Web Studio API")
    parser.add_argument("--port", type=int, default=8000, help="Port for web server (default 8000)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host for web server (default 127.0.0.1)")
    parser.add_argument("--query", type=str, help="Directly execute a query through the multi-agent pipeline")
    parser.add_argument("--agents", type=str, help="Comma-separated agent IDs to execute (e.g. osint,threat_intel,coder)")
    parser.add_argument("--headless", action="store_true", help="Run in non-interactive headless mode")

    args = parser.parse_args()

    if args.check:
        ok = run_health_check()
        sys.exit(0 if ok else 1)

    if args.web:
        render_banner()
        print(f"\n🚀 Launching CyberAgent X Web Studio Server on http://{args.host}:{args.port}")
        from api.server import start_server
        start_server(host=args.host, port=args.port)
        return

    if args.query:
        attach_terminal_streamer()
        custom_agents = [a.strip() for a in args.agents.split(",")] if args.agents else None
        res = pipeline.execute(args.query, custom_agents=custom_agents)
        print("\n\n=== PIPELINE EXECUTION SUMMARY ===")
        print(f"Total Duration: {res['total_duration_s']}s")
        print(f"Stages Executed: {res['agent_plan']}")
        return

    # Default to interactive CLI
    run_interactive_cli()


if __name__ == "__main__":
    main()
