"""
CyberAgent X — Unified Launch Controller (run.py)

Usage:
    python run.py              → Interactive mode selector
    python run.py web          → Start Web Studio  (http://127.0.0.1:8000)
    python run.py cli          → Interactive terminal CLI
    python run.py check        → System diagnostics
    python run.py test         → Run full test suite
    python run.py setup        → First-time setup (deps + model pull)
    python run.py query "..."  → One-shot pipeline query

This is the single recommended entry point.
"""

import sys
import os
import subprocess
from pathlib import Path

# ── Load .env if present ─────────────────────────────────────────────────────
ENV_FILE = Path(__file__).parent / ".env"
if ENV_FILE.exists():
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip())

# ── GPU environment lock (must happen before any import) ────────────────────
os.environ.setdefault("CUDA_DEVICE_ORDER", "PCI_BUS_ID")
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0")
os.environ.setdefault("OLLAMA_NUM_GPU", "99")
os.environ.setdefault("NVIDIA_VISIBLE_DEVICES", "all")

BANNER = """
  +=================================================================+
  |   ** CYBERAGENT X  v2.0 - NEMOTRON EDITION **                  |
  |      OFFLINE - NVIDIA RTX 3050 6GB - 10-AGENT SWARM INTEL      |
  +=================================================================+
"""

REQUIRED_MODELS = [
    "qwen3:8b",
    "qwen3:4b",
    "deepseek-r1:8b",
    "qwen2.5-coder:7b",
    "gemma3:4b",
    "phi4-mini:3.8b",
    "nemotron-mini:4b",
]


# ── Pre-flight checks ────────────────────────────────────────────────────────

def check_python() -> bool:
    v = sys.version_info
    ok = v.major == 3 and v.minor >= 11
    status = "[OK]" if ok else "[!!]"
    print(f"  {status}  Python {v.major}.{v.minor}.{v.micro}", end="")
    if not ok:
        print("  <- requires Python 3.11+")
    else:
        print()
    return ok


def check_ollama() -> bool:
    import httpx
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    try:
        r = httpx.get(f"{host}/api/tags", timeout=3.0)
        online = r.status_code == 200
    except Exception:
        online = False
    print(f"  {'[OK]' if online else '[!!]'}  Ollama  ->  {host}")
    if not online:
        print("        Run: ollama serve   (or install from https://ollama.com)")
    return online


def check_models() -> tuple[list, list]:
    import httpx
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    try:
        r = httpx.get(f"{host}/api/tags", timeout=5.0)
        installed_names = [m.get("name", "") for m in r.json().get("models", [])]
    except Exception:
        installed_names = []

    ok, missing = [], []
    for model in REQUIRED_MODELS:
        found = any(model in n for n in installed_names)
        (ok if found else missing).append(model)
        print(f"  {'[OK]' if found else '[ ]'}  {model}")
    return ok, missing


def check_gpu() -> bool:
    try:
        import pynvml  # type: ignore
        pynvml.nvmlInit()
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        name = pynvml.nvmlDeviceGetName(handle).decode()
        mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
        total_mb = mem.total // 1024 // 1024
        free_mb  = mem.free  // 1024 // 1024
        print(f"  [OK]  GPU: {name}  ({free_mb} MB free / {total_mb} MB total)")
        return True
    except Exception:
        print("  [ ]  GPU: NVML unavailable (CPU fallback mode)")
        return False


def run_preflight(verbose: bool = True) -> dict:
    if verbose:
        print("\n--- Pre-flight checks -----------------------------------------------")
    py_ok      = check_python()
    ollama_ok  = check_ollama()
    _ok, missing = check_models()
    gpu_ok     = check_gpu()
    if verbose:
        print("---------------------------------------------------------------------\n")
    return {
        "python": py_ok,
        "ollama": ollama_ok,
        "missing_models": missing,
        "gpu": gpu_ok,
        "ready": py_ok and ollama_ok,
    }


# ── Actions ──────────────────────────────────────────────────────────────────

def action_check():
    print(BANNER)
    status = run_preflight()
    if status["missing_models"]:
        print("  Missing models. Pull them with:")
        for m in status["missing_models"]:
            print(f"    ollama pull {m}")
    else:
        print("  [OK]  All models ready. System is fully operational.\n")
    return 0 if status["ready"] else 1


def action_web():
    status = run_preflight(verbose=False)
    if not status["ollama"]:
        print("\n  [ERROR] Ollama is not running. Start it first: ollama serve\n")
        sys.exit(1)

    host = os.getenv("SERVER_HOST", "127.0.0.1")
    port = int(os.getenv("SERVER_PORT", "8000"))

    print(BANNER)
    print(f"  [WEB]  Web Studio  ->  http://{host}:{port}")
    print(f"  [API]  API Docs    ->  http://{host}:{port}/docs\n")

    from api.server import start_server
    start_server(host=host, port=port)


def action_cli():
    print(BANNER)
    status = run_preflight(verbose=False)
    if not status["ollama"]:
        print("\n  [ERROR] Ollama is not running. Start it first: ollama serve\n")
        sys.exit(1)

    import logging
    logging.basicConfig(level=getattr(logging, os.getenv("LOG_LEVEL", "WARNING")))
    from main import run_interactive_cli
    run_interactive_cli()


def action_test():
    print(BANNER)
    print("  [TEST]  Running CyberAgent X Test Suite (30 tests)...\n")
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=Path(__file__).parent,
    )
    sys.exit(result.returncode)


def action_setup():
    print(BANNER)
    root = Path(__file__).parent

    print("  [1/4]  Installing Python dependencies...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt",
                    "--quiet", "--upgrade"], cwd=root, check=True)

    print("  [2/4]  Installing Web Studio (npm)...")
    web_dir = root / "web"
    subprocess.run(["npm", "install", "--silent"], cwd=web_dir, shell=True)

    print("  [3/4]  Building Web Studio bundle...")
    subprocess.run(["npm", "run", "build"], cwd=web_dir, shell=True)

    print("  [4/4]  Pre-flight check...")
    action_check()

    print("  [OK]  Setup complete. Run:  python run.py web\n")


def action_query(query: str, agents: str = None):
    status = run_preflight(verbose=False)
    if not status["ollama"]:
        print("[ERROR] Ollama offline. Run: ollama serve")
        sys.exit(1)
    import logging
    logging.basicConfig(level=logging.WARNING)
    from core.pipeline import pipeline
    from ui.terminal_ui import attach_terminal_streamer
    attach_terminal_streamer()
    custom = [a.strip() for a in agents.split(",")] if agents else None
    res = pipeline.execute(query, custom_agents=custom)
    print(f"\n=== DONE ===  Duration: {res.get('total_duration_s', '?')}s")


# ── Interactive Menu ─────────────────────────────────────────────────────────

def interactive_menu():
    print(BANNER)
    run_preflight()
    print("  Select launch mode:")
    print("  [1]  >> Web Studio         (http://127.0.0.1:8000)")
    print("  [2]  >> Terminal CLI")
    print("  [3]  >> System Diagnostics")
    print("  [4]  >> Run Test Suite")
    print("  [5]  >> First-Time Setup")
    print("  [0]  Exit\n")

    choice = input("  Enter choice: ").strip()
    if choice == "1":
        action_web()
    elif choice == "2":
        action_cli()
    elif choice == "3":
        action_check()
    elif choice == "4":
        action_test()
    elif choice == "5":
        action_setup()
    elif choice == "0":
        sys.exit(0)
    else:
        print("  Invalid choice.")
        interactive_menu()


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args = sys.argv[1:]

    if not args:
        interactive_menu()
    elif args[0] == "web":
        action_web()
    elif args[0] == "cli":
        action_cli()
    elif args[0] == "check":
        sys.exit(action_check())
    elif args[0] == "test":
        action_test()
    elif args[0] == "setup":
        action_setup()
    elif args[0] == "query" and len(args) >= 2:
        action_query(args[1], agents=args[2] if len(args) > 2 else None)
    else:
        print(__doc__)
        sys.exit(1)
