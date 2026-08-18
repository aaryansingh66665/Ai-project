"""
Local Python Code Sandbox & Shell Command Execution Tool.
Allows agents to execute computational scripts, test payloads, compute hashes, and parse binaries.
"""

import sys
import os
import subprocess
import time
import uuid
import logging
from pathlib import Path
from typing import Dict, Any
from core.config import SANDBOX_DIR

logger = logging.getLogger("CyberAgent.CodeSandbox")


class CodeSandbox:
    """Executes Python code or shell commands in local workspace sandbox."""

    def __init__(self, sandbox_dir: Path = SANDBOX_DIR):
        self.sandbox_dir = sandbox_dir

    def execute_python(self, code: str, timeout_seconds: int = 15) -> Dict[str, Any]:
        """Execute a Python snippet in a clean subprocess and capture stdout/stderr."""
        script_id = f"script_{uuid.uuid4().hex[:8]}.py"
        script_path = self.sandbox_dir / script_id

        # Write script to disk
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(code)

        start_time = time.time()
        try:
            res = subprocess.run(
                [sys.executable, str(script_path)],
                cwd=str(self.sandbox_dir),
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
            duration = round(time.time() - start_time, 3)
            return {
                "success": res.returncode == 0,
                "exit_code": res.returncode,
                "stdout": res.stdout.strip(),
                "stderr": res.stderr.strip(),
                "duration_s": duration,
                "script_path": str(script_path),
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Execution timed out after {timeout_seconds}s.",
                "duration_s": timeout_seconds,
                "script_path": str(script_path),
            }
        except Exception as e:
            return {
                "success": False,
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
                "duration_s": round(time.time() - start_time, 3),
                "script_path": str(script_path),
            }


# Singleton code sandbox instance
code_sandbox = CodeSandbox()
