"""
Offensive & Defensive Coding Agent (Forge-3) - Powered by qwen2.5-coder:7b.
Generates full-scale exploit proofs-of-concept, automated security tooling, and defensive patches.
"""

from typing import Dict, Any, Optional
from agents.base_agent import BaseAgent
from core.config import AGENT_MODELS, AGENT_PROMPTS


class CodingAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_id="coder",
            name="Offensive & Defensive Coder (Forge-3)",
            role="Exploit Scripting, Security Patching & Tool Engineering",
            model=AGENT_MODELS["coder"],
            system_prompt=AGENT_PROMPTS["coder"],
            emoji="💻",
        )

    def generate_security_code(self, query: str, context: Optional[str] = None, step_index: int = 1, total_steps: int = 1) -> Dict[str, Any]:
        prompt = f"""
Engineer complete, functional technical implementations for:
"{query}"

You MUST deliver:
1. **Technical Proof-of-Concept (PoC) / Exploit / Automation Harness**:
   - Provide clean, robust Python or C/C++ code.
   - Include complete socket/HTTP handling, payload delivery, error catching, and CLI argument parsing (`argparse`).
   - No mock code or placeholders.
2. **Defensive Hardening & Remediation Patch**:
   - Provide the exact corrected source code snippet, secure configuration, or input sanitizer preventing the flaw.
3. **Execution Instructions & Environment Setup**:
   - Dependencies, compiler flags, and runtime flags.
"""
        return self.run(prompt, context=context, step_index=step_index, total_steps=total_steps)
