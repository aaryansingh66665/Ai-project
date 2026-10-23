"""
NVIDIA Nemotron Neural Reasoner & Threat Modeler (Nemo-8) - Powered by nemotron-mini:4b / nemotron:latest.
Performs hardware-accelerated deep analytical reasoning, zero-hallucination threat modeling,
and multi-tier vulnerability triage strictly bound to verified evidence.
"""

from typing import Dict, Any, Optional
from agents.base_agent import BaseAgent
from core.config import AGENT_MODELS, AGENT_PROMPTS
from tools.threat_intel_fetcher import threat_intel_fetcher


class NemotronAgent(BaseAgent):
    """
    Autonomous NVIDIA Nemotron Agent specializing in deep analytical reasoning,
    exploit prerequisite validation, zero-hallucination CVE threat modeling, and remediation synthesis.
    """

    def __init__(self, model_name: Optional[str] = None):
        selected_model = model_name or AGENT_MODELS.get("nemotron", "nemotron-mini:4b")
        super().__init__(
            agent_id="nemotron",
            name="NVIDIA Nemotron Reasoner (Nemo-8)",
            role="Deep Multi-Step Threat Modeling & Hardware-Accelerated Neural Reasoning",
            model=selected_model,
            system_prompt=AGENT_PROMPTS.get("nemotron", ""),
            emoji="🟢",
        )

    def analyze_vulnerability_posture(
        self,
        query: str,
        context: Optional[str] = None,
        step_index: int = 1,
        total_steps: int = 1,
    ) -> Dict[str, Any]:
        """
        Executes an end-to-end Nemotron AI reasoning analysis over verified vulnerability indicators.
        """
        # Fetch multi-tier threat intel
        db_intel = self.query_threat_dbs(query, max_per_source=4)

        enriched_parts = []
        if db_intel:
            enriched_parts.append(db_intel)
        if context:
            enriched_parts.append(f"--- [PRIOR AGENT & SYSTEM CONTEXT] ---\n{context}")
        enriched_context = "\n\n".join(enriched_parts) if enriched_parts else None

        prompt = f"""
Execute an exhaustive NVIDIA Nemotron Deep Neural Threat Modeling Analysis on:
"{query}"

Ground your evaluation strictly on the technical evidence, CPE 2.3 identifiers, and threat database records provided above.

Structure your deliverable with strict analytical rigor:
1. **Threat Architecture & Prerequisite Matrix**:
   - Exact Target Platform, Architecture, and Affected Version Ranges.
   - Authentication Preconditions & Network Vector Requirements.
2. **Exploitation Execution Flow & Root-Cause Mechanics**:
   - Precise technical mechanism (e.g. race condition, type confusion, path normalization bypass, unsafe deserialization).
   - Weaponized Exploitability Status (Cross-reference CISA KEV and Exploit-DB references).
3. **MITRE ATT&CK & Defense-in-Depth Decomposition**:
   - Tactics, Techniques & Sub-techniques (e.g. T1190, T1059, T1068).
   - Attack Complexity vs Impact Analysis (Confidentiality, Integrity, Availability).
4. **Concrete Hardware-Accelerated Remediation Roadmap**:
   - Immediate virtual patching / WAF rule syntax.
   - Permanent code-level patch and configuration hardening instructions.
"""
        return self.run(prompt, context=enriched_context, step_index=step_index, total_steps=total_steps)
