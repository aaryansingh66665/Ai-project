"""
Threat Intelligence & Deep Reasoning Agent (Aegis-2) - Powered by deepseek-r1:8b.
Performs deep chain-of-thought analysis, vulnerability root-cause mapping, and MITRE ATT&CK alignment.
"""

from typing import Dict, Any, Optional
from agents.base_agent import BaseAgent
from core.config import AGENT_MODELS, AGENT_PROMPTS


class ThreatIntelAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_id="threat_intel",
            name="Threat Intelligence (Aegis-2)",
            role="Deep Chain-of-Thought Vulnerability & Threat Actor Modeling",
            model=AGENT_MODELS["threat_intel"],
            system_prompt=AGENT_PROMPTS["threat_intel"],
            emoji="🧠",
        )

    def analyze_threat(self, query: str, context: Optional[str] = None, step_index: int = 1, total_steps: int = 1) -> Dict[str, Any]:
        prompt = f"""
Conduct an exhaustive Threat Intelligence and Root-Cause Analysis for:
"{query}"

Structure your analysis:
1. **Executive Vulnerability Breakdown**: CVSS v3.1/v4.0 vector, Affected Components, Attack Complexity.
2. **Root-Cause Architectural Analysis**: Detailed code/memory mechanics (e.g. stack corruption, unsafe JNDI lookup, prototype pollution, deserialization).
3. **MITRE ATT&CK TTP Mapping**: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion.
4. **Exploitation Prerequisites & Kill Chain**: Required privileges, network reachability, payload constraints.
5. **Defensive Assessment**: Detection strategies, telemetry indicators (SIEM/EDR), and mitigation obstacles.
"""
        return self.run(prompt, context=context, step_index=step_index, total_steps=total_steps)
