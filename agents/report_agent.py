"""
Executive Report & Documentation Generator (Scribe-6) - Powered by gemma3:4b.
Synthesizes multi-agent intelligence into executive reports, threat matrices, and remediation roadmaps.
"""

from typing import Dict, Any, Optional
from agents.base_agent import BaseAgent
from core.config import AGENT_MODELS, AGENT_PROMPTS


class ReportAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_id="report",
            name="Executive Report Generator (Scribe-6)",
            role="Intelligence Synthesis, Executive Summaries & Remediation Plans",
            model=AGENT_MODELS["report"],
            system_prompt=AGENT_PROMPTS["report"],
            emoji="📝",
        )

    def generate_report(self, query: str, swarm_context: str, step_index: int = 1, total_steps: int = 1) -> Dict[str, Any]:
        prompt = f"""
Synthesize all prior agent intelligence into a comprehensive, publication-grade Technical Threat & Intelligence Report.

TARGET OBJECTIVE:
"{query}"

AGENT SWARM INTELLIGENCE FINDINGS:
{swarm_context}

Structure the final deliverable:
# 🛡️ CYBERAGENT X INTELLIGENCE REPORT: {query}
## 1. Executive Summary & Risk Rating (Critical / High / Medium / Low)
## 2. Comprehensive Threat Vector & Technical Architecture
## 3. Technical Proof-of-Concept & Exploitability Analysis
## 4. Detection Engineering (YARA / Suricata / Wireshark Filters)
## 5. Strategic Remediation Roadmap (Immediate, Short-term, Long-term)
## 6. Appendix: Indicators of Compromise (IOCs) & Technical References
"""
        return self.run(prompt, context=swarm_context, step_index=step_index, total_steps=total_steps)
