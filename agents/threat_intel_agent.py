"""
Threat Intelligence & Deep Reasoning Agent (Aegis-2) - Powered by deepseek-r1:8b.
Performs deep chain-of-thought analysis, vulnerability root-cause mapping, and MITRE ATT&CK alignment.
Integrates: NVD, CISA KEV, GitHub Advisory, ExploitDB, Vulners, Rapid7, Metasploit, Crawl4AI.
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
        # Pre-fetch live threat intelligence from all 8 databases in parallel
        db_intel = self.query_threat_dbs(query, max_per_source=5)

        # Merge DB intel with any prior agent context
        enriched_context_parts = []
        if db_intel:
            enriched_context_parts.append(db_intel)
        if context:
            enriched_context_parts.append(f"--- [PRIOR AGENT CONTEXT] ---\n{context}")
        enriched_context = "\n\n".join(enriched_context_parts) if enriched_context_parts else None

        prompt = f"""
Conduct an exhaustive Threat Intelligence and Root-Cause Analysis for:
"{query}"

You have been pre-loaded with LIVE threat database intelligence from NVD, CISA KEV, GitHub Advisory DB,
ExploitDB, Vulners, Rapid7 VulnDB, and Metasploit Framework above. Use this data to ground your analysis.

Structure your analysis:
1. **Executive Vulnerability Breakdown**: CVSS v3.1/v4.0 vector, Affected Components, Attack Complexity.
   Cross-reference with NVD and CISA KEV records provided.
2. **Root-Cause Architectural Analysis**: Detailed code/memory mechanics (stack corruption, unsafe JNDI lookup,
   prototype pollution, deserialization, etc.).
3. **MITRE ATT&CK TTP Mapping**: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion.
4. **Active Exploitation Evidence**: Reference CISA KEV status, ExploitDB/Metasploit module availability,
   and Vulners/Rapid7 records from the intel block above.
5. **Exploitation Prerequisites & Kill Chain**: Required privileges, network reachability, payload constraints.
6. **Defensive Assessment**: Detection strategies, telemetry indicators (SIEM/EDR), and mitigation obstacles.
"""
        return self.run(prompt, context=enriched_context, step_index=step_index, total_steps=total_steps)
