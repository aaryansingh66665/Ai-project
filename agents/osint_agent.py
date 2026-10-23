"""
OSINT & Deep Search Agent (Recon-1) - Powered by qwen3:4b / qwen3:8b.
Performs unrestricted search, document RAG, threat intel DB queries, and reconnaissance dossiers.
Integrates: NVD, CISA KEV, GitHub Advisory, ExploitDB, Vulners, Rapid7, Metasploit, Crawl4AI.
"""

from typing import Dict, List, Any, Optional
from agents.base_agent import BaseAgent
from core.config import AGENT_MODELS, AGENT_PROMPTS


class OSINTAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_id="osint",
            name="OSINT & Deep Search (Recon-1)",
            role="Unrestricted Intelligence Gathering & Document RAG",
            model=AGENT_MODELS["osint"],
            system_prompt=AGENT_PROMPTS["osint"],
            emoji="🕵️",
        )

    def execute_recon(self, target_query: str, step_index: int = 1, total_steps: int = 1) -> Dict[str, Any]:
        """
        Gathers live intelligence via web search + threat intel DBs + local document RAG,
        then produces a structured dossier.
        """
        # 1. Multi-source web search
        web_results = self.search_web(target_query, max_results=5)
        # 2. Local Document RAG
        rag_results = self.query_rag(target_query, top_k=3)

        # 3. Threat Intel DB query (for CVEs / vulnerability topics)
        vuln_keywords = ["cve-", "exploit", "vuln", "rce", "lfi", "xss", "sqli", "overflow",
                         "bypass", "injection", "patch", "disclosure", "0day", "zero-day",
                         "malware", "ransomware", "backdoor", "payload"]
        is_vuln_query = any(kw in target_query.lower() for kw in vuln_keywords)
        db_intel_block = ""
        if is_vuln_query:
            db_intel_block = self.query_threat_dbs(target_query, max_per_source=4)

        # Assemble intelligence bundle
        intel_parts = []
        if db_intel_block:
            intel_parts.append("### LIVE THREAT DATABASE INTELLIGENCE (NVD / CISA KEV / GitHub / ExploitDB / Vulners / Rapid7 / Metasploit):")
            intel_parts.append(db_intel_block)

        if web_results:
            intel_parts.append("### LIVE WEB SEARCH INTELLIGENCE:")
            for idx, r in enumerate(web_results, 1):
                intel_parts.append(f"{idx}. [{r.get('title')}]({r.get('url')}):\n   {r.get('snippet')}")

        if rag_results:
            intel_parts.append("\n### LOCAL DOCUMENT ARCHIVE FINDINGS:")
            for idx, r in enumerate(rag_results, 1):
                intel_parts.append(f"{idx}. File: {r.get('filename')} (Score: {r.get('score')}):\n   {r.get('text')}")

        intel_context = "\n".join(intel_parts) if intel_parts else "No immediate search results returned."

        prompt = f"""
Perform comprehensive intelligence reconnaissance for:
QUERY / TARGET: "{target_query}"

LIVE DISCOVERED DATA:
{intel_context}

Produce a structured OSINT Dossier containing:
1. Target Overview & Technical Classification
2. Known Vulnerabilities / CVEs & Severity Metrics (cross-reference NVD, CISA KEV, ExploitDB data above)
3. Exposed Attack Surface, Repositories & Artifacts
4. Real-world Exploitation Activity & Threat Actor Associations (ExploitDB/Metasploit modules noted)
5. Key Takeaways for Downstream Technical Agents
"""
        return self.run(prompt, context=intel_context, step_index=step_index, total_steps=total_steps)
