"""
Master Orchestrator Agent (Apex-0) - Powered by qwen3:8b.
Decomposes complex requests, dynamically builds execution DAGs, and coordinates the agent swarm.
"""

from typing import Dict, List, Any, Optional
from agents.base_agent import BaseAgent
from core.config import AGENT_MODELS, AGENT_PROMPTS


class OrchestratorAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_id="orchestrator",
            name="Master Orchestrator (Apex-0)",
            role="Autonomous Workflow Planner & Swarm Coordinator",
            model=AGENT_MODELS["orchestrator"],
            system_prompt=AGENT_PROMPTS["orchestrator"],
            emoji="👑",
        )

    def plan_workflow(self, user_goal: str) -> List[str]:
        """
        Intelligently select the most effective agent pipeline sequence for the user goal.
        """
        prompt = f"""
Analyze the following objective and select the required sequence of specialized agents:
OBJECTIVE: "{user_goal}"

Available Specialized Agents:
1. `osint` (OSINT & Deep Search: web recon, CVE lookup, document search)
2. `threat_intel` (Threat Intelligence: vulnerability root-cause, MITRE TTPs, CoT analysis)
3. `coder` (Offensive & Defensive Coder: exploit PoC, patch code, automation scripts)
4. `malware` (Malware & Reverse Eng: binary disassembly, shellcode, deobfuscation)
5. `network` (Network & Packet Analysis: PCAP dissection, firewall & IDS rules)
6. `redteam` (Red Team & CTF: privilege escalation, attack chains, CTF walkthroughs)
7. `report` (Executive Report Generator: final synthesis, remediation roadmap, summary)

Respond ONLY with a valid Python list of agent IDs to execute sequentially, for example:
["osint", "threat_intel", "coder", "report"]
"""
        res = self.run(prompt)
        text = res.get("output", "")
        # Parse list from response
        try:
            import ast
            import re
            match = re.search(r"\[.*?\]", text, re.DOTALL)
            if match:
                agents = ast.literal_eval(match.group(0))
                if isinstance(agents, list) and all(isinstance(x, str) for x in agents):
                    # Filter valid agent IDs
                    valid = [a for a in agents if a in AGENT_MODELS and a != "orchestrator"]
                    if valid:
                        return valid
        except Exception:
            pass

        # Smart default fallback based on keywords
        goal_lower = user_goal.lower()
        pipeline = []
        if any(w in goal_lower for w in ["search", "find", "cve", "recon", "what is", "osint", "gather"]):
            pipeline.append("osint")
        if any(w in goal_lower for w in ["threat", "vuln", "cve", "impact", "risk", "mitre"]):
            pipeline.append("threat_intel")
        if any(w in goal_lower for w in ["code", "exploit", "poc", "script", "patch", "fix", "program", "c++", "python"]):
            pipeline.append("coder")
        if any(w in goal_lower for w in ["malware", "binary", "reverse", "disasm", "asm", "shellcode", "pe", "elf"]):
            pipeline.append("malware")
        if any(w in goal_lower for w in ["packet", "pcap", "network", "traffic", "port", "wireshark", "snort"]):
            pipeline.append("network")
        if any(w in goal_lower for w in ["ctf", "redteam", "privilege", "escalat", "bypass", "ad", "domain"]):
            pipeline.append("redteam")

        if not pipeline:
            pipeline = ["threat_intel", "coder", "report"]
        elif "report" not in pipeline and len(pipeline) >= 2:
            pipeline.append("report")

        return pipeline
