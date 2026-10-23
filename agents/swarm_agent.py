"""
Swarm Intelligence Agent (Nexus-8) — Unified 3-Round Collaborative Stage.

Combines NetworkAgent (Vanguard-5) and ThreatIntelAgent (Aegis-2) into a
tightly coupled iterative swarm where each agent reads structured findings
from the previous round and writes back to a shared SwarmContext.

Round Protocol:
  Round 1 → NetworkAgent   → Discovers open ports, banners, services, CPEs
  Round 2 → ThreatIntelAgent → Binds CVEs/TTPs to Round-1 verified CPEs
  Round 3 → NetworkAgent   → Generates IDS rules + firewall configs targeting Round-2 CVEs
"""

import time
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

from agents.base_agent import BaseAgent
from agents.network_agent import NetworkAgent
from agents.threat_intel_agent import ThreatIntelAgent
from core.config import AGENT_MODELS, AGENT_PROMPTS
from core.message_bus import message_bus, AgentEvent
from tools.vuln_correlator import extract_verified_cpe_from_banner

logger = logging.getLogger("CyberAgent.SwarmAgent")


# ---------------------------------------------------------------------------
# SwarmContext — Structured shared state passed between swarm rounds
# ---------------------------------------------------------------------------

@dataclass
class SwarmContext:
    """Live shared state that each swarm round reads from and writes to."""
    target: str = ""

    # Round 1 outputs (Network Agent)
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)   # {port, service, product, version, banner, cpe}
    banners: List[str] = field(default_factory=list)
    network_raw: str = ""  # Full Round-1 narrative

    # Round 2 outputs (Threat Intel Agent)
    cves: List[Dict[str, Any]] = field(default_factory=list)       # {cve_id, product, cpe, cvss, ttps}
    ttps: List[str] = field(default_factory=list)                  # MITRE ATT&CK technique IDs
    exploit_refs: List[str] = field(default_factory=list)          # ExploitDB / Metasploit refs
    threat_raw: str = ""  # Full Round-2 narrative

    # Round 3 outputs (Network Agent — hardening pass)
    ids_rules: List[str] = field(default_factory=list)             # Snort/Suricata rules
    firewall_rules: List[str] = field(default_factory=list)        # iptables / nftables rules
    final_network_report: str = ""  # Full Round-3 narrative

    def to_round1_prompt_context(self) -> str:
        return f"Target: {self.target}\nInitial scan requested — extract all services, banners, CPE strings."

    def to_round2_prompt_context(self) -> str:
        """Serialize Round-1 findings as structured context for Threat Intel."""
        if not self.services:
            return f"Target: {self.target}\nNo verified services detected in Round 1.\nInsufficient evidence to determine CVE mappings."
        lines = [f"Target: {self.target}", "=== ROUND 1 VERIFIED SERVICES ==="]
        for s in self.services:
            cpe_str = ", ".join(s.get("cpe", [])) or "No CPE extracted"
            lines.append(
                f"  Port {s.get('port')}/{s.get('service')} — {s.get('product','')} {s.get('version','')}"
                f"\n    Banner: {s.get('banner','N/A')}"
                f"\n    CPE: {cpe_str}"
            )
        lines.append("\nOnly map CVEs using the verified CPE strings listed above. Do not assume services not listed.")
        return "\n".join(lines)

    def to_round3_prompt_context(self) -> str:
        """Serialize Round-1 + Round-2 findings as context for IDS/hardening pass."""
        lines = ["=== ROUND 1 VERIFIED SERVICES ==="]
        for s in self.services:
            cpe_str = ", ".join(s.get("cpe", [])) or "No CPE"
            lines.append(f"  Port {s.get('port')}/{s.get('service')} — {s.get('product','')} {s.get('version','')} | CPE: {cpe_str}")

        lines.append("\n=== ROUND 2 CONFIRMED CVEs & TTPs ===")
        if self.cves:
            for c in self.cves:
                lines.append(f"  {c.get('cve_id','?')} | Product: {c.get('product','?')} | CVSS: {c.get('cvss','?')} | TTPs: {', '.join(c.get('ttps', []))}")
        else:
            lines.append("  No confirmed CVEs from Round 2.")
        if self.exploit_refs:
            lines.append(f"  Exploit refs: {', '.join(self.exploit_refs)}")

        lines.append(
            "\nUsing the above verified CVEs and services, generate:"
            "\n1. Complete Snort/Suricata IDS rules targeting each CVE."
            "\n2. iptables / nftables firewall hardening rules."
            "\n3. Unified threat summary with remediation priorities."
        )
        return "\n".join(lines)

    def to_summary_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "services_found": len(self.services),
            "cves_confirmed": len(self.cves),
            "ttps_mapped": len(self.ttps),
            "exploit_refs": len(self.exploit_refs),
            "ids_rules_generated": len(self.ids_rules),
            "firewall_rules_generated": len(self.firewall_rules),
        }


# ---------------------------------------------------------------------------
# SwarmAgent
# ---------------------------------------------------------------------------

class SwarmAgent(BaseAgent):
    """
    Unified Swarm Intelligence Agent (Nexus-8).

    Orchestrates a 3-round collaborative loop between NetworkAgent and
    ThreatIntelAgent. Each round enriches the shared SwarmContext before
    passing consolidated results to the main pipeline.
    """

    def __init__(self):
        super().__init__(
            agent_id="swarm",
            name="Swarm Intelligence (Nexus-8)",
            role="Network × Threat Intel 3-Round Collaborative Analysis",
            model=AGENT_MODELS["swarm"],
            system_prompt=AGENT_PROMPTS["swarm"],
            emoji="🕸️",
        )
        # Sub-agents — instantiated once, reused across rounds
        self.network_agent = NetworkAgent()
        self.threat_intel_agent = ThreatIntelAgent()

    # ------------------------------------------------------------------
    # Primary entry point
    # ------------------------------------------------------------------

    def run_swarm(
        self,
        query: str,
        prior_context: Optional[str] = None,
        scan_data: Optional[Dict[str, Any]] = None,
        step_index: int = 1,
        total_steps: int = 1,
    ) -> Dict[str, Any]:
        """
        Execute the 3-round swarm collaboration and return a unified result.

        Returns:
            {
                "success": bool,
                "agent_id": "swarm",
                "swarm_context": SwarmContext.to_summary_dict(),
                "output": merged final narrative,
                "rounds": [r1_result, r2_result, r3_result],
                "services": list[dict],
                "cves": list[dict],
                "ids_rules": list[str],
                "duration_s": float,
            }
        """
        start_time = time.time()
        target = query.split()[0] if query else "unknown"
        ctx = SwarmContext(target=target)

        # Emit swarm pipeline start
        self._emit_swarm_event("swarm_start", {
            "query": query,
            "rounds_planned": 3,
            "sub_agents": [self.network_agent.name, self.threat_intel_agent.name],
        }, step_index, total_steps)

        rounds: List[Dict[str, Any]] = []

        # ── Round 1: Network Agent — Port/Banner/Service Discovery ──────
        r1 = self._run_round(
            round_num=1,
            label="Network Surface Discovery",
            agent=self.network_agent,
            query=query,
            context=ctx.to_round1_prompt_context() + (f"\n\n[PRIOR INTEL]:\n{prior_context}" if prior_context else ""),
            scan_data=scan_data,
            step_index=step_index,
            total_steps=total_steps,
        )
        rounds.append(r1)
        ctx.network_raw = r1.get("output", "")

        # Parse Round-1 output to populate ctx.services and ctx.banners
        self._parse_round1_into_context(ctx, r1, scan_data)

        self._emit_swarm_event("swarm_round_complete", {
            "round": 1, "agent": self.network_agent.name,
            "services_extracted": len(ctx.services),
            "banners_found": len(ctx.banners),
        }, step_index, total_steps)

        # ── Round 2: Threat Intel Agent — CVE Binding & TTP Mapping ────
        r2 = self._run_round(
            round_num=2,
            label="CVE Binding & TTP Mapping",
            agent=self.threat_intel_agent,
            query=query,
            context=ctx.to_round2_prompt_context(),
            scan_data=None,
            step_index=step_index,
            total_steps=total_steps,
        )
        rounds.append(r2)
        ctx.threat_raw = r2.get("output", "")

        # Parse Round-2 output to populate ctx.cves, ctx.ttps, ctx.exploit_refs
        self._parse_round2_into_context(ctx, r2)

        self._emit_swarm_event("swarm_round_complete", {
            "round": 2, "agent": self.threat_intel_agent.name,
            "cves_confirmed": len(ctx.cves),
            "ttps_mapped": len(ctx.ttps),
            "exploits_referenced": len(ctx.exploit_refs),
        }, step_index, total_steps)

        # ── Round 3: Network Agent — IDS Rules & Hardening Pass ────────
        r3 = self._run_round(
            round_num=3,
            label="IDS Rules & Firewall Hardening",
            agent=self.network_agent,
            query=query,
            context=ctx.to_round3_prompt_context(),
            scan_data=None,
            step_index=step_index,
            total_steps=total_steps,
        )
        rounds.append(r3)
        ctx.final_network_report = r3.get("output", "")

        # Parse Round-3 output to populate ctx.ids_rules and ctx.firewall_rules
        self._parse_round3_into_context(ctx, r3)

        self._emit_swarm_event("swarm_round_complete", {
            "round": 3, "agent": self.network_agent.name,
            "ids_rules_generated": len(ctx.ids_rules),
            "firewall_rules_generated": len(ctx.firewall_rules),
        }, step_index, total_steps)

        # ── Merge: Build unified output narrative ───────────────────────
        merged_output = self._merge_output(ctx)
        duration = round(time.time() - start_time, 2)

        self._emit_swarm_event("swarm_complete", {
            "duration_s": duration,
            "summary": ctx.to_summary_dict(),
        }, step_index, total_steps)

        logger.info(
            f"[SwarmAgent] 3-round swarm complete in {duration}s | "
            f"Services: {len(ctx.services)}, CVEs: {len(ctx.cves)}, "
            f"IDS rules: {len(ctx.ids_rules)}"
        )

        return {
            "success": all(r.get("success", False) for r in rounds),
            "agent_id": self.agent_id,
            "agent_name": self.name,
            "model": self.model,
            "duration_s": duration,
            "output": merged_output,
            "thinking": "\n---\n".join(r.get("thinking", "") for r in rounds if r.get("thinking")),
            "swarm_context": ctx.to_summary_dict(),
            "services": ctx.services,
            "cves": ctx.cves,
            "ttps": ctx.ttps,
            "exploit_refs": ctx.exploit_refs,
            "ids_rules": ctx.ids_rules,
            "firewall_rules": ctx.firewall_rules,
            "rounds": rounds,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_round(
        self,
        round_num: int,
        label: str,
        agent: BaseAgent,
        query: str,
        context: str,
        scan_data: Optional[Dict[str, Any]],
        step_index: int,
        total_steps: int,
    ) -> Dict[str, Any]:
        """Dispatch a single swarm round to the appropriate sub-agent."""
        self._emit_swarm_event("swarm_round_start", {
            "round": round_num,
            "label": label,
            "agent": agent.name,
        }, step_index, total_steps)

        logger.info(f"[SwarmAgent] Round {round_num}: {label} → {agent.name}")

        if isinstance(agent, NetworkAgent):
            if round_num == 1 and scan_data:
                # Use structured nmap data if available
                return agent.execute_nmap_analysis(
                    query, scan_data=scan_data, context=context,
                    step_index=step_index, total_steps=total_steps,
                )
            else:
                return agent.analyze_network_traffic(
                    query, context=context,
                    step_index=step_index, total_steps=total_steps,
                )

        elif isinstance(agent, ThreatIntelAgent):
            return agent.analyze_threat(
                query, context=context,
                step_index=step_index, total_steps=total_steps,
            )

        # Fallback
        return agent.run(query, context=context, step_index=step_index, total_steps=total_steps)

    def _parse_round1_into_context(
        self,
        ctx: SwarmContext,
        r1_result: Dict[str, Any],
        scan_data: Optional[Dict[str, Any]],
    ):
        """
        Extract structured service records from Round-1 (nmap scan_data + banner parsing).
        Prioritizes structured scan_data; falls back to banner extraction from raw text output.
        """
        if scan_data:
            # Build ctx.services from structured Nmap XML data
            for host in scan_data.get("hosts", []):
                for port_info in host.get("ports", []):
                    banner = port_info.get("banner", "") or ""
                    cpe_list = port_info.get("cpe", []) or []
                    if not cpe_list and banner:
                        parsed_cpe = extract_verified_cpe_from_banner(banner)
                        if parsed_cpe:
                            cpe_list = [parsed_cpe]
                    svc = {
                        "ip": host.get("ip", ctx.target),
                        "port": port_info.get("port"),
                        "service": port_info.get("service", ""),
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                        "banner": banner,
                        "cpe": cpe_list,
                    }
                    ctx.services.append(svc)
                    if banner:
                        ctx.banners.append(banner)
                    if port_info.get("port"):
                        ctx.open_ports.append({"port": port_info.get("port"), "service": svc["service"]})
        else:
            # Try banner extraction from raw narrative output
            raw = r1_result.get("output", "")
            # Extract any lines that look like banners
            for line in raw.splitlines():
                stripped = line.strip()
                if "Server:" in stripped or "SSH-" in stripped or "FTP" in stripped or "HTTP" in stripped:
                    cpe = extract_verified_cpe_from_banner(stripped)
                    if cpe:
                        ctx.banners.append(stripped)
                        parts = cpe.split(":")
                        prod = parts[4].replace("_", " ") if len(parts) > 4 else "unknown"
                        ver = parts[5] if len(parts) > 5 and parts[5] != "*" else ""
                        ctx.services.append({
                            "ip": ctx.target,
                            "port": None,
                            "service": prod,
                            "product": prod,
                            "version": ver,
                            "banner": stripped,
                            "cpe": [cpe],
                        })

    def _parse_round2_into_context(self, ctx: SwarmContext, r2_result: Dict[str, Any]):
        """
        Extract CVE IDs, TTPs, and exploit refs from Round-2 narrative output.
        Uses deterministic regex patterns on the raw text.
        """
        import re
        raw = r2_result.get("output", "")

        # Extract CVE IDs
        cve_ids = re.findall(r"CVE-\d{4}-\d{4,7}", raw, re.IGNORECASE)
        for cve_id in dict.fromkeys(cve_ids):  # deduplicate while preserving order
            ctx.cves.append({"cve_id": cve_id.upper(), "product": "", "cpe": "", "cvss": "", "ttps": []})

        # Extract MITRE ATT&CK technique IDs (T1xxx or T1xxx.xxx)
        ttp_ids = re.findall(r"\bT1\d{3}(?:\.\d{3})?\b", raw)
        ctx.ttps = list(dict.fromkeys(ttp_ids))

        # Extract exploit references (ExploitDB EDB-IDs or MSF module paths)
        edb_ids = re.findall(r"EDB-ID[:\s#-]*(\d+)", raw, re.IGNORECASE)
        msf_mods = re.findall(r"exploit/\S+", raw)
        ctx.exploit_refs = [f"EDB-{e}" for e in edb_ids] + msf_mods

    def _parse_round3_into_context(self, ctx: SwarmContext, r3_result: Dict[str, Any]):
        """
        Extract Snort/Suricata rule blocks and iptables/nftables commands from Round-3 output.
        """
        import re
        raw = r3_result.get("output", "")

        # Snort/Suricata rules start with alert/drop/log followed by a protocol
        ctx.ids_rules = re.findall(
            r"(?:alert|drop|log)\s+(?:tcp|udp|icmp|http|dns|tls)\b[^\n]+",
            raw,
            re.IGNORECASE,
        )

        # iptables / nftables lines
        ctx.firewall_rules = re.findall(
            r"(?:iptables|ip6tables|nft)\s+[^\n]+",
            raw,
            re.IGNORECASE,
        )

    def _merge_output(self, ctx: SwarmContext) -> str:
        """Assemble the unified swarm output narrative for the pipeline context."""
        sections = [
            "=== [SWARM INTELLIGENCE — 3-ROUND COLLABORATIVE ANALYSIS] ===",
            f"Target: {ctx.target}",
            "",
            "━━━ ROUND 1: NETWORK SURFACE & SERVICE DISCOVERY ━━━",
            ctx.network_raw or "No output.",
            "",
            "━━━ ROUND 2: THREAT INTELLIGENCE — CVE BINDING & TTP MAPPING ━━━",
            ctx.threat_raw or "No output.",
            "",
            "━━━ ROUND 3: IDS RULES & FIREWALL HARDENING ━━━",
            ctx.final_network_report or "No output.",
        ]
        if ctx.ids_rules:
            sections += [
                "",
                "── Extracted IDS Signatures ──",
                *[f"  {r}" for r in ctx.ids_rules[:10]],
            ]
        if ctx.firewall_rules:
            sections += [
                "",
                "── Extracted Firewall Rules ──",
                *[f"  {r}" for r in ctx.firewall_rules[:10]],
            ]
        summary = ctx.to_summary_dict()
        sections += [
            "",
            "━━━ SWARM SUMMARY ━━━",
            f"  Services discovered : {summary['services_found']}",
            f"  CVEs confirmed      : {summary['cves_confirmed']}",
            f"  MITRE TTPs mapped   : {summary['ttps_mapped']}",
            f"  Exploit refs        : {summary['exploit_refs']}",
            f"  IDS rules generated : {summary['ids_rules_generated']}",
            f"  Firewall rules      : {summary['firewall_rules_generated']}",
        ]
        return "\n".join(sections)

    def _emit_swarm_event(self, event_type: str, payload: Dict[str, Any],
                          step_index: int, total_steps: int):
        message_bus.emit_sync(AgentEvent(
            event_type=event_type,
            agent_id=self.agent_id,
            agent_name=self.name,
            payload=payload,
            step_index=step_index,
            total_steps=total_steps,
        ))
