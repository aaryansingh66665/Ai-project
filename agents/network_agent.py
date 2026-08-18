"""
Network & Packet Analysis Agent (Vanguard-5) - Powered by gemma3:4b.
Performs protocol packet dissection, PCAP traffic analysis, and Snort/Suricata IDS rule generation.
"""

from typing import Dict, Any, Optional
from agents.base_agent import BaseAgent
from core.config import AGENT_MODELS, AGENT_PROMPTS


class NetworkAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_id="network",
            name="Network & Packet Analyst (Vanguard-5)",
            role="PCAP Dissection, Protocol Analysis & IDS/IPS Engineering",
            model=AGENT_MODELS["network"],
            system_prompt=AGENT_PROMPTS["network"],
            emoji="📡",
        )

    def analyze_network_traffic(self, query: str, context: Optional[str] = None, step_index: int = 1, total_steps: int = 1) -> Dict[str, Any]:
        prompt = f"""
Conduct deep Network Protocol, Nmap Reconnaissance & Traffic Analysis for:
"{query}"

Deliver:
1. **Network Surface & Port Topology**: Analysis of open ports, daemon versions, protocol risks, and exposed entry points.
2. **Protocol & Handshake Breakdown**: TCP/IP flags, TLS handshakes, HTTP headers, DNS query structures.
3. **Traffic Anomaly & Threat Vector Identification**: Port scanning patterns, C2 heartbeat intervals, exfiltration channels.
4. **Wireshark / TShark Display Filters**: Exact display syntax for isolating the malicious traffic.
5. **Suricata / Snort IDS Signatures**: Complete, syntax-valid rule definitions for automated detection.
6. **Firewall & Network Hardening Rules**: iptables, nftables, or pfSense firewall rules.
"""
        return self.run(prompt, context=context, step_index=step_index, total_steps=total_steps)

    def execute_nmap_analysis(
        self,
        target: str,
        scan_data: Optional[Dict[str, Any]] = None,
        context: Optional[str] = None,
        step_index: int = 1,
        total_steps: int = 1,
    ) -> Dict[str, Any]:
        """
        Takes structured Nmap scan results (or executes a live scan) and generates in-depth technical analysis.
        """
        # If no pre-parsed scan data provided, run scan tool
        if not scan_data:
            scan_data = self.scan_nmap(target, profile="standard")

        # Format scan summary for agent prompt
        hosts_summary = []
        for host in scan_data.get("hosts", []):
            ip = host.get("ip", "unknown")
            hostnames = ", ".join(host.get("hostnames", [])) or "None"
            ports = host.get("ports", [])
            port_lines = []
            for p in ports:
                port_num = p.get("port")
                proto = p.get("protocol", "tcp")
                svc = p.get("service", "unknown")
                prod = p.get("product", "")
                ver = p.get("version", "")
                scripts = p.get("scripts", {})
                script_str = f" | Scripts: {scripts}" if scripts else ""
                port_lines.append(f"  - {port_num}/{proto} [{svc}] {prod} {ver}{script_str}")

            ports_str = "\n".join(port_lines) if port_lines else "  - No open ports detected"
            hosts_summary.append(f"HOST: {ip} ({hostnames})\n{ports_str}")

        scan_context_str = "\n\n".join(hosts_summary) if hosts_summary else "No live hosts or open ports discovered."

        prompt = f"""
Analyze the following NMAP NETWORK RECONNAISSANCE SCAN RESULTS for target: "{target}"

### DISCOVERED NMAP SCAN FINDINGS:
{scan_context_str}

Provide comprehensive network security intelligence:
1. **Exposed Attack Surface Assessment**: High-risk ports, outdated service versions, and banner disclosures.
2. **Exploitation Vectors**: Potential CVE attack paths against discovered software and services.
3. **NSE Script & Configuration Insights**: Interpretation of script findings (e.g. SSL certs, HTTP headers, SMB dialect).
4. **Defensive Hardening**: Specific port closure rules, firewall filters (iptables/UFW), and IDS detection rules.
5. **Recommendations for Threat Intel and Exploitation Agents**: Exact software targets and parameters for downstream testing.
"""
        full_context = f"{context}\n\n{scan_context_str}" if context else scan_context_str
        return self.run(prompt, context=full_context, step_index=step_index, total_steps=total_steps)

