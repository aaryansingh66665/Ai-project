"""
Unit tests for SwarmAgent 3-round collaborative stage.
Tests: SwarmContext data flow, round parsing, banner-to-service extraction, CVE parsing.
"""

import unittest
from agents.swarm_agent import SwarmAgent, SwarmContext
from tools.vuln_correlator import extract_verified_cpe_from_banner


class TestSwarmContext(unittest.TestCase):

    def test_round1_context_prompt_no_services(self):
        ctx = SwarmContext(target="192.168.1.1")
        prompt = ctx.to_round1_prompt_context()
        self.assertIn("192.168.1.1", prompt)

    def test_round2_context_prompt_empty_services(self):
        ctx = SwarmContext(target="10.0.0.1")
        prompt = ctx.to_round2_prompt_context()
        self.assertIn("Insufficient evidence", prompt)

    def test_round2_context_prompt_with_services(self):
        ctx = SwarmContext(target="10.0.0.1")
        ctx.services = [
            {
                "port": 80,
                "service": "http",
                "product": "Apache http_server",
                "version": "2.4.49",
                "banner": "Server: Apache/2.4.49",
                "cpe": ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"],
            }
        ]
        prompt = ctx.to_round2_prompt_context()
        self.assertIn("Port 80/http", prompt)
        self.assertIn("cpe:2.3:a:apache:http_server:2.4.49", prompt)
        self.assertIn("Only map CVEs using the verified CPE strings", prompt)

    def test_round3_context_prompt_with_cves(self):
        ctx = SwarmContext(target="10.0.0.1")
        ctx.services = [{"port": 80, "service": "http", "product": "nginx", "version": "1.20.1", "banner": "", "cpe": ["cpe:2.3:a:f5:nginx:1.20.1:*:*:*:*:*:*:*"]}]
        ctx.cves = [{"cve_id": "CVE-2021-23017", "product": "nginx", "cpe": "cpe:2.3:a:f5:nginx:1.20.1:*:*:*:*:*:*:*", "cvss": "7.7", "ttps": ["T1190"]}]
        prompt = ctx.to_round3_prompt_context()
        self.assertIn("CVE-2021-23017", prompt)
        self.assertIn("T1190", prompt)
        self.assertIn("Snort/Suricata", prompt)

    def test_summary_dict_fields(self):
        ctx = SwarmContext(target="10.0.0.1")
        ctx.services = [{"port": 22}]
        ctx.cves = [{"cve_id": "CVE-2021-00001"}]
        ctx.ttps = ["T1021"]
        ctx.ids_rules = ["alert tcp any any -> any 22"]
        summary = ctx.to_summary_dict()
        self.assertEqual(summary["services_found"], 1)
        self.assertEqual(summary["cves_confirmed"], 1)
        self.assertEqual(summary["ttps_mapped"], 1)
        self.assertEqual(summary["ids_rules_generated"], 1)


class TestSwarmAgentParsers(unittest.TestCase):

    def setUp(self):
        self.agent = SwarmAgent()

    def test_parse_round1_from_scan_data(self):
        ctx = SwarmContext(target="192.168.1.5")
        scan_data = {
            "hosts": [{
                "ip": "192.168.1.5",
                "ports": [
                    {
                        "port": 80, "service": "http",
                        "product": "Apache", "version": "2.4.49",
                        "banner": "Server: Apache/2.4.49",
                        "cpe": [],
                    },
                    {
                        "port": 22, "service": "ssh",
                        "product": "OpenSSH", "version": "8.2p1",
                        "banner": "SSH-2.0-OpenSSH_8.2p1",
                        "cpe": [],
                    },
                ]
            }]
        }
        self.agent._parse_round1_into_context(ctx, {}, scan_data)
        self.assertEqual(len(ctx.services), 2)
        # CPE should be auto-extracted from banners
        cpe_strings = [c for s in ctx.services for c in s.get("cpe", [])]
        self.assertTrue(any("apache" in c for c in cpe_strings))
        self.assertTrue(any("openssh" in c for c in cpe_strings))

    def test_parse_round2_cve_extraction(self):
        ctx = SwarmContext(target="10.0.0.5")
        mock_output = """
        CVE-2021-41773 path traversal in Apache. T1190 - Exploit Public-Facing Application.
        CVE-2021-42013 also affects Apache 2.4.50. T1059.001 also applicable.
        ExploitDB EDB-ID: 50383 available. exploit/multi/http/apache_normalize_path_rce in Metasploit.
        """
        r2_result = {"output": mock_output, "success": True}
        self.agent._parse_round2_into_context(ctx, r2_result)
        cve_ids = [c["cve_id"] for c in ctx.cves]
        self.assertIn("CVE-2021-41773", cve_ids)
        self.assertIn("CVE-2021-42013", cve_ids)
        self.assertIn("T1190", ctx.ttps)
        self.assertIn("EDB-50383", ctx.exploit_refs)
        self.assertTrue(any("apache_normalize" in e for e in ctx.exploit_refs))

    def test_parse_round3_ids_rule_extraction(self):
        ctx = SwarmContext(target="10.0.0.5")
        mock_output = """
        Snort rule: alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 80 (msg:"Apache Path Traversal CVE-2021-41773"; content:"/."; sid:9000001;)
        iptables -A INPUT -p tcp --dport 80 -m string --string "/../" --algo bm -j DROP
        """
        r3_result = {"output": mock_output, "success": True}
        self.agent._parse_round3_into_context(ctx, r3_result)
        self.assertTrue(len(ctx.ids_rules) >= 1)
        self.assertTrue(len(ctx.firewall_rules) >= 1)
        self.assertTrue(any("Apache" in r or "tcp" in r for r in ctx.ids_rules))

    def test_merge_output_includes_all_sections(self):
        ctx = SwarmContext(target="10.0.0.1")
        ctx.network_raw = "Round 1 network analysis here."
        ctx.threat_raw = "Round 2 threat intel here."
        ctx.final_network_report = "Round 3 IDS hardening here."
        ctx.ids_rules = ["alert tcp any any -> any 80"]
        ctx.firewall_rules = ["iptables -A INPUT -j DROP"]
        merged = self.agent._merge_output(ctx)
        self.assertIn("ROUND 1", merged)
        self.assertIn("ROUND 2", merged)
        self.assertIn("ROUND 3", merged)
        self.assertIn("Extracted IDS Signatures", merged)
        self.assertIn("Extracted Firewall Rules", merged)
        self.assertIn("SWARM SUMMARY", merged)


class TestSwarmAgentImport(unittest.TestCase):

    def test_swarm_agent_instantiation(self):
        agent = SwarmAgent()
        self.assertEqual(agent.agent_id, "swarm")
        self.assertEqual(agent.emoji, "🕸️")
        self.assertIsNotNone(agent.network_agent)
        self.assertIsNotNone(agent.threat_intel_agent)

    def test_pipeline_has_swarm_agent(self):
        from core.pipeline import pipeline, FULL_DAG_PLAN
        self.assertIn("swarm", pipeline.agents)
        self.assertIn("swarm", FULL_DAG_PLAN)
        self.assertNotIn("network", FULL_DAG_PLAN)  # replaced by swarm


if __name__ == "__main__":
    unittest.main()
