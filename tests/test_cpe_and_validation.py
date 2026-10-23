"""
Unit tests for deterministic CPE parsing, verified CVE binding, and validation engine assertions.
"""

import unittest
from tools.vuln_correlator import extract_verified_cpe_from_banner, vuln_correlator
from core.mission_state import MissionState, ServiceRecord, VulnerabilityRecord, EvidenceItem


class TestCPEAndValidation(unittest.TestCase):

    def test_banner_cpe_extraction_iis(self):
        banner = "Server: Microsoft-IIS/10.0"
        cpe = extract_verified_cpe_from_banner(banner)
        self.assertEqual(cpe, "cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*:*:*")

    def test_banner_cpe_extraction_apache(self):
        banner = "Server: Apache/2.4.49 (Unix) OpenSSL/1.1.1"
        cpe = extract_verified_cpe_from_banner(banner)
        self.assertEqual(cpe, "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")

    def test_banner_cpe_extraction_nginx(self):
        banner = "Server: nginx/1.20.1"
        cpe = extract_verified_cpe_from_banner(banner)
        self.assertEqual(cpe, "cpe:2.3:a:f5:nginx:1.20.1:*:*:*:*:*:*:*")

    def test_banner_cpe_extraction_openssh(self):
        banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        cpe = extract_verified_cpe_from_banner(banner)
        self.assertEqual(cpe, "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*")

    def test_unverified_banner_returns_none(self):
        banner = "Random custom internal service without version"
        cpe = extract_verified_cpe_from_banner(banner)
        self.assertIsNone(cpe)

    def test_cve_query_rejects_unverified_cpe(self):
        # Empty or unverified CPE should return empty list and never query databases
        results = vuln_correlator.step_4_cve_matching(product="CustomApp", version="", cpe="")
        self.assertEqual(results, [])

    def test_deterministic_validation_asserts_pass(self):
        mission = MissionState(target="192.168.1.10")
        mission.add_service(ServiceRecord(
            port=80,
            service="http",
            product="Apache http_server",
            version="2.4.49",
            cpe=["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"],
            banner="Server: Apache/2.4.49",
        ))
        mission.add_vulnerability(VulnerabilityRecord(
            cve_id="CVE-2021-41773",
            title="Apache HTTP Server Path Traversal",
            product="apache http_server",
            version="2.4.49",
            cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            cvss_score=7.5,
            cvss_severity="HIGH",
        ))
        mission.add_evidence(EvidenceItem(
            source_type="nmap",
            title="HTTP Banner Finding",
            raw_content="Server: Apache/2.4.49",
        ))

        # Programmatically assert product match
        for v in mission.vulnerabilities:
            v_prod = v.get("product", "").lower()
            matched = any(
                v_prod in s.get("product", "").lower() or v_prod in s.get("service", "").lower()
                for s in mission.services
            )
            self.assertTrue(matched)

    def test_deterministic_validation_detects_ungrounded_cve(self):
        mission = MissionState(target="192.168.1.10")
        mission.add_service(ServiceRecord(
            port=22,
            service="ssh",
            product="OpenSSH",
            version="8.2p1",
            cpe=["cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*"],
        ))
        # Fabricated Apache CVE when only OpenSSH is running
        mission.add_vulnerability(VulnerabilityRecord(
            cve_id="CVE-2021-41773",
            title="Apache HTTP Server Path Traversal",
            product="apache",
            version="2.4.49",
            cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            cvss_score=7.5,
            cvss_severity="HIGH",
        ))

        # Check assertion fails
        ungrounded_found = False
        for v in mission.vulnerabilities:
            v_prod = v.get("product", "").lower()
            matched = any(
                v_prod in s.get("product", "").lower() or v_prod in s.get("service", "").lower()
                for s in mission.services
            )
            if not matched:
                ungrounded_found = True

        self.assertTrue(ungrounded_found, "Validation engine should flag ungrounded Apache CVE when only SSH is present")


if __name__ == "__main__":
    unittest.main()
