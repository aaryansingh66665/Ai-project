"""
Comprehensive Test Suite for:
  1. Extended Verified NIST CPE 2.3 Mapping & Banner Extraction Engine
  2. Dual-Engine Hybrid Search (Okapi BM25 + Dense Semantic Embeddings)
  3. Reciprocal Rank Fusion (RRF) & Score Normalization
  4. Local Security KB & Document RAG Hybrid Retrieval
"""

import unittest
from tools.vuln_correlator import extract_verified_cpe_from_banner, vuln_correlator, PRODUCT_CPE_MAP
from tools.hybrid_search import (
    hybrid_search_engine,
    get_embedding,
    cosine_similarity,
    OfflineDenseVectorizer,
)
from tools.security_kb import LocalSecurityKB, SecurityKBEntry
from tools.document_rag import DocumentRAGEngine, DocumentChunk


class TestHybridSearchAndCPE(unittest.TestCase):

    # ------------------------------------------------------------------ #
    # 1. Extended NIST CPE 2.3 & Banner Extraction Tests
    # ------------------------------------------------------------------ #
    def test_extended_product_cpe_mappings(self):
        """Verify expanded PRODUCT_CPE_MAP contains key technologies and maps to standard NIST CPE 2.3."""
        expected_mappings = {
            "haproxy": ("haproxy", "haproxy"),
            "caddy": ("caddyserver", "caddy"),
            "lighttpd": ("lighttpd", "lighttpd"),
            "spring boot": ("pivotal", "spring_boot"),
            "wordpress": ("wordpress", "wordpress"),
            "drupal": ("drupal", "drupal"),
            "joomla": ("joomla", "joomla"),
            "redis": ("redis", "redis"),
            "dropbear": ("dropbear_ssh_project", "dropbear_ssh"),
            "pure-ftpd": ("pureftpd", "pure-ftpd"),
            "cisco ios": ("cisco", "ios"),
            "fortinet": ("fortinet", "fortios"),
            "mikrotik": ("mikrotik", "routeros"),
            "rabbitmq": ("pivotal_software", "rabbitmq"),
            "mosquitto": ("eclipse", "mosquitto"),
            "vault": ("hashicorp", "vault"),
            "keycloak": ("redhat", "keycloak"),
        }

        for prod, (vendor, expected_p) in expected_mappings.items():
            self.assertIn(prod, PRODUCT_CPE_MAP, f"Expected '{prod}' in PRODUCT_CPE_MAP")
            v, p = PRODUCT_CPE_MAP[prod]
            self.assertEqual(v, vendor)
            self.assertEqual(p, expected_p)

            # Test step_3_cpe produces valid CPE
            cpe = vuln_correlator.step_3_cpe(product=prod, version="2.4.0")
            self.assertTrue(cpe.startswith("cpe:2.3:a:") or cpe.startswith("cpe:2.3:o:"))
            self.assertIn(vendor, cpe)
            self.assertIn(expected_p, cpe)
            self.assertIn("2.4.0", cpe)

    def test_banner_cpe_extractions_standard_servers(self):
        """Verify deterministic banner regexes for web servers, proxies, and frameworks."""
        test_cases = [
            ("Server: HAProxy 2.4.8", "cpe:2.3:a:haproxy:haproxy:2.4.8:*:*:*:*:*:*:*"),
            ("Server: Caddy v2.6.4", "cpe:2.3:a:caddyserver:caddy:2.6.4:*:*:*:*:*:*:*"),
            ("Server: lighttpd/1.4.59", "cpe:2.3:a:lighttpd:lighttpd:1.4.59:*:*:*:*:*:*:*"),
            ("Server: Traefik/v2.5.3", "cpe:2.3:a:traefik:traefik:2.5.3:*:*:*:*:*:*:*"),
            ("Server: squid/4.13", "cpe:2.3:a:squid-cache:squid:4.13:*:*:*:*:*:*:*"),
            ("Server: Varnish 6.5.1", "cpe:2.3:a:varnish_software:varnish_cache:6.5.1:*:*:*:*:*:*:*"),
            ("Jetty(9.4.43.v20210629)", "cpe:2.3:a:eclipse:jetty:9.4.43:*:*:*:*:*:*:*"),
            ("SSH-2.0-dropbear_2020.81", "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:2020.81:*:*:*:*:*:*:*"),
            ("220 Welcome to Pure-FTPd 1.0.49", "cpe:2.3:a:pureftpd:pure-ftpd:1.0.49:*:*:*:*:*:*:*"),
            ("X-Powered-By: Express 4.17.1", "cpe:2.3:a:expressjs:express:4.17.1:*:*:*:*:*:*:*"),
            ("X-Powered-By: PHP/8.1.2", "cpe:2.3:a:php:php:8.1.2:*:*:*:*:*:*:*"),
            ("X-Jenkins: 2.303.1", "cpe:2.3:a:jenkins:jenkins:2.303.1:*:*:*:*:*:*:*"),
            ("Grafana v8.3.0", "cpe:2.3:a:grafana:grafana:8.3.0:*:*:*:*:*:*:*"),
            ("WordPress 5.8.1", "cpe:2.3:a:wordpress:wordpress:5.8.1:*:*:*:*:*:*:*"),
            ("Drupal 9.2.4", "cpe:2.3:a:drupal:drupal:9.2.4:*:*:*:*:*:*:*"),
            ("Joomla! 3.9.28", "cpe:2.3:a:joomla:joomla:3.9.28:*:*:*:*:*:*:*"),
            ("mosquitto version 2.0.11", "cpe:2.3:a:eclipse:mosquitto:2.0.11:*:*:*:*:*:*:*"),
            ("RabbitMQ 3.8.14", "cpe:2.3:a:pivotal_software:rabbitmq:3.8.14:*:*:*:*:*:*:*"),
            ("Cisco IOS Software, 15.2(4)M1", "cpe:2.3:o:cisco:ios:15.2(4)M1:*:*:*:*:*:*:*"),
            ("FortiOS v6.4.5", "cpe:2.3:o:fortinet:fortios:6.4.5:*:*:*:*:*:*:*"),
            ("MikroTik RouterOS 6.48.2", "cpe:2.3:o:mikrotik:routeros:6.48.2:*:*:*:*:*:*:*"),
        ]

        for banner, expected_cpe in test_cases:
            cpe = extract_verified_cpe_from_banner(banner)
            self.assertEqual(cpe, expected_cpe, f"Failed banner extraction for: '{banner}'")

    # ------------------------------------------------------------------ #
    # 2. Dual-Engine Hybrid Search (BM25 + Semantic Vectorizer) Tests
    # ------------------------------------------------------------------ #
    def test_offline_dense_vectorizer(self):
        """Verify offline dense vectorizer produces normalized vectors with non-zero similarity for related text."""
        vec1 = get_embedding("Apache HTTP Server remote code execution in path traversal mod_cgi")
        vec2 = get_embedding("Apache web server RCE vulnerability via cgi-bin directory traversal")
        vec3 = get_embedding("MySQL database password cracking authentication bypass")

        self.assertEqual(len(vec1), 256)
        self.assertEqual(len(vec2), 256)

        sim_related = cosine_similarity(vec1, vec2)
        sim_unrelated = cosine_similarity(vec1, vec3)

        self.assertGreater(sim_related, 0.0)
        self.assertGreater(sim_related, sim_unrelated, "Related vulnerability descriptions should have higher cosine similarity than unrelated topics")

    def test_bm25_exact_cve_token_match(self):
        """Verify Okapi BM25 precision matching on technical tokens (CVE ID, versions)."""
        docs = [
            {"id": "doc1", "tokens": hybrid_search_engine.tokenize("CVE-2021-44228 Apache Log4j Remote Code Execution JNDI injection")},
            {"id": "doc2", "tokens": hybrid_search_engine.tokenize("CVE-2021-41773 Apache HTTP Server 2.4.49 path traversal")},
            {"id": "doc3", "tokens": hybrid_search_engine.tokenize("OpenSSH 8.2p1 privilege escalation and authentication")},
        ]

        query_tokens = hybrid_search_engine.tokenize("CVE-2021-44228")
        scores = hybrid_search_engine.compute_bm25_scores(query_tokens, docs)

        self.assertGreater(scores[0], scores[1])
        self.assertEqual(scores[2], 0.0)

    def test_hybrid_rrf_fusion(self):
        """Verify Reciprocal Rank Fusion properly balances BM25 and dense semantic scores."""
        bm25_scores = [10.5, 0.0, 4.2]
        semantic_scores = [0.45, 0.85, 0.60]

        # Balanced hybrid fusion (alpha=0.5)
        fused = hybrid_search_engine.hybrid_fuse(bm25_scores, semantic_scores, alpha=0.5, method="rrf")

        self.assertEqual(len(fused), 3)
        for f in fused:
            self.assertIn("hybrid_score", f)
            self.assertIn("bm25_score", f)
            self.assertIn("semantic_score", f)
            self.assertGreater(f["hybrid_score"], 0.0)

    # ------------------------------------------------------------------ #
    # 3. Local Security KB Hybrid Search Integration Tests
    # ------------------------------------------------------------------ #
    def test_security_kb_hybrid_search(self):
        """Verify LocalSecurityKB hybrid retrieval returns ranked entries with explainable score breakdowns."""
        kb = LocalSecurityKB()
        kb.entries = []  # isolate test

        e1 = SecurityKBEntry(
            id="kb_cve_2021_44228",
            source_layer="combined",
            cve_id="CVE-2021-44228",
            title="Apache Log4j JNDI Remote Code Execution (Log4Shell)",
            description="Apache Log4j2 versions 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP.",
            cvss_score=10.0,
            cvss_severity="CRITICAL",
            cpe_list=["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"],
            is_cisa_kev=True,
            exploit_db_refs=[{"id": "EDB-50592", "title": "Log4j RCE"}],
        )
        e1.tokens = kb._tokenize(e1.to_search_text())
        e1.embedding = get_embedding(e1.to_search_text())

        e2 = SecurityKBEntry(
            id="kb_cve_2021_41773",
            source_layer="combined",
            cve_id="CVE-2021-41773",
            title="Apache HTTP Server Path Traversal and RCE",
            description="A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root.",
            cvss_score=7.5,
            cvss_severity="HIGH",
            cpe_list=["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"],
            is_cisa_kev=True,
        )
        e2.tokens = kb._tokenize(e2.to_search_text())
        e2.embedding = get_embedding(e2.to_search_text())

        kb.entries = [e1, e2]
        kb._rebuild_bm25_stats()

        # Query exact CVE
        res_cve = kb.search_hybrid("CVE-2021-44228", top_k=2, mode="hybrid")
        self.assertGreater(len(res_cve), 0)
        self.assertEqual(res_cve[0]["entry"]["cve_id"], "CVE-2021-44228")
        self.assertIn("bm25_score", res_cve[0])
        self.assertIn("semantic_score", res_cve[0])
        self.assertIn("score", res_cve[0])

        # Query conceptual phrase ("path traversal web server vulnerability")
        res_concept = kb.search_hybrid("path traversal web server vulnerability", top_k=2, mode="hybrid")
        self.assertGreater(len(res_concept), 0)
        self.assertEqual(res_concept[0]["entry"]["cve_id"], "CVE-2021-41773")

    # ------------------------------------------------------------------ #
    # 4. Document RAG Hybrid Search Integration Tests
    # ------------------------------------------------------------------ #
    def test_document_rag_hybrid_search(self):
        """Verify DocumentRAGEngine indexes chunks with dense embeddings and performs hybrid retrieval."""
        rag = DocumentRAGEngine()
        rag.chunks = []

        chunk1 = DocumentChunk(
            doc_id="doc_0",
            filename="kernel_exploit.c",
            chunk_index=0,
            text="Linux kernel eBPF privilege escalation vulnerability via memory corruption in verifier array bounds check.",
        )
        chunk2 = DocumentChunk(
            doc_id="doc_1",
            filename="web_writeup.md",
            chunk_index=0,
            text="SQL injection in login authentication endpoint allows bypass of admin password verification.",
        )

        rag.chunks = [chunk1, chunk2]
        rag._rebuild_stats()

        results = rag.search_hybrid("eBPF kernel root exploit", top_k=2, mode="hybrid")
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0]["filename"], "kernel_exploit.c")
        self.assertIn("bm25_score", results[0])
        self.assertIn("semantic_score", results[0])


if __name__ == "__main__":
    unittest.main()
