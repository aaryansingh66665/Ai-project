"""
Unit and Integration Tests for NVIDIA Nemotron AI:
  1. NemotronAgent Instantiation & Prompt Validation
  2. Multi-Agent Pipeline Registration
  3. Security KB Neural Synthesis with Nemotron Engine
  4. Nemotron Model Configurations & Supported Models List
"""

import unittest
from core.config import AGENT_MODELS, SUPPORTED_NEMOTRON_MODELS, AGENT_PROMPTS
from agents.nemotron_agent import NemotronAgent
from core.pipeline import pipeline, PHASE_MAP
from tools.security_kb import LocalSecurityKB, SecurityKBEntry


class TestNemotronAI(unittest.TestCase):

    def test_nemotron_agent_instantiation(self):
        """Verify NemotronAgent instantiates with correct metadata and persona."""
        agent = NemotronAgent()
        self.assertEqual(agent.agent_id, "nemotron")
        self.assertEqual(agent.emoji, "🟢")
        self.assertIn("nemotron", agent.model.lower())
        self.assertIn("NVIDIA Nemotron", agent.name)
        self.assertIn("NEVER FABRICATE", agent.system_prompt)
        self.assertIn("NVIDIA Nemotron Neural Reasoner", agent.system_prompt)

    def test_nemotron_model_configuration(self):
        """Verify config contains Nemotron models and valid settings."""
        self.assertIn("nemotron", AGENT_MODELS)
        self.assertIn("nemotron-mini:4b", SUPPORTED_NEMOTRON_MODELS)
        self.assertIn("nemotron:latest", SUPPORTED_NEMOTRON_MODELS)
        self.assertIn("nemotron-70b", SUPPORTED_NEMOTRON_MODELS)
        self.assertIn("nemotron", AGENT_PROMPTS)

    def test_pipeline_nemotron_registration(self):
        """Verify NemotronAgent is registered in the main agent pipeline and phase map."""
        self.assertIn("nemotron", pipeline.agents)
        self.assertIsInstance(pipeline.agents["nemotron"], NemotronAgent)
        self.assertIn("nemotron", PHASE_MAP)
        self.assertEqual(PHASE_MAP["nemotron"]["phase_name"], "PHASE 2 // DEEP REASONING")

    def test_security_kb_nemotron_synthesis_structure(self):
        """Verify LocalSecurityKB.query_with_nemotron executes and formats Nemotron deliverable correctly."""
        kb = LocalSecurityKB()
        kb.entries = []  # isolate test

        e1 = SecurityKBEntry(
            id="kb_cve_2021_44228",
            source_layer="combined",
            cve_id="CVE-2021-44228",
            title="Apache Log4j RCE (Log4Shell)",
            description="Remote code execution vulnerability in Apache Log4j2 JNDI parser.",
            cvss_score=10.0,
            cvss_severity="CRITICAL",
            cpe_list=["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"],
            is_cisa_kev=True,
        )
        kb.entries = [e1]
        kb._rebuild_bm25_stats()

        # Run query with Nemotron model
        res = kb.query_with_nemotron("CVE-2021-44228", model="nemotron-mini:4b")

        self.assertIn("query", res)
        self.assertIn("model", res)
        self.assertEqual(res["model"], "nemotron-mini:4b")
        self.assertIn("vector_db_matches", res)
        self.assertIn("synthesis", res)
        self.assertIn("nemotron_synthesis", res)
        self.assertIsNotNone(res["nemotron_synthesis"])
        self.assertIn("qwen_synthesis", res)
        self.assertIn("duration_s", res)


if __name__ == "__main__":
    unittest.main()
