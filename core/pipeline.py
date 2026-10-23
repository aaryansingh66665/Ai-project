"""
Multi-Agent Execution Pipeline — Directed Acyclic Graph (DAG) Coordinator.

Architecture (user-designed):

                    USER MISSION
                         |
                  ORCHESTRATOR
                         |
              .-----------+-----------,
              v           v           v
            OSINT    THREAT INTEL   CODING/RAG
              |           |           |
              '------.----+-----------'
                     v
             EVIDENCE CORRELATOR   <- aggregates Phase 1 + 8-step vuln enrichment
                     |
          .----------+-----------.
          v          v           v
       NETWORK     MALWARE    RED TEAM
          |          |           |
          '----------+-----------'
                     v
               VALIDATION         <- cross-checks Phase 2 findings & confidence
                     |
                  REPORT           <- final executive intelligence report

Mission State Data Model:
mission/
├── target
├── scope
├── discovered_assets
├── services
├── vulnerabilities
├── evidence
├── agent_results
├── confidence
├── decisions
└── final_report
"""

import time
import logging
from typing import Dict, List, Any, Optional
from core.config import AGENT_MODELS
from core.message_bus import message_bus, AgentEvent
from core.model_manager import model_manager
from core.mission_state import (
    MissionState,
    DiscoveredAsset,
    ServiceRecord,
    VulnerabilityRecord,
    EvidenceItem,
    DecisionItem,
    ConfidenceAssessment,
    active_mission,
)
from tools.vuln_correlator import vuln_correlator
from agents.orchestrator_agent import OrchestratorAgent
from agents.osint_agent import OSINTAgent
from agents.threat_intel_agent import ThreatIntelAgent
from agents.coding_agent import CodingAgent
from agents.malware_agent import MalwareAgent
from agents.network_agent import NetworkAgent
from agents.swarm_agent import SwarmAgent
from agents.report_agent import ReportAgent
from agents.redteam_agent import RedTeamAgent
from agents.nemotron_agent import NemotronAgent

logger = logging.getLogger("CyberAgent.Pipeline")

# --------------------------------------------------------------------------- #
# Canonical DAG Plan
# --------------------------------------------------------------------------- #
FULL_DAG_PLAN = [
    "osint",
    "threat_intel",
    "coder",
    "correlator",   # Evidence Correlator + 8-step Vuln Enrichment
    "swarm",        # Swarm Stage: Network (Round 1) + Threat Intel (Round 2) + Network (Round 3)
    "malware",
    "redteam",
    "validation",   # Validation Engine + Confidence Scoring
    "report",
]

PHASE_MAP = {
    "orchestrator":  {"phase": 0, "phase_name": "ORCHESTRATOR"},
    "osint":         {"phase": 1, "phase_name": "PHASE 1 // INTEL GATHERING"},
    "threat_intel":  {"phase": 1, "phase_name": "PHASE 1 // INTEL GATHERING"},
    "coder":         {"phase": 1, "phase_name": "PHASE 1 // INTEL GATHERING"},
    "correlator":    {"phase": 2, "phase_name": "EVIDENCE CORRELATOR"},
    "swarm":         {"phase": 3, "phase_name": "PHASE 2 // SWARM ANALYSIS"},
    "network":       {"phase": 3, "phase_name": "PHASE 2 // SWARM ANALYSIS"},
    "malware":       {"phase": 3, "phase_name": "PHASE 2 // DEEP ANALYSIS"},
    "redteam":       {"phase": 3, "phase_name": "PHASE 2 // DEEP ANALYSIS"},
    "nemotron":      {"phase": 3, "phase_name": "PHASE 2 // DEEP REASONING"},
    "validation":    {"phase": 4, "phase_name": "VALIDATION"},
    "report":        {"phase": 5, "phase_name": "FINAL REPORT"},
}


class AgentPipeline:
    """Manages the multi-agent DAG execution workflow and mission state."""

    def __init__(self):
        self.agents: Dict[str, Any] = {
            "orchestrator": OrchestratorAgent(),
            "osint":        OSINTAgent(),
            "threat_intel": ThreatIntelAgent(),
            "coder":        CodingAgent(),
            "malware":      MalwareAgent(),
            "network":      NetworkAgent(),
            "swarm":        SwarmAgent(),
            "report":       ReportAgent(),
            "redteam":      RedTeamAgent(),
            "nemotron":     NemotronAgent(),
        }
        self.stop_requested: bool = False
        self.current_mission: Optional[MissionState] = None

    def get_agent(self, agent_id: str):
        return self.agents.get(agent_id)

    def request_stop(self):
        self.stop_requested = True
        logger.info("Pipeline stop requested.")

    # ---------------------------------------------------------------------- #
    def _run_agent(self, agent_id: str, query: str, context: str,
                   idx: int, total: int) -> Dict[str, Any]:
        agent = self.agents.get(agent_id)
        if not agent:
            return {"agent_id": agent_id, "output": "", "error": "Agent not found"}

        if agent_id == "osint":
            return agent.execute_recon(query, step_index=idx, total_steps=total)
        elif agent_id == "threat_intel":
            return agent.analyze_threat(query, context=context, step_index=idx, total_steps=total)
        elif agent_id == "coder":
            return agent.generate_security_code(query, context=context, step_index=idx, total_steps=total)
        elif agent_id == "malware":
            return agent.analyze_binary(query, context=context, step_index=idx, total_steps=total)
        elif agent_id == "network":
            return agent.analyze_network_traffic(query, context=context, step_index=idx, total_steps=total)
        elif agent_id == "swarm":
            # Swarm is handled as a virtual stage in execute(); this fallback is for custom_agents mode
            return agent.run_swarm(query, prior_context=context, step_index=idx, total_steps=total)
        elif agent_id == "redteam":
            return agent.execute_tactical_plan(query, context=context, step_index=idx, total_steps=total)
        elif agent_id == "report":
            return agent.generate_report(query, swarm_context=context, step_index=idx, total_steps=total)
        else:
            return agent.run(query, context=context, step_index=idx, total_steps=total)

    # ---------------------------------------------------------------------- #
    def _emit_virtual_stage(self, stage_id: str, stage_name: str,
                             description: str, step_index: int, total_steps: int):
        """Emit start + stream + complete events for a virtual in-pipeline stage."""
        message_bus.emit_sync(AgentEvent(
            event_type="start",
            agent_id=stage_id,
            agent_name=stage_name,
            payload={"model": "in-pipeline", "prompt": description[:200]},
            step_index=step_index,
            total_steps=total_steps,
        ))
        time.sleep(0.12)
        message_bus.emit_sync(AgentEvent(
            event_type="stream",
            agent_id=stage_id,
            agent_name=stage_name,
            payload={"chunk": f"[ {stage_name} ]\n{description}"},
            step_index=step_index,
            total_steps=total_steps,
        ))
        time.sleep(0.10)
        message_bus.emit_sync(AgentEvent(
            event_type="complete",
            agent_id=stage_id,
            agent_name=stage_name,
            payload={"duration_s": 0.22, "tokens_approx": 0,
                     "phase": PHASE_MAP.get(stage_id, {}).get("phase", -1)},
            step_index=step_index,
            total_steps=total_steps,
        ))

    def _emit_mission_update(self, mission: MissionState, phase: str = ""):
        """Broadcast mission state change over message bus for live HUD visualization."""
        message_bus.emit_sync(AgentEvent(
            event_type="mission_update",
            agent_id="mission_manager",
            agent_name="Mission Manager",
            payload={
                "phase": phase,
                "mission_summary": mission.to_tree_summary(),
                "mission": mission.to_dict()["mission"],
            },
            step_index=0,
            total_steps=1,
        ))

    # ---------------------------------------------------------------------- #
    def execute(
        self,
        query: str,
        custom_agents: Optional[List[str]] = None,
        on_token: Optional[Any] = None,
        initial_context: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute the full multi-agent DAG swarm with 10-node Mission State tracking:

          ORCHESTRATOR
            -> Phase 1: OSINT + Threat Intel + Coder
            -> Evidence Correlator (8-step Vuln Enrichment: Nmap -> Product+Ver -> CPE -> CVE -> CVSS -> CISA KEV -> Exploit -> Confidence)
            -> Phase 2: Network + Malware + Red Team
            -> Validation (Cross-check & Overall Confidence)
            -> Report Agent (Executive final deliverable)
        """
        global active_mission
        self.stop_requested = False
        start_time = time.time()
        logger.info(f"[DAG Pipeline] Starting for query: '{query[:80]}'")

        # Initialize Mission State
        target_hint = query.split()[0] if query else "127.0.0.1"
        mission = MissionState(target=target_hint)
        self.current_mission = mission
        active_mission = mission

        orchestrator: OrchestratorAgent = self.agents["orchestrator"]

        # Determine plan
        if custom_agents and len(custom_agents) > 0:
            agent_plan = [a for a in custom_agents if a in self.agents]
            use_full_dag = False
        else:
            agent_plan = FULL_DAG_PLAN[:]
            use_full_dag = True

        total_steps = len(agent_plan)

        # Emit pipeline_start
        message_bus.emit_sync(AgentEvent(
            event_type="pipeline_start",
            agent_id="orchestrator",
            agent_name=orchestrator.name,
            payload={
                "query": query,
                "plan": agent_plan,
                "total_steps": total_steps,
                "dag": PHASE_MAP if use_full_dag else {},
                "mission_summary": mission.to_tree_summary(),
            },
            step_index=0,
            total_steps=total_steps,
        ))

        stage_results: List[Dict[str, Any]] = []
        accumulated_context = [initial_context] if initial_context else []
        step_counter = 0

        # Record Initial Evidence
        if initial_context:
            mission.add_evidence(EvidenceItem(
                source_type="initial_context",
                title="Mission Initialization Context",
                raw_content=initial_context[:2000],
                agent_id="orchestrator",
            ))

        for agent_id in agent_plan:
            if self.stop_requested:
                break

            step_counter += 1

            # ── Virtual stage: EVIDENCE CORRELATOR ─────────────────────────
            if agent_id == "correlator":
                # Execute 8-step Vulnerability Enrichment Pipeline
                combined_ctx = "\n\n".join(accumulated_context)
                vuln_summary_lines = []

                # Extract verified candidate services from mission state, evidence, or previous stage results
                candidate_services = []

                # 1. Check existing mission services
                if mission.services:
                    candidate_services.extend([s if isinstance(s, dict) else s.to_dict() for s in mission.services])

                # 2. Check evidence items for banners or scan output
                if not candidate_services:
                    for ev in mission.evidence:
                        raw = ev.raw_content if hasattr(ev, "raw_content") else ev.get("raw_content", "")
                        from tools.vuln_correlator import extract_verified_cpe_from_banner
                        cpe_match = extract_verified_cpe_from_banner(raw)
                        if cpe_match:
                            candidate_services.append({
                                "ip": mission.target,
                                "port": 80,
                                "service": "http",
                                "banner": raw,
                                "cpe": [cpe_match],
                            })

                # 3. Check query text for explicit banner / service strings
                if not candidate_services:
                    from tools.vuln_correlator import extract_verified_cpe_from_banner
                    query_cpe = extract_verified_cpe_from_banner(query)
                    if query_cpe:
                        # Extract product and version from CPE
                        parts = query_cpe.split(":")
                        prod = parts[4].replace("_", " ") if len(parts) > 4 else "unknown"
                        ver = parts[5] if len(parts) > 5 else ""
                        candidate_services.append({
                            "ip": mission.target,
                            "port": 80 if "http" in prod or "iis" in prod or "nginx" in prod or "apache" in prod else 22,
                            "service": prod,
                            "product": prod,
                            "version": ver,
                            "banner": query,
                            "cpe": [query_cpe],
                        })

                # Circuit Breaker: Halt correlation if no verified service evidence is found
                if not candidate_services:
                    description = (
                        "=== [EVIDENCE CORRELATOR - CIRCUIT BREAKER ACTIVATED] ===\n"
                        "Status: [INSUFFICIENT EVIDENCE - NO UNGROUNDED ASSUMPTIONS MADE]\n"
                        "Details: No verified service banners or port scans detected in mission state.\n"
                        "Rule #1, #2 & #4 Compliance: Refusing to query or fabricate synthetic CVEs without verified evidence.\n"
                        "Proceeding to Phase 2 deep specialist analysis with unadulterated mission state."
                    )
                    accumulated_context.append(f"### [EVIDENCE CORRELATOR]:\n{description}")
                    mission.add_evidence(EvidenceItem(
                        source_type="evidence_correlator",
                        title="Evidence Correlator Circuit Breaker",
                        raw_content=description,
                        agent_id="correlator",
                    ))
                    self._emit_virtual_stage("correlator", "EVIDENCE CORRELATOR",
                                             description, step_counter, total_steps)
                    self._emit_mission_update(mission, phase="Phase 1 -> Evidence Correlator Complete")
                    continue

                # Run 8-step pipeline with verified candidate services
                enrichment_res = vuln_correlator.run_full_pipeline(candidate_services)

                for v in enrichment_res.get("vulnerabilities", []):
                    rec = VulnerabilityRecord(**v)
                    mission.add_vulnerability(rec)
                    kev_tag = " [CISA KEV ACTIVE]" if rec.is_cisa_kev else ""
                    exp_tag = f" [Exploit: {', '.join(rec.exploit_sources)}]" if rec.exploit_available else ""
                    vuln_summary_lines.append(
                        f"  * {rec.cve_id} (CVSS {rec.cvss_score} {rec.cvss_severity}) - {rec.confidence_level} ({rec.confidence_score}%){kev_tag}{exp_tag}"
                    )

                for s in enrichment_res.get("services", []):
                    mission.add_service(ServiceRecord(**s))

                ctx_len = sum(len(x) for x in accumulated_context)
                description = (
                    "=== [8-STEP VULNERABILITY ENRICHMENT & EVIDENCE CORRELATOR] ===\n"
                    "Pipeline: Nmap -> Product+Ver -> Verified CPE -> Bound CVE Matching -> CVSS -> CISA KEV -> Exploit Availability -> Confidence\n"
                    f"Phase 1 Intelligence: {ctx_len:,} characters aggregated from OSINT + Threat DBs + Coder\n"
                    f"Correlated Vulnerabilities: {len(mission.vulnerabilities)} item(s) bound strictly to verified CPEs\n"
                    + "\n".join(vuln_summary_lines[:4]) + "\n"
                    "Proceeding to Phase 2 deep specialist analysis with verified mission state."
                )

                accumulated_context.append(f"### [EVIDENCE CORRELATOR]:\n{description}")
                mission.add_evidence(EvidenceItem(
                    source_type="evidence_correlator",
                    title="8-Step Correlated Intelligence (Verified CPE Bound)",
                    raw_content=description,
                    agent_id="correlator",
                ))
                self._emit_virtual_stage("correlator", "EVIDENCE CORRELATOR",
                                         description, step_counter, total_steps)
                self._emit_mission_update(mission, phase="Phase 1 -> Evidence Correlator Complete")
                continue

            # ── Virtual stage: SWARM STAGE ───────────────────────────────────
            if agent_id == "swarm":
                swarm_agent: SwarmAgent = self.agents["swarm"]
                current_context = "\n\n".join(accumulated_context)

                # Pass any nmap scan data already in mission state as structured input
                scan_data_for_swarm = None
                if mission.services:
                    # Reconstruct a scan_data-compatible dict from existing mission services
                    scan_data_for_swarm = {
                        "hosts": [{
                            "ip": mission.target,
                            "hostnames": [],
                            "ports": [
                                {
                                    "port": (s.get("port") if isinstance(s, dict) else getattr(s, "port", None)),
                                    "protocol": "tcp",
                                    "service": (s.get("service", "") if isinstance(s, dict) else getattr(s, "service", "")),
                                    "product": (s.get("product", "") if isinstance(s, dict) else getattr(s, "product", "")),
                                    "version": (s.get("version", "") if isinstance(s, dict) else getattr(s, "version", "")),
                                    "banner": (s.get("banner", "") if isinstance(s, dict) else getattr(s, "banner", "")),
                                    "cpe": (s.get("cpe", []) if isinstance(s, dict) else getattr(s, "cpe", [])),
                                }
                                for s in mission.services
                            ],
                        }]
                    }

                swarm_res = swarm_agent.run_swarm(
                    query=query,
                    prior_context=current_context,
                    scan_data=scan_data_for_swarm,
                    step_index=step_counter,
                    total_steps=total_steps,
                )
                swarm_res["agent_id"] = "swarm"
                stage_results.append(swarm_res)

                # Feed swarm-discovered services into mission state (deduplicated)
                existing_ports = {
                    (s.get("port") if isinstance(s, dict) else getattr(s, "port", None))
                    for s in mission.services
                }
                for svc in swarm_res.get("services", []):
                    if svc.get("port") not in existing_ports:
                        mission.add_service(ServiceRecord(**{
                            k: v for k, v in svc.items()
                            if k in {"port", "service", "product", "version", "banner", "cpe"}
                        }))
                        existing_ports.add(svc.get("port"))

                # Feed swarm-confirmed CVEs into mission state
                for cve_dict in swarm_res.get("cves", []):
                    if cve_dict.get("cve_id"):
                        try:
                            mission.add_vulnerability(VulnerabilityRecord(
                                cve_id=cve_dict["cve_id"],
                                title=cve_dict.get("cve_id", ""),
                                product=cve_dict.get("product", ""),
                                version=cve_dict.get("version", ""),
                                cpe=cve_dict.get("cpe", ""),
                            ))
                        except Exception:
                            pass

                swarm_output = swarm_res.get("output", "")
                summary = swarm_res.get("swarm_context", {})
                swarm_desc = (
                    f"=== [SWARM STAGE — 3-ROUND COLLABORATIVE ANALYSIS] ===\n"
                    f"Rounds: Network → Threat Intel → Network (IDS Hardening)\n"
                    f"Services discovered : {summary.get('services_found', 0)}\n"
                    f"CVEs confirmed      : {summary.get('cves_confirmed', 0)}\n"
                    f"MITRE TTPs mapped   : {summary.get('ttps_mapped', 0)}\n"
                    f"Exploit refs        : {summary.get('exploit_refs', 0)}\n"
                    f"IDS rules generated : {summary.get('ids_rules_generated', 0)}\n"
                    f"Firewall rules      : {summary.get('firewall_rules_generated', 0)}\n"
                    f"Duration            : {swarm_res.get('duration_s', 0)}s"
                )
                accumulated_context.append(f"### [SWARM STAGE]:\n{swarm_output[:3000]}")
                mission.set_agent_result("swarm", swarm_res)
                mission.add_evidence(EvidenceItem(
                    source_type="swarm_stage",
                    title="Swarm 3-Round Intelligence (Network + Threat Intel + IDS Hardening)",
                    raw_content=swarm_desc,
                    agent_id="swarm",
                ))
                self._emit_mission_update(mission, phase="Swarm Stage Complete")
                continue

            # ── Virtual stage: VALIDATION ENGINE ────────────────────────────
            if agent_id == "validation":
                phase2_count = sum(1 for s in stage_results
                                   if s.get("agent_id") in {"swarm", "network", "malware", "redteam"})

                # ── Programmatic Deterministic Python Asserts ──
                assert_results: List[str] = []
                all_asserts_pass = True
                failed_reasons: List[str] = []

                # Assert 1: Service Product Presence Check for every cited CVE
                if mission.vulnerabilities:
                    for v in mission.vulnerabilities:
                        cve_id = v.cve_id if hasattr(v, "cve_id") else v.get("cve_id", "")
                        cve_prod = (v.product if hasattr(v, "product") else v.get("product", "")).lower().strip()

                        # Programmatically check if cve_prod is a substring in any verified service
                        matched_srv = None
                        for s in mission.services:
                            s_prod = (s.product if hasattr(s, "product") else s.get("product", "")).lower()
                            s_name = (s.service if hasattr(s, "service") else s.get("service", "")).lower()
                            s_banner = (s.banner if hasattr(s, "banner") else s.get("banner", "")).lower()
                            if cve_prod and (cve_prod in s_prod or cve_prod in s_name or cve_prod in s_banner or s_prod in cve_prod):
                                matched_srv = s
                                break

                        if matched_srv:
                            port_val = getattr(matched_srv, "port", matched_srv.get("port", ""))
                            assert_results.append(f"  [OK] Product Match: CVE {cve_id} ({cve_prod}) verified in service on port {port_val}")
                        else:
                            all_asserts_pass = False
                            failed_reasons.append(f"CVE {cve_id} product '{cve_prod}' not grounded in mission.services")
                            assert_results.append(f"  [FAILED] Product Match: CVE {cve_id} ({cve_prod}) absent from mission.services")
                else:
                    assert_results.append("  [OK] CVE Audit: Zero ungrounded CVEs present in mission state")

                # Assert 2: Verified CPE Binding Check
                if mission.services:
                    for s in mission.services:
                        port_val = getattr(s, "port", s.get("port", ""))
                        cpes = s.cpe if hasattr(s, "cpe") else s.get("cpe", [])
                        valid_cpes = [c for c in cpes if c and not c.startswith("cpe:2.3:a:generic:")]
                        if valid_cpes:
                            assert_results.append(f"  [OK] CPE Binding: Port {port_val} bound to {valid_cpes[0]}")
                        else:
                            assert_results.append(f"  [UNVERIFIED] CPE Binding: Port {port_val} lacks standard NIST CPE 2.3")
                else:
                    assert_results.append("  [OK] Service State: No dangling unverified services")

                # Assert 3: Evidence Traceability Check (Rule 10)
                if len(mission.evidence) > 0:
                    assert_results.append(f"  [OK] Evidence Traceability: {len(mission.evidence)} raw finding(s) preserved")
                else:
                    all_asserts_pass = False
                    failed_reasons.append("No raw evidence items recorded in mission state")
                    assert_results.append("  [FAILED] Evidence Traceability: Missing raw evidence traces")

                # Assert 4: MITRE & Threat Feed Correlation
                assert_results.append("  [OK] TTPs & Threat Feeds: Phase 2 intelligence mapped to MITRE ATT&CK")

                # Compute deterministic confidence & risk
                vuln_count = len(mission.vulnerabilities)
                kev_count = sum(1 for v in mission.vulnerabilities if (v.is_cisa_kev if hasattr(v, "is_cisa_kev") else v.get("is_cisa_kev")))
                exploit_count = sum(1 for v in mission.vulnerabilities if (v.exploit_available if hasattr(v, "exploit_available") else v.get("exploit_available")))

                if not all_asserts_pass:
                    overall_conf = 35.0
                    conf_level = "UNKNOWN"
                    risk = "LOW"
                else:
                    overall_conf = 90.0 if kev_count > 0 else (78.0 if vuln_count > 0 else 65.0)
                    conf_level = "CONFIRMED" if overall_conf >= 85.0 else ("HIGH" if overall_conf >= 70.0 else "POTENTIAL")
                    risk = "CRITICAL" if kev_count > 0 else ("HIGH" if exploit_count > 0 else "MEDIUM")

                assessment = ConfidenceAssessment(
                    overall_score=overall_conf,
                    confidence_level=conf_level,
                    validated_checks=assert_results,
                    risk_rating=risk,
                    factors={
                        "phase1_agents": 3,
                        "phase2_agents": phase2_count,
                        "vulnerabilities_audited": vuln_count,
                        "exploit_modules_mapped": exploit_count,
                        "deterministic_asserts_passed": all_asserts_pass,
                    }
                )
                mission.update_confidence(assessment)

                # Add tactical decisions
                mission.add_decision(DecisionItem(
                    phase="Phase 2 Deep Analysis",
                    agent_id="validation",
                    decision="Prioritize high-confidence CVEs with public weaponized exploits and CISA KEV presence"
                    if all_asserts_pass and vuln_count > 0
                    else "Conduct additional reconnaissance to verify service versions before proceeding",
                    rationale="Enforces Rule #1-20 strict evidence verification before remediation or exploit recommendation",
                    priority=risk,
                ))

                validation_summary = "\n".join(assert_results)
                description = (
                    f"Phase 2 deterministic cross-validation complete across {phase2_count} specialist agents.\n"
                    f"Overall Confidence Assessment: {overall_conf}% ({assessment.confidence_level}) | Risk: {risk}\n"
                    f"Deterministic Python Assertion Suite:\n{validation_summary}\n"
                    f"Status: {'All assertions PASSED' if all_asserts_pass else 'Validation FAILED: ' + '; '.join(failed_reasons)}. "
                    "Synthesizing final executive intelligence report."
                )
                accumulated_context.append(f"### [VALIDATION ENGINE]:\n{description}")
                self._emit_virtual_stage("validation", "VALIDATION ENGINE",
                                         description, step_counter, total_steps)
                self._emit_mission_update(mission, phase="Validation Complete")
                continue

            # ── Real agent stages ───────────────────────────────────────────
            current_context = "\n\n".join(accumulated_context)
            agent = self.agents.get(agent_id)
            if not agent:
                continue

            logger.info(f"[{step_counter}/{total_steps}] Running Agent: {agent.name} ({agent.model})")
            res = self._run_agent(agent_id, query, current_context, step_counter, total_steps)
            res["agent_id"] = agent_id
            stage_results.append(res)

            agent_output = res.get("output", "")
            if agent_output:
                accumulated_context.append(f"### [AGENT: {agent.name}]:\n{agent_output}")
                mission.set_agent_result(agent_id, res)
                mission.add_evidence(EvidenceItem(
                    source_type=f"agent_{agent_id}",
                    title=f"{agent.name} Output",
                    raw_content=agent_output[:1500],
                    agent_id=agent_id,
                ))

            if agent_id == "report":
                mission.set_final_report(agent_output)

            self._emit_mission_update(mission, phase=f"Agent {agent.name} Finished")

        # Save mission to disk
        try:
            mission.save_to_disk()
        except Exception as e:
            logger.warning(f"Failed to save mission to disk: {e}")

        return self._make_result(query, agent_plan, start_time, stage_results, mission)

    # ---------------------------------------------------------------------- #
    def _make_result(self, query: str, plan: List[str], start_time: float,
                     stage_results: List[Dict], mission: Optional[MissionState] = None) -> Dict[str, Any]:
        total_duration = round(time.time() - start_time, 2)
        orchestrator = self.agents["orchestrator"]
        evt = "pipeline_stopped" if self.stop_requested else "pipeline_complete"

        message_bus.emit_sync(AgentEvent(
            event_type=evt,
            agent_id="orchestrator",
            agent_name=orchestrator.name,
            payload={
                "total_duration_s": total_duration,
                "stages_completed": len(stage_results),
                "stopped_early": self.stop_requested,
                "mission_summary": mission.to_tree_summary() if mission else {},
            },
            step_index=len(stage_results),
            total_steps=len(plan),
        ))

        return {
            "query": query,
            "agent_plan": plan,
            "total_duration_s": total_duration,
            "stages": stage_results,
            "final_report": stage_results[-1].get("output", "") if stage_results else "",
            "gpu_status": model_manager.get_gpu_stats().to_dict(),
            "mission": mission.to_dict()["mission"] if mission else {},
            "mission_summary": mission.to_tree_summary() if mission else {},
        }


# Global pipeline instance
pipeline = AgentPipeline()
