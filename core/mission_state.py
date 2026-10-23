"""
Mission State Model & Hierarchical Data Structure for CyberAgent X.

Implements the user-specified mission hierarchy:
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

import json
import time
import uuid
import logging
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional

logger = logging.getLogger("CyberAgent.MissionState")

MISSIONS_DIR = Path(__file__).resolve().parent.parent / "reports" / "missions"
MISSIONS_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class DiscoveredAsset:
    ip: str
    hostnames: List[str] = field(default_factory=list)
    mac: str = ""
    vendor: str = ""
    os_matches: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "up"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ServiceRecord:
    port: int
    protocol: str = "tcp"
    service: str = "unknown"
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: List[str] = field(default_factory=list)
    banner: str = ""
    scripts_output: Dict[str, str] = field(default_factory=dict)
    ip: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VulnerabilityRecord:
    cve_id: str
    title: str
    product: str
    version: str
    cpe: str
    cvss_score: Optional[float]
    cvss_severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_vector: str = ""
    is_cisa_kev: bool = False
    cisa_kev_details: Dict[str, Any] = field(default_factory=dict)
    exploit_available: bool = False
    exploit_sources: List[str] = field(default_factory=list)  # ExploitDB, Metasploit, Rapid7, GitHub
    exploit_details: Dict[str, Any] = field(default_factory=dict)
    confidence_score: float = 0.0  # 0.0 to 100.0
    confidence_level: str = "POTENTIAL"  # CONFIRMED, HIGH, PROBABLE, POTENTIAL
    confidence_breakdown: Dict[str, Any] = field(default_factory=dict)
    port: Optional[int] = None
    ip: str = ""
    remediation: str = ""
    reference_urls: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceItem:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    source_type: str = "nmap"  # nmap, osint, threat_db, malware, pcap, code_sandbox, agent_reasoning
    title: str = ""
    raw_content: str = ""
    parsed_content: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    agent_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DecisionItem:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    phase: str = ""
    agent_id: str = ""
    decision: str = ""
    rationale: str = ""
    priority: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ConfidenceAssessment:
    overall_score: float = 0.0  # 0.0 to 100.0
    confidence_level: str = "PROBABLE"  # CONFIRMED, HIGH, PROBABLE, POTENTIAL
    validated_checks: List[str] = field(default_factory=list)
    risk_rating: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW
    factors: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MissionState:
    """
    Unified Mission State representation adhering to the 10-node mission tree:
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

    def __init__(self, target: str = "", scope: Optional[Dict[str, Any]] = None, mission_id: Optional[str] = None):
        self.mission_id: str = mission_id or f"mission-{int(time.time())}-{str(uuid.uuid4())[:6]}"
        self.created_at: float = time.time()
        self.updated_at: float = time.time()

        # ── The 10 Core Mission Nodes ───────────────────────────────────────── #
        self.target: str = target
        self.scope: Dict[str, Any] = scope or {
            "allowed_domains": [target] if target else [],
            "allowed_ips": [target] if target and target.replace(".", "").isdigit() else [],
            "restricted_ports": [],
            "mode": "AUDIT_AND_EXPLOIT_POC",
            "stealth_level": "STANDARD",
        }
        self.discovered_assets: List[Dict[str, Any]] = []
        self.services: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.evidence: List[Dict[str, Any]] = []
        self.agent_results: Dict[str, Any] = {}
        self.confidence: Dict[str, Any] = ConfidenceAssessment().to_dict()
        self.decisions: List[Dict[str, Any]] = []
        self.final_report: str = ""

    def add_asset(self, asset: DiscoveredAsset) -> None:
        self.discovered_assets.append(asset.to_dict())
        self.updated_at = time.time()

    def add_service(self, service: ServiceRecord) -> None:
        self.services.append(service.to_dict())
        self.updated_at = time.time()

    def add_vulnerability(self, vuln: VulnerabilityRecord) -> None:
        self.vulnerabilities.append(vuln.to_dict())
        self.updated_at = time.time()

    def add_evidence(self, evidence: EvidenceItem) -> None:
        self.evidence.append(evidence.to_dict())
        self.updated_at = time.time()

    def add_decision(self, decision: DecisionItem) -> None:
        self.decisions.append(decision.to_dict())
        self.updated_at = time.time()

    def set_agent_result(self, agent_id: str, result: Dict[str, Any]) -> None:
        self.agent_results[agent_id] = result
        self.updated_at = time.time()

    def update_confidence(self, assessment: ConfidenceAssessment) -> None:
        self.confidence = assessment.to_dict()
        self.updated_at = time.time()

    def set_final_report(self, report_markdown: str) -> None:
        self.final_report = report_markdown
        self.updated_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize full 10-node mission structure."""
        return {
            "mission_id": self.mission_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "mission": {
                "target": self.target,
                "scope": self.scope,
                "discovered_assets": self.discovered_assets,
                "services": self.services,
                "vulnerabilities": self.vulnerabilities,
                "evidence": self.evidence,
                "agent_results": self.agent_results,
                "confidence": self.confidence,
                "decisions": self.decisions,
                "final_report": self.final_report,
            },
        }

    def to_tree_summary(self) -> Dict[str, Any]:
        """Provides a lightweight tree node count & status for visual UI display."""
        return {
            "mission_id": self.mission_id,
            "nodes": [
                {"name": "target", "count": 1 if self.target else 0, "status": "active" if self.target else "empty", "preview": self.target},
                {"name": "scope", "count": len(self.scope.get("allowed_domains", [])) + len(self.scope.get("allowed_ips", [])), "status": "configured" if self.scope else "empty", "preview": self.scope.get("mode", "")},
                {"name": "discovered_assets", "count": len(self.discovered_assets), "status": "populated" if self.discovered_assets else "empty", "preview": f"{len(self.discovered_assets)} host(s)"},
                {"name": "services", "count": len(self.services), "status": "populated" if self.services else "empty", "preview": f"{len(self.services)} service(s)"},
                {"name": "vulnerabilities", "count": len(self.vulnerabilities), "status": "populated" if self.vulnerabilities else "empty", "preview": f"{len(self.vulnerabilities)} vuln(s)"},
                {"name": "evidence", "count": len(self.evidence), "status": "populated" if self.evidence else "empty", "preview": f"{len(self.evidence)} item(s)"},
                {"name": "agent_results", "count": len(self.agent_results), "status": "populated" if self.agent_results else "empty", "preview": f"{len(self.agent_results)} agent(s)"},
                {"name": "confidence", "count": 1, "status": "scored", "preview": f"{self.confidence.get('overall_score', 0)}% ({self.confidence.get('confidence_level', 'PROBABLE')})"},
                {"name": "decisions", "count": len(self.decisions), "status": "populated" if self.decisions else "empty", "preview": f"{len(self.decisions)} tactical decision(s)"},
                {"name": "final_report", "count": 1 if self.final_report else 0, "status": "ready" if self.final_report else "pending", "preview": f"{len(self.final_report)} chars"},
            ]
        }

    def save_to_disk(self) -> Path:
        """Persist mission state to reports/missions/<mission_id>.json."""
        out_path = MISSIONS_DIR / f"{self.mission_id}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        return out_path


# Global active mission pointer
active_mission: MissionState = MissionState(target="127.0.0.1")
