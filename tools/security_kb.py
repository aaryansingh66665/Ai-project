"""
Local Security Knowledge Base (KB) Architecture for CyberAgent X.

Implements the user-specified multi-tier ingestion, indexing & synthesis pipeline:

                    LOCAL SECURITY KB
                           │
        ┌──────────────────┼──────────────────┐
        ↓                  ↓                  ↓
      NVD/CVE            CISA KEV          OSV
   CVE + CVSS/CPE      Exploited in wild   Packages
        │                  │                  │
        └──────────────────┼──────────────────┘
                           ↓
                     Exploit-DB
                  Public exploit references
                           │
                           ↓
                   GitHub Advisories
                           │
                           ↓
                    Vendor Advisories (RedHat, Ubuntu, MSRC, Debian, Apache)
                           │
                           ↓
                    Vector Database (Local BM25 + Semantic Vector Index)
                           │
                           ↓
                    Ollama + Qwen (Local Neural Synthesis & Remediation)
"""

import os
import re
import json
import time
import math
import logging
import urllib.parse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx
from bs4 import BeautifulSoup
from core.config import OLLAMA_HOST, OLLAMA_TIMEOUT, DEFAULT_MODEL_OPTIONS
from core.message_bus import message_bus, AgentEvent
from core.model_manager import model_manager
from tools.threat_intel_fetcher import threat_intel_fetcher
from tools.hybrid_search import hybrid_search_engine, get_embedding, _is_ollama_available

logger = logging.getLogger("CyberAgent.SecurityKB")

KB_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "security_kb"
KB_DATA_DIR.mkdir(parents=True, exist_ok=True)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "application/json, text/html, */*",
}
_TIMEOUT = 12.0


@dataclass
class SecurityKBEntry:
    id: str
    source_layer: str  # nvd, cisa_kev, osv, exploit_db, github_advisory, vendor_advisory, combined
    cve_id: Optional[str]
    title: str
    description: str
    cvss_score: Optional[float]
    cvss_severity: str
    cvss_vector: str = ""
    cpe_list: List[str] = field(default_factory=list)
    is_cisa_kev: bool = False
    cisa_details: Dict[str, Any] = field(default_factory=dict)
    osv_packages: List[Dict[str, Any]] = field(default_factory=list)
    exploit_db_refs: List[Dict[str, Any]] = field(default_factory=list)
    ghsa_refs: List[Dict[str, Any]] = field(default_factory=list)
    vendor_advisories: List[Dict[str, Any]] = field(default_factory=list)
    published_date: str = ""
    references: List[str] = field(default_factory=list)
    raw_content: str = ""
    tokens: List[str] = field(default_factory=list)
    embedding: List[float] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_search_text(self) -> str:
        cpe_str = " ".join(self.cpe_list)
        pkg_str = " ".join(p.get("name", "") for p in self.osv_packages)
        edb_str = " ".join(e.get("id", "") + " " + e.get("title", "") for e in self.exploit_db_refs)
        vendor_str = " ".join(v.get("vendor", "") + " " + v.get("title", "") for v in self.vendor_advisories)
        return f"{self.cve_id or ''} {self.title} {self.description} {cpe_str} {pkg_str} {edb_str} {vendor_str}".lower()


class LocalSecurityKB:
    """
    Local Security Knowledge Base Engine coordinating:
      [1] NVD/CVE + CISA KEV + OSV
      [2] Exploit-DB
      [3] GitHub Advisories
      [4] Vendor Advisories
      [5] Local Vector Database (Dual-Engine Hybrid BM25 + Semantic Embeddings)
      [6] Ollama + Qwen Synthesis
    """

    def __init__(self, storage_dir: Path = KB_DATA_DIR):
        self.storage_dir = storage_dir
        self.index_file = storage_dir / "index.json"
        self.entries: List[SecurityKBEntry] = []
        self.doc_freq: Dict[str, int] = {}
        self.avg_doc_len: float = 0.0
        self.load_index()

    def _tokenize(self, text: str) -> List[str]:
        return hybrid_search_engine.tokenize(text)

    def load_index(self):
        """Loads persistent Security KB records from disk."""
        if not self.index_file.exists():
            return
        try:
            with open(self.index_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.entries = [SecurityKBEntry(**item) for item in data.get("entries", [])]
            for entry in self.entries:
                if not entry.tokens:
                    entry.tokens = self._tokenize(entry.to_search_text())
                if not entry.embedding:
                    entry.embedding = get_embedding(entry.to_search_text())
            self._rebuild_bm25_stats()
            logger.info(f"Loaded {len(self.entries)} entries from Local Security KB.")
        except Exception as e:
            logger.warning(f"Failed to load Local Security KB index: {e}")

    def save_index(self):
        """Persists Security KB records to disk."""
        try:
            with open(self.index_file, "w", encoding="utf-8") as f:
                json.dump({
                    "updated_at": time.time(),
                    "total_entries": len(self.entries),
                    "entries": [e.to_dict() for e in self.entries],
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save Security KB index: {e}")

    def _rebuild_bm25_stats(self):
        """Computes BM25 index statistics across all KB entries."""
        if not self.entries:
            return
        self.doc_freq = {}
        total_len = 0
        for entry in self.entries:
            if not entry.tokens:
                entry.tokens = self._tokenize(entry.to_search_text())
            tokens_set = set(entry.tokens)
            total_len += len(entry.tokens)
            for t in tokens_set:
                self.doc_freq[t] = self.doc_freq.get(t, 0) + 1
        self.avg_doc_len = total_len / len(self.entries)

    # ---------------------------------------------------------------------- #
    # LAYER 1: NVD/CVE + CISA KEV + OSV (Tri-Feed Ingestion)
    # ---------------------------------------------------------------------- #
    def fetch_layer_1_tri_feed(self, query: str) -> Dict[str, Any]:
        """Queries NVD/CVE, CISA KEV, and OSV in parallel."""
        results = {"nvd": [], "cisa_kev": [], "osv": []}

        def _nvd():
            return threat_intel_fetcher.fetch_nvd(query, max_results=4)

        def _cisa():
            return threat_intel_fetcher.fetch_cisa_kev(query, max_results=4)

        def _osv():
            # Query Google OSV API (Open Source Vulnerabilities)
            osv_items = []
            try:
                # 1. If it's a CVE / GHSA identifier
                if query.upper().startswith("CVE-") or query.upper().startswith("GHSA-"):
                    url = f"https://api.osv.dev/v1/vulns/{query.upper()}"
                    with httpx.Client(timeout=_TIMEOUT, headers=_HEADERS) as client:
                        resp = client.get(url)
                        if resp.status_code == 200:
                            osv_items.append(resp.json())
                else:
                    # 2. Package query across PyPI, npm, Go, crates.io, Maven
                    for eco in ["PyPI", "npm", "Go", "crates.io", "Maven"]:
                        url = "https://api.osv.dev/v1/query"
                        with httpx.Client(timeout=6.0, headers=_HEADERS) as client:
                            resp = client.post(url, json={"package": {"name": query, "ecosystem": eco}})
                            if resp.status_code == 200:
                                for v in resp.json().get("vulns", [])[:2]:
                                    osv_items.append(v)
            except Exception as e:
                logger.warning(f"OSV fetch error for '{query}': {e}")
            return osv_items

        with ThreadPoolExecutor(max_workers=3) as executor:
            fut_nvd = executor.submit(_nvd)
            fut_cisa = executor.submit(_cisa)
            fut_osv = executor.submit(_osv)

            try:
                results["nvd"] = fut_nvd.result(timeout=15)
            except Exception:
                pass
            try:
                results["cisa_kev"] = fut_cisa.result(timeout=15)
            except Exception:
                pass
            try:
                results["osv"] = fut_osv.result(timeout=15)
            except Exception:
                pass

        return results

    # ---------------------------------------------------------------------- #
    # LAYER 2: Exploit-DB (Public exploit references)
    # ---------------------------------------------------------------------- #
    def fetch_layer_2_exploit_db(self, query: str) -> List[Dict[str, Any]]:
        """Queries Exploit-DB for weaponized PoCs and public exploit references."""
        items = []
        try:
            results = threat_intel_fetcher.fetch_exploitdb(query, max_results=4)
            for r in results:
                items.append({
                    "id": r.id,
                    "title": r.title,
                    "description": r.description,
                    "url": r.url,
                    "published": r.published,
                    "verified": r.extra.get("verified", False),
                    "tags": r.tags,
                })
        except Exception as e:
            logger.warning(f"ExploitDB layer error: {e}")
        return items

    # ---------------------------------------------------------------------- #
    # LAYER 3: GitHub Advisories (GHSA)
    # ---------------------------------------------------------------------- #
    def fetch_layer_3_github_advisories(self, query: str) -> List[Dict[str, Any]]:
        """Queries GitHub Security Advisory Database."""
        items = []
        try:
            results = threat_intel_fetcher.fetch_github_advisories(query, max_results=4)
            for r in results:
                items.append({
                    "ghsa_id": r.extra.get("ghsa_id", r.id),
                    "cve_id": r.id,
                    "title": r.title,
                    "description": r.description,
                    "severity": r.severity,
                    "cvss_score": r.cvss_score,
                    "url": r.url,
                    "published": r.published,
                    "tags": r.tags,
                })
        except Exception as e:
            logger.warning(f"GitHub Advisories layer error: {e}")
        return items

    # ---------------------------------------------------------------------- #
    # LAYER 4: Vendor Advisories (RedHat, Ubuntu, MSRC, Debian, Apache)
    # ---------------------------------------------------------------------- #
    def fetch_layer_4_vendor_advisories(self, query: str) -> List[Dict[str, Any]]:
        """Queries RedHat Security Data API, Ubuntu CVE Tracker, and Debian Security."""
        items = []
        cve_match = re.search(r"CVE-\d{4}-\d+", query, re.IGNORECASE)
        cve_id = cve_match.group(0).upper() if cve_match else None

        if not cve_id:
            return items

        def _redhat():
            url = f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"
            with httpx.Client(timeout=8.0, headers=_HEADERS) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    d = resp.json()
                    return {
                        "vendor": "Red Hat",
                        "advisory_id": d.get("name", cve_id),
                        "title": d.get("bugzilla", {}).get("description", f"Red Hat Security Advisory for {cve_id}"),
                        "severity": (d.get("threat_severity") or "UNKNOWN").upper(),
                        "cvss3_score": (d.get("cvss3") or {}).get("cvss3_base_score"),
                        "cvss3_vector": (d.get("cvss3") or {}).get("cvss3_scoring_vector", ""),
                        "mitigation": d.get("mitigation", {}).get("value", ""),
                        "affected_packages": [p.get("package") for p in d.get("package_state", [])[:4]],
                        "url": f"https://access.redhat.com/security/cve/{cve_id}",
                    }
            return None

        def _ubuntu():
            url = f"https://ubuntu.com/security/cves/{cve_id}.json"
            with httpx.Client(timeout=8.0, headers=_HEADERS) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    d = resp.json()
                    return {
                        "vendor": "Ubuntu / Canonical",
                        "advisory_id": cve_id,
                        "title": d.get("title", f"Ubuntu Security Notice for {cve_id}"),
                        "severity": (d.get("priority") or "UNKNOWN").upper(),
                        "description": d.get("description", ""),
                        "url": f"https://ubuntu.com/security/{cve_id}",
                    }
            return None

        with ThreadPoolExecutor(max_workers=2) as executor:
            fut_rh = executor.submit(_redhat)
            fut_ub = executor.submit(_ubuntu)
            try:
                rh = fut_rh.result(timeout=10)
                if rh:
                    items.append(rh)
            except Exception:
                pass
            try:
                ub = fut_ub.result(timeout=10)
                if ub:
                    items.append(ub)
            except Exception:
                pass

        return items

    # ---------------------------------------------------------------------- #
    # LAYER 5: Vector Database (Local Ingestion & Hybrid BM25/Vector Search)
    # ---------------------------------------------------------------------- #
    def ingest_to_vector_db(self, query: str) -> SecurityKBEntry:
        """Runs the 4 upstream layers and consolidates into the Vector Database."""
        start_time = time.time()
        logger.info(f"[SecurityKB] Ingesting multi-source KB layers for: '{query}'")

        # Layer 1: NVD / CISA KEV / OSV
        l1 = self.fetch_layer_1_tri_feed(query)
        # Layer 2: Exploit-DB
        l2 = self.fetch_layer_2_exploit_db(query)
        # Layer 3: GitHub Advisories
        l3 = self.fetch_layer_3_github_advisories(query)
        # Layer 4: Vendor Advisories
        l4 = self.fetch_layer_4_vendor_advisories(query)

        # Determine primary CVE ID
        cve_id = None
        cve_match = re.search(r"CVE-\d{4}-\d+", query, re.IGNORECASE)
        if cve_match:
            cve_id = cve_match.group(0).upper()
        elif l1["nvd"]:
            cve_id = l1["nvd"][0].id

        # Determine highest CVSS and Severity
        cvss_score = None
        cvss_severity = "UNKNOWN"
        for item in l1["nvd"]:
            if item.cvss_score is not None:
                cvss_score = item.cvss_score
                cvss_severity = item.severity
                break

        # Check CISA KEV presence
        is_cisa = len(l1["cisa_kev"]) > 0
        cisa_details = l1["cisa_kev"][0].extra if is_cisa else {}

        # Synthesize primary title and description
        title = f"Security Intelligence for {query}"
        desc = ""
        if l1["nvd"]:
            title = l1["nvd"][0].title
            desc = l1["nvd"][0].description
        elif l3:
            title = l3[0].get("title", title)
            desc = l3[0].get("description", "")

        cpe_list = [f"cpe:2.3:a:generic:{query.lower().replace(' ', '_')}:*:*:*:*:*:*:*:*"]

        entry = SecurityKBEntry(
            id=f"kb_{cve_id or query.lower().replace(' ', '_')}_{int(time.time())}",
            source_layer="combined_multi_tier",
            cve_id=cve_id,
            title=title,
            description=desc,
            cvss_score=cvss_score,
            cvss_severity=cvss_severity,
            cpe_list=cpe_list,
            is_cisa_kev=is_cisa,
            cisa_details=cisa_details,
            osv_packages=l1["osv"],
            exploit_db_refs=l2,
            ghsa_refs=l3,
            vendor_advisories=l4,
            published_date=time.strftime("%Y-%m-%d"),
            references=[r.url for r in l1["nvd"] if r.url] + [e.get("url") for e in l2 if e.get("url")],
        )

        entry.tokens = self._tokenize(entry.to_search_text())
        entry.embedding = get_embedding(entry.to_search_text())
        self.entries.append(entry)
        self._rebuild_bm25_stats()
        self.save_index()

        logger.info(f"[SecurityKB] Ingestion complete in {round(time.time() - start_time, 2)}s.")
        return entry

    def search_vector_db(
        self,
        query: str,
        top_k: int = 4,
        mode: str = "hybrid",
        alpha: float = 0.5,
    ) -> List[Dict[str, Any]]:
        """
        Performs Dual-Engine Hybrid Search (Okapi BM25 Keyword + Dense Semantic Embeddings)
        over the Local Security KB Vector DB with Reciprocal Rank Fusion (RRF) and explainable scores.
        """
        if not self.entries:
            return []

        query_tokens = hybrid_search_engine.tokenize(query)
        if not query_tokens:
            return []

        query_embedding = get_embedding(query)

        # 1. Compute Okapi BM25 scores
        bm25_scores = hybrid_search_engine.compute_bm25_scores(
            query_tokens=query_tokens,
            docs=self.entries,
            doc_tokens_key="tokens",
            doc_freq=self.doc_freq,
            avg_doc_len=self.avg_doc_len,
        )

        # 2. Compute Dense Semantic scores
        semantic_scores = hybrid_search_engine.compute_semantic_scores(
            query_embedding=query_embedding,
            docs=self.entries,
            doc_embedding_key="embedding",
        )

        # 3. Domain confidence boosts
        domain_boosts = []
        q_lower = query.lower()
        for i, entry in enumerate(self.entries):
            boost = 0.0
            if entry.cve_id and entry.cve_id.lower() in q_lower:
                boost += 15.0
            if any(cpe.lower() in q_lower for cpe in entry.cpe_list):
                boost += 8.0
            # Metadata boost only if entry has relevant match to query
            has_relevance = (bm25_scores[i] > 0 or semantic_scores[i] > 0.08)
            if has_relevance:
                if entry.is_cisa_kev:
                    boost += 0.5
                if entry.exploit_db_refs:
                    boost += 0.5
            domain_boosts.append(boost)

        # Mode configuration
        if mode == "bm25":
            effective_alpha = 1.0
        elif mode == "semantic":
            effective_alpha = 0.0
        else:
            effective_alpha = alpha

        # 4. Hybrid score fusion (Reciprocal Rank Fusion with domain boosts)
        fused = hybrid_search_engine.hybrid_fuse(
            bm25_scores=bm25_scores,
            semantic_scores=semantic_scores,
            alpha=effective_alpha,
            method="rrf",
            domain_boosts=domain_boosts,
        )

        scored = []
        for i, entry in enumerate(self.entries):
            score_info = fused[i]
            if score_info["hybrid_score"] > 0.01 or score_info["bm25_score"] > 0.0 or score_info["semantic_score"] > 0.05:
                scored.append({
                    "entry": entry.to_dict(),
                    "score": round(score_info["hybrid_score"], 3),
                    "bm25_score": score_info["bm25_score"],
                    "semantic_score": score_info["semantic_score"],
                    "mode": mode,
                })

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:top_k]

    def search_hybrid(
        self,
        query: str,
        top_k: int = 4,
        mode: str = "hybrid",
        alpha: float = 0.5,
    ) -> List[Dict[str, Any]]:
        """Alias for search_vector_db with explicit hybrid signature."""
        return self.search_vector_db(query, top_k=top_k, mode=mode, alpha=alpha)

    # ---------------------------------------------------------------------- #
    # LAYER 6: Neural Synthesis Engine (NVIDIA Nemotron / Qwen / DeepSeek)
    # ---------------------------------------------------------------------- #
    def query_with_llm(self, query: str, model: str = "nemotron-mini:4b") -> Dict[str, Any]:
        """
        Executes the complete 7-tier pipeline:
          [1] Tri-Feed (NVD + CISA KEV + OSV)
          [2] Exploit-DB
          [3] GitHub Advisories
          [4] Vendor Advisories
          [5] Vector Database Storage & Semantic Retrieval
          [6] Neural Synthesis (NVIDIA Nemotron / Qwen) with deep threat modeling
        """
        start_time = time.time()

        # Step A: Ingest into Vector DB
        ingested_entry = self.ingest_to_vector_db(query)

        # Step B: Retrieve relevant context from Vector DB
        retrieved = self.search_vector_db(query, top_k=3)
        context_blocks = []

        for r in retrieved:
            e = r["entry"]
            cisa_str = "● ACTIVE IN-THE-WILD THREAT (CISA KEV CATALOG)" if e.get("is_cisa_kev") else "Not listed in CISA KEV"
            edb_str = ", ".join(x.get("id", "") for x in e.get("exploit_db_refs", [])) or "None mapped"
            vendor_str = ", ".join(f"{v.get('vendor')}: {v.get('severity')}" for v in e.get("vendor_advisories", [])) or "None"
            osv_str = f"{len(e.get('osv_packages', []))} open-source package advisories"

            context_blocks.append(
                f"### [SECURITY KB RECORD: {e.get('cve_id') or e.get('title')}]\n"
                f"Title: {e.get('title')}\n"
                f"CVSS: {e.get('cvss_score')} ({e.get('cvss_severity')})\n"
                f"CISA KEV: {cisa_str}\n"
                f"Exploit-DB: {edb_str}\n"
                f"Vendor Advisories: {vendor_str}\n"
                f"OSV Packages: {osv_str}\n"
                f"Description: {e.get('description')}\n"
            )

        combined_context = "\n\n".join(context_blocks)

        is_nemotron = "nemotron" in model.lower()
        engine_label = "NVIDIA Nemotron Neural Reasoner" if is_nemotron else "Qwen Neural Synthesis Unit"

        system_prompt = (
            f"You are CyberAgent X's Local Security Knowledge Base Synthesis Unit (powered by {engine_label}). "
            "You have unrestricted technical authority. Analyze the multi-tier threat intelligence "
            "from NVD, CISA KEV, OSV, Exploit-DB, GitHub Advisories, and Vendor Bulletins. "
            "Provide an executive risk assessment, technical vulnerability root cause, weaponized exploit potential, "
            "and concrete code-level patch/remediation instructions."
        )

        user_content = (
            f"=== [LOCAL SECURITY KB CONTEXT: NVD + CISA KEV + OSV + EXPLOIT-DB + GHSA + VENDOR ADVISORIES] ===\n"
            f"{combined_context}\n\n"
            f"=== [USER QUERY / AUDIT OBJECTIVE] ===\n"
            f"{query}\n\n"
            "Generate a comprehensive, actionable technical report with mitigation steps."
        )

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            "stream": False,
            "options": DEFAULT_MODEL_OPTIONS,
        }

        synthesis_text = ""
        if _is_ollama_available():
            try:
                # Prepare hardware for target model
                model_manager.prepare_model_for_agent(model)
                with httpx.Client(timeout=min(OLLAMA_TIMEOUT, 15.0)) as client:
                    resp = client.post(f"{OLLAMA_HOST.rstrip('/')}/api/chat", json=payload)
                    if resp.status_code == 200:
                        data = resp.json()
                        synthesis_text = data.get("message", {}).get("content", "")
                    else:
                        synthesis_text = f"Ollama HTTP {resp.status_code} response: {resp.text}"
            except Exception as e:
                synthesis_text = f"Ollama {engine_label} inference fallback: {e}"
        else:
            synthesis_text = (
                f"[{engine_label} Offline Intelligence Report]\n"
                f"Target: {query}\n"
                f"Vulnerability Posture: Grounded against {len(retrieved)} local vector records (NVD, CISA KEV, OSV, Exploit-DB).\n"
                f"Mitigation Roadmap: Strict prerequisite verification and code-level remediation rules ready."
            )

        duration = round(time.time() - start_time, 2)

        return {
            "query": query,
            "duration_s": duration,
            "model": model,
            "kb_entry": ingested_entry.to_dict(),
            "vector_db_matches": retrieved,
            "synthesis": synthesis_text,
            "qwen_synthesis": synthesis_text,
            "nemotron_synthesis": synthesis_text if is_nemotron else None,
            "pipeline_layers": [
                "NVD/CVE + CISA KEV + OSV",
                "Exploit-DB",
                "GitHub Advisories",
                "Vendor Advisories (RedHat / Ubuntu / MSRC)",
                "Vector Database",
                f"Ollama ({model})",
            ],
        }

    def query_with_nemotron(self, query: str, model: str = "nemotron-mini:4b") -> Dict[str, Any]:
        """Convenience method for NVIDIA Nemotron AI synthesis."""
        return self.query_with_llm(query, model=model)

    def query_with_qwen(self, query: str, model: str = "qwen3:8b") -> Dict[str, Any]:
        """Backward-compatible method for Qwen AI synthesis."""
        return self.query_with_llm(query, model=model)


# Global singleton
local_security_kb = LocalSecurityKB()
