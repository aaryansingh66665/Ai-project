"""
Unified Threat Intelligence Database Fetcher for CyberAgent X.
Queries 8 specialized cybersecurity databases in parallel (no API keys required):
  - NVD (NIST National Vulnerability Database)
  - CISA Known Exploited Vulnerabilities (KEV) feed
  - GitHub Security Advisory Database
  - ExploitDB
  - Vulners
  - Rapid7 VulnDB
  - Metasploit Framework module search
  - Crawl4AI-powered deep web crawling for detail pages
"""

import re
import time
import logging
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger("CyberAgent.ThreatIntelFetcher")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "application/json, text/html, */*",
}

_HTTP_TIMEOUT = 12.0


@dataclass
class ThreatIntelResult:
    source: str
    id: str
    title: str
    description: str
    severity: str
    cvss_score: Optional[float]
    url: str
    published: str
    tags: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "url": self.url,
            "published": self.published,
            "tags": self.tags,
            "extra": self.extra,
        }

    def to_context_string(self) -> str:
        score_str = f" (CVSS {self.cvss_score})" if self.cvss_score else ""
        return (
            f"[{self.source}] {self.id} -- {self.severity}{score_str}\n"
            f"  Title: {self.title}\n"
            f"  {self.description[:300]}\n"
            f"  URL: {self.url}\n"
            f"  Published: {self.published}"
        )


def _cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


class ThreatIntelFetcher:
    """Parallel multi-source threat intelligence aggregator."""

    def __init__(self):
        self._cisa_kev_cache: Optional[List[Dict]] = None
        self._cisa_kev_ts: float = 0.0
        self._cisa_cache_ttl: float = 3600.0

    def search_all(self, query: str, max_per_source: int = 5) -> List[ThreatIntelResult]:
        """Fan-out parallel search across all 8 threat intelligence databases."""
        sources = [
            ("NVD",         self.fetch_nvd),
            ("CISA_KEV",    self.fetch_cisa_kev),
            ("GitHub_Adv",  self.fetch_github_advisories),
            ("ExploitDB",   self.fetch_exploitdb),
            ("Vulners",     self.fetch_vulners),
            ("Rapid7",      self.fetch_rapid7),
            ("Metasploit",  self.fetch_metasploit),
        ]
        all_results: List[ThreatIntelResult] = []
        with ThreadPoolExecutor(max_workers=7) as executor:
            future_map = {executor.submit(fn, query, max_per_source): name for name, fn in sources}
            for future in as_completed(future_map, timeout=20):
                src_name = future_map[future]
                try:
                    results = future.result()
                    all_results.extend(results)
                    logger.info(f"[ThreatIntel] {src_name}: {len(results)} result(s)")
                except Exception as exc:
                    logger.warning(f"[ThreatIntel] {src_name} failed: {exc}")

        seen_ids: set = set()
        deduped: List[ThreatIntelResult] = []
        for r in all_results:
            key = r.id.upper()
            if key not in seen_ids:
                seen_ids.add(key)
                deduped.append(r)

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        deduped.sort(key=lambda r: severity_order.get(r.severity, 4))
        return deduped

    def build_context_block(self, results: List[ThreatIntelResult]) -> str:
        if not results:
            return "No threat intelligence records found in external databases."
        lines = [
            f"=== THREAT INTELLIGENCE DATABASE RESULTS ({len(results)} entries) ===",
            "Sources queried: NVD, CISA KEV, GitHub Advisory, ExploitDB, Vulners, Rapid7, Metasploit\n",
        ]
        for r in results:
            lines.append(r.to_context_string())
            lines.append("")
        return "\n".join(lines)

    # SOURCE 1: NVD
    def fetch_nvd(self, query: str, max_results: int = 5) -> List[ThreatIntelResult]:
        results: List[ThreatIntelResult] = []
        try:
            is_cve = bool(re.match(r"CVE-\d{4}-\d+", query, re.IGNORECASE))
            if is_cve:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={query.upper()}"
            else:
                kw = urllib.parse.quote(query)
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={kw}&resultsPerPage={max_results}"
            with httpx.Client(timeout=_HTTP_TIMEOUT, headers=_HEADERS) as client:
                resp = client.get(url)
                if resp.status_code != 200:
                    return results
                data = resp.json()
            for item in data.get("vulnerabilities", [])[:max_results]:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "UNKNOWN")
                desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                cvss_score = None
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    arr = cve.get("metrics", {}).get(key, [])
                    if arr:
                        cvss_score = arr[0].get("cvssData", {}).get("baseScore")
                        break
                results.append(ThreatIntelResult(
                    source="NVD", id=cve_id, title=cve_id, description=desc,
                    severity=_cvss_to_severity(cvss_score), cvss_score=cvss_score,
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    published=cve.get("published", "")[:10],
                    tags=[r.get("type","") for r in cve.get("references",[])[:4]],
                ))
        except Exception as e:
            logger.warning(f"NVD fetch error: {e}")
        return results

    # SOURCE 2: CISA KEV
    def fetch_cisa_kev(self, query: str, max_results: int = 5) -> List[ThreatIntelResult]:
        results: List[ThreatIntelResult] = []
        try:
            feed = self._get_cisa_kev_feed()
            q_lower = query.lower()
            matched = [v for v in feed if
                q_lower in v.get("cveID","").lower() or
                q_lower in v.get("vulnerabilityName","").lower() or
                q_lower in v.get("product","").lower() or
                q_lower in v.get("vendorProject","").lower() or
                q_lower in v.get("shortDescription","").lower()]
            for v in matched[:max_results]:
                cve_id = v.get("cveID","UNKNOWN")
                results.append(ThreatIntelResult(
                    source="CISA_KEV", id=cve_id,
                    title=v.get("vulnerabilityName", cve_id),
                    description=v.get("shortDescription",""),
                    severity="HIGH", cvss_score=None,
                    url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    published=v.get("dateAdded",""),
                    tags=["actively-exploited", v.get("vendorProject",""), v.get("product","")],
                    extra={"required_action": v.get("requiredAction",""), "due_date": v.get("dueDate",""), "ransomware": v.get("knownRansomwareCampaignUse","")},
                ))
        except Exception as e:
            logger.warning(f"CISA KEV fetch error: {e}")
        return results

    def _get_cisa_kev_feed(self) -> List[Dict]:
        now = time.time()
        if self._cisa_kev_cache and (now - self._cisa_kev_ts) < self._cisa_cache_ttl:
            return self._cisa_kev_cache
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        with httpx.Client(timeout=15.0, headers=_HEADERS) as client:
            resp = client.get(url)
            resp.raise_for_status()
            data = resp.json()
        self._cisa_kev_cache = data.get("vulnerabilities", [])
        self._cisa_kev_ts = now
        return self._cisa_kev_cache

    # SOURCE 3: GitHub Advisory
    def fetch_github_advisories(self, query: str, max_results: int = 5) -> List[ThreatIntelResult]:
        results: List[ThreatIntelResult] = []
        try:
            kw = urllib.parse.quote(query)
            url = f"https://api.github.com/advisories?query={kw}&per_page={max_results}"
            headers = {**_HEADERS, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
            with httpx.Client(timeout=_HTTP_TIMEOUT, headers=headers) as client:
                resp = client.get(url)
                if resp.status_code != 200:
                    return results
                items = resp.json()
            for item in (items if isinstance(items, list) else [])[:max_results]:
                ghsa_id = item.get("ghsa_id","UNKNOWN")
                cve_id = item.get("cve_id") or ghsa_id
                cvss_score = (item.get("cvss") or {}).get("score")
                results.append(ThreatIntelResult(
                    source="GitHub_Advisory", id=cve_id,
                    title=item.get("summary", ghsa_id),
                    description=item.get("description",""),
                    severity=(item.get("severity") or "UNKNOWN").upper(),
                    cvss_score=cvss_score,
                    url=item.get("html_url", f"https://github.com/advisories/{ghsa_id}"),
                    published=item.get("published_at","")[:10],
                    tags=[v.get("package",{}).get("name","") for v in item.get("vulnerabilities",[])[:4]],
                    extra={"ghsa_id": ghsa_id},
                ))
        except Exception as e:
            logger.warning(f"GitHub Advisory fetch error: {e}")
        return results

    # SOURCE 4: ExploitDB
    def fetch_exploitdb(self, query: str, max_results: int = 5) -> List[ThreatIntelResult]:
        results: List[ThreatIntelResult] = []
        try:
            is_cve = bool(re.match(r"CVE-\d{4}-\d+", query, re.IGNORECASE))
            if is_cve:
                url = f"https://www.exploit-db.com/search?cve={urllib.parse.quote(query)}&draw=1&start=0&length={max_results}&_=1"
            else:
                url = f"https://www.exploit-db.com/search?q={urllib.parse.quote(query)}&draw=1&start=0&length={max_results}&_=1"
            headers = {**_HEADERS, "X-Requested-With": "XMLHttpRequest", "Referer": "https://www.exploit-db.com/"}
            with httpx.Client(timeout=_HTTP_TIMEOUT, headers=headers, follow_redirects=True) as client:
                resp = client.get(url)
                if resp.status_code != 200:
                    return results
                data = resp.json()
            for row in data.get("data",[])[:max_results]:
                edb_id = str(row.get("id",""))
                title_raw = row.get("description","") or row.get("codes","")
                title = title_raw if isinstance(title_raw, str) else str(title_raw)
                results.append(ThreatIntelResult(
                    source="ExploitDB", id=f"EDB-{edb_id}", title=title,
                    description=f"Platform: {row.get('platform','')} | Type: {row.get('type','')}",
                    severity="HIGH", cvss_score=None,
                    url=f"https://www.exploit-db.com/exploits/{edb_id}",
                    published=str(row.get("date_published","")),
                    tags=[row.get("type",""), row.get("platform","")],
                    extra={"verified": row.get("verified", False), "cve": row.get("codes","")},
                ))
        except Exception as e:
            logger.warning(f"ExploitDB fetch error: {e}")
        return results

    # SOURCE 5: Vulners
    def fetch_vulners(self, query: str, max_results: int = 5) -> List[ThreatIntelResult]:
        results: List[ThreatIntelResult] = []
        try:
            payload = {"query": query, "size": max_results, "fields": ["id","title","description","cvss","published","type","href"]}
            with httpx.Client(timeout=_HTTP_TIMEOUT, headers=_HEADERS) as client:
                resp = client.post("https://vulners.com/api/v3/search/lucene/", json=payload)
                if resp.status_code != 200:
                    return results
                data = resp.json()
            for item in data.get("data",{}).get("search",[])[:max_results]:
                src = item.get("_source",{})
                cvss_score = (src.get("cvss") or {}).get("score")
                results.append(ThreatIntelResult(
                    source="Vulners", id=src.get("id","UNKNOWN"),
                    title=src.get("title",""), description=src.get("description","")[:400],
                    severity=_cvss_to_severity(cvss_score), cvss_score=cvss_score,
                    url=src.get("href", f"https://vulners.com/{src.get('type','')}/{src.get('id','')}"),
                    published=str(src.get("published",""))[:10],
                    tags=[src.get("type","")],
                ))
        except Exception as e:
            logger.warning(f"Vulners fetch error: {e}")
        return results

    # SOURCE 6: Rapid7
    def fetch_rapid7(self, query: str, max_results: int = 5) -> List[ThreatIntelResult]:
        results: List[ThreatIntelResult] = []
        try:
            kw = urllib.parse.quote(query)
            url = f"https://www.rapid7.com/db/?q={kw}&type=nexpose"
            with httpx.Client(timeout=_HTTP_TIMEOUT, headers=_HEADERS, follow_redirects=True) as client:
                resp = client.get(url)
                if resp.status_code != 200:
                    return results
                soup = BeautifulSoup(resp.text, "html.parser")
            cards = soup.select("a.vulndb__item") or soup.select("div.vulndb__item")
            for card in cards[:max_results]:
                title_el = card.select_one("h3,h2,.vulndb__item-title")
                title = title_el.get_text(strip=True) if title_el else "Unknown"
                href = card.get("href","")
                if href and not href.startswith("http"):
                    href = "https://www.rapid7.com" + href
                desc_el = card.select_one("p,.vulndb__item-description")
                desc = desc_el.get_text(strip=True) if desc_el else ""
                badge_el = card.select_one(".severity,.badge")
                sev_text = badge_el.get_text(strip=True).upper() if badge_el else "UNKNOWN"
                sev = sev_text if sev_text in ("CRITICAL","HIGH","MEDIUM","LOW") else "UNKNOWN"
                results.append(ThreatIntelResult(
                    source="Rapid7", id=title.split()[0] if title else "UNKNOWN",
                    title=title, description=desc, severity=sev, cvss_score=None,
                    url=href or f"https://www.rapid7.com/db/?q={kw}",
                    published="", tags=["rapid7","nexpose"],
                ))
        except Exception as e:
            logger.warning(f"Rapid7 fetch error: {e}")
        return results

    # SOURCE 7: Metasploit (via GitHub code search)
    def fetch_metasploit(self, query: str, max_results: int = 5) -> List[ThreatIntelResult]:
        results: List[ThreatIntelResult] = []
        try:
            kw = urllib.parse.quote(query)
            url = (f"https://api.github.com/search/code"
                   f"?q={kw}+repo:rapid7/metasploit-framework+language:Ruby+path:modules"
                   f"&per_page={max_results}")
            headers = {**_HEADERS, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
            with httpx.Client(timeout=_HTTP_TIMEOUT, headers=headers) as client:
                resp = client.get(url)
                if resp.status_code != 200:
                    return results
                data = resp.json()
            for item in data.get("items",[])[:max_results]:
                module_path = item.get("path","")
                file_name = item.get("name","unknown.rb")
                tag = "exploit" if "/exploits/" in module_path else "auxiliary" if "/auxiliary/" in module_path else "post" if "/post/" in module_path else "module"
                results.append(ThreatIntelResult(
                    source="Metasploit", id=f"MSF:{file_name.replace('.rb','')}",
                    title=f"Metasploit {tag.capitalize()}: {file_name}",
                    description=f"Module path: {module_path}",
                    severity="HIGH", cvss_score=None,
                    url=item.get("html_url",""),
                    published="", tags=[tag,"metasploit"],
                ))
        except Exception as e:
            logger.warning(f"Metasploit search error: {e}")
        return results

    # SOURCE 8: Crawl4AI deep page extractor
    def crawl_detail_page(self, url: str, max_chars: int = 3000) -> str:
        """Deep-crawl a vulnerability detail page (crawl4ai if available, else httpx fallback)."""
        try:
            import importlib
            if importlib.util.find_spec("crawl4ai"):
                import asyncio
                from crawl4ai import AsyncWebCrawler
                async def _crawl():
                    async with AsyncWebCrawler(verbose=False) as crawler:
                        result = await crawler.arun(url=url)
                        return result.markdown or result.cleaned_html or ""
                try:
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor(1) as pool:
                        fut = pool.submit(asyncio.run, _crawl())
                        return fut.result(timeout=15)[:max_chars]
                except Exception as e:
                    logger.debug(f"crawl4ai failed for {url}: {e}")
        except Exception:
            pass
        try:
            with httpx.Client(timeout=_HTTP_TIMEOUT, headers=_HEADERS, follow_redirects=True) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    for tag in soup(["script","style","nav","footer","header","noscript"]):
                        tag.decompose()
                    return " ".join(soup.get_text(separator=" ").split())[:max_chars]
        except Exception as e:
            logger.warning(f"Crawl fallback failed for {url}: {e}")
        return ""


# Singleton
threat_intel_fetcher = ThreatIntelFetcher()
