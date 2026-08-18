"""
Unrestricted Multi-Source Search & Web Intelligence Engine.
Zero API keys required, zero rate-limit blocks, zero content refusal.
Supports DuckDuckGo, Wikipedia, ArXiv, and raw web page scraper.
"""

import re
import urllib.parse
import httpx
import logging
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup

logger = logging.getLogger("CyberAgent.SearchEngine")

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


class SearchResult:
    def __init__(self, title: str, url: str, snippet: str, source: str = "web"):
        self.title = title.strip()
        self.url = url.strip()
        self.snippet = snippet.strip()
        self.source = source

    def to_dict(self) -> Dict[str, str]:
        return {
            "title": self.title,
            "url": self.url,
            "snippet": self.snippet,
            "source": self.source,
        }


class UnrestrictedSearchEngine:
    """Multi-source unrestricted search provider."""

    def __init__(self):
        self.headers = {"User-Agent": USER_AGENT}

    def search(self, query: str, max_results: int = 6) -> List[Dict[str, str]]:
        """Run search across all available sources with automatic fallback."""
        results: List[SearchResult] = []

        # 1. Try DuckDuckGo via DDGS library
        try:
            results.extend(self._search_ddgs(query, max_results))
        except Exception as e:
            logger.warning(f"DDGS search failed: {e}, falling back to HTML scraper")

        # 2. If results are sparse, try DuckDuckGo HTML / Lite
        if len(results) < 3:
            try:
                results.extend(self._search_ddg_html(query, max_results - len(results)))
            except Exception as e:
                logger.warning(f"DDG HTML search failed: {e}")

        # 3. If query mentions Wikipedia or definitions / CVEs, query Wikipedia API
        if len(results) < 3 or any(w in query.lower() for w in ["what is", "cve-", "exploit", "protocol", "architecture", "algorithm"]):
            try:
                wiki_res = self._search_wikipedia(query, max_results=2)
                results.extend(wiki_res)
            except Exception as e:
                logger.warning(f"Wikipedia search failed: {e}")

        # Deduplicate results by URL
        seen = set()
        deduped = []
        for r in results:
            if r.url and r.url not in seen:
                seen.add(r.url)
                deduped.append(r.to_dict())

        return deduped[:max_results]

    def _search_ddgs(self, query: str, max_results: int) -> List[SearchResult]:
        from ddgs import DDGS
        results = []
        with DDGS() as ddgs:
            for item in ddgs.text(query, max_results=max_results):
                title = item.get("title", "")
                url = item.get("href", "")
                snippet = item.get("body", "")
                if title and url:
                    results.append(SearchResult(title=title, url=url, snippet=snippet, source="duckduckgo"))
        return results

    def _search_ddg_html(self, query: str, max_results: int) -> List[SearchResult]:
        url = "https://html.duckduckgo.com/html/"
        data = {"q": query, "b": ""}
        results = []
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            resp = client.post(url, data=data, headers=self.headers)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                links = soup.find_all("div", class_="result__body")
                for link in links[:max_results]:
                    title_elem = link.find("a", class_="result__a")
                    snippet_elem = link.find("a", class_="result__snippet")
                    if title_elem:
                        raw_href = title_elem.get("href", "")
                        # Parse actual target URL from DDG redirect
                        if "uddg=" in raw_href:
                            parsed_url = urllib.parse.unquote(raw_href.split("uddg=")[1].split("&")[0])
                        else:
                            parsed_url = raw_href
                        title = title_elem.get_text()
                        snippet = snippet_elem.get_text() if snippet_elem else ""
                        results.append(SearchResult(title=title, url=parsed_url, snippet=snippet, source="ddg_html"))
        return results

    def _search_wikipedia(self, query: str, max_results: int = 2) -> List[SearchResult]:
        clean_q = re.sub(r"[^a-zA-Z0-9\s]", "", query).strip()
        url = f"https://en.wikipedia.org/w/api.php?action=opensearch&search={urllib.parse.quote(clean_q)}&limit={max_results}&namespace=0&format=json"
        results = []
        with httpx.Client(timeout=8.0) as client:
            res = client.get(url, headers=self.headers)
            if res.status_code == 200:
                data = res.json()
                if len(data) >= 4 and len(data[1]) > 0:
                    titles = data[1]
                    snippets = data[2]
                    urls = data[3]
                    for i in range(len(titles)):
                        results.append(SearchResult(
                            title=titles[i],
                            url=urls[i],
                            snippet=snippets[i] if i < len(snippets) else "",
                            source="wikipedia"
                        ))
        return results

    def scrape_url_content(self, url: str, max_chars: int = 4000) -> str:
        """Fetch and extract clean readable text from any URL."""
        try:
            with httpx.Client(timeout=10.0, follow_redirects=True) as client:
                res = client.get(url, headers=self.headers)
                if res.status_code == 200:
                    soup = BeautifulSoup(res.text, "html.parser")
                    # Remove script and style elements
                    for script in soup(["script", "style", "nav", "footer", "header", "noscript"]):
                        script.decompose()
                    text = soup.get_text(separator=" ")
                    # Clean whitespace
                    clean_text = " ".join(text.split())
                    return clean_text[:max_chars]
        except Exception as e:
            logger.error(f"Failed to scrape {url}: {e}")
            return f"Error scraping {url}: {str(e)}"
        return ""


# Singleton search instance
search_engine = UnrestrictedSearchEngine()
