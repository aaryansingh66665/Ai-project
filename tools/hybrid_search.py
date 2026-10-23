"""
Dual-Engine Hybrid Search (Okapi BM25 + Dense Semantic Embeddings) Engine for CyberAgent X.

Combines:
  1. Okapi BM25 Lexical Keyword Search (exact token matching, CVE-IDs, CPE strings, ports, versions)
  2. Dense Semantic Vector Embeddings (conceptual similarity via Ollama embeddings or fast offline dense subword vectorizer)
  3. Reciprocal Rank Fusion (RRF) & Normalized Score Combination
  4. Domain-specific confidence boosters (Exact CVE match, CISA KEV active exploitation, Exploit-DB weaponization)
"""

import re
import math
import time
import logging
from typing import List, Dict, Any, Optional, Tuple
import httpx

from core.config import OLLAMA_HOST

logger = logging.getLogger("CyberAgent.HybridSearch")

# Default Embedding Models supported in Ollama
OLLAMA_EMBED_MODELS = [
    "nomic-embed-text",
    "all-minilm",
    "bge-m3",
    "mxbai-embed-large",
    "qwen3:4b",
    "deepseek-r1:8b",
]

_TIMEOUT = 10.0


class OfflineDenseVectorizer:
    """
    Zero-dependency, high-speed offline subword dense vectorizer.
    Produces deterministic L2-normalized 256-dimensional semantic embeddings
    based on character n-grams and hashed subword features.
    Provides a 100% offline fallback when Ollama embedding models are offline.
    """

    def __init__(self, dim: int = 256):
        self.dim = dim

    def embed(self, text: str) -> List[float]:
        if not text:
            return [0.0] * self.dim

        vec = [0.0] * self.dim
        clean = text.lower().strip()
        tokens = re.findall(r"[a-zA-Z0-9_\-\.\:\/]+", clean)

        # 1. Word-level hashing
        for token in tokens:
            # Hash token to dimension
            h = hash(token) % self.dim
            vec[h] += 1.5

            # 2. Character 3-gram and 4-gram hashing for morphological capture
            t_len = len(token)
            if t_len >= 3:
                for i in range(t_len - 2):
                    g3 = token[i : i + 3]
                    h3 = hash(g3) % self.dim
                    vec[h3] += 0.8
            if t_len >= 4:
                for i in range(t_len - 3):
                    g4 = token[i : i + 4]
                    h4 = hash(g4) % self.dim
                    vec[h4] += 0.5

        # 3. L2 Normalization
        norm = math.sqrt(sum(x * x for x in vec))
        if norm > 0:
            return [round(x / norm, 6) for x in vec]
        return vec


_ollama_checked = False
_ollama_available = False
_last_check_ts = 0.0


def _is_ollama_available() -> bool:
    global _ollama_checked, _ollama_available, _last_check_ts
    now = time.time()
    if _ollama_checked and (now - _last_check_ts < 30.0):
        return _ollama_available
    try:
        with httpx.Client(timeout=0.3) as client:
            r = client.get(f"{OLLAMA_HOST.rstrip('/')}/api/tags")
            _ollama_available = (r.status_code == 200)
    except Exception:
        _ollama_available = False
    _ollama_checked = True
    _last_check_ts = now
    return _ollama_available


_offline_vectorizer = OfflineDenseVectorizer(dim=256)


def get_embedding(text: str, model_name: Optional[str] = None) -> List[float]:
    """
    Generates a dense embedding vector for the given text.
    First attempts Ollama embeddings API (`/api/embeddings` or `/api/embed`) if Ollama is running.
    Falls back gracefully to high-performance offline dense vectorizer if Ollama is unavailable.
    """
    if not text or not text.strip():
        return _offline_vectorizer.embed("")

    # Try Ollama embeddings if running
    if _is_ollama_available():
        try:
            url = f"{OLLAMA_HOST.rstrip('/')}/api/embeddings"
            target_model = model_name or "nomic-embed-text"
            with httpx.Client(timeout=1.0) as client:
                resp = client.post(url, json={"model": target_model, "prompt": text[:2000]})
                if resp.status_code == 200:
                    data = resp.json()
                    emb = data.get("embedding", [])
                    if emb:
                        norm = math.sqrt(sum(x * x for x in emb))
                        if norm > 0:
                            return [round(x / norm, 6) for x in emb]
                        return emb
        except Exception:
            pass

    # Seamless deterministic offline fallback
    return _offline_vectorizer.embed(text)


def cosine_similarity(v1: List[float], v2: List[float]) -> float:
    """Computes cosine similarity between two vectors (dot product if L2-normalized)."""
    if not v1 or not v2 or len(v1) != len(v2):
        return 0.0
    dot = sum(a * b for a, b in zip(v1, v2))
    return max(0.0, min(1.0, dot))


class HybridSearchEngine:
    """
    Generic Dual-Engine Hybrid Search Engine:
      - Tokenizes text with domain-specific cybersecurity filters (preserving CVEs, CPEs, versions, symbols).
      - Computes Okapi BM25 keyword matching scores.
      - Computes Dense Semantic Cosine Similarity.
      - Combines scores using Reciprocal Rank Fusion (RRF) and Normalized Weighted Fusion.
    """

    def __init__(self, k1: float = 1.5, b: float = 0.75, rrf_k: int = 60):
        self.k1 = k1
        self.b = b
        self.rrf_k = rrf_k

    @staticmethod
    def tokenize(text: str) -> List[str]:
        """Cybersecurity-aware tokenizer preserving CVE-IDs, CPEs, versions, IPs, and symbols."""
        if not text:
            return []
        return re.findall(r"[a-zA-Z0-9_\-\.\:\/]+", text.lower())

    def compute_bm25_scores(
        self,
        query_tokens: List[str],
        docs: List[Dict[str, Any]],
        doc_tokens_key: str = "tokens",
        doc_freq: Optional[Dict[str, int]] = None,
        avg_doc_len: Optional[float] = None,
    ) -> List[float]:
        """
        Calculates Okapi BM25 scores for a list of documents.
        docs: List of document dicts or objects containing token lists.
        """
        N = len(docs)
        if N == 0 or not query_tokens:
            return [0.0] * N

        # Build doc frequencies if not provided
        if doc_freq is None or avg_doc_len is None:
            df = {}
            total_len = 0
            for doc in docs:
                tokens = doc.get(doc_tokens_key, []) if isinstance(doc, dict) else getattr(doc, doc_tokens_key, [])
                tokens_set = set(tokens)
                total_len += len(tokens)
                for t in tokens_set:
                    df[t] = df.get(t, 0) + 1
            doc_freq = df
            avg_doc_len = total_len / N if N > 0 else 1.0

        scores = []
        for doc in docs:
            tokens = doc.get(doc_tokens_key, []) if isinstance(doc, dict) else getattr(doc, doc_tokens_key, [])
            doc_len = len(tokens)
            score = 0.0

            # Count term frequencies in current doc
            tf_dict: Dict[str, int] = {}
            for t in tokens:
                tf_dict[t] = tf_dict.get(t, 0) + 1

            for qt in query_tokens:
                if qt in tf_dict:
                    tf = tf_dict[qt]
                    d_freq = doc_freq.get(qt, 1)
                    # Lucene / Okapi IDF formula
                    idf = math.log(1.0 + (N - d_freq + 0.5) / (d_freq + 0.5))
                    denom = tf + self.k1 * (1.0 - self.b + self.b * (doc_len / max(avg_doc_len, 1.0)))
                    score += idf * (tf * (self.k1 + 1.0)) / max(denom, 0.001)

            scores.append(score)

        return scores

    def compute_semantic_scores(
        self,
        query_embedding: List[float],
        docs: List[Dict[str, Any]],
        doc_embedding_key: str = "embedding",
    ) -> List[float]:
        """Calculates dense cosine similarities for a list of documents against query embedding."""
        scores = []
        for doc in docs:
            emb = doc.get(doc_embedding_key) if isinstance(doc, dict) else getattr(doc, doc_embedding_key, None)
            if emb and len(emb) == len(query_embedding):
                sim = cosine_similarity(query_embedding, emb)
                scores.append(sim)
            else:
                scores.append(0.0)
        return scores

    def hybrid_fuse(
        self,
        bm25_scores: List[float],
        semantic_scores: List[float],
        alpha: float = 0.5,
        method: str = "normalized_weighted",
        domain_boosts: Optional[List[float]] = None,
    ) -> List[Dict[str, float]]:
        """
        Fuses BM25 and Dense Semantic scores.
        alpha: Weight for BM25 (1.0 = pure BM25, 0.0 = pure semantic, 0.5 = balanced hybrid).
        method: 'normalized_weighted' or 'rrf' (Reciprocal Rank Fusion).
        Returns a list of dicts with fused scores:
          [{ 'hybrid_score': float, 'bm25_score': float, 'semantic_score': float }]
        """
        n = len(bm25_scores)
        if n == 0:
            return []

        boosts = domain_boosts or [0.0] * n

        if method == "rrf":
            # Reciprocal Rank Fusion: RRF = alpha / (k + rank_bm25) + (1 - alpha) / (k + rank_sem)
            bm25_ranked = sorted(range(n), key=lambda i: bm25_scores[i], reverse=True)
            sem_ranked = sorted(range(n), key=lambda i: semantic_scores[i], reverse=True)

            bm25_ranks = {doc_idx: rank + 1 for rank, doc_idx in enumerate(bm25_ranked)}
            sem_ranks = {doc_idx: rank + 1 for rank, doc_idx in enumerate(sem_ranked)}

            results = []
            for i in range(n):
                r_bm25 = bm25_ranks[i]
                r_sem = sem_ranks[i]
                rrf_bm25 = alpha / (self.rrf_k + r_bm25) if bm25_scores[i] > 0 else 0.0
                rrf_sem = (1.0 - alpha) / (self.rrf_k + r_sem) if semantic_scores[i] > 0 else 0.0
                hybrid = (rrf_bm25 + rrf_sem) * 100.0 + boosts[i]
                results.append({
                    "hybrid_score": round(hybrid, 4),
                    "bm25_score": round(bm25_scores[i], 3),
                    "semantic_score": round(semantic_scores[i], 4),
                })
            return results

        # Normalized weighted linear combination
        max_bm25 = max(bm25_scores) if bm25_scores else 1.0
        min_bm25 = min(bm25_scores) if bm25_scores else 0.0
        bm25_range = max_bm25 - min_bm25 if (max_bm25 - min_bm25) > 0.001 else 1.0

        results = []
        for i in range(n):
            norm_bm25 = (bm25_scores[i] - min_bm25) / bm25_range if bm25_scores[i] > 0 else 0.0
            sem = semantic_scores[i]
            hybrid = (alpha * norm_bm25 + (1.0 - alpha) * sem) * 10.0 + boosts[i]
            results.append({
                "hybrid_score": round(hybrid, 3),
                "bm25_score": round(bm25_scores[i], 3),
                "semantic_score": round(semantic_scores[i], 4),
            })

        return results


# Global singleton hybrid engine
hybrid_search_engine = HybridSearchEngine()
