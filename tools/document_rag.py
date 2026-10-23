"""
Offline Local Document Indexing and RAG (Retrieval-Augmented Generation) Engine.
Indexes PDF, TXT, Markdown, JSON, Code (Python, C, Rust), and Log files.
Performs Dual-Engine Hybrid Search (Okapi BM25 + Dense Semantic Embeddings) 100% offline.
"""

import os
import re
import json
import math
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from core.config import DOCUMENTS_DIR
from tools.hybrid_search import hybrid_search_engine, get_embedding

logger = logging.getLogger("CyberAgent.DocumentRAG")


class DocumentChunk:
    def __init__(
        self,
        doc_id: str,
        filename: str,
        chunk_index: int,
        text: str,
        embedding: Optional[List[float]] = None,
        tokens: Optional[List[str]] = None,
    ):
        self.doc_id = doc_id
        self.filename = filename
        self.chunk_index = chunk_index
        self.text = text
        self.tokens = tokens or hybrid_search_engine.tokenize(text)
        self.embedding = embedding or get_embedding(text)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "filename": self.filename,
            "chunk_index": self.chunk_index,
            "text": self.text,
            "tokens": self.tokens,
            "embedding": self.embedding,
        }


class DocumentRAGEngine:
    """Fast, 100% offline document indexer and dual-engine hybrid search retriever."""

    def __init__(self, storage_dir: Path = DOCUMENTS_DIR):
        self.storage_dir = storage_dir
        self.index_file = storage_dir / "index.json"
        self.chunks: List[DocumentChunk] = []
        self.doc_freq: Dict[str, int] = {}
        self.total_docs = 0
        self.avg_doc_len = 0.0
        self.load_index()

    def _tokenize(self, text: str) -> List[str]:
        """Simple tokenizer that preserves code symbols, CVEs, and technical terms."""
        return hybrid_search_engine.tokenize(text)

    def add_document(self, filename: str, content: str) -> int:
        """Ingest a text/code/markdown document, chunk it, generate embeddings, and add to index."""
        # Clean text
        content = content.replace("\r\n", "\n")
        doc_id = f"doc_{len(self.chunks)}_{filename}"

        # Chunk text into ~350-token blocks with 60-token overlap
        words = content.split()
        chunk_size = 350
        overlap = 60
        new_chunks = []

        if len(words) <= chunk_size:
            chunk = DocumentChunk(doc_id, filename, 0, content)
            new_chunks.append(chunk)
        else:
            idx = 0
            for i in range(0, len(words), chunk_size - overlap):
                chunk_words = words[i : i + chunk_size]
                chunk_text = " ".join(chunk_words)
                if len(chunk_text.strip()) > 30:
                    chunk = DocumentChunk(doc_id, filename, idx, chunk_text)
                    new_chunks.append(chunk)
                    idx += 1

        self.chunks.extend(new_chunks)
        self._rebuild_stats()
        self.save_index()
        logger.info(f"Ingested '{filename}': {len(new_chunks)} chunks created with dense embeddings.")
        return len(new_chunks)

    def _rebuild_stats(self):
        """Recompute BM25 term frequencies and document frequencies."""
        self.total_docs = len(self.chunks)
        if self.total_docs == 0:
            return

        self.doc_freq = {}
        total_len = 0
        for chunk in self.chunks:
            tokens = set(chunk.tokens or self._tokenize(chunk.text))
            total_len += len(tokens)
            for t in tokens:
                self.doc_freq[t] = self.doc_freq.get(t, 0) + 1

        self.avg_doc_len = total_len / self.total_docs

    def search(
        self,
        query: str,
        top_k: int = 4,
        mode: str = "hybrid",
        alpha: float = 0.5,
    ) -> List[Dict[str, Any]]:
        """
        Dual-Engine Hybrid search (BM25 Keyword + Semantic Embeddings) across all indexed chunks.
        mode: 'hybrid' | 'bm25' | 'semantic'
        alpha: Weight for BM25 (1.0 = pure BM25, 0.0 = pure semantic, 0.5 = balanced hybrid)
        """
        if not self.chunks:
            return []

        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []

        query_embedding = get_embedding(query)

        # 1. Compute Okapi BM25 scores
        bm25_scores = hybrid_search_engine.compute_bm25_scores(
            query_tokens=query_tokens,
            docs=self.chunks,
            doc_tokens_key="tokens",
            doc_freq=self.doc_freq,
            avg_doc_len=self.avg_doc_len,
        )

        # 2. Compute Dense Semantic scores
        semantic_scores = hybrid_search_engine.compute_semantic_scores(
            query_embedding=query_embedding,
            docs=self.chunks,
            doc_embedding_key="embedding",
        )

        # Mode configuration
        if mode == "bm25":
            effective_alpha = 1.0
        elif mode == "semantic":
            effective_alpha = 0.0
        else:
            effective_alpha = alpha

        # 3. Fuse scores via Reciprocal Rank Fusion
        fused = hybrid_search_engine.hybrid_fuse(
            bm25_scores=bm25_scores,
            semantic_scores=semantic_scores,
            alpha=effective_alpha,
            method="rrf",
        )

        results = []
        for i, chunk in enumerate(self.chunks):
            score_info = fused[i]
            if score_info["hybrid_score"] > 0.001 or score_info["bm25_score"] > 0.0 or score_info["semantic_score"] > 0.05:
                results.append({
                    "filename": chunk.filename,
                    "chunk_index": chunk.chunk_index,
                    "text": chunk.text,
                    "score": round(score_info["hybrid_score"], 3),
                    "bm25_score": score_info["bm25_score"],
                    "semantic_score": score_info["semantic_score"],
                    "mode": mode,
                })

        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:top_k]

    def search_hybrid(
        self,
        query: str,
        top_k: int = 4,
        mode: str = "hybrid",
        alpha: float = 0.5,
    ) -> List[Dict[str, Any]]:
        """Explicit alias for hybrid document retrieval."""
        return self.search(query=query, top_k=top_k, mode=mode, alpha=alpha)

    def list_documents(self) -> List[Dict[str, Any]]:
        """List summary of all indexed files."""
        docs = {}
        for c in self.chunks:
            if c.filename not in docs:
                docs[c.filename] = {"filename": c.filename, "chunks": 0, "preview": c.text[:120]}
            docs[c.filename]["chunks"] += 1
        return list(docs.values())

    def save_index(self):
        """Save chunk index to disk."""
        try:
            data = [c.to_dict() for c in self.chunks]
            with open(self.index_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save index: {e}")

    def load_index(self):
        """Load index from disk if present."""
        if self.index_file.exists():
            try:
                with open(self.index_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.chunks = []
                    for item in data:
                        chunk = DocumentChunk(
                            doc_id=item.get("doc_id", ""),
                            filename=item.get("filename", ""),
                            chunk_index=item.get("chunk_index", 0),
                            text=item.get("text", ""),
                            embedding=item.get("embedding"),
                            tokens=item.get("tokens"),
                        )
                        self.chunks.append(chunk)
                    self._rebuild_stats()
                    logger.info(f"Loaded {len(self.chunks)} chunks from {self.index_file}")
            except Exception as e:
                logger.error(f"Failed to load index: {e}")


# Singleton document RAG instance
document_rag = DocumentRAGEngine()

