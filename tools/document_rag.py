"""
Offline Local Document Indexing and RAG (Retrieval-Augmented Generation) Engine.
Indexes PDF, TXT, Markdown, JSON, Code (Python, C, Rust), and Log files.
Performs BM25 / TF-IDF semantic keyword retrieval 100% offline.
"""

import os
import re
import json
import math
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from core.config import DOCUMENTS_DIR

logger = logging.getLogger("CyberAgent.DocumentRAG")


class DocumentChunk:
    def __init__(self, doc_id: str, filename: str, chunk_index: int, text: str):
        self.doc_id = doc_id
        self.filename = filename
        self.chunk_index = chunk_index
        self.text = text

    def to_dict(self) -> Dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "filename": self.filename,
            "chunk_index": self.chunk_index,
            "text": self.text,
        }


class DocumentRAGEngine:
    """Fast, 100% offline document indexer and search retriever."""

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
        return re.findall(r"[a-zA-Z0-9_\-\.\:\/]+", text.lower())

    def add_document(self, filename: str, content: str) -> int:
        """Ingest a text/code/markdown document, chunk it, and add to index."""
        # Clean text
        content = content.replace("\r\n", "\n")
        doc_id = f"doc_{len(self.chunks)}_{filename}"

        # Chunk text into ~500-token blocks with 100-token overlap
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
        logger.info(f"Ingested '{filename}': {len(new_chunks)} chunks created.")
        return len(new_chunks)

    def _rebuild_stats(self):
        """Recompute BM25 term frequencies and document frequencies."""
        self.total_docs = len(self.chunks)
        if self.total_docs == 0:
            return

        self.doc_freq = {}
        total_len = 0
        for chunk in self.chunks:
            tokens = set(self._tokenize(chunk.text))
            total_len += len(tokens)
            for t in tokens:
                self.doc_freq[t] = self.doc_freq.get(t, 0) + 1

        self.avg_doc_len = total_len / self.total_docs

    def search(self, query: str, top_k: int = 4) -> List[Dict[str, Any]]:
        """BM25 search across all indexed chunks."""
        if not self.chunks:
            return []

        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []

        k1 = 1.5
        b = 0.75
        scores = []

        for chunk in self.chunks:
            chunk_tokens = self._tokenize(chunk.text)
            doc_len = len(chunk_tokens)
            score = 0.0

            # Count frequencies in current chunk
            tf_dict = {}
            for t in chunk_tokens:
                tf_dict[t] = tf_dict.get(t, 0) + 1

            for qt in query_tokens:
                if qt in tf_dict:
                    tf = tf_dict[qt]
                    df = self.doc_freq.get(qt, 1)
                    # IDF formula
                    idf = math.log(1.0 + (self.total_docs - df + 0.5) / (df + 0.5))
                    # BM25 TF component
                    denom = tf + k1 * (1.0 - b + b * (doc_len / max(self.avg_doc_len, 1.0)))
                    score += idf * (tf * (k1 + 1.0)) / max(denom, 0.001)

            if score > 0:
                scores.append((score, chunk))

        # Sort descending by score
        scores.sort(key=lambda x: x[0], reverse=True)
        results = []
        for s, c in scores[:top_k]:
            results.append({
                "filename": c.filename,
                "chunk_index": c.chunk_index,
                "text": c.text,
                "score": round(s, 3),
            })
        return results

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
                    self.chunks = [DocumentChunk(**item) for item in data]
                    self._rebuild_stats()
                    logger.info(f"Loaded {len(self.chunks)} chunks from {self.index_file}")
            except Exception as e:
                logger.error(f"Failed to load index: {e}")


# Singleton document RAG instance
document_rag = DocumentRAGEngine()
