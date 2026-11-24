"""Retrieval over the synthetic document corpus (PDR 5, 6.1, 6.3.2).

Default backend is an in-process TF-IDF index so the slice runs offline.
ChromaDB is used when installed and selected via SENTINEL_VECTOR_BACKEND.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

from .config import get_settings
from .data_generation import generate_corpus


class VectorStore:
    def __init__(self, documents: list[dict[str, Any]] | None = None, backend: str | None = None) -> None:
        settings = get_settings()
        self.backend = backend or settings.vector_backend
        self.documents = documents if documents is not None else self._load_documents()
        self._vectorizer = TfidfVectorizer(stop_words="english", sublinear_tf=True)
        texts = [f"{d.get('title','')} {d.get('content','')}" for d in self.documents]
        self._matrix = self._vectorizer.fit_transform(texts) if texts else None
        self._norms = np.asarray(self._matrix.multiply(self._matrix).sum(axis=1)).ravel() if self._matrix is not None else np.array([])
        if self.backend == "chroma":
            self._try_chroma()

    def _load_documents(self) -> list[dict[str, Any]]:
        path = Path(get_settings().corpus_path)
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass
        return generate_corpus()

    def _try_chroma(self) -> None:
        try:
            import chromadb  # type: ignore

            client = chromadb.Client()
            collection = client.get_or_create_collection("sentinelops")
            if collection.count() == 0:
                collection.add(
                    ids=[str(d["id"]) for d in self.documents],
                    documents=[d["content"] for d in self.documents],
                    metadatas=[{"tenant_id": str(d["tenant_id"]), "trust": d["trust"], "source": d["source"]} for d in self.documents],
                )
            self._chroma = collection
        except Exception:
            # Memory index remains usable when the optional backend is absent.
            self.backend = "memory"
            self._chroma = None

    def search(self, query: str, tenant_id: int, top_k: int = 5, defended: bool = True) -> list[dict[str, Any]]:
        """Return the most relevant chunks, tenant-scoped in defended mode."""
        candidates = [d for d in self.documents if (not defended or d.get("tenant_id") == tenant_id)]
        if not candidates or self._matrix is None:
            return []
        q = self._vectorizer.transform([query])
        qnorm = float(np.asarray(q.multiply(q).sum()).ravel()[0])
        if qnorm == 0:
            return []
        scores = []
        for d in candidates:
            idx = self.documents.index(d)
            denom = float(np.sqrt(qnorm * self._norms[idx])) or 1.0
            sim = float((self._matrix[idx] @ q.T).toarray().ravel()[0]) / denom
            scores.append((sim, d))
        scores.sort(key=lambda x: x[0], reverse=True)
        return [d for sim, d in scores[:top_k] if sim > 0.0]
