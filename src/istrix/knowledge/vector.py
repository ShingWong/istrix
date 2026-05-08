"""Vector-based CVE semantic search using pgvector + embedding models.

Enhances the remediation engine by finding semantically similar CVEs
when exact pattern matching fails. Two-layer architecture:

  1. In-memory cache of known CVE embeddings (fast, no DB required)
  2. PostgreSQL pgvector storage for cross-scan intelligence (optional)

Embedding model: text-embedding-3-small (1536d) via OpenRouter/OpenAI.
Falls back gracefully when no AI API key is configured.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import yaml

VULNDB_PATH = Path(__file__).parent.parent.parent.parent / "config" / "vulndb.yaml"

_HTTP_AVAILABLE = False
_USER_AGENT = "istrix/0.1.0 (https://github.com/ShingWong/istrix)"
try:
    import urllib.request
    import urllib.error
    _HTTP_AVAILABLE = True
except ImportError:
    pass


@dataclass
class CveEntry:
    """A single CVE knowledge-base entry with its embedding."""
    cve_id: str
    title: str = ""
    cvss: str = "N/A"
    summary: str = ""
    exploit_narrative: str = ""
    commands: list[str] = field(default_factory=list)
    embedding: list[float] | None = None


class VectorSearch:
    """Vector-based CVE similarity search engine.

    Builds an in-memory index of known CVEs from vulndb.yaml and the
    internal CVE_KB. When exact regex/product matching fails, uses
    cosine similarity to find the closest known CVE and its remediation.

    Usage:
        vs = VectorSearch()
        best, score = vs.find_closest("OpenSSH before 9.8 has RCE...")
        if score > 0.7:
            print(best.commands)
    """

    def __init__(
        self,
        api_key: str | None = None,
        api_base: str | None = None,
        embedding_model: str = "openai/text-embedding-3-small",
    ):
        self._api_key = api_key or os.getenv("STRIX_AI_API_KEY")
        self._api_base = api_base or os.getenv(
            "STRIX_AI_API_BASE", "https://openrouter.ai/api/v1"
        )
        self._embedding_model = embedding_model
        self._entries: list[CveEntry] = []
        self._matrix: np.ndarray | None = None
        self._built = False
        self._db_session = None

    # ── Index building ──────────────────────────────────────────────

    def build_index(self, extra_entries: dict[str, dict] | None = None) -> int:
        """Build the in-memory vector index from knowledge base sources.

        Load order:
          1. pgvector cache (if DB has current vulndb.yaml version) — zero API cost
          2. vulndb.yaml + API (if stale or no DB) — stores result in pgvector
          3. extra_entries dict passed by caller (e.g. CVE_KB from generator)

        Returns the number of entries indexed.
        """
        entries: list[CveEntry] = []
        seen: set[str] = set()
        vulndb_version = "0"

        # Load vulndb.yaml metadata
        data: dict = {}
        try:
            with open(VULNDB_PATH) as f:
                data = yaml.safe_load(f) or {}
            vulndb_version = str(data.get("metadata", {}).get("last_updated", "0"))
        except (FileNotFoundError, yaml.YAMLError):
            pass

        # ── 1. Try loading cached embeddings from pgvector ──
        if vulndb_version and vulndb_version != "0":
            cached = self._load_cached_embeddings(vulndb_version)
            if cached is not None and len(cached) > 0:
                vectors = []
                for e in cached:
                    if e.embedding:
                        vectors.append(e.embedding)
                        self._entries.append(e)
                        seen.add(e.cve_id)
                if vectors:
                    self._matrix = np.array(vectors, dtype=np.float64)
                    self._built = True
                    # Merge extra entries that may not be in DB
                    self._merge_extra(extra_entries, seen)
                    return len(self._entries)

        # ── 2. Parse vulndb.yaml entries ──
        vulns = data.get("vulnerabilities", {})
        for cve_id, info in vulns.items():
            entry = CveEntry(
                cve_id=cve_id,
                title=info.get("title", ""),
                cvss=str(info.get("cvss", "N/A")),
                summary=info.get("summary", ""),
                exploit_narrative=info.get("exploit_narrative", ""),
                commands=list(info.get("commands", [])),
            )
            entries.append(entry)
            seen.add(cve_id)

        # ── 3. Merge extra entries ──
        entries = self._merge_extra(extra_entries, seen, entries)

        if not entries:
            self._entries = []
            self._matrix = None
            self._built = True
            return 0

        # ── 4. Generate embeddings via API ──
        texts = [self._embed_text(e) for e in entries]
        vectors = self._batch_embed(texts)

        for entry, vec in zip(entries, vectors):
            entry.embedding = vec
            self._entries.append(entry)

        self._matrix = np.array(vectors, dtype=np.float64)
        self._built = True

        # ── 5. Persist to pgvector for next restart ──
        if vulndb_version and vulndb_version != "0":
            self._store_cached_embeddings(entries, vulndb_version)

        return len(self._entries)

    def _merge_extra(
        self,
        extra_entries: dict[str, dict] | None,
        seen: set[str],
        entries: list[CveEntry] | None = None,
    ) -> list[CveEntry]:
        """Merge extra_entries into the entry list."""
        result = list(entries) if entries else list(self._entries)
        if not extra_entries:
            return result
        for cve_id, info in extra_entries.items():
            if cve_id in seen:
                continue
            if isinstance(info, dict):
                entry = CveEntry(
                    cve_id=cve_id,
                    title=info.get("title", str(cve_id)),
                    cvss=str(info.get("cvss", "N/A")),
                    summary=info.get("summary", ""),
                    exploit_narrative=info.get("exploit_narrative", ""),
                    commands=list(info.get("commands", [])),
                )
                result.append(entry)
                seen.add(cve_id)
        return result

    # ── pgvector persistence ─────────────────────────────────────────

    def _load_cached_embeddings(self, version: str) -> list[CveEntry] | None:
        """Load CVE embeddings from pgvector if version matches.

        Returns None if DB unavailable, empty, or stale.
        """
        import asyncio
        try:
            return asyncio.run(self._load_from_db_async(version))
        except Exception:
            return None

    async def _load_from_db_async(self, version: str) -> list[CveEntry] | None:
        """Async: load embeddings where source_version matches."""
        try:
            from istrix.db import AsyncSessionLocal
            from sqlalchemy import text
            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    text(
                        "SELECT cve_id, title, summary, commands, embedding "
                        "FROM cve_embeddings "
                        "ORDER BY cve_id"
                    )
                )
                rows = result.fetchall()
                if not rows:
                    return None
                # Check version match — first row's source_version must match
                ver_check = await session.execute(
                    text(
                        "SELECT source_version FROM cve_embeddings LIMIT 1"
                    )
                )
                stored_ver = ver_check.scalar()
                if stored_ver != version:
                    return None  # stale — will regenerate
                entries = []
                for row in rows:
                    emb = row[4]  # embedding column
                    if emb is None:
                        continue
                    vec = list(emb) if hasattr(emb, '__iter__') else [float(x) for x in str(emb).strip('[]').split(',')]
                    entry = CveEntry(
                        cve_id=row[0],
                        title=row[1] or "",
                        summary=row[2] or "",
                        commands=list(row[3]) if row[3] else [],
                        embedding=vec,
                    )
                    entries.append(entry)
                return entries if entries else None
        except Exception:
            return None

    def _store_cached_embeddings(self, entries: list[CveEntry], version: str):
        """Persist embeddings to pgvector for future restarts."""
        import asyncio
        try:
            asyncio.run(self._store_to_db_async(entries, version))
        except Exception:
            pass

    async def _store_to_db_async(self, entries: list[CveEntry], version: str):
        """Async: store embeddings in cve_embeddings table."""
        try:
            from istrix.db import AsyncSessionLocal
            from istrix.db.models import CveEmbedding
            from sqlalchemy import text
            async with AsyncSessionLocal() as session:
                # Clear old entries
                await session.execute(text("DELETE FROM cve_embeddings"))
                # Insert new
                for e in entries:
                    if e.embedding is None:
                        continue
                    row = CveEmbedding(
                        cve_id=e.cve_id,
                        title=e.title[:512] if e.title else None,
                        summary=e.summary,
                        commands=e.commands,
                        embedding=e.embedding,
                        source_version=version,
                    )
                    session.add(row)
                await session.commit()
        except Exception:
            pass

    # ── Search ──────────────────────────────────────────────────────

    def find_closest(
        self,
        description: str,
        min_score: float = 0.6,
    ) -> tuple[CveEntry | None, float]:
        """Find the closest known CVE to the given description.

        Args:
            description: Text to search (CVE description, finding detail, etc.)
            min_score: Minimum cosine similarity threshold (0.0-1.0).

        Returns:
            Tuple of (best_match, similarity_score) or (None, 0.0).
        """
        if not self._built:
            self.build_index()
        if not self._entries or self._matrix is None:
            return None, 0.0

        query_vec = self._embed_single(self._clean_text(description))
        if query_vec is None:
            return None, 0.0

        query = np.array(query_vec, dtype=np.float64).reshape(1, -1)

        # Cosine similarity: dot product of normalized vectors
        norms = np.linalg.norm(self._matrix, axis=1, keepdims=True)
        query_norm = np.linalg.norm(query)
        if query_norm == 0:
            return None, 0.0

        similarities = np.dot(self._matrix, query.T).flatten() / (norms.flatten() * query_norm + 1e-10)

        best_idx = int(np.argmax(similarities))
        best_score = float(similarities[best_idx])

        if best_score < min_score:
            return None, best_score

        return self._entries[best_idx], best_score

    def find_top_k(
        self, description: str, k: int = 3, min_score: float = 0.5
    ) -> list[tuple[CveEntry, float]]:
        """Find top-k closest CVEs sorted by similarity."""
        if not self._built:
            self.build_index()
        if not self._entries or self._matrix is None:
            return []

        query_vec = self._embed_single(self._clean_text(description))
        if query_vec is None:
            return []

        query = np.array(query_vec, dtype=np.float64).reshape(1, -1)
        norms = np.linalg.norm(self._matrix, axis=1, keepdims=True)
        query_norm = np.linalg.norm(query)
        if query_norm == 0:
            return []

        similarities = np.dot(self._matrix, query.T).flatten() / (norms.flatten() * query_norm + 1e-10)
        top_indices = np.argsort(similarities)[-k:][::-1]

        results: list[tuple[CveEntry, float]] = []
        for idx in top_indices:
            score = float(similarities[idx])
            if score >= min_score:
                results.append((self._entries[int(idx)], score))
        return results

    # ── Database persistence (optional) ─────────────────────────────

    async def store_finding_embedding(self, finding_cve: str, detail: str,
                                       embedding: list[float] | None = None):
        """Store a finding's embedding in PostgreSQL for cross-scan queries."""
        embedding = embedding or self._embed_single(self._clean_text(detail))
        if not embedding:
            return
        # Requires running database — no-op if not connected
        if self._db_session is None:
            try:
                from istrix.db import AsyncSessionLocal
                from sqlalchemy import text
                async with AsyncSessionLocal() as session:
                    await session.execute(
                        text(
                            "UPDATE findings SET embedding = :emb WHERE cve = :cve AND detail = :d"
                        ),
                        {"emb": str(embedding), "cve": finding_cve, "d": detail},
                    )
                    await session.commit()
            except Exception:
                pass

    # ── Embedding generation ────────────────────────────────────────

    def _batch_embed(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for a batch of texts."""
        results: list[list[float]] = []
        for i in range(0, len(texts), 20):
            batch = texts[i : i + 20]
            try:
                batch_results = self._call_embedding_api(batch)
                results.extend(batch_results)
            except Exception:
                # Fallback: zero vectors so the index is consistent
                results.extend([[0.0] * 1536 for _ in batch])
            if i + 20 < len(texts):
                time.sleep(0.25)  # rate limiting
        return results

    def _embed_single(self, text: str) -> list[float] | None:
        """Generate a single embedding."""
        try:
            return self._call_embedding_api([text])[0]
        except Exception:
            return None

    def _call_embedding_api(self, texts: list[str]) -> list[list[float]]:
        """Call OpenAI-compatible embeddings API."""
        if not _HTTP_AVAILABLE or not self._api_key:
            raise RuntimeError("Embedding API not available")
        if not texts:
            return []

        url = f"{self._api_base.rstrip('/')}/embeddings"
        payload = json.dumps({
            "model": self._embedding_model,
            "input": texts,
        }).encode("utf-8")

        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Authorization", f"Bearer {self._api_key}")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", _USER_AGENT)

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body = json.loads(e.read().decode()) if e.fp else {}
            raise RuntimeError(f"Embedding API error: {body.get('error', str(e))}")

        data_list = body.get("data", [])
        data_list.sort(key=lambda d: d.get("index", 0))
        return [d.get("embedding", [0.0] * 1536) for d in data_list]

    def _embed_text(self, entry: CveEntry) -> str:
        """Create the text to embed for a knowledge-base entry."""
        return self._clean_text(f"{entry.title}. {entry.summary}")

    @staticmethod
    def _clean_text(text: str) -> str:
        """Normalize text for embedding."""
        return " ".join(text.replace("\n", " ").split())


# ── Global singleton ────────────────────────────────────────────────

_vector_search: VectorSearch | None = None


def get_vector_search() -> VectorSearch:
    """Get or create the global VectorSearch instance."""
    global _vector_search
    if _vector_search is None:
        _vector_search = VectorSearch()
    return _vector_search


def reset_vector_search():
    """Reset the global vector search instance (useful for tests)."""
    global _vector_search
    _vector_search = None
