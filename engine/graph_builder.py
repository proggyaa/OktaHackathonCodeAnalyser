"""
graph_builder.py
================
Main orchestrator for repository-wide semantic analysis.

Author  : Staff Compiler Engineer / Technical VC Due Diligence Expert
Python  : 3.10+
Dependencies: networkx, datetime, pathlib
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import networkx as nx

from .parsers.python_ast import ASTParser
from .parsers.javascript import JSTSParser
from .parsers.sca import SCAParser


class DeepSemanticGraphBuilder:
    """
    Main orchestrator for repository-wide semantic analysis.

    Pipeline
    --------
    1. **Phase 1** – Dispatch each file to the appropriate parser
       (:class:`ASTParser`, :class:`JSTSParser`, or :class:`SCAParser`).
    2. **Phase 2** – Assemble a directed :class:`networkx.DiGraph` from
       parsed import relationships.
    3. **Phase 3** – Compute VC-grade risk metrics per node and emit a
       ``3d-force-graph``-compatible payload.

    Parameters
    ----------
    None.  Call :meth:`build` with the repository payload.

    Examples
    --------
    >>> builder = DeepSemanticGraphBuilder()
    >>> payload = builder.build(file_records)
    >>> # payload["nodes"] and payload["links"] are ready for 3d-force-graph
    """

    # ── Constants ─────────────────────────────────────────────────────────

    #: Number of days before a file is considered stale (partial staleness starts)
    STALE_PARTIAL_DAYS: int = 180
    #: Number of days before staleness score reaches 1.0
    STALE_MAX_DAYS: int = 730  # ~2 years

    #: Min node visual size
    MIN_NODE_SIZE: float = 2.0

    #: Concurrency density threshold for isAsyncHeavy
    ASYNC_HEAVY_THRESHOLD: int = 5

    def __init__(self) -> None:
        self._graph: nx.DiGraph = nx.DiGraph()
        self._node_data: dict[str, dict[str, Any]] = {}
        self._dependency_map: dict[str, str] = {}
        self._filepaths: list[str] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self, file_records: list[FileRecord]) -> GraphPayload:
        """
        Execute the full analysis pipeline.

        Parameters
        ----------
        file_records : list[FileRecord]
            Each record must contain:
            ``filepath`` (str), ``code_string`` (str),
            ``last_commit_date`` (ISO-8601 str), ``unique_author_count`` (int).

        Returns
        -------
        GraphPayload
            ``{"nodes": [...], "links": [...]}`` ready for ``3d-force-graph``.
        """
        self._graph = nx.DiGraph()
        self._node_data = {}
        self._dependency_map = {}
        self._filepaths = [r["filepath"] for r in file_records]

        # ── Phase 1 : parse all files ──────────────────────────────────
        for record in file_records:
            self._parse_file(record)

        # ── Phase 2 : assemble graph ───────────────────────────────────
        self._assemble_graph()

        # ── Phase 3 : compute metrics ──────────────────────────────────
        return self._emit_payload()

    # ------------------------------------------------------------------
    # Phase 1 – per-file dispatch
    # ------------------------------------------------------------------

    def _parse_file(self, record: FileRecord) -> None:
        """
        Route *record* to the appropriate parser and store intermediate
        analysis results in ``_node_data``.
        """
        filepath: str = record["filepath"]
        code: str = record.get("code_string", "")
        last_commit: str = record.get("last_commit_date", "2000-01-01T00:00:00")
        author_count: int = record.get("unique_author_count", 1)

        ext = Path(filepath).suffix.lower()
        fname = Path(filepath).name.lower()

        # SCA files – side-effect only, still add as a node
        if fname in {"requirements.txt", "package.json"}:
            SCAParser(filepath, code, self._dependency_map).parse()

        # Dispatch to language-specific parser
        parsed: dict[str, Any]
        if ext == ".py":
            parsed = ASTParser(filepath, code).parse()
        elif ext in {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}:
            parsed = JSTSParser(filepath, code).parse()
        else:
            # Unknown extension – still add as node with blank analysis
            parsed = {
                "parse_error": f"unsupported extension: {ext}",
                "imports": [],
                "astComplexity": 0,
                "modulePurpose": "",
                "exportedEntities": [],
                "apiEndpoints": [],
                "databaseModels": [],
                "stateMutations": 0,
                "highEntropySecrets": 0,
                "handlesPII": False,
                "criticalVulnerabilities": [],
                "swallowsExceptions": False,
                "concurrencyDensity": 0,
                "isAsyncHeavy": False,
            }

        # Merge metadata
        parsed["filepath"] = filepath
        parsed["last_commit_date"] = last_commit
        parsed["unique_author_count"] = author_count

        self._node_data[filepath] = parsed
        self._graph.add_node(filepath)

    # ------------------------------------------------------------------
    # Phase 2 – graph assembly
    # ------------------------------------------------------------------

    def _resolve_import(self, source_fp: str, import_path: str) -> str | None:
        """
        Attempt to resolve a raw import string to a known filepath.

        Strategy (priority order):
        1. Exact filepath match.
        2. Stem match (``db`` → ``db.py``).
        3. Relative match within the same directory.
        4. Partial suffix match (``models.user`` → ``models/user.py``).
        """
        # Normalize the import to a path fragment
        frag = import_path.replace(".", "/")
        source_dir = str(Path(source_fp).parent)

        candidates: list[str] = []

        # Stem-based candidates
        for fp in self._filepaths:
            stem = Path(fp).stem
            full_stem = str(Path(fp).with_suffix(""))

            if stem == import_path:
                candidates.append(fp)
            elif full_stem.endswith(frag):
                candidates.append(fp)
            elif fp == import_path:
                candidates.append(fp)

        # Prefer candidates in the same directory
        same_dir = [c for c in candidates if str(Path(c).parent) == source_dir]
        if same_dir:
            return same_dir[0]
        if candidates:
            return candidates[0]
        return None

    def _assemble_graph(self) -> None:
        """Draw directed edges for all resolved import relationships."""
        for filepath, data in self._node_data.items():
            for imp in data.get("imports", []):
                target = self._resolve_import(filepath, imp)
                if target and target != filepath:
                    self._graph.add_edge(filepath, target)

    # ------------------------------------------------------------------
    # Phase 3 – metric computation & payload emission
    # ------------------------------------------------------------------

    @staticmethod
    def _staleness_score(last_commit_iso: str) -> float:
        """
        Map *last_commit_iso* to a [0.0, 1.0] staleness score.

        * 0.0 → committed today
        * 1.0 → not touched for ≥ 2 years
        """
        try:
            commit_dt = datetime.fromisoformat(last_commit_iso.replace("Z", "+00:00"))
            if commit_dt.tzinfo is None:
                commit_dt = commit_dt.replace(tzinfo=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            days_old = max(0, (now - commit_dt).days)
        except (ValueError, TypeError):
            # Unparseable date → treat as maximally stale
            return 1.0

        stale_partial = 180
        stale_max = 730
        if days_old <= stale_partial:
            return 0.0
        if days_old >= stale_max:
            return 1.0
        return (days_old - stale_partial) / (stale_max - stale_partial)

    @staticmethod
    def _test_exists(filepath: str, all_filepaths: list[str]) -> bool:
        """Return True if a matching ``test_<stem>`` or ``<stem>_test`` file exists."""
        stem = Path(filepath).stem
        for fp in all_filepaths:
            other_stem = Path(fp).stem
            if other_stem in {f"test_{stem}", f"{stem}_test", f"tests_{stem}"} or stem in {
                f"test_{other_stem}", f"{other_stem}_test"
            }:
                return True
        return False

    def _build_node_profile(self, filepath: str) -> NodeProfile:
        """
        Compose the full :data:`NodeProfile` for a single file node,
        incorporating graph-level metrics, security signals, and VC metadata.
        """
        data = self._node_data.get(filepath, {})
        in_deg: int = self._graph.in_degree(filepath)   # type: ignore[arg-type]
        out_deg: int = self._graph.out_degree(filepath)  # type: ignore[arg-type]
        complexity: int = data.get("astComplexity", 0)

        # ── Visual size ────────────────────────────────────────────────
        val = max(
            self.MIN_NODE_SIZE,
            (in_deg * 1.5) + (out_deg * 0.5) + (complexity * 0.2),
        )

        # ── Staleness ─────────────────────────────────────────────────
        staleness = self._staleness_score(data.get("last_commit_date", "2000-01-01"))

        # ── Bus factor risk ────────────────────────────────────────────
        author_count: int = data.get("unique_author_count", 1)
        state_mutations: int = data.get("stateMutations", 0)
        bus_factor_risk = (
            author_count == 1
            and complexity > 15
            and state_mutations > 3
        )

        # ── PII / proprietary ─────────────────────────────────────────
        handles_pii: bool = data.get("handlesPII", False)
        is_proprietary = (
            complexity > 10
            and in_deg > 1
            and out_deg < 3
            and not handles_pii
        )

        # ── Test coverage mock ─────────────────────────────────────────
        test_exists = self._test_exists(filepath, self._filepaths)
        test_coverage: float
        if complexity > 5 and not test_exists:
            test_coverage = 0.1
        else:
            test_coverage = 1.0  # Assume covered if test file found

        return {
            # Standard
            "id": filepath,
            "inDegree": in_deg,
            "outDegree": out_deg,
            "val": round(val, 3),
            # Risk & Security
            "astComplexity": complexity,
            "handlesPII": handles_pii,
            "highEntropySecrets": data.get("highEntropySecrets", 0),
            "criticalVulnerabilities": data.get("criticalVulnerabilities", []),
            "testCoverage": test_coverage,
            # VC / Team IP
            "stalenessScore": round(staleness, 4),
            "busFactorRisk": bus_factor_risk,
            "isProprietaryIP": is_proprietary,
            # Domain & Architecture
            "modulePurpose": data.get("modulePurpose", ""),
            "exportedEntities": data.get("exportedEntities", []),
            "apiEndpoints": data.get("apiEndpoints", []),
            "databaseModels": data.get("databaseModels", []),
            "stateMutations": state_mutations,
            "isAsyncHeavy": data.get("isAsyncHeavy", False),
            "swallowsExceptions": data.get("swallowsExceptions", False),
            # Bonus: surface parse errors for debugging
            "_parseError": data.get("parse_error"),
        }

    def _emit_payload(self) -> GraphPayload:
        """
        Assemble and return the final ``3d-force-graph`` payload.

        Returns
        -------
        GraphPayload
            ``{"nodes": [NodeProfile, ...], "links": [{"source": ..., "target": ...}, ...]}``
        """
        nodes: list[NodeProfile] = [
            self._build_node_profile(fp) for fp in self._graph.nodes
        ]

        links: list[dict[str, str]] = [
            {"source": src, "target": tgt}
            for src, tgt in self._graph.edges
        ]

        return {"nodes": nodes, "links": links}

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    @property
    def dependency_map(self) -> dict[str, str]:
        """Return the SCA dependency map populated during the last :meth:`build` call."""
        return dict(self._dependency_map)

    def summary(self) -> dict[str, Any]:
        """
        Return a high-level repository summary after :meth:`build` has been called.

        Useful for a quick VC-style executive report without iterating nodes.
        """
        nodes = [self._build_node_profile(fp) for fp in self._graph.nodes]
        total = len(nodes)
        return {
            "totalFiles": total,
            "totalEdges": self._graph.number_of_edges(),
            "filesWithVulnerabilities": sum(
                1 for n in nodes if n["criticalVulnerabilities"]
            ),
            "highRiskFiles": [
                n["id"]
                for n in nodes
                if n["busFactorRisk"] or n["criticalVulnerabilities"]
            ],
            "proprietaryIPFiles": [n["id"] for n in nodes if n["isProprietaryIP"]],
            "avgStaleness": round(
                sum(n["stalenessScore"] for n in nodes) / max(total, 1), 4
            ),
            "totalDependencies": len(self._dependency_map),
            "avgComplexity": round(
                sum(n["astComplexity"] for n in nodes) / max(total, 1), 2
            ),
        }


# Type aliases
FileRecord = dict[str, Any]          # {filepath, code_string, last_commit_date, unique_author_count}
NodeProfile = dict[str, Any]         # final per-node output dict
GraphPayload = dict[str, list[Any]]  # {"nodes": [...], "links": [...]}


# ---------------------------------------------------------------------------
