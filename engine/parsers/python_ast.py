"""
python_ast.py
=============
AST parser for Python source files.

Author  : Staff Compiler Engineer / Technical VC Due Diligence Expert
Python  : 3.10+
Dependencies: ast, re
"""

from __future__ import annotations

import ast
import re
from typing import Any

from ..security import SecurityScanner


class ASTParser:
    """
    Compiler front-end for Python source files.

    Responsibilities
    ----------------
    * Cyclomatic complexity via node-type counting.
    * Import topology extraction.
    * Module docstring, class names, public function names.
    * API route detection with auth-guard flags.
    * ORM / raw SQL model detection.
    * State mutation counting.
    * Exception handling quality (swallowsExceptions).
    * Concurrency density (isAsyncHeavy).
    * Delegates security checks to :class:`SecurityScanner`.
    """

    #: AST node types that each add 1 to cyclomatic complexity
    COMPLEXITY_NODES: tuple[type, ...] = (
        ast.If,
        ast.For,
        ast.While,
        ast.Try,
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.ClassDef,
        ast.ExceptHandler,
        ast.With,
        ast.AsyncWith,
        ast.ListComp,
        ast.DictComp,
        ast.SetComp,
        ast.GeneratorExp,
        ast.IfExp,
    )

    #: Decorator fragments that indicate an HTTP route
    ROUTE_DECORATORS: frozenset[str] = frozenset(
        {"route", "get", "post", "put", "patch", "delete", "head", "options"}
    )

    #: Auth-related decorator fragments
    AUTH_DECORATORS: frozenset[str] = frozenset(
        {"auth", "login_required", "jwt", "bearer", "permission", "require_user"}
    )

    #: ORM base-class names indicating a DB model
    ORM_BASES: frozenset[str] = frozenset({"Model", "Base", "Document", "BaseModel"})

    #: Sink call patterns that constitute a state mutation
    MUTATION_CALLS: frozenset[str] = frozenset(
        {"commit", "save", "flush", "write", "execute", "executemany", "insert", "update", "delete"}
    )

    #: Concurrency-related node identifiers
    CONCURRENCY_NAMES: frozenset[str] = frozenset(
        {"asyncio", "threading", "multiprocessing", "concurrent", "aiohttp", "trio"}
    )

    def __init__(self, filepath: str, code: str) -> None:
        self.filepath = filepath
        self.code = code
        self._tree: ast.Module | None = None
        self._parse_error: str | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_tree(self) -> bool:
        """Parse the source into an AST tree. Return True on success."""
        if self._tree is not None:
            return True
        if self._parse_error is not None:
            return False
        try:
            self._tree = ast.parse(self.code, filename=self.filepath)
            return True
        except SyntaxError as exc:
            self._parse_error = str(exc)
            return False

    @staticmethod
    def _decorator_names(func_node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> list[str]:
        """Return a flat list of lower-cased decorator-related name fragments."""
        names: list[str] = []
        for dec in func_node.decorator_list:
            if isinstance(dec, ast.Name):
                names.append(dec.id.lower())
            elif isinstance(dec, ast.Attribute):
                names.append(dec.attr.lower())
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    names.append(dec.func.id.lower())
                elif isinstance(dec.func, ast.Attribute):
                    names.append(dec.attr.lower())
        return names

    @staticmethod
    def _call_name(call: ast.Call) -> str | None:
        """Extract the method/function name from a Call node."""
        if isinstance(call.func, ast.Name):
            return call.func.id
        if isinstance(call.func, ast.Attribute):
            return call.func.attr
        return None

    # ------------------------------------------------------------------
    # Public parse method
    # ------------------------------------------------------------------

    def parse(self) -> dict[str, Any]:
        """
        Execute the full Phase-1 analysis on the Python file.

        Returns
        -------
        result : dict
            Keyed fields consumed by the graph assembler.
        """
        result: dict[str, Any] = {
            "parse_error": None,
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
            "isAsyncHeavy": False,
            "concurrencyDensity": 0,
        }

        if not self._ensure_tree():
            result["parse_error"] = self._parse_error
            return result

        tree = self._tree  # type: ignore[assignment]

        # ── Complexity ─────────────────────────────────────────────────
        complexity = sum(
            1 for node in ast.walk(tree)
            if isinstance(node, self.COMPLEXITY_NODES)
        )
        result["astComplexity"] = complexity

        # ── Module docstring ───────────────────────────────────────────
        result["modulePurpose"] = ast.get_docstring(tree) or ""

        # ── Imports ────────────────────────────────────────────────────
        imports: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module)
        result["imports"] = imports

        # ── Exported entities, routes, models ─────────────────────────
        exported: list[str] = []
        endpoints: list[str] = []
        db_models: list[str] = []
        state_mutations = 0
        vulnerabilities: list[str] = []
        empty_excepts = 0
        logged_excepts = 0
        concurrency_density = 0

        for node in ast.walk(tree):

            # ── Classes ───────────────────────────────────────────────
            if isinstance(node, ast.ClassDef):
                exported.append(node.name)
                # ORM model detection via base-class names
                for base in node.bases:
                    base_name = None
                    if isinstance(base, ast.Name):
                        base_name = base.id
                    elif isinstance(base, ast.Attribute):
                        base_name = base.attr
                    if base_name and base_name in self.ORM_BASES:
                        db_models.append(node.name)

            # ── Functions ─────────────────────────────────────────────
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not node.name.startswith("_"):
                    exported.append(node.name)

                dec_names = self._decorator_names(node)

                # Route detection
                if any(d in self.ROUTE_DECORATORS for d in dec_names):
                    auth_flag = any(d in self.AUTH_DECORATORS for d in dec_names)
                    # Extract route path from decorator argument
                    route_path = "/"
                    for dec in node.decorator_list:
                        if isinstance(dec, ast.Call) and dec.args:
                            first = dec.args[0]
                            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                                route_path = first.value
                                break
                    # Determine HTTP method
                    method = "ROUTE"
                    for d in dec_names:
                        if d in self.ROUTE_DECORATORS - {"route"}:
                            method = d.upper()
                            break
                    auth_str = "TRUE" if auth_flag else "FALSE"
                    endpoints.append(f"{method} {route_path} [AUTH: {auth_str}]")

                    # Taint analysis on route handlers
                    vulns = SecurityScanner.taint_analysis(node)
                    vulnerabilities.extend(vulns)

                # Async/concurrency density
                if isinstance(node, ast.AsyncFunctionDef):
                    concurrency_density += 1

            # ── Await expressions ─────────────────────────────────────
            elif isinstance(node, ast.Await):
                concurrency_density += 1

            # ── Calls ─────────────────────────────────────────────────
            elif isinstance(node, ast.Call):
                call_name = self._call_name(node)
                if call_name:
                    # State mutations
                    if call_name in self.MUTATION_CALLS:
                        state_mutations += 1
                    # eval / exec as standalone vulnerability
                    if call_name in {"eval", "exec"}:
                        vulnerabilities.append(
                            f"DANGEROUS: bare '{call_name}()' call in {self.filepath}"
                        )

            # ── String SQL heuristic ───────────────────────────────────
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                upper = node.value.upper()
                if "SELECT" in upper or "CREATE TABLE" in upper:
                    # Extract rough table name
                    match = re.search(
                        r"(?:FROM|INTO|TABLE)\s+([`\"]?[\w.]+[`\"]?)", node.value, re.IGNORECASE
                    )
                    table = match.group(1).strip("`\"'") if match else "unknown_table"
                    if table not in db_models:
                        db_models.append(f"SQL:{table}")

            # ── Exception handling quality ─────────────────────────────
            elif isinstance(node, ast.ExceptHandler):
                body = node.body
                is_empty = all(
                    isinstance(stmt, ast.Pass)
                    or (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant))
                    for stmt in body
                )
                has_logging = any(
                    isinstance(stmt, ast.Expr)
                    and isinstance(stmt.value, ast.Call)
                    and (
                        (isinstance(stmt.value.func, ast.Attribute) and stmt.value.func.attr in {"error", "warning", "exception", "critical", "info", "debug"})
                        or (isinstance(stmt.value.func, ast.Name) and stmt.value.func.id in {"print", "logger"})
                    )
                    for stmt in body
                )
                has_reraise = any(isinstance(stmt, ast.Raise) for stmt in body)
                if is_empty:
                    empty_excepts += 1
                elif has_logging or has_reraise:
                    logged_excepts += 1
                else:
                    empty_excepts += 1  # silent handler with no logging also counts

            # ── Global concurrency imports ─────────────────────────────
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in self.CONCURRENCY_NAMES:
                        concurrency_density += 2

            # ── Assignments to globals ─────────────────────────────────
            elif isinstance(node, ast.Assign):
                # Crude global detection: assignments at module level
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        state_mutations += 1  # counts module-level assignments too (conservative)
                        break  # only count once per assignment

        # ── Security scan ─────────────────────────────────────────────
        entropy_count, handles_pii = SecurityScanner.scan_string_literals(tree)

        result.update(
            imports=imports,
            exportedEntities=list(dict.fromkeys(exported)),  # dedup, preserve order
            apiEndpoints=endpoints,
            databaseModels=db_models,
            stateMutations=state_mutations,
            highEntropySecrets=entropy_count,
            handlesPII=handles_pii,
            criticalVulnerabilities=vulnerabilities,
            swallowsExceptions=(empty_excepts > logged_excepts),
            concurrencyDensity=concurrency_density,
            isAsyncHeavy=(concurrency_density >= 5),
        )
        return result
