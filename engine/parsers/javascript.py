"""
javascript.py
=============
Regex-based parser for JavaScript and TypeScript files.

Author  : Staff Compiler Engineer / Technical VC Due Diligence Expert
Python  : 3.10+
Dependencies: re
"""

from __future__ import annotations

import re
from typing import Any

from ..security import SecurityScanner


class JSTSParser:
    """
    Regex-based compiler front-end for JavaScript and TypeScript files.

    Extracts heuristic complexity, module dependencies, JSDoc comments,
    exported symbols, route declarations, and delegates security scanning
    to :class:`SecurityScanner`.
    """

    # Complexity signal patterns
    _COMPLEXITY_RE = re.compile(
        r"\bif\s*\(|\bfor\s*\(|\bcatch\s*\(|=>\s*\{?|\bfunction\s*\w*\s*\("
    )

    # require() imports: require('...') or require("...")
    _REQUIRE_RE = re.compile(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""")

    # ES6 import: import ... from '...'
    _IMPORT_RE = re.compile(r"""import\s+.+?\s+from\s+['"]([^'"]+)['"]""")

    # Named exports: export function Foo, export class Bar, export const baz
    _EXPORT_RE = re.compile(
        r"""export\s+(?:default\s+)?(?:async\s+)?(?:function\s*\*?\s*|class\s+|const\s+|let\s+|var\s+)(\w+)"""
    )

    # JSDoc block: /** ... */  (non-greedy)
    _JSDOC_RE = re.compile(r"/\*\*(.*?)\*/", re.DOTALL)

    # Express-style routes: app.get('/path', ...) or router.post('/path', ...)
    _ROUTE_RE = re.compile(
        r"""(?:app|router)\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*['"]([^'"]+)['"]""",
        re.IGNORECASE,
    )

    # Auth middleware hints in route chains (simplified)
    _AUTH_HINT_RE = re.compile(r"\b(?:auth|jwt|bearer|verifyToken|isAuthenticated|requireLogin)\b")

    # State mutation patterns
    _MUTATION_RE = re.compile(
        r"""\.(?:save|commit|flush|write|execute|update|delete|insert|create)\s*\("""
    )

    # Concurrency patterns
    _CONCURRENCY_RE = re.compile(
        r"\basync\b|\bawait\b|\bnew\s+Promise\b|\bsetTimeout\b|\bsetInterval\b"
    )

    # Exception handler patterns
    _CATCH_EMPTY_RE = re.compile(r"catch\s*\([^)]*\)\s*\{\s*\}")
    _CATCH_LOGGED_RE = re.compile(
        r"""catch\s*\([^)]*\)\s*\{[^}]*(?:console\.|logger\.|log\(|throw\s)[^}]*\}"""
    )

    def __init__(self, filepath: str, code: str) -> None:
        self.filepath = filepath
        self.code = code

    def parse(self) -> dict[str, Any]:
        """Execute Phase-1 analysis on the JS/TS file."""
        code = self.code

        # ── Complexity ─────────────────────────────────────────────────
        complexity = len(self._COMPLEXITY_RE.findall(code))

        # ── Imports ────────────────────────────────────────────────────
        imports = (
            self._REQUIRE_RE.findall(code) + self._IMPORT_RE.findall(code)
        )
        imports = list(dict.fromkeys(imports))

        # ── Exported entities ─────────────────────────────────────────
        exported = list(dict.fromkeys(self._EXPORT_RE.findall(code)))

        # ── JSDoc → modulePurpose (first block only) ───────────────────
        module_purpose = ""
        jsdoc_matches = self._JSDOC_RE.findall(code)
        if jsdoc_matches:
            # Clean up asterisks and leading/trailing whitespace
            raw = jsdoc_matches[0]
            cleaned = re.sub(r"\n\s*\*\s?", " ", raw).strip()
            module_purpose = cleaned

        # ── Routes ────────────────────────────────────────────────────
        endpoints: list[str] = []
        for match in self._ROUTE_RE.finditer(code):
            method = match.group(1).upper()
            path = match.group(2)
            # Check surrounding ~200 chars for auth hints
            surrounding = code[max(0, match.start() - 50): match.end() + 200]
            auth = bool(self._AUTH_HINT_RE.search(surrounding))
            auth_str = "TRUE" if auth else "FALSE"
            endpoints.append(f"{method} {path} [AUTH: {auth_str}]")

        # ── DB models (heuristic) ──────────────────────────────────────
        db_models: list[str] = []
        sql_re = re.compile(
            r"""(?:SELECT|CREATE\s+TABLE|FROM|INTO)\s+[`'"]?([\w.]+)[`'"]?""",
            re.IGNORECASE,
        )
        for m in sql_re.finditer(code):
            name = m.group(1)
            if name.upper() not in {"FROM", "INTO", "WHERE", "SELECT"}:
                entry = f"SQL:{name}"
                if entry not in db_models:
                    db_models.append(entry)

        # ── State mutations ────────────────────────────────────────────
        state_mutations = len(self._MUTATION_RE.findall(code))

        # ── Exception quality ──────────────────────────────────────────
        empty_excepts = len(self._CATCH_EMPTY_RE.findall(code))
        logged_excepts = len(self._CATCH_LOGGED_RE.findall(code))
        swallows = empty_excepts > logged_excepts

        # ── Concurrency ────────────────────────────────────────────────
        concurrency_density = len(self._CONCURRENCY_RE.findall(code))
        is_async_heavy = concurrency_density >= 5

        # ── Security ──────────────────────────────────────────────────
        entropy_count, handles_pii = SecurityScanner.scan_string_literals_js(code)

        # Eval/exec as explicit vulnerability
        vulnerabilities: list[str] = []
        if re.search(r"\beval\s*\(", code):
            vulnerabilities.append(f"DANGEROUS: bare 'eval()' call in {self.filepath}")
        if re.search(r"\bFunction\s*\(", code):
            vulnerabilities.append(f"DANGEROUS: dynamic 'new Function()' call in {self.filepath}")

        return {
            "parse_error": None,
            "imports": imports,
            "astComplexity": complexity,
            "modulePurpose": module_purpose,
            "exportedEntities": exported,
            "apiEndpoints": endpoints,
            "databaseModels": db_models,
            "stateMutations": state_mutations,
            "highEntropySecrets": entropy_count,
            "handlesPII": handles_pii,
            "criticalVulnerabilities": vulnerabilities,
            "swallowsExceptions": swallows,
            "concurrencyDensity": concurrency_density,
            "isAsyncHeavy": is_async_heavy,
        }
