"""
security.py
===========
Security scanning utilities for VC-grade risk assessment.

Author  : Staff Compiler Engineer / Technical VC Due Diligence Expert
Python  : 3.10+
Dependencies: ast
"""

from __future__ import annotations

import ast
import math
import re
from typing import Any


class SecurityScanner:
    """
    Stateless auditor responsible for three security checks:

    1. **High-Entropy Secret Detection** – Shannon entropy on all string
       literals; strings > 16 chars with entropy > 4.5 bits are flagged.
    2. **Source-to-Sink Taint Tracking** – For route handler functions,
       checks whether user-supplied arguments flow directly into dangerous
       sinks (DB exec, eval, exec, open).
    3. **PII Keyword Matching** – Checks identifiers/string literals for
       password, secret, token, stripe, auth, ssn patterns.
    """

    #: Entropy threshold (bits per character)
    ENTROPY_THRESHOLD: float = 4.5
    #: Minimum string length to be entropy-checked
    MIN_SECRET_LEN: int = 16

    #: PII-related keywords (lower-case)
    PII_KEYWORDS: frozenset[str] = frozenset(
        {"password", "secret", "token", "stripe", "auth", "ssn"}
    )

    #: Dangerous sink call names
    DANGEROUS_SINKS: frozenset[str] = frozenset(
        {"eval", "exec", "open", "execute", "executemany", "raw"}
    )

    #: User-input source argument patterns (common Flask/FastAPI/Django names)
    SOURCE_ARGS: frozenset[str] = frozenset(
        {"request", "req", "payload", "data", "body", "form", "args", "kwargs"}
    )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def shannon_entropy(cls, value: str) -> float:
        """Return the Shannon entropy (bits/char) of *value*."""
        if not value:
            return 0.0
        freq: dict[str, int] = {}
        for ch in value:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(value)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    @classmethod
    def scan_string_literals(
        cls, tree: ast.Module
    ) -> tuple[int, bool]:
        """
        Walk all string constants in *tree*.

        Returns
        -------
        high_entropy_count : int
            Number of strings exceeding entropy threshold.
        handles_pii : bool
            True if any identifier or string contains a PII keyword.
        """
        high_entropy_count = 0
        handles_pii = False

        for node in ast.walk(tree):
            # String literal
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val: str = node.value
                # PII check
                lower = val.lower()
                if any(kw in lower for kw in cls.PII_KEYWORDS):
                    handles_pii = True
                # Entropy check
                if len(val) > cls.MIN_SECRET_LEN:
                    if cls.shannon_entropy(val) > cls.ENTROPY_THRESHOLD:
                        high_entropy_count += 1

            # Identifier names (variable, function, attribute)
            elif isinstance(node, ast.Name):
                lower = node.id.lower()
                if any(kw in lower for kw in cls.PII_KEYWORDS):
                    handles_pii = True
            elif isinstance(node, ast.Attribute):
                lower = node.attr.lower()
                if any(kw in lower for kw in cls.PII_KEYWORDS):
                    handles_pii = True

        return high_entropy_count, handles_pii

    @classmethod
    def scan_string_literals_js(
        cls, code: str
    ) -> tuple[int, bool]:
        """
        Regex-based equivalent of :meth:`scan_string_literals` for JS/TS.

        Returns
        -------
        high_entropy_count : int
        handles_pii : bool
        """
        high_entropy_count = 0
        handles_pii = False

        # Extract all quoted string values
        string_pattern = re.compile(
            r"""(?:["'`])([^"'`\n\\]{16,})(?:["'`])"""
        )
        for match in string_pattern.finditer(code):
            val = match.group(1)
            lower = val.lower()
            if any(kw in lower for kw in cls.PII_KEYWORDS):
                handles_pii = True
            if cls.shannon_entropy(val) > cls.ENTROPY_THRESHOLD:
                high_entropy_count += 1

        # Also check identifier names in code
        ident_lower = code.lower()
        if any(kw in ident_lower for kw in cls.PII_KEYWORDS):
            handles_pii = True

        return high_entropy_count, handles_pii

    @classmethod
    def taint_analysis(
        cls, func_node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> list[str]:
        """
        Perform intra-procedural source-to-sink taint analysis on *func_node*.

        A vulnerability is reported when a source argument name appears as a
        direct argument to a dangerous sink call within the same function body.

        Returns
        -------
        vulnerabilities : list[str]
            Human-readable descriptions of each tainted path found.
        """
        vulnerabilities: list[str] = []

        # Collect source argument names
        source_names: set[str] = set()
        for arg in func_node.args.args:
            if arg.arg.lower() in cls.SOURCE_ARGS:
                source_names.add(arg.arg)
        # Also treat *args / **kwargs
        if func_node.args.vararg:
            source_names.add(func_node.args.vararg.arg)
        if func_node.args.kwarg:
            source_names.add(func_node.args.kwarg.arg)

        if not source_names:
            return vulnerabilities

        # Walk function body for Call nodes
        for node in ast.walk(func_node):
            if not isinstance(node, ast.Call):
                continue

            # Determine sink name
            sink_name: str | None = None
            if isinstance(node.func, ast.Name) and node.func.id in cls.DANGEROUS_SINKS:
                sink_name = node.func.id
            elif isinstance(node.func, ast.Attribute) and node.func.attr in cls.DANGEROUS_SINKS:
                sink_name = node.func.attr

            if sink_name is None:
                continue

            # Check if any argument is a tainted source variable
            all_args = list(node.args) + [kw.value for kw in node.keywords]
            for arg_node in all_args:
                if isinstance(arg_node, ast.Name) and arg_node.id in source_names:
                    vuln = (
                        f"TAINT: user-supplied '{arg_node.id}' flows directly "
                        f"into '{sink_name}()' in function '{func_node.name}'"
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities
