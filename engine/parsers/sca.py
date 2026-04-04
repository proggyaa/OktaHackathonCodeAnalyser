"""
sca.py
======
Software Composition Analysis parser for dependency files.

Author  : Staff Compiler Engineer / Technical VC Due Diligence Expert
Python  : 3.10+
Dependencies: json, re, pathlib
"""

from __future__ import annotations

import json
import re
from pathlib import Path


class SCAParser:
    """
    Software Composition Analysis parser.

    Extracts dependency names and pinned versions from:
    * ``requirements.txt``  – one package per line, supports ``==``, ``>=``, etc.
    * ``package.json``      – parses ``dependencies`` and ``devDependencies``.

    Results are stored in a shared ``dependency_map`` dict.
    """

    _REQ_LINE_RE = re.compile(
        r"""^\s*([\w.\-]+)\s*(?:[><=!~^]+\s*([\w.*]+))?"""
    )

    def __init__(self, filepath: str, code: str, dependency_map: dict[str, str]) -> None:
        self.filepath = filepath
        self.code = code
        self.dependency_map = dependency_map

    def parse(self) -> None:
        """Populate ``dependency_map`` in-place."""
        fname = Path(self.filepath).name.lower()

        if fname == "requirements.txt":
            for line in self.code.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = self._REQ_LINE_RE.match(line)
                if m:
                    pkg, version = m.group(1), m.group(2) or "unpinned"
                    self.dependency_map[pkg] = version

        elif fname == "package.json":
            try:
                data = json.loads(self.code)
                for section in ("dependencies", "devDependencies", "peerDependencies"):
                    for pkg, version in data.get(section, {}).items():
                        self.dependency_map[pkg] = version
            except json.JSONDecodeError:
                pass  # malformed package.json – skip silently
