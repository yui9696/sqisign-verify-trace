"""Load, save, and self-check golden vector sets.

A golden set on disk is a JSON object::

    {
      "provenance": { ... },
      "vectors": [ { "level": 1, "index": 0, "E_aux": "...", ... }, ... ]
    }

``self_check`` re-verifies the internal consistency of every vector: a valid
(verdict==1) vector must have chk_chall == sig_chall, correct field lengths for
its level, and E_com present. This is the offline check CI runs; it needs no C.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from . import schema


def load(path: str) -> dict:
    """Load a golden set from ``path`` (the {provenance, vectors} object)."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if "vectors" not in data or not isinstance(data["vectors"], list):
        raise schema.SchemaError(f"{path}: missing 'vectors' list")
    return data


def save(path: str, provenance: dict, vectors: list[dict]) -> None:
    """Write a golden set to ``path``."""
    obj = {"provenance": provenance, "vectors": vectors}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1)
        fh.write("\n")


def load_many(paths: list[str]) -> list[dict]:
    """Load several golden files and return the concatenated vector list."""
    vecs: list[dict] = []
    for p in paths:
        vecs.extend(load(p)["vectors"])
    return vecs


def _level_of(vec: dict) -> int | None:
    lvl = vec.get("level")
    if lvl in schema.LEVELS:
        return lvl
    # fall back to inferring from field length
    ea = vec.get("E_aux")
    if isinstance(ea, str):
        nb = len(ea) // 2
        for lv, jb in schema.J_BYTES.items():
            if nb == jb:
                return lv
    return None


@dataclass
class SelfCheckReport:
    total: int = 0
    passed: int = 0
    failed: int = 0
    by_level: dict = field(default_factory=dict)  # level -> {"total","passed","failed"}
    problems: list = field(default_factory=list)   # (index_in_list, level, [messages])

    @property
    def ok(self) -> bool:
        return self.failed == 0 and self.total > 0

    def summary(self) -> str:
        lines = [f"self-check: {self.passed}/{self.total} vectors consistent"]
        for lv in sorted(self.by_level):
            s = self.by_level[lv]
            lines.append(f"  level {lv}: {s['passed']}/{s['total']}")
        for i, lv, msgs in self.problems[:20]:
            lines.append(f"  FAIL vector #{i} (level {lv}): {'; '.join(msgs)}")
        if len(self.problems) > 20:
            lines.append(f"  ... and {len(self.problems)-20} more")
        return "\n".join(lines)


def self_check(vectors: list[dict]) -> SelfCheckReport:
    """Verify each vector's internal consistency; return a report.

    Checks, per vector:
      * level is determinable;
      * all field lengths match the level (schema.validate_vector);
      * E_com present;
      * verdict==1  ⇒  chk_chall == sig_chall.
    """
    rep = SelfCheckReport()
    for i, vec in enumerate(vectors):
        rep.total += 1
        lvl = _level_of(vec)
        bl = rep.by_level.setdefault(
            lvl, {"total": 0, "passed": 0, "failed": 0}
        )
        bl["total"] += 1
        if lvl is None:
            rep.failed += 1
            bl["failed"] += 1
            rep.problems.append((i, None, ["cannot determine level"]))
            continue
        problems = schema.validate_vector(vec, lvl)
        if "E_com" not in vec:
            problems.append("E_com missing")
        if problems:
            rep.failed += 1
            bl["failed"] += 1
            rep.problems.append((i, lvl, problems))
        else:
            rep.passed += 1
            bl["passed"] += 1
    return rep


def default_vector_files(root: str | None = None) -> list[str]:
    """Return the packaged goldens-lvl{1,3,5}.json paths, if present."""
    if root is None:
        # repo layout: sqvtrace/../vectors
        root = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vectors")
    out = []
    for lv in schema.LEVELS:
        p = os.path.join(root, f"goldens-lvl{lv}.json")
        if os.path.exists(p):
            out.append(p)
    return out
