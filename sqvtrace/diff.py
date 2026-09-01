"""Interop tool: compare two golden sets and report the FIRST diverging stage.

Given your golden set and another implementation's trace (parsed into the same
vector shape), this pairs vectors by (level, index) and, for each pair, walks the
verification pipeline in order:

    E_aux → E_chall → E_chall_after_2resp → E_com → chk_chall

and reports the first stage whose hex differs. That tells an implementer *where*
their verifier goes wrong — "my E_com differs ⇒ my 2D isogeny is off" — instead
of only "my verdict differs".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .schema import DIFF_STAGES


def _key(vec: dict, fallback_index: int) -> tuple:
    return (vec.get("level"), vec.get("index", fallback_index))


@dataclass
class VectorDivergence:
    key: tuple                    # (level, index)
    stage: str | None             # first diverging stage, or None if identical
    a: str | None = None          # value in set A at that stage
    b: str | None = None          # value in set B at that stage
    note: str = ""                # e.g. "stage present in A only"

    @property
    def diverges(self) -> bool:
        return self.stage is not None or bool(self.note)


@dataclass
class DiffReport:
    compared: int = 0
    identical: int = 0
    divergences: list = field(default_factory=list)   # VectorDivergence
    only_in_a: list = field(default_factory=list)      # keys
    only_in_b: list = field(default_factory=list)      # keys
    first_stage_counts: dict = field(default_factory=dict)

    @property
    def clean(self) -> bool:
        return not self.divergences and not self.only_in_a and not self.only_in_b

    def summary(self) -> str:
        lines = [
            f"diff: compared {self.compared} paired vectors, "
            f"{self.identical} identical, {len(self.divergences)} diverging"
        ]
        if self.only_in_a:
            lines.append(f"  {len(self.only_in_a)} vector(s) only in A")
        if self.only_in_b:
            lines.append(f"  {len(self.only_in_b)} vector(s) only in B")
        if self.first_stage_counts:
            order = {s: i for i, s in enumerate(DIFF_STAGES)}
            for stage in sorted(self.first_stage_counts, key=lambda s: order.get(s, 99)):
                lines.append(
                    f"  first divergence at {stage}: "
                    f"{self.first_stage_counts[stage]} vector(s)"
                )
        for d in self.divergences[:20]:
            if d.stage is not None:
                lines.append(
                    f"  {d.key}: first diverges at {d.stage}\n"
                    f"      A={_short(d.a)}\n      B={_short(d.b)}"
                )
            else:
                lines.append(f"  {d.key}: {d.note}")
        if len(self.divergences) > 20:
            lines.append(f"  ... and {len(self.divergences)-20} more")
        return "\n".join(lines)


def _short(h: str | None) -> str:
    if not h:
        return "<absent>"
    return h if len(h) <= 24 else f"{h[:16]}…{h[-8:]}"


def diff_vector(a: dict, b: dict, key: tuple) -> VectorDivergence:
    """Compare two vectors stage by stage; return the first divergence."""
    for stage in DIFF_STAGES:
        va = a.get(stage)
        vb = b.get(stage)
        if va is None and vb is None:
            continue
        if va is None or vb is None:
            # one side reached this stage and the other did not
            note = (
                f"{stage} present in {'A' if va is not None else 'B'} only "
                f"(the other verifier stopped earlier)"
            )
            return VectorDivergence(key, stage, va, vb, note)
        if va != vb:
            return VectorDivergence(key, stage, va, vb)
    return VectorDivergence(key, None)


def diff_sets(a_vectors: list[dict], b_vectors: list[dict]) -> DiffReport:
    """Pair vectors by (level, index) and diff each pair."""
    rep = DiffReport()
    a_map = {_key(v, i): v for i, v in enumerate(a_vectors)}
    b_map = {_key(v, i): v for i, v in enumerate(b_vectors)}

    for k in a_map:
        if k not in b_map:
            rep.only_in_a.append(k)
    for k in b_map:
        if k not in a_map:
            rep.only_in_b.append(k)

    for k in sorted(set(a_map) & set(b_map), key=lambda x: (x[0] or 0, x[1] or 0)):
        rep.compared += 1
        d = diff_vector(a_map[k], b_map[k], k)
        if d.diverges:
            rep.divergences.append(d)
            if d.stage is not None:
                rep.first_stage_counts[d.stage] = (
                    rep.first_stage_counts.get(d.stage, 0) + 1
                )
        else:
            rep.identical += 1
    return rep
