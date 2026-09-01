"""Parse tracer output (`TRACE <tag> <hex>` lines) into a golden-vector dict.

The instrumented verifier (harness/trace_lvlN) prints, per verification:

    TRACE E_aux <hex>
    TRACE E_chall <hex>
    TRACE E_chall_after_2resp <hex>     # only when a two-response isogeny ran
    TRACE E_com <hex>
    TRACE chk_chall <hex>
    TRACE sig_chall <hex>
    TRACE verdict <0|1>
    TRACE result <0|1>

A rejected verification stops early: the stages reached before the failing step
appear, later ones do not (this is exactly what makes the tool useful for
localizing where an alternative verifier diverges).
"""

from __future__ import annotations

from .schema import CURVE_STAGES, SCALAR_STAGES

_HEX_STAGES = set(CURVE_STAGES) | set(SCALAR_STAGES)
_INT_STAGES = {"verdict", "result"}


def parse_trace(text: str) -> dict:
    """Parse a block of tracer output into a partial golden-vector dict.

    Only ``TRACE`` lines are read; any other output (warnings, blank lines) is
    ignored. Hex stages are stored as lowercase hex strings; ``verdict`` and
    ``result`` are stored as ints. Stages that never appeared are simply absent.
    """
    vec: dict = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("TRACE"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        tag = parts[1]
        val = parts[2] if len(parts) > 2 else ""
        if tag in _INT_STAGES:
            try:
                vec[tag] = int(val)
            except ValueError:
                continue
        elif tag in _HEX_STAGES:
            vec[tag] = val.lower()
        # unknown tags are ignored on purpose (forward compatibility)
    return vec


def parse_trace_stream(text: str) -> list[dict]:
    """Parse output containing multiple verifications back to back.

    Each verification is delimited by its ``TRACE result`` line (the last line
    the driver prints). Returns one dict per verification, in order.
    """
    vecs: list[dict] = []
    buf: list[str] = []
    for raw in text.splitlines():
        buf.append(raw)
        if raw.strip().startswith("TRACE result"):
            vecs.append(parse_trace("\n".join(buf)))
            buf = []
    if any(l.strip().startswith("TRACE") for l in buf):
        # trailing verification with no result line
        vecs.append(parse_trace("\n".join(buf)))
    return vecs
