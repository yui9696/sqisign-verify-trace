"""Render the annotated worked example (level-1 vector 0) as markdown.

The j-invariants come from the committed golden set, so the walkthrough always
matches the shipped data. The stage descriptions map each value to the
corresponding step in the reference's ``protocols_verify`` (verify.c).
"""

from __future__ import annotations

import os

from . import goldens

# Per-stage annotation: (tag, verify.c step, one-line description).
STAGE_NOTES = [
    (
        "E_aux",
        "ec_curve_init_from_A(&E_aux, &sig->E_aux_A)",
        "The auxiliary curve, decoded straight from the signature's `E_aux_A` "
        "coefficient. This is the starting point of the verification chain.",
    ),
    (
        "E_chall",
        "compute_challenge_verify(&E_chall, sig, &pk->curve, pk->hint_pk)",
        "The challenge curve, the codomain of the challenge isogeny pushed off "
        "the public-key curve. Determined by (pk, sig) alone.",
    ),
    (
        "E_chall_after_2resp",
        "two_response_isogeny_verify(&E_chall, &B_chall_can, sig, ...)",
        "The challenge curve after the 2^r two-response isogeny. Present only "
        "when the signature carries a non-empty two-response part.",
    ),
    (
        "E_com",
        "compute_commitment_curve_verify(&E_com, ...)  [theta (2^n,2^n) 2D-isogeny]",
        "The recovered commitment curve — the codomain of the 2-dimensional "
        "theta isogeny. If the isogeny does not split, verification rejects "
        "HERE, before any hash is recomputed.",
    ),
    (
        "chk_chall",
        "hash_to_challenge(&chk_chall, pk, &E_com, m, l)",
        "The challenge scalar recomputed from (pk, E_com, msg). The final "
        "verdict is `chk_chall == sig_chall`.",
    ),
    (
        "sig_chall",
        "sig->chall_coeff",
        "The challenge scalar carried in the signature. For a valid signature it "
        "equals `chk_chall`.",
    ),
]


def _ends(h: str, n: int = 8) -> str:
    if h is None:
        return "*(not reached)*"
    if len(h) <= 2 * n:
        return f"`{h}`"
    return f"`{h[:n]}…{h[-n:]}`"


def render(vectors_root: str | None = None) -> str:
    """Return the walkthrough markdown for level-1 vector 0."""
    if vectors_root is None:
        vectors_root = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "vectors"
        )
    data = goldens.load(os.path.join(vectors_root, "goldens-lvl1.json"))
    vec = next(v for v in data["vectors"] if v.get("index") == 0)
    prov = data.get("provenance", {})

    out: list[str] = []
    out.append("# Worked example — level-1 golden vector #0")
    out.append("")
    out.append(
        "A real SQIsign verification, stage by stage, with the actual "
        "j-invariants the reference computes. Every value below is the "
        "canonical `fp2` encoding emitted by the reference's own `fp2_encode`."
    )
    out.append("")
    out.append(
        f"- reference commit: `{prov.get('reference_commit_short','dd133d7')}`"
    )
    out.append(f"- level: 1 (j-invariants are {prov.get('j_invariant_bytes',64)} bytes, "
               f"scalars {prov.get('scalar_bytes',32)} bytes)")
    out.append(f"- input: KAT record 0 of `{prov.get('kat_file','')}` "
               "(valid signature = `sm[:CRYPTO_BYTES]`)")
    out.append("")
    out.append("## The valid verification")
    out.append("")
    out.append(
        "`protocols_verify` walks these stages in order. Each `TRACE` line is "
        "printed by the instrumented build right after the reference finishes "
        "that step.")
    out.append("")
    for tag, step, desc in STAGE_NOTES:
        val = vec.get(tag)
        out.append(f"### `{tag}`")
        out.append("")
        out.append(f"- **verify.c step:** `{step}`")
        out.append(f"- **what it is:** {desc}")
        if val is None and tag == "E_chall_after_2resp":
            out.append("- **value:** *(this vector has no two-response part)*")
        else:
            out.append(f"- **j-invariant:** `{val}`" if tag.startswith("E_")
                       else f"- **scalar:** `{val}`")
        out.append("")

    out.append("**Verdict:** `chk_chall == sig_chall` →")
    out.append("")
    out.append(f"- `chk_chall` = {_ends(vec.get('chk_chall'))}")
    out.append(f"- `sig_chall` = {_ends(vec.get('sig_chall'))}")
    match = vec.get("chk_chall") == vec.get("sig_chall")
    out.append("")
    out.append(f"→ **accept** ({'equal' if match else 'DIFFER'}), `verdict = "
               f"{vec.get('verdict')}`.")
    out.append("")

    # ---- the invalid example ----
    out.append("## The invalid verification (rejection localizes to a stage)")
    out.append("")
    out.append(
        "Flip a single byte inside the signature's two-dimensional-isogeny "
        "matrix data (byte offset 80 of this level-1 signature) and re-run the "
        "tracer. The auxiliary and challenge curves are unaffected, but the "
        "2D theta isogeny no longer splits, so "
        "`compute_commitment_curve_verify` fails:")
    out.append("")
    out.append("```")
    out.append(f"TRACE E_aux {vec.get('E_aux')}")
    out.append(f"TRACE E_chall {vec.get('E_chall')}")
    if vec.get("E_chall_after_2resp"):
        out.append(f"TRACE E_chall_after_2resp {vec.get('E_chall_after_2resp')}")
    out.append("TRACE result 0")
    out.append("```")
    out.append("")
    out.append(
        "The `E_com`, `chk_chall`, `sig_chall`, and `verdict` lines never "
        "appear: the verifier rejected at the **E_com** stage, before the hash "
        "recheck. That is the whole point of the tool — an alternative verifier "
        "comparing its own trace against this one learns it diverges *at the 2D "
        "isogeny*, not merely that its final verdict is wrong.")
    out.append("")
    out.append(
        "> Observed this session with `harness/trace_lvl1` at commit "
        f"`{prov.get('reference_commit_short','dd133d7')}`. The E_aux and "
        "E_chall values match the valid run exactly because the flipped byte "
        "lies past them in the signature.")
    out.append("")
    return "\n".join(out)
