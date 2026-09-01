"""Exercise the generate → parse pipeline with a stub tracer (no C reference)."""

import json
import os
import stat
import textwrap

from sqvtrace import cli, goldens, walkthrough


STUB = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import sys
    # ignore argv (pk msg sig); emit a fixed, self-consistent level-1 trace
    print("TRACE E_aux " + "a1"*64)
    print("TRACE E_chall " + "b2"*64)
    print("TRACE E_chall_after_2resp " + "c3"*64)
    print("TRACE E_com " + "d4"*64)
    print("TRACE chk_chall " + "e5"*32)
    print("TRACE sig_chall " + "e5"*32)
    print("TRACE verdict 1")
    print("TRACE result 1")
    """
)

# a two-record KAT file (smlen - mlen = CRYPTO_BYTES; values are dummy hex)
KAT = textwrap.dedent(
    """\
    # SQIsign_lvl1

    count = 0
    seed = 00
    mlen = 2
    msg = beef
    pk = aa
    sk = aa
    smlen = 5
    sm = 001122334455beef

    count = 1
    seed = 01
    mlen = 2
    msg = f00d
    pk = bb
    sk = bb
    smlen = 5
    sm = 66778899aabbf00d
    """
)


def _write_stub(tmp_path):
    p = tmp_path / "stub_tracer.py"
    p.write_text(STUB)
    p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(p)


def test_generate_pipeline(tmp_path):
    bin_path = _write_stub(tmp_path)
    kat_path = tmp_path / "kat.rsp"
    kat_path.write_text(KAT)
    out_path = tmp_path / "out.json"

    args = cli.build_parser().parse_args(
        ["generate", "--level", "1", "--kat", str(kat_path),
         "--bin", bin_path, "--out", str(out_path)]
    )
    rc = args.func(args)
    assert rc == 0

    data = goldens.load(str(out_path))
    assert len(data["vectors"]) == 2
    assert data["vectors"][0]["index"] == 0
    assert data["vectors"][1]["index"] == 1
    rep = goldens.self_check(data["vectors"])
    assert rep.ok


def test_kat_signature_extraction():
    # direct check of the sm[:CRYPTO_BYTES] slice logic
    record = {"mlen": "2", "smlen": "5", "sm": "001122334455beef", "pk": "aa", "msg": "beef"}
    pk, msg, sig = cli.kat_signature(record)
    assert pk == "aa"
    assert msg == "beef"
    # CRYPTO_BYTES = 5 - 2 = 3 bytes -> 6 hex chars
    assert sig == "001122"


def test_walkthrough_renders_committed_data(vectors_dir):
    md = walkthrough.render(vectors_dir)
    assert "Worked example" in md
    # the real level-1 vector-0 E_aux must appear verbatim
    data = goldens.load(os.path.join(vectors_dir, "goldens-lvl1.json"))
    vec = next(v for v in data["vectors"] if v["index"] == 0)
    assert vec["E_aux"] in md
    assert vec["E_com"] in md
    assert "reject" in md.lower()
