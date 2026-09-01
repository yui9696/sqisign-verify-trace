"""Command-line interface for sqisign-verify-trace."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

from . import __version__, goldens, parse
from .diff import diff_sets


# --------------------------------------------------------------------------
# KAT parsing (only needed for `generate`; stdlib only)
# --------------------------------------------------------------------------
def parse_kat(path: str) -> list[dict]:
    """Parse a PQCsignKAT .rsp file into records with pk, msg, sm, mlen, smlen."""
    text = open(path, "r", encoding="utf-8").read()
    records = []
    for block in re.split(r"\n\s*\n", text):
        fields = dict(re.findall(r"^(\w+)\s*=\s*(\S*)\s*$", block, re.M))
        if "sm" in fields and "pk" in fields:
            records.append(fields)
    return records


def kat_signature(record: dict) -> tuple[str, str, str]:
    """Return (pk_hex, msg_hex, sig_hex) for one KAT record.

    The valid signature is sm[:CRYPTO_BYTES] where CRYPTO_BYTES = smlen - mlen.
    """
    mlen = int(record["mlen"])
    smlen = int(record["smlen"])
    crypto_bytes = smlen - mlen
    sig_hex = record["sm"][: crypto_bytes * 2]
    return record["pk"], record.get("msg", ""), sig_hex


# --------------------------------------------------------------------------
# subcommands
# --------------------------------------------------------------------------
def cmd_build(args: argparse.Namespace) -> int:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    script = os.path.join(here, "harness", "build.sh")
    if not os.path.exists(script):
        print(f"harness build script not found: {script}", file=sys.stderr)
        return 1
    env = dict(os.environ)
    if args.src:
        env["SQISIGN_SRC"] = args.src
    if args.build:
        env["SQISIGN_BUILD"] = args.build
    print(f"$ harness/build.sh {args.level}", file=sys.stderr)
    return subprocess.call(["bash", script, str(args.level)], env=env)


def cmd_generate(args: argparse.Namespace) -> int:
    if not os.access(args.bin, os.X_OK):
        print(f"tracer binary not runnable: {args.bin}", file=sys.stderr)
        return 1
    records = parse_kat(args.kat)
    if args.limit:
        records = records[: args.limit]
    vectors = []
    for i, rec in enumerate(records):
        pk, msg, sig = kat_signature(rec)
        out = subprocess.run(
            [args.bin, pk, msg, sig], capture_output=True, text=True
        ).stdout
        vec = parse.parse_trace(out)
        vec = {"level": args.level, "index": i, **vec}
        vectors.append(vec)
        if (i + 1) % 25 == 0:
            print(f"  ... {i+1}/{len(records)}", file=sys.stderr)

    rep = goldens.self_check(vectors)
    provenance = {
        "reference_commit_short": "dd133d7",
        "generated_by": "sqisign-verify-trace generate",
        "level": args.level,
        "count": len(vectors),
        "kat_file": os.path.basename(args.kat),
        "tracer": os.path.basename(args.bin),
    }
    if args.out:
        goldens.save(args.out, provenance, vectors)
        print(f"wrote {len(vectors)} vectors to {args.out}", file=sys.stderr)
    else:
        import json

        json.dump({"provenance": provenance, "vectors": vectors}, sys.stdout, indent=1)
        print()
    print(rep.summary(), file=sys.stderr)
    return 0 if rep.ok else 2


def cmd_check(args: argparse.Namespace) -> int:
    paths = args.goldens or goldens.default_vector_files()
    if not paths:
        print("no golden files given and none found in vectors/", file=sys.stderr)
        return 1
    vectors = goldens.load_many(paths)
    rep = goldens.self_check(vectors)
    print(rep.summary())
    return 0 if rep.ok else 2


def cmd_crosscheck(args: argparse.Namespace) -> int:
    from collections import defaultdict

    from .crosscheck import crosscheck_e_aux

    paths = args.goldens or goldens.default_vector_files()
    if not paths:
        print("no golden files given and none found in vectors/", file=sys.stderr)
        return 1
    vectors = goldens.load_many(paths)
    by_level: dict = defaultdict(list)
    for v in vectors:
        lvl = v.get("level")
        if lvl in (1, 3, 5):
            by_level[lvl].append(v)
    if args.limit:
        by_level = {lvl: vs[: args.limit] for lvl, vs in by_level.items()}

    all_ok = True
    grand_total = grand_matched = 0
    print("independent pure-Python cross-check of the E_aux stage")
    print("  (recompute j(A) from E_aux_A; compare to the reference's E_aux)")
    for lvl in sorted(by_level):
        r = crosscheck_e_aux(by_level[lvl], lvl)
        grand_total += r.total
        grand_matched += r.matched
        all_ok = all_ok and r.ok
        status = "ok" if r.ok else f"FAIL ({len(r.mismatches)} mismatch)"
        print(f"  level {lvl}: {r.matched}/{r.total} match  {status}")
        for idx, exp, got in r.mismatches[:3]:
            print(f"    vec {idx}: expected {exp[:16]}... got {got[:16]}...")
    print(f"  total: {grand_matched}/{grand_total} independently reproduced")

    if args.echall:
        from .challenge import crosscheck_e_chall, crosscheck_e_chall_after_2resp

        print()
        print("independent pure-Python cross-check of the E_chall stage")
        print("  (the challenge isogeny, via the reference's exact 4-isogeny strategy)")
        for lvl in sorted(by_level):
            r = crosscheck_e_chall(by_level[lvl], lvl)
            grand_total += r.total
            grand_matched += r.matched
            all_ok = all_ok and r.ok
            status = "ok" if r.ok else f"FAIL ({len(r.mismatches)} mismatch)"
            print(f"  level {lvl}: {r.matched}/{r.total} match  {status}")
            for idx, exp, got in r.mismatches[:3]:
                print(f"    vec {idx}: expected {exp[:16]}... got {got[:16]}...")

        print()
        print("independent pure-Python cross-check of the E_chall_after_2resp stage")
        print("  (the 2-response isogeny; needs the exact E_chall Montgomery model)")
        for lvl in sorted(by_level):
            r = crosscheck_e_chall_after_2resp(by_level[lvl], lvl)
            grand_total += r.total
            grand_matched += r.matched
            all_ok = all_ok and r.ok
            status = "ok" if r.ok else f"FAIL ({len(r.mismatches)} mismatch)"
            print(f"  level {lvl}: {r.matched}/{r.total} match  {status}")
            for idx, exp, got in r.mismatches[:3]:
                print(f"    vec {idx}: expected {exp[:16]}... got {got[:16]}...")

    if args.ecom:
        from .theta import crosscheck_e_com

        print()
        print("independent pure-Python cross-check of the E_com stage")
        print("  (the dimension-2 theta (2^n,2^n)-isogeny: gluing -> chain -> splitting)")
        for lvl in sorted(by_level):
            r = crosscheck_e_com(by_level[lvl], lvl)
            grand_total += r.total
            grand_matched += r.matched
            all_ok = all_ok and r.ok
            status = "ok" if r.ok else f"FAIL ({len(r.mismatches)} mismatch)"
            print(f"  level {lvl}: {r.matched}/{r.total} match  {status}")
            for idx, exp, got in r.mismatches[:3]:
                print(f"    vec {idx}: expected {exp[:16]}... got {got[:16]}...")

    return 0 if all_ok and grand_total > 0 else 2


def cmd_diff(args: argparse.Namespace) -> int:
    a = _load_side(args.a)
    b = _load_side(args.b)
    rep = diff_sets(a, b)
    print(rep.summary())
    return 0 if rep.clean else 3


def cmd_verify(args: argparse.Namespace) -> int:
    from .verify import verify_signature

    if args.kat:
        records = parse_kat(args.kat)
        if args.limit:
            records = records[: args.limit]
        accepted = 0
        for i, rec in enumerate(records):
            pk, msg, sig = kat_signature(rec)
            ok = verify_signature(pk, sig, bytes.fromhex(msg) if msg else b"", args.level)
            accepted += ok
            if not ok:
                print(f"  vec {i}: REJECT (expected accept for a valid KAT signature)")
        print(f"pure-Python verify: {accepted}/{len(records)} accepted "
              f"(level {args.level}); all valid KAT signatures should accept")
        return 0 if accepted == len(records) else 2

    if not (args.pk and args.sig):
        print("give --kat FILE, or --pk and --sig (and --msg)", file=sys.stderr)
        return 1
    msg = bytes.fromhex(args.msg) if args.msg else b""
    ok = verify_signature(args.pk, args.sig, msg, args.level)
    print("ACCEPT" if ok else "REJECT")
    return 0 if ok else 1


def cmd_walkthrough(args: argparse.Namespace) -> int:
    from . import walkthrough

    md = walkthrough.render()
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(md + "\n")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(md)
    return 0


def _load_side(path: str) -> list[dict]:
    """Load a diff operand: a golden JSON file, or raw tracer output text."""
    if path.endswith(".json"):
        return goldens.load(path)["vectors"]
    # treat as tracer output stream
    text = open(path, "r", encoding="utf-8").read()
    vecs = parse.parse_trace_stream(text)
    return [{"index": i, **v} for i, v in enumerate(vecs)]


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sqisign-verify-trace",
        description="Golden intermediate-value vectors for SQIsign verification.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="build the C tracer via harness/build.sh")
    b.add_argument("--level", type=int, default=1, choices=(1, 3, 5))
    b.add_argument("--src", help="reference source dir (SQISIGN_SRC)")
    b.add_argument("--build", help="reference build dir (SQISIGN_BUILD)")
    b.set_defaults(func=cmd_build)

    g = sub.add_parser("generate", help="produce goldens from the tracer + a KAT file")
    g.add_argument("--level", type=int, required=True, choices=(1, 3, 5))
    g.add_argument("--kat", required=True, help="PQCsignKAT .rsp file")
    g.add_argument("--bin", required=True, help="path to trace_lvlN binary")
    g.add_argument("--out", help="output JSON (default: stdout)")
    g.add_argument("--limit", type=int, help="only first N records")
    g.set_defaults(func=cmd_generate)

    x = sub.add_parser(
        "crosscheck",
        help="independently recompute the E_aux stage in pure Python and compare",
    )
    x.add_argument("--goldens", nargs="*", help="golden JSON files (default: vectors/)")
    x.add_argument("--echall", action="store_true",
                   help="also cross-check the E_chall stage (the challenge isogeny; slower)")
    x.add_argument("--ecom", action="store_true",
                   help="also cross-check the E_com stage (the dimension-2 theta isogeny; slowest)")
    x.add_argument("--limit", type=int, default=None,
                   help="check at most N vectors per level (E_chall in pure Python is slow)")
    x.set_defaults(func=cmd_crosscheck)

    c = sub.add_parser("check", help="self-consistency check of a golden set")
    c.add_argument("--goldens", nargs="*", help="golden JSON file(s); default: vectors/")
    c.set_defaults(func=cmd_check)

    d = sub.add_parser("diff", help="report the first diverging stage between two sets")
    d.add_argument("--a", required=True, help="golden JSON or tracer output")
    d.add_argument("--b", required=True, help="golden JSON or tracer output")
    d.set_defaults(func=cmd_diff)

    ver = sub.add_parser(
        "verify",
        help="verify a signature end-to-end in pure Python (accept/reject)",
    )
    ver.add_argument("--level", type=int, default=1, choices=(1, 3, 5))
    ver.add_argument("--kat", help="verify every signature in a PQCsignKAT .rsp file")
    ver.add_argument("--limit", type=int, help="only the first N KAT records")
    ver.add_argument("--pk", help="public key (hex) for a single verification")
    ver.add_argument("--sig", help="signature (hex) for a single verification")
    ver.add_argument("--msg", help="message (hex) for a single verification", default="")
    ver.set_defaults(func=cmd_verify)

    w = sub.add_parser("walkthrough", help="print the level-1 vector-0 worked example")
    w.add_argument("--out", help="write markdown to a file instead of stdout")
    w.set_defaults(func=cmd_walkthrough)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
