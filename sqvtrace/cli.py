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


def cmd_diff(args: argparse.Namespace) -> int:
    a = _load_side(args.a)
    b = _load_side(args.b)
    rep = diff_sets(a, b)
    print(rep.summary())
    return 0 if rep.clean else 3


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

    c = sub.add_parser("check", help="self-consistency check of a golden set")
    c.add_argument("--goldens", nargs="*", help="golden JSON file(s); default: vectors/")
    c.set_defaults(func=cmd_check)

    d = sub.add_parser("diff", help="report the first diverging stage between two sets")
    d.add_argument("--a", required=True, help="golden JSON or tracer output")
    d.add_argument("--b", required=True, help="golden JSON or tracer output")
    d.set_defaults(func=cmd_diff)

    w = sub.add_parser("walkthrough", help="print the level-1 vector-0 worked example")
    w.add_argument("--out", help="write markdown to a file instead of stdout")
    w.set_defaults(func=cmd_walkthrough)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
