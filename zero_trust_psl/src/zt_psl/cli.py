"""zt-psl command line.

    zt-psl check    --catalog policy_fields.yaml FILE.psl ...   compile; print rules (exit 1 on error)
    zt-psl describe --catalog policy_fields.yaml --out RULES.md FILE.psl ...
    zt-psl sign     --key PRIVATE.pem [--issuer I --key-id K] FILE ...
    zt-psl verify   --pub PUBLIC.pem [--issuer I --key-id K] FILE ...
    zt-psl intent   --intent policy_intent.yaml --bindings policy_intent_bindings.yaml
                    --catalog policy_fields.yaml --out intent.psl [--report REPORT.md]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .compiler import describe, load_policy_set
from .parser import PSLError
from .signing import PolicySignatureError, load_private_key, load_public_key, sign_file, verify_file


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="zt-psl", description="PSL policy tools for the Zero Trust Backplane")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("check", "describe"):
        s = sub.add_parser(name)
        s.add_argument("--catalog", required=True)
        s.add_argument("files", nargs="+")
        if name == "describe":
            s.add_argument("--out", required=True)
            s.add_argument("--title", default="PSL policy set")
    s = sub.add_parser("intent")
    for opt in ("--intent", "--bindings", "--catalog", "--out"):
        s.add_argument(opt, required=True)
    s.add_argument("--report", default="")
    s.add_argument("--source-label", default="")
    for name in ("sign", "verify"):
        s = sub.add_parser(name)
        s.add_argument("--key" if name == "sign" else "--pub", required=True)
        s.add_argument("--issuer", default="policy.prototype")
        s.add_argument("--key-id", default="policy-1")
        s.add_argument("files", nargs="+")
    ns = ap.parse_args(argv)

    if ns.cmd in ("check", "describe"):
        try:
            ps = load_policy_set([Path(f) for f in ns.files], Path(ns.catalog))
        except PSLError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if ns.cmd == "check":
            for r in ps.rules:
                print(f"{r.kind:12} {r.on_violation if r.kind != 'permit' else '-':15} {r.rule_id}  "
                      f"[{r.psl_file}:{r.line}]")
            print(f"{len(ps.rules)} rules, source sha256 {ps.digest[:16]}")
        else:
            Path(ns.out).write_text(describe(ps, ns.title), encoding="utf-8")
            print(f"wrote {ns.out}")
        return 0
    if ns.cmd == "intent":
        import yaml
        from .compiler import compile_policy_set
        from .fields import FieldCatalog
        from .intent import IntentError, IntentTranslator, report_markdown, to_psl
        intent = yaml.safe_load(Path(ns.intent).read_text(encoding="utf-8"))
        bindings = yaml.safe_load(Path(ns.bindings).read_text(encoding="utf-8"))
        label = ns.source_label or Path(ns.intent).as_posix()
        try:
            trs = IntentTranslator(bindings).translate(intent)
            text = to_psl(trs, version=_intent_version(intent), source=label)
            compile_policy_set([(Path(ns.out).name, text)], FieldCatalog.load(ns.catalog))   # must compile
        except (IntentError, PSLError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        Path(ns.out).write_text(text, encoding="utf-8")
        if ns.report:
            Path(ns.report).write_text(report_markdown(trs, label), encoding="utf-8")
        parts = sum(len(t.parts) for t in trs)
        print(f"{len(trs)} intent rules -> {parts} PSL rules "
              f"({sum(1 for t in trs if t.disabled)} disabled, {sum(1 for t in trs if not t.parts)} realized by "
              f"other rules); wrote {ns.out}")
        return 0
    if ns.cmd == "sign":
        key = load_private_key(ns.key)
        for f in ns.files:
            print(f"signed {sign_file(f, key, issuer=ns.issuer, key_id=ns.key_id)}")
        return 0
    pub = load_public_key(ns.pub)

    def lookup(issuer: str, key_id: str):
        if (issuer, key_id) != (ns.issuer, ns.key_id):
            raise PolicySignatureError(f"signer {issuer}/{key_id} is not {ns.issuer}/{ns.key_id}")
        return pub

    bad = 0
    for f in ns.files:
        try:
            verify_file(f, lookup)
            print(f"ok      {f}")
        except PolicySignatureError as exc:
            print(f"INVALID {f}: {exc}")
            bad += 1
    return 1 if bad else 0


def _intent_version(intent: dict) -> str:
    v = str(intent.get("zt_ir_version", "1.0"))
    parts = (v.split(".") + ["0", "0", "0"])[:3]
    return ".".join(p if p.isdigit() else "0" for p in parts)


if __name__ == "__main__":
    sys.exit(main())
