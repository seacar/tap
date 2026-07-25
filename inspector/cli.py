#!/usr/bin/env python3
"""TAP Inspector CLI — local dev tool to mint test Passports, sign/verify Events,
and visualize a record's chain (whitepaper §15). No new crypto or verification
logic: every command is a thin wrapper over `inspector.core`, which itself only
calls `tap_sdk`.

A standalone entrypoint for the Inspector's local developer tooling.
itself draws the line between TAP-the-protocol and TAPClient-the-product, and a
third party building their own Signer against just tap/+shared+shim+verifier
shouldn't need control-plane dependencies to use the Inspector.

Usage (run from the distribution/ directory, or with it on PYTHONPATH):
    python -m inspector.cli generate-key
    python -m inspector.cli mint-passport --private-key-hex ... --kid ... \\
        --prompt "Resolve ticket #123" --scope read:database
    python -m inspector.cli sign-event --passport-file p.json \\
        --private-key-hex ... --kid ... --tool db_query --scope-used read:database
    python -m inspector.cli verify --jwks http://localhost:8000 \\
        --passport-file p.json --event-file e1.json --event-file e2.json
    python -m inspector.cli show-chain --passport-file p.json --event-file e1.json
    python -m inspector.cli show-chain --from-verifier <aid> http://localhost:8000
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# distribution/ -> makes the `inspector` package importable (for `python
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx

def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))

def _load_json_arg(text: str) -> dict:
    path = Path(text)
    return json.loads(path.read_text() if path.exists() else text)

def generate_key_command(args: argparse.Namespace) -> int:
    from inspector import core
    _print(core.generate_key(kid=args.kid))
    return 0

def mint_passport_command(args: argparse.Namespace) -> int:
    from inspector import core
    p = core.mint_passport(
        private_key_hex=args.private_key_hex, kid=args.kid, task_prompt=args.prompt,
        scope=args.scope, ttl_s=args.ttl, cid=args.cid, attestation=args.attestation,
        agent_id=args.agent_id, framework=args.framework, model=args.model,
    )
    _print({"compact": p.compact, "claims": p.claims, "attestation": p.attestation})
    return 0

def sign_event_command(args: argparse.Namespace) -> int:
    from inspector import core

    passport_text = args.passport_file or args.passport_compact
    if not passport_text:
        print("one of --passport-file / --passport-compact is required", file=sys.stderr)
        return 2
    passport = core.load_passport(passport_text)
    event = core.sign_event_for_passport(
        private_key_hex=args.private_key_hex, kid=args.kid, passport=passport,
        kind=args.kind, intent=args.intent or f"Call {args.tool}", tool=args.tool,
        scope_used=args.scope_used, args=_load_json_arg(args.args_json) if args.args_json else None,
        status=args.status, code=args.code, action_ref=args.action_ref,
        attestor=args.attestor,
    )
    _print(event)
    return 0

def verify_command(args: argparse.Namespace) -> int:
    from inspector import core

    passport_compact = None
    if args.passport_file or args.passport_compact:
        passport_compact = core.load_passport(args.passport_file or args.passport_compact).compact
    events = [_load_json_arg(f) for f in (args.event_file or [])]
    events += [_load_json_arg(j) for j in (args.event_json or [])]
    report = core.verify(jwks_source=args.jwks, passport_compact=passport_compact, events=events)
    _print(report)
    return 0

def show_chain_command(args: argparse.Namespace) -> int:
    from inspector import core
    import tap_sdk.verify as V

    if args.from_verifier:
        aid, verifier_url = args.from_verifier
        resp = httpx.get(f"{verifier_url.rstrip('/')}/v1/records/{aid}", timeout=10.0)
        resp.raise_for_status()
        record = resp.json()
    elif args.from_verifier_chain:
        cid, verifier_url = args.from_verifier_chain
        resp = httpx.get(f"{verifier_url.rstrip('/')}/v1/chains/{cid}", timeout=10.0)
        resp.raise_for_status()
        record = resp.json()
    else:
        if not args.jwks:
            print("--jwks is required for a local (non --from-verifier) chain view", file=sys.stderr)
            return 2
        passport_text = args.passport_file or args.passport_compact
        if not passport_text:
            print("one of --passport-file / --passport-compact is required", file=sys.stderr)
            return 2
        passport = core.load_passport(passport_text)
        events = [_load_json_arg(f) for f in (args.event_file or [])]
        resolve_key = core.make_resolver(args.jwks)
        local_record = core.build_record_from_local(
            passport_claims=passport.claims, events=events, resolve_key=resolve_key)
        record = V.annotate_assurance(local_record)

    if args.json:
        _print(record)
    else:
        print(core.render_chain_ascii(record))
    return 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="inspector")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate-key", help="mint a fresh Ed25519 test identity")
    gen.add_argument("--kid", help="explicit kid (default: freshly generated)")
    gen.set_defaults(func=generate_key_command)

    mint = sub.add_parser("mint-passport", help="mint a test Passport")
    mint.add_argument("--private-key-hex", required=True)
    mint.add_argument("--kid", required=True)
    mint.add_argument("--prompt", required=True, dest="prompt")
    mint.add_argument("--scope", action="append", required=True, help="repeatable")
    mint.add_argument("--ttl", type=int, default=3600)
    mint.add_argument("--cid", help="inherit a parent record's context id")
    mint.add_argument("--attestation", choices=["none", "requested", "server"], default="none")
    mint.add_argument("--agent-id")
    mint.add_argument("--framework")
    mint.add_argument("--model")
    mint.set_defaults(func=mint_passport_command)

    sign = sub.add_parser("sign-event", help="sign a test Event for a Passport")
    sign.add_argument("--passport-file", help="path to a mint-passport JSON blob")
    sign.add_argument("--passport-compact", help="a bare compact Passport JWT")
    sign.add_argument("--private-key-hex", required=True)
    sign.add_argument("--kid", required=True)
    sign.add_argument("--tool", required=True)
    sign.add_argument("--scope-used")
    sign.add_argument("--kind", default="tool_call")
    sign.add_argument("--intent")
    sign.add_argument("--args-json", help="JSON string or path")
    sign.add_argument("--status", default="success")
    sign.add_argument("--code", default="OK")
    sign.add_argument("--action-ref")
    sign.add_argument("--attestor", default="agent", choices=["agent", "server"])
    sign.set_defaults(func=sign_event_command)

    verify = sub.add_parser("verify", help="verify a Passport and/or Events")
    verify.add_argument("--jwks", required=True, help="Verifier base URL or a local JWKS JSON file")
    verify.add_argument("--passport-file")
    verify.add_argument("--passport-compact")
    verify.add_argument("--event-file", action="append", help="repeatable; path to a signed event JSON")
    verify.add_argument("--event-json", action="append", help="repeatable; literal event JSON")
    verify.set_defaults(func=verify_command)

    chain = sub.add_parser("show-chain", help="visualize a record's chain")
    chain.add_argument("--jwks", help="Verifier base URL or a local JWKS JSON file (local mode)")
    chain.add_argument("--passport-file")
    chain.add_argument("--passport-compact")
    chain.add_argument("--event-file", action="append", help="repeatable")
    chain.add_argument("--from-verifier", nargs=2, metavar=("AID", "VERIFIER_URL"))
    chain.add_argument("--from-verifier-chain", nargs=2, metavar=("CID", "VERIFIER_URL"))
    chain.add_argument("--json", action="store_true", help="dump the raw structured record instead")
    chain.set_defaults(func=show_chain_command)

    return parser

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)

if __name__ == "__main__":
    raise SystemExit(main())
