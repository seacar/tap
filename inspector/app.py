"""TAP Inspector — local web UI (whitepaper §15).

A small FastAPI app, server-rendered HTML (hand-built strings, no Jinja2 — this
repo has no templating dependency today and a handful of simple forms doesn't
warrant adding one). Every handler calls straight into `inspector.core` — the
exact same functions the CLI (`inspector.cli`) calls — so the two front-ends
can never diverge in behavior. Stateless: no session store; each result page
pre-fills the next form's fields via query-string links.

Run:  python distribution/inspector/serve.py   (binds 127.0.0.1 only by default)
"""
from __future__ import annotations

import html
import json
import sys
from pathlib import Path
from urllib.parse import urlencode

_DIST = str(Path(__file__).resolve().parents[1])
if _DIST not in sys.path:
    sys.path.insert(0, _DIST)

import httpx
from fastapi import FastAPI, Form, Query
from fastapi.responses import HTMLResponse

from inspector import core
import tap_sdk.verify as V

app = FastAPI(title="TAP Inspector", version="0.1.0", docs_url=None, redoc_url=None)

_STYLE = """
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 860px;
         margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }
  nav a { margin-right: 1rem; }
  h1 { font-size: 1.4rem; }
  h2 { font-size: 1.1rem; margin-top: 2rem; }
  form { display: grid; gap: 0.5rem; margin: 1rem 0; }
  label { font-size: 0.85rem; font-weight: 600; }
  input, textarea, select { font-family: inherit; padding: 0.4rem; width: 100%;
                            box-sizing: border-box; }
  textarea { min-height: 4rem; font-family: ui-monospace, monospace; font-size: 0.85rem; }
  button { padding: 0.5rem 1rem; width: fit-content; cursor: pointer; }
  pre { background: #f4f4f4; padding: 1rem; overflow-x: auto; white-space: pre-wrap;
       word-break: break-all; }
  .banner { padding: 0.6rem 1rem; border-radius: 4px; margin: 1rem 0; }
  .ok { background: #e6f4ea; color: #1e4620; }
  .bad { background: #fce8e6; color: #611a15; }
  .hint { color: #666; font-size: 0.8rem; }
</style>
"""

def _page(title: str, body: str) -> HTMLResponse:
    nav = (
        '<nav><a href="/">Inspector</a> | <a href="/mint">mint passport</a> | '
        '<a href="/sign-event">sign event</a> | <a href="/verify">verify</a> | '
        '<a href="/chain">show chain</a></nav>'
    )
    return HTMLResponse(f"<title>{html.escape(title)}</title>{_STYLE}{nav}<h1>{html.escape(title)}</h1>{body}")

def _field(label: str, name: str, *, value: str = "", kind: str = "text",
          textarea: bool = False, options: list[str] | None = None) -> str:
    v = html.escape(value or "")
    if options is not None:
        opts = "".join(
            f'<option value="{html.escape(o)}"{" selected" if o == value else ""}>{html.escape(o)}</option>'
            for o in options
        )
        field = f'<select name="{name}">{opts}</select>'
    elif textarea:
        field = f'<textarea name="{name}">{v}</textarea>'
    else:
        field = f'<input type="{kind}" name="{name}" value="{v}">'
    return f'<label>{html.escape(label)}</label>{field}'

def _pre(obj) -> str:
    if isinstance(obj, str):
        text = obj
    else:
        text = json.dumps(obj, indent=2, default=str)
    return f"<pre>{html.escape(text)}</pre>"

@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    body = (
        "<p>Local dev tool to mint test Passports, sign/verify Events, and "
        "visualize a record's chain (TAP whitepaper §15). Everything here runs "
        "against your own local keys — nothing is submitted to a live Verifier "
        "unless you explicitly point a form at one.</p>"
        '<ul><li><a href="/mint">Mint a Passport</a></li>'
        '<li><a href="/sign-event">Sign an Event</a></li>'
        '<li><a href="/verify">Verify a Passport / Events</a></li>'
        '<li><a href="/chain">Visualize a record\'s chain</a></li></ul>'
    )
    return _page("TAP Inspector", body)

# --- mint ----------------------------------------------------------------------

def _mint_form(*, private_key_hex="", kid="", prompt="", scope="", attestation="none") -> str:
    return (
        '<form method="post" action="/mint">'
        + _field("Private key hex (blank = generate a fresh one)", "private_key_hex", value=private_key_hex)
        + _field("kid (blank = auto)", "kid", value=kid)
        + _field("Task prompt", "prompt", value=prompt)
        + _field("Scope (comma-separated)", "scope", value=scope)
        + _field("Attestation", "attestation", value=attestation,
                 options=["none", "requested", "server"])
        + '<p class="hint">attestation="server" declares this record expects a '
          "server-attested leg (TAP-spec §4.1) — a Verifier will flag it as "
          "conflicting if that leg never actually arrives.</p>"
        + "<button>Mint</button></form>"
    )

@app.get("/mint", response_class=HTMLResponse)
def mint_get() -> HTMLResponse:
    return _page("Mint a Passport", _mint_form())

@app.post("/mint", response_class=HTMLResponse)
def mint_post(
    private_key_hex: str = Form(""), kid: str = Form(""), prompt: str = Form(...),
    scope: str = Form(""), attestation: str = Form("none"),
) -> HTMLResponse:
    if not private_key_hex or not kid:
        key = core.generate_key(kid=kid or None)
        private_key_hex, kid = key["private_key_hex"], key["kid"]
    scope_list = [s.strip() for s in scope.split(",") if s.strip()]
    passport = core.mint_passport(private_key_hex=private_key_hex, kid=kid, task_prompt=prompt,
                                  scope=scope_list, attestation=attestation)
    result = {"private_key_hex": private_key_hex, "kid": kid,
              "compact": passport.compact, "claims": passport.claims}
    # Pass the FULL blob (not just .compact) onward — `attestation` is Inspector
    # bookkeeping, not part of the wire JWT's claims, so a bare compact string
    # would silently lose it and the next-signed event would never stamp nego.
    passport_blob = json.dumps({"compact": passport.compact, "claims": passport.claims,
                                "attestation": passport.attestation})
    sign_link = "/sign-event?" + urlencode({
        "passport_compact": passport_blob, "private_key_hex": private_key_hex, "kid": kid,
    })
    body = _pre(result) + f'<p><a href="{html.escape(sign_link)}">Sign an event for this passport &rarr;</a></p>'
    body += "<h2>Mint another</h2>" + _mint_form(attestation=attestation)
    return _page("Passport minted", body)

# --- sign-event ------------------------------------------------------------------

def _sign_form(*, passport_compact="", private_key_hex="", kid="", tool="",
              scope_used="", attestation_hint: str | None = None) -> str:
    hint = ""
    if attestation_hint:
        hint = f'<p class="hint">passport attestation: {html.escape(attestation_hint)}</p>'
    return (
        '<form method="post" action="/sign-event">'
        + _field("Passport (compact JWT, or a mint-passport JSON blob)", "passport",
                 value=passport_compact, textarea=True)
        + hint
        + _field("Private key hex (signing key — usually the same as the passport's)",
                 "private_key_hex", value=private_key_hex)
        + _field("kid", "kid", value=kid)
        + _field("Kind", "kind", value="tool_call",
                 options=["tool_call", "agent_delegate", "received_delegation",
                         "agent_message", "denied", "decision", "checkpoint"])
        + _field("Tool", "tool", value=tool)
        + _field("Scope used", "scope_used", value=scope_used)
        + _field("Attestor", "attestor", value="agent", options=["agent", "server"])
        + _field("Status", "status", value="success", options=["success", "failure", "denied"])
        + _field("Code", "code", value="OK")
        + _field("Args (JSON, optional)", "args_json", textarea=True)
        + "<button>Sign event</button></form>"
    )

@app.get("/sign-event", response_class=HTMLResponse)
def sign_event_get(
    passport_compact: str = Query(""), private_key_hex: str = Query(""), kid: str = Query(""),
) -> HTMLResponse:
    return _page("Sign an Event", _sign_form(
        passport_compact=passport_compact, private_key_hex=private_key_hex, kid=kid))

@app.post("/sign-event", response_class=HTMLResponse)
def sign_event_post(
    passport: str = Form(...), private_key_hex: str = Form(...), kid: str = Form(...),
    kind: str = Form("tool_call"), tool: str = Form(...), scope_used: str = Form(""),
    attestor: str = Form("agent"), status: str = Form("success"), code: str = Form("OK"),
    args_json: str = Form(""),
) -> HTMLResponse:
    p = core.load_passport(passport)
    args = json.loads(args_json) if args_json.strip() else None
    event = core.sign_event_for_passport(
        private_key_hex=private_key_hex, kid=kid, passport=p, kind=kind,
        intent=f"Call {tool}", tool=tool, scope_used=scope_used or None, args=args,
        status=status, code=code, attestor=attestor,
    )
    chain_link = "/chain?" + urlencode({"passport_compact": p.compact, "private_key_hex": private_key_hex, "kid": kid})
    body = _pre(event)
    body += f'<p><a href="{html.escape(chain_link)}">View this in the chain visualizer &rarr;</a></p>'
    body += "<h2>Sign another event for the same passport</h2>" + _sign_form(
        passport_compact=p.compact, private_key_hex=private_key_hex, kid=kid,
        attestation_hint=p.attestation)
    return _page("Event signed", body)

# --- verify ----------------------------------------------------------------------

@app.get("/verify", response_class=HTMLResponse)
def verify_get() -> HTMLResponse:
    body = (
        '<form method="post" action="/verify">'
        + _field("JWKS source (Verifier URL, local file path, or pasted JWKS JSON)", "jwks", textarea=True)
        + _field("Passport (compact JWT, optional)", "passport", textarea=True)
        + _field("Events (JSON array, optional)", "events_json", textarea=True)
        + "<button>Verify</button></form>"
    )
    return _page("Verify", body)

@app.post("/verify", response_class=HTMLResponse)
def verify_post(jwks: str = Form(...), passport: str = Form(""), events_json: str = Form("")) -> HTMLResponse:
    passport_compact = core.load_passport(passport).compact if passport.strip() else None
    events = json.loads(events_json) if events_json.strip() else []
    try:
        report = core.verify(jwks_source=jwks, passport_compact=passport_compact, events=events)
        ok = report.get("verified", report.get("valid", True))
        banner = f'<div class="banner {"ok" if ok else "bad"}">{"PASS" if ok else "review findings below"}</div>'
        body = banner + _pre(report)
    except Exception as exc:
        body = f'<div class="banner bad">error: {html.escape(str(exc))}</div>'
    return _page("Verification report", body)

# --- chain -----------------------------------------------------------------------

@app.get("/chain", response_class=HTMLResponse)
def chain_get(
    passport_compact: str = Query(""), private_key_hex: str = Query(""), kid: str = Query(""),
) -> HTMLResponse:
    body = (
        "<p>Either fetch a live record/chain from a running Verifier, or build one "
        "locally from a passport + a set of signed events.</p>"
        '<form method="post" action="/chain/live">'
        + _field("Verifier URL", "verifier_url", value="http://127.0.0.1:8000")
        + _field("aid (record) — or leave blank and fill cid below", "aid")
        + _field("cid (chain) — takes priority over aid if both are set", "cid")
        + "<button>Fetch from Verifier</button></form>"
        + "<h2>Local (offline)</h2>"
        + '<form method="post" action="/chain/local">'
        + _field("JWKS source (Verifier URL, local file, or pasted JWKS JSON)", "jwks", textarea=True)
        + _field("Passport (compact JWT)", "passport_compact", value=passport_compact, textarea=True)
        + _field("Events (JSON array)", "events_json", textarea=True)
        + "<button>Build locally</button></form>"
    )
    return _page("Show chain", body)

def _fetch_live_chain(verifier_url: str, aid: str, cid: str) -> HTMLResponse:
    """Shared by GET and POST /chain/live so a plain URL (no form submit) can
    deep-link straight to a live record/chain view — e.g. from another tool
    that already knows the aid/cid, without hand-filling the form."""
    base = verifier_url.rstrip("/")
    try:
        if cid.strip():
            resp = httpx.get(f"{base}/v1/chains/{cid.strip()}", timeout=10.0)
        else:
            resp = httpx.get(f"{base}/v1/records/{aid.strip()}", timeout=10.0)
        resp.raise_for_status()
        record = resp.json()
    except Exception as exc:
        return _page("Chain (live)", f'<div class="banner bad">{html.escape(str(exc))}</div>')
    body = f"<pre>{html.escape(core.render_chain_ascii(record))}</pre>" + _pre(record)
    return _page("Chain (live)", body)

@app.get("/chain/live", response_class=HTMLResponse)
def chain_live_get(
    verifier_url: str = Query(...), aid: str = Query(""), cid: str = Query(""),
) -> HTMLResponse:
    return _fetch_live_chain(verifier_url, aid, cid)

@app.post("/chain/live", response_class=HTMLResponse)
def chain_live_post(
    verifier_url: str = Form(...), aid: str = Form(""), cid: str = Form(""),
) -> HTMLResponse:
    return _fetch_live_chain(verifier_url, aid, cid)

@app.post("/chain/local", response_class=HTMLResponse)
def chain_local(jwks: str = Form(...), passport_compact: str = Form(...), events_json: str = Form(...)) -> HTMLResponse:
    try:
        resolve_key = core.make_resolver(jwks)
        p = core.load_passport(passport_compact)
        events = json.loads(events_json)
        local_record = core.build_record_from_local(passport_claims=p.claims, events=events,
                                                     resolve_key=resolve_key)
        record = V.annotate_assurance(local_record)
    except Exception as exc:
        return _page("Chain (local)", f'<div class="banner bad">{html.escape(str(exc))}</div>')
    body = f"<pre>{html.escape(core.render_chain_ascii(record))}</pre>" + _pre(record)
    return _page("Chain (local)", body)
