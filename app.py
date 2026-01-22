# app.py
# PAT v0.2 (repo edition): Flask UI wired to the pat/ core modules.
#
# Run:
#   pip install -r requirements.txt
#   python app.py
#
# Visit:
#   http://127.0.0.1:5000

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

from flask import Flask, abort, redirect, render_template_string, request, url_for

from pat.config import (
    APP_NAME,
    KEYRING_PATH,
    LOG_PATH,
    DEFAULT_POLICY,
    PRESETS,
)
from pat.ledger import (
    append_receipt,
    ensure_log_exists,
    find_latest_by_event_id,
    read_all_receipts,
    tamper_last_log_line,
    verify_chain,
    reset_log,
)
from pat.keys import (
    ensure_demo_approver,
    ensure_keyring_exists,
    get_public_key_b64,
    load_keyring,
    new_approver_keypair,
    verify_signature,
)
from pat.receipt import (
    build_approval_transition,
    build_new_receipt,
)
from pat.replay import replay_and_compare
from pat.hashing import compute_rules_hash

app = Flask(__name__)


BASE_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>{{ title }}</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; margin: 0; padding: 0; background: #0b0e14; color: #e7e9ee; }
    a { color: #9ad0ff; text-decoration: none; }
    a:hover { text-decoration: underline; }
    code { background: #0b1220; border: 1px solid #26324a; padding: 2px 6px; border-radius: 10px; }
    .wrap { max-width: 1150px; margin: 0 auto; padding: 24px; }
    .header { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; margin-bottom: 16px; }
    .muted { color: #a7acb8; font-size: 14px; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    .card { background: #111827; border: 1px solid #243045; border-radius: 16px; padding: 16px; box-shadow: 0 10px 30px rgba(0,0,0,0.35); }
    .card h3 { margin: 0 0 10px 0; font-size: 16px; }
    .badge { display: inline-block; padding: 6px 10px; border-radius: 999px; font-weight: 800; font-size: 12px; letter-spacing: 0.4px; }
    .ok { background: rgba(34,197,94,0.18); border: 1px solid rgba(34,197,94,0.45); color: #77f2a1; }
    .bad { background: rgba(239,68,68,0.18); border: 1px solid rgba(239,68,68,0.45); color: #ff9a9a; }
    .warn { background: rgba(245,158,11,0.18); border: 1px solid rgba(245,158,11,0.45); color: #ffd08a; }
    textarea, input, select { width: 100%; background: #0b1220; border: 1px solid #26324a; border-radius: 12px; color: #e7e9ee; padding: 10px; box-sizing: border-box; }
    textarea { min-height: 140px; resize: vertical; }
    label { display: block; margin: 10px 0 6px; font-size: 13px; color: #c9ceda; }
    button { background: #2563eb; border: 0; color: white; padding: 10px 14px; border-radius: 12px; font-weight: 800; cursor: pointer; }
    button.secondary { background: #334155; }
    button.danger { background: #b91c1c; }
    button.ghost { background: transparent; border: 1px solid #26324a; color: #c9ceda; }
    pre { background: #0b1220; border: 1px solid #26324a; border-radius: 12px; padding: 12px; overflow: auto; }
    .row { display: flex; gap: 10px; }
    .row > div { flex: 1; }
    .checks { margin: 10px 0 0; padding: 0; list-style: none; }
    .checks li { margin: 8px 0; padding: 8px 10px; border-radius: 12px; border: 1px solid #26324a; background: #0b1220; }
    .tiny { font-size: 12px; color: #a7acb8; }
    .hr { height: 1px; background: #243045; margin: 12px 0; }
    .toplinks { display:flex; gap: 12px; align-items: center; }
    .pillbar { display:flex; gap:10px; flex-wrap: wrap; margin-top: 10px; }
    .pill { display:flex; gap:8px; align-items:center; padding: 8px 10px; border: 1px solid #26324a; border-radius: 999px; background: #0b1220; }
    .pill form { margin:0; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <div>
        <div style="font-size: 20px; font-weight: 900;">{{ app_name }}</div>
        <div class="muted">{{ subtitle }}</div>
      </div>
      <div class="toplinks">
        <a href="{{ url_for('index') }}">New Event</a>
        <a href="{{ url_for('events') }}">Events</a>
        <a href="{{ url_for('verify') }}">Verify Log</a>
        <a href="{{ url_for('keys') }}">Keys</a>
      </div>
    </div>

    {{ body|safe }}

    <div class="hr"></div>
    <div class="muted tiny">
      Append-only log: <code>{{ log_path }}</code> &nbsp;|&nbsp; Keyring: <code>{{ key_path }}</code>
    </div>
  </div>
</body>
</html>
"""


def page(body: str, subtitle: str) -> str:
    return render_template_string(
        BASE_HTML,
        title=APP_NAME,
        app_name=APP_NAME,
        subtitle=subtitle,
        body=body,
        log_path=LOG_PATH,
        key_path=KEYRING_PATH,
    )


def badge_for(decision: str) -> str:
    return "ok" if decision == "PERMITTED" else "bad"


@app.get("/")
def index():
    preset_pills = ""
    for k, p in PRESETS.items():
        preset_pills += render_template_string("""
          <div class="pill">
            <form method="post" action="{{ url_for('preset') }}">
              <input type="hidden" name="preset_id" value="{{ preset_id }}"/>
              <button type="submit" class="ghost">▶</button>
            </form>
            <div class="tiny muted">{{ label }}</div>
          </div>
        """, preset_id=k, label=p["name"])

    body = render_template_string("""
    <div class="card">
      <h3>One-click scenarios</h3>
      <div class="tiny muted">For recording a 90-second demo. Click ▶ to generate a receipt.</div>
      <div class="pillbar">{{ pills|safe }}</div>
    </div>

    <div style="height: 16px;"></div>

    <div class="grid">
      <div class="card">
        <h3>Create an event</h3>
        <form method="post" action="{{ url_for('submit') }}">
          <label>Prompt</label>
          <textarea name="prompt" placeholder="Describe the situation..."></textarea>

          <label>Model Output</label>
          <textarea name="model_output" placeholder="Paste the model output... (optional: include 'confidence: 0.92')"></textarea>

          <div class="row">
            <div>
              <label>Proposed Action</label>
              <select name="action_type">
                <option value="LOCKDOWN">LOCKDOWN (high-stakes)</option>
                <option value="DISPATCH_POLICE">DISPATCH_POLICE (high-stakes)</option>
                <option value="ESCALATE_INCIDENT">ESCALATE_INCIDENT (high-stakes)</option>
                <option value="NOTIFY">NOTIFY (low-stakes)</option>
                <option value="LOG_ONLY">LOG_ONLY (low-stakes)</option>
                <option value="NOOP">NOOP (low-stakes)</option>
              </select>
            </div>
            <div>
              <label>Target</label>
              <input name="action_target" placeholder="SCHOOL_12 / ZONE_A / etc" />
            </div>
          </div>

          <div class="row">
            <div>
              <label>Confidence (override, optional 0..1)</label>
              <input name="confidence" placeholder="0.92" />
              <div class="tiny">If blank, we parse from model output.</div>
            </div>
            <div>
              <label>Action Params (JSON, optional)</label>
              <input name="action_params" placeholder='{"duration_min":30}' />
            </div>
          </div>

          <div style="margin-top: 12px;">
            <button type="submit">Generate Receipt</button>
          </div>
        </form>
      </div>

      <div class="card">
        <h3>Policy (live)</h3>
        <div class="tiny muted">This policy is hashed into every receipt.</div>

        <div class="hr"></div>
        <div class="tiny muted">policy_id</div>
        <pre>{{ policy_id }}</pre>

        <div class="tiny muted">version</div>
        <pre>{{ policy_version }}</pre>

        <div class="tiny muted">confidence_threshold</div>
        <pre>{{ threshold }}</pre>

        <div class="tiny muted">high_stakes_actions</div>
        <pre>{{ high_stakes }}</pre>

        <div class="tiny muted">rules_hash</div>
        <pre>{{ rules_hash }}</pre>
      </div>
    </div>
    """,
    pills=preset_pills,
    policy_id=DEFAULT_POLICY.policy_id,
    policy_version=DEFAULT_POLICY.version,
    threshold=DEFAULT_POLICY.confidence_threshold,
    high_stakes=json.dumps(list(DEFAULT_POLICY.high_stakes_actions), indent=2),
    rules_hash=compute_rules_hash(DEFAULT_POLICY.as_text()),
    )
    return page(body, subtitle="Receipts, not vibes. Deterministic policy + append-only audit trail.")


@app.post("/preset")
def preset():
    preset_id = (request.form.get("preset_id") or "").strip()
    if preset_id not in PRESETS:
        abort(400, "Unknown preset.")
    p = PRESETS[preset_id]
    receipt = build_new_receipt(
        prompt=p["prompt"],
        model_output_raw=p["model_output"],
        proposed_action_type=p["action_type"],
        proposed_action_target=p["action_target"],
        proposed_action_params=p["action_params"],
        confidence_override=p["confidence"],
        policy=DEFAULT_POLICY,
    )
    append_receipt(receipt)
    return redirect(url_for("event", event_id=receipt["event_id"]))


@app.post("/submit")
def submit():
    prompt = (request.form.get("prompt") or "").strip()
    model_output = (request.form.get("model_output") or "").strip()
    action_type = (request.form.get("action_type") or "").strip().upper()
    action_target = (request.form.get("action_target") or "").strip()
    confidence_str = (request.form.get("confidence") or "").strip()
    action_params_str = (request.form.get("action_params") or "").strip()

    confidence_override: Optional[float] = None
    if confidence_str:
        try:
            confidence_override = float(confidence_str)
        except ValueError:
            abort(400, "Confidence must be a number between 0 and 1.")
        if not (0.0 <= confidence_override <= 1.0):
            abort(400, "Confidence must be between 0 and 1.")

    params: Dict[str, Any] = {}
    if action_params_str:
        try:
            params = json.loads(action_params_str)
            if not isinstance(params, dict):
                abort(400, "Action Params must be a JSON object.")
        except Exception:
            abort(400, "Action Params must be valid JSON.")

    receipt = build_new_receipt(
        prompt=prompt,
        model_output_raw=model_output,
        proposed_action_type=action_type,
        proposed_action_target=action_target,
        proposed_action_params=params,
        confidence_override=confidence_override,
        policy=DEFAULT_POLICY,
    )
    append_receipt(receipt)
    return redirect(url_for("event", event_id=receipt["event_id"]))


@app.get("/events")
def events():
    receipts = list(reversed(read_all_receipts()))
    rows = []
    for r in receipts[:250]:
        eid = r.get("event_id")
        dec = (r.get("decision") or {}).get("result", "?")
        action = (r.get("proposed_action") or {}).get("type", "")
        approved = bool((r.get("approval") or {}).get("approved", False))
        b = badge_for(dec)
        rows.append(f"""
          <li style="margin: 8px 0;">
            <span class="badge {b}">{dec}</span>
            <span style="margin-left: 8px;"><a href="{url_for('event', event_id=eid)}"><b>{eid}</b></a></span>
            <span class="tiny muted" style="margin-left: 8px;">action={action} approved={approved}</span>
          </li>
        """)

    body = f"""
    <div class="card">
      <h3>Events</h3>
      <div class="tiny muted">Newest first. Multiple append-only receipts may exist for the same event_id (approval transition).</div>
      <div class="hr"></div>
      <ul style="list-style:none; padding:0; margin:0;">
        {''.join(rows) if rows else '<li class="muted">No events yet.</li>'}
      </ul>
    </div>
    """
    return page(body, subtitle="Browse the append-only ledger.")


@app.get("/event/<event_id>")
def event(event_id: str):
    r = find_latest_by_event_id(event_id)
    if not r:
        abort(404, "Event not found.")

    decision = (r.get("decision") or {}).get("result", "BLOCKED")
    reason = (r.get("decision") or {}).get("reason", "")
    badge = badge_for(decision)

    checks_html = ""
    for c in r.get("policy_checks", []):
        res = c.get("result", "FAIL")
        cid = c.get("check_id", "?")
        details = c.get("details", {})
        c_badge = "ok" if res == "PASS" else "bad"
        checks_html += f"""
          <li>
            <span class="badge {c_badge}">{res}</span>
            <b style="margin-left: 8px;">{cid}</b>
            <div class="tiny muted" style="margin-top: 4px;">{json.dumps(details, ensure_ascii=False)}</div>
          </li>
        """

    approval_required = bool((r.get("approval") or {}).get("required", False))
    approved = bool((r.get("approval") or {}).get("approved", False))
    approver_id = (r.get("approval") or {}).get("approver_id", None)
    signature = (r.get("approval") or {}).get("signature", None)

    sig_ok = False
    if approved and approver_id and signature:
        canonical_hash = (r.get("integrity") or {}).get("canonical_hash")
        sig_ok = verify_signature(approver_id, canonical_hash, signature)

    approve_panel = ""
    if approval_required and not approved:
        default_approver = ensure_demo_approver()
        key_ids = sorted((load_keyring().get("keys") or {}).keys())
        approve_panel = render_template_string("""
          <div class="hr"></div>
          <h3>Approve (Ed25519 signature)</h3>
          <div class="tiny muted">Appends a new signed receipt line for the same event_id.</div>
          <form method="post" action="{{ url_for('approve', event_id=event_id) }}" style="margin-top: 10px;">
            <label>Approver ID</label>
            <select name="approver_id">
              {% for kid in key_ids %}
                <option value="{{ kid }}" {% if kid == default_approver %}selected{% endif %}>{{ kid }}</option>
              {% endfor %}
            </select>
            <div style="margin-top: 12px;">
              <button type="submit">Sign & Recompute Decision</button>
            </div>
          </form>
        """, event_id=event_id, key_ids=key_ids, default_approver=default_approver)

    integ = r.get("integrity") or {}
    pol = r.get("policy") or {}

    ledger_blob = {
        "policy_id": pol.get("policy_id"),
        "policy_version": pol.get("version"),
        "rules_hash": pol.get("rules_hash"),
        "prev_hash": integ.get("prev_hash"),
        "canonical_hash": integ.get("canonical_hash"),
        "this_hash": integ.get("this_hash"),
        "approver_id": approver_id,
        "signature_alg": (r.get("approval") or {}).get("signature_alg"),
    }

    body = render_template_string("""
    <div class="grid">
      <div class="card">
        <h3>Receipt View</h3>
        <div class="tiny muted">Event: <b>{{ event_id }}</b></div>

        <label>Prompt</label>
        <pre>{{ prompt }}</pre>

        <label>Model Output (raw)</label>
        <pre>{{ model_output }}</pre>

        <label>Proposed Action</label>
        <pre>{{ proposed_action }}</pre>
      </div>

      <div class="card">
        <h3>Decision</h3>
        <div style="display:flex; align-items:center; gap:10px; margin-bottom: 8px;">
          <span class="badge {{ badge }}">{{ decision }}</span>
          <span class="tiny muted">{{ reason }}</span>
        </div>

        <h3>Policy Checks</h3>
        <ul class="checks">{{ checks|safe }}</ul>

        <div class="hr"></div>

        <div class="row">
          <div><a href="{{ url_for('receipt_json', event_id=event_id) }}">Receipt JSON</a></div>
          <div style="text-align:right;"><a href="{{ url_for('replay', event_id=event_id) }}"><b>Replay →</b></a></div>
        </div>

        {{ approve_panel|safe }}

        <div class="hr"></div>
        <h3>Ledger View</h3>
        <pre>{{ ledger }}</pre>

        <div class="hr"></div>
        <div class="tiny muted">
          Approval required: <b>{{ approval_required }}</b><br/>
          Approved: <b>{{ approved }}</b><br/>
          Signature verified: <b>{{ sig_ok }}</b>
        </div>
      </div>
    </div>
    """,
    event_id=event_id,
    prompt=(r.get("inputs") or {}).get("prompt", ""),
    model_output=(r.get("model_output") or {}).get("raw", ""),
    proposed_action=json.dumps(r.get("proposed_action") or {}, indent=2, ensure_ascii=False),
    decision=decision,
    reason=reason,
    badge=badge,
    checks=checks_html,
    approve_panel=approve_panel,
    ledger=json.dumps(ledger_blob, indent=2, ensure_ascii=False),
    approval_required=approval_required,
    approved=approved,
    sig_ok=sig_ok,
    )
    return page(body, subtitle="Left = perception + proposed. Right = decision + ledger.")


@app.post("/approve/<event_id>")
def approve(event_id: str):
    r = find_latest_by_event_id(event_id)
    if not r:
        abort(404, "Event not found.")

    approver_id = (request.form.get("approver_id") or "").strip()
    if not approver_id:
        abort(400, "Approver ID required.")
    if not get_public_key_b64(approver_id):
        abort(400, "Unknown approver ID.")

    updated = build_approval_transition(r, approver_id=approver_id, policy=DEFAULT_POLICY)
    append_receipt(updated)
    return redirect(url_for("event", event_id=event_id))


@app.get("/receipt/<event_id>.json")
def receipt_json(event_id: str):
    r = find_latest_by_event_id(event_id)
    if not r:
        abort(404, "Event not found.")

    body = render_template_string("""
      <div class="card">
        <h3>Receipt JSON</h3>
        <div class="tiny muted">Append-only record. Hash chained. Signed when approved.</div>
        <pre>{{ blob }}</pre>
        <div class="row" style="margin-top: 10px;">
          <div><a href="{{ url_for('event', event_id=event_id) }}">← Back</a></div>
          <div style="text-align:right;"><a href="{{ url_for('replay', event_id=event_id) }}"><b>Replay →</b></a></div>
        </div>
      </div>
    """, blob=json.dumps(r, indent=2, ensure_ascii=False), event_id=event_id)
    return page(body, subtitle="The receipt is the product.")


@app.get("/replay/<event_id>")
def replay(event_id: str):
    r = find_latest_by_event_id(event_id)
    if not r:
        abort(404, "Event not found.")

    receipts = read_all_receipts()
    chain_ok, chain_errors = verify_chain(receipts)

    replay_result = replay_and_compare(r, DEFAULT_POLICY)

    approved = bool((r.get("approval") or {}).get("approved", False))
    approver_id = (r.get("approval") or {}).get("approver_id", None)
    signature = (r.get("approval") or {}).get("signature", None)
    sig_present = bool(signature)
    sig_ok = False
    if approved and approver_id and signature:
        canonical_hash = (r.get("integrity") or {}).get("canonical_hash")
        sig_ok = verify_signature(approver_id, canonical_hash, signature)

    body = render_template_string("""
    <div class="grid">
      <div class="card">
        <h3>Replay Verification</h3>

        <div class="row" style="align-items:center;">
          <div>
            <div class="tiny muted">Hash chain</div>
            <div><span class="badge {{ 'ok' if chain_ok else 'bad' }}">{{ 'VERIFIED' if chain_ok else 'FAILED' }}</span></div>
          </div>
          <div>
            <div class="tiny muted">Deterministic replay</div>
            <div><span class="badge {{ 'ok' if replay_ok else 'bad' }}">{{ 'MATCH' if replay_ok else 'MISMATCH' }}</span></div>
          </div>
          <div>
            <div class="tiny muted">Signature</div>
            {% if sig_present %}
              <div><span class="badge {{ 'ok' if sig_ok else 'bad' }}">{{ 'VERIFIED' if sig_ok else 'FAILED' }}</span></div>
            {% else %}
              <div><span class="badge warn">NONE</span></div>
            {% endif %}
          </div>
        </div>

        {% if not chain_ok %}
          <div class="hr"></div>
          <h3>Chain errors</h3>
          <ul class="checks">
            {% for e in errors %}
              <li><span class="badge bad">FAIL</span> <span style="margin-left:8px;">{{ e }}</span></li>
            {% endfor %}
          </ul>
        {% endif %}

        <div class="hr"></div>
        <h3>Recomputed vs Stored</h3>
        <label>Stored</label>
        <pre>{{ stored }}</pre>
        <label>Recomputed</label>
        <pre>{{ recomputed }}</pre>

        <div class="hr"></div>
        <div class="row">
          <div><a href="{{ url_for('event', event_id=event_id) }}">← Back</a></div>
          <div style="text-align:right;"><a href="{{ url_for('receipt_json', event_id=event_id) }}">Receipt JSON</a></div>
        </div>
      </div>

      <div class="card">
        <h3>Money Shot Tools</h3>
        <div class="tiny muted">Tamper the log → verification breaks.</div>

        <div class="hr"></div>

        <form method="post" action="{{ url_for('tamper') }}">
          <button class="danger" type="submit">Tamper last log entry</button>
          <div class="tiny muted" style="margin-top:8px;">Corrupts last JSONL line → breaks hash chain.</div>
        </form>

        <div class="hr"></div>

        <div class="tiny muted">rules_hash</div>
        <pre>{{ rules_hash }}</pre>

        <div class="tiny muted">canonical_hash</div>
        <pre>{{ canonical_hash }}</pre>
      </div>
    </div>
    """,
    event_id=event_id,
    chain_ok=chain_ok,
    errors=chain_errors,
    replay_ok=replay_result["match"],
    sig_present=sig_present,
    sig_ok=sig_ok,
    stored=json.dumps(replay_result["stored"], indent=2, ensure_ascii=False),
    recomputed=json.dumps(replay_result["recomputed"], indent=2, ensure_ascii=False),
    rules_hash=compute_rules_hash(DEFAULT_POLICY.as_text()),
    canonical_hash=(r.get("integrity") or {}).get("canonical_hash"),
    )
    return page(body, subtitle="Replay = same inputs → same checks → same outcome → same receipt.")


@app.post("/tamper")
def tamper():
    ok, msg = tamper_last_log_line(field_path="decision.reason")
    if not ok:
        abort(400, msg)
    return redirect(url_for("verify"))


@app.get("/verify")
def verify():
    receipts = read_all_receipts()
    ok, errors = verify_chain(receipts)

    body = render_template_string("""
      <div class="card">
        <h3>Log Verification</h3>
        <div>
          <span class="badge {{ 'ok' if ok else 'bad' }}">{{ 'VERIFIED' if ok else 'FAILED' }}</span>
          <span class="tiny muted" style="margin-left: 10px;">records={{ n }}</span>
        </div>

        <div class="hr"></div>

        <div class="row">
          <div>
            <form method="post" action="{{ url_for('tamper') }}">
              <button class="danger" type="submit">Tamper last log entry</button>
              <div class="tiny muted" style="margin-top:8px;">One click: break the chain.</div>
            </form>
          </div>
          <div>
            <form method="post" action="{{ url_for('reset_demo') }}">
              <button class="secondary" type="submit">Reset demo data</button>
              <div class="tiny muted" style="margin-top:8px;">Deletes pat_log.jsonl only (keeps keys).</div>
            </form>
          </div>
        </div>

        {% if not ok %}
          <div class="hr"></div>
          <h3>Errors</h3>
          <ul class="checks">
            {% for e in errors %}
              <li><span class="badge bad">FAIL</span> <span style="margin-left:8px;">{{ e }}</span></li>
            {% endfor %}
          </ul>
        {% else %}
          <div class="hr"></div>
          <div class="muted">Chain is consistent. Edit any line in JSONL and this turns red.</div>
        {% endif %}
      </div>
    """, ok=ok, errors=errors, n=len(receipts))
    return page(body, subtitle="Tamper-evidence check for the append-only ledger.")


@app.post("/reset")
def reset_demo():
    reset_log()
    return redirect(url_for("index"))


@app.get("/keys")
def keys():
    default_approver = ensure_demo_approver()
    kr = load_keyring()
    keys = kr.get("keys") or {}

    items = ""
    for kid in sorted(keys.keys()):
        pub = keys[kid].get("public_key_b64")
        created = keys[kid].get("created_utc")
        items += f"""
          <li style="margin: 10px 0;">
            <b>{kid}</b> <span class="tiny muted">created={created}</span>
            <div class="tiny muted" style="margin-top:6px;">public_key_b64</div>
            <pre>{pub}</pre>
          </li>
        """

    body = render_template_string("""
      <div class="card">
        <h3>Approver Keys</h3>
        <div class="tiny muted">Demo keyring stores Ed25519 keys locally (private key included for demo).</div>
        <div class="hr"></div>

        <div class="row">
          <div>
            <form method="post" action="{{ url_for('new_key') }}">
              <label>New approver ID</label>
              <input name="approver_id" placeholder="alice.ops" required/>
              <div style="margin-top: 12px;">
                <button type="submit">Generate keypair</button>
              </div>
            </form>
          </div>
          <div>
            <div class="tiny muted">Default approver</div>
            <pre>{{ default_approver }}</pre>
          </div>
        </div>

        <div class="hr"></div>
        <h3>Public keys</h3>
        <ul style="list-style:none; padding:0; margin:0;">
          {{ items|safe }}
        </ul>
      </div>
    """, items=items, default_approver=default_approver)
    return page(body, subtitle="Human approval = verifiable signature over receipt payload.")


@app.post("/keys/new")
def new_key():
    approver_id = (request.form.get("approver_id") or "").strip()
    if not approver_id:
        abort(400, "approver_id required")
    new_approver_keypair(approver_id)
    return redirect(url_for("keys"))


if __name__ == "__main__":
    ensure_log_exists()
    ensure_keyring_exists()
    ensure_demo_approver()

    print(f"{APP_NAME} running")
    print(f"Log:     {os.path.abspath(LOG_PATH)}")
    print(f"Keyring: {os.path.abspath(KEYRING_PATH)}")
    print("Open: http://127.0.0.1:5000")

    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=True)
