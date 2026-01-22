from __future__ import annotations

import datetime as dt
import json
from typing import Any, Dict, Optional

from .config import PolicyRuleSet
from .hashing import compute_canonical_hash, compute_rules_hash, compute_this_hash, canonical_json
from .ledger import read_all_receipts, get_last_hash
from .keys import get_public_key_b64, sign_with_approver
from .policy import extract_confidence, run_policy_checks

import threading

_event_counter_lock = threading.Lock()


def next_event_id() -> str:
    now = dt.datetime.utcnow().replace(microsecond=0)
    ts = now.isoformat() + "Z"
    with _event_counter_lock:
        n = len(read_all_receipts()) + 1
    return f"{ts}_{n:05d}"


def build_new_receipt(
    prompt: str,
    model_output_raw: str,
    proposed_action_type: str,
    proposed_action_target: str,
    proposed_action_params: Dict[str, Any],
    confidence_override: Optional[float],
    policy: PolicyRuleSet,
) -> Dict[str, Any]:
    receipts = read_all_receipts()
    prev_hash = get_last_hash(receipts)

    event_id = next_event_id()
    ts_utc = event_id.split("_")[0]

    parsed_conf = extract_confidence(model_output_raw)
    confidence = confidence_override if confidence_override is not None else parsed_conf

    checks, decision, reason, approval_required = run_policy_checks(
        proposed_action_type=proposed_action_type,
        confidence=confidence,
        approval_present=False,
        policy=policy,
    )

    rules_hash = compute_rules_hash(policy.as_text())

    receipt: Dict[str, Any] = {
        "event_id": event_id,
        "ts_utc": ts_utc,
        "inputs": {"prompt": prompt, "context": {"source": "sim", "channel": "demo"}},
        "model_output": {
            "raw": model_output_raw,
            "model": "demo-model",
            "temperature": 0.2,
            "parsed_confidence": parsed_conf,
            "effective_confidence": confidence,
        },
        "proposed_action": {
            "type": (proposed_action_type or "").strip().upper(),
            "target": (proposed_action_target or "").strip(),
            "params": proposed_action_params or {},
        },
        "policy": {
            "policy_id": policy.policy_id,
            "version": policy.version,
            "rules_hash": rules_hash,
        },
        "policy_checks": checks,
        "decision": {"result": decision, "reason": reason, "decision_by": "policy_engine"},
        "approval": {
            "required": approval_required,
            "approved": False,
            "approver_id": None,
            "public_key_b64": None,
            "signature_alg": None,
            "signature": None,
            "signed_ts_utc": None,
        },
        "actuation": {"attempted": False, "executed": False, "actuation_event_id": None},
        "integrity": {"prev_hash": prev_hash, "canonical_hash": None, "this_hash": None},
    }

    canonical_hash = compute_canonical_hash(receipt)
    receipt["integrity"]["canonical_hash"] = canonical_hash
    receipt["integrity"]["this_hash"] = compute_this_hash(prev_hash, canonical_hash)
    return receipt


def build_approval_transition(
    receipt_latest: Dict[str, Any],
    approver_id: str,
    policy: PolicyRuleSet,
) -> Dict[str, Any]:
    base = json.loads(canonical_json(receipt_latest))

    base["approval"]["required"] = True
    base["approval"]["approved"] = True
    base["approval"]["approver_id"] = approver_id
    base["approval"]["signature_alg"] = "ed25519"
    base["approval"]["public_key_b64"] = get_public_key_b64(approver_id)
    base["approval"]["signed_ts_utc"] = dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    confidence = base.get("model_output", {}).get("effective_confidence", None)
    action_type = base.get("proposed_action", {}).get("type", "")

    checks, decision, reason, _approval_required = run_policy_checks(
        proposed_action_type=action_type,
        confidence=confidence,
        approval_present=True,
        policy=policy,
    )
    base["policy_checks"] = checks
    base["decision"]["result"] = decision
    base["decision"]["reason"] = reason

    base["actuation"]["attempted"] = decision == "PERMITTED"
    base["actuation"]["executed"] = False
    base["actuation"]["actuation_event_id"] = None

    receipts = read_all_receipts()
    prev_hash = get_last_hash(receipts)
    base["integrity"]["prev_hash"] = prev_hash

    canonical_hash = compute_canonical_hash(base)
    base["integrity"]["canonical_hash"] = canonical_hash

    base["approval"]["signature"] = sign_with_approver(approver_id, canonical_hash)

    base["integrity"]["this_hash"] = compute_this_hash(prev_hash, canonical_hash)
    return base
