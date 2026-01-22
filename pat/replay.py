from __future__ import annotations

from typing import Any, Dict

from .config import PolicyRuleSet
from .hashing import canonical_json, sha256_hex
from .policy import run_policy_checks


def replay_and_compare(receipt: Dict[str, Any], policy: PolicyRuleSet) -> Dict[str, Any]:
    action_type = receipt.get("proposed_action", {}).get("type", "")
    confidence = receipt.get("model_output", {}).get("effective_confidence", None)
    approved = bool(receipt.get("approval", {}).get("approved", False))

    checks, decision, reason, approval_required = run_policy_checks(
        proposed_action_type=action_type,
        confidence=confidence,
        approval_present=approved,
        policy=policy,
    )

    stored_checks = receipt.get("policy_checks", [])
    stored_decision = receipt.get("decision", {}).get("result")
    stored_reason = receipt.get("decision", {}).get("reason")

    recomputed_blob = canonical_json({"checks": checks, "decision": decision, "reason": reason})
    stored_blob = canonical_json({"checks": stored_checks, "decision": stored_decision, "reason": stored_reason})

    return {
        "recomputed": {"policy_checks": checks, "decision": decision, "reason": reason, "approval_required": approval_required},
        "stored": {"policy_checks": stored_checks, "decision": stored_decision, "reason": stored_reason},
        "match": sha256_hex(recomputed_blob.encode("utf-8")) == sha256_hex(stored_blob.encode("utf-8")),
    }
