from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .config import ALL_ACTIONS, PolicyRuleSet


def extract_confidence(model_output_raw: str) -> Optional[float]:
    s = (model_output_raw or "").lower()
    m = re.search(r"confidence\s*[:=]\s*([0-9]*\.?[0-9]+)\s*%?", s)
    if not m:
        return None
    val = float(m.group(1))
    if "%" in m.group(0) or val > 1.0:
        if val > 1.0:
            val = val / 100.0
    return max(0.0, min(1.0, val))


def run_policy_checks(
    proposed_action_type: str,
    confidence: Optional[float],
    approval_present: bool,
    policy: PolicyRuleSet,
) -> Tuple[List[Dict[str, Any]], str, str, bool]:
    checks: List[Dict[str, Any]] = []
    action_type = (proposed_action_type or "").strip().upper()

    approval_required = action_type in set(policy.high_stakes_actions)

    allowed = action_type in ALL_ACTIONS
    checks.append(
        {
            "check_id": "ALLOWED_ACTIONS",
            "result": "PASS" if allowed else "FAIL",
            "details": {"action_type": action_type, "allowed": allowed},
        }
    )
    if not allowed:
        return checks, "BLOCKED", "Action not in allowed list", approval_required

    if confidence is None:
        checks.append(
            {
                "check_id": "CONFIDENCE_PRESENT",
                "result": "FAIL",
                "details": {"confidence": None, "note": "No confidence provided/parsed"},
            }
        )
    else:
        checks.append(
            {
                "check_id": "CONFIDENCE_THRESHOLD",
                "result": "PASS" if confidence >= policy.confidence_threshold else "FAIL",
                "details": {"confidence": confidence, "threshold": policy.confidence_threshold},
            }
        )

    if approval_required:
        checks.append(
            {
                "check_id": "HUMAN_AUTH_REQUIRED",
                "result": "PASS" if approval_present else "FAIL",
                "details": {"required": True, "present": approval_present},
            }
        )
    else:
        checks.append(
            {
                "check_id": "HUMAN_AUTH_NOT_REQUIRED",
                "result": "PASS",
                "details": {"required": False, "present": approval_present},
            }
        )

    if approval_required:
        if not approval_present:
            return checks, "BLOCKED", "High-stakes action requires human authorization", approval_required
        if confidence is None or confidence < policy.confidence_threshold:
            return checks, "BLOCKED", "Confidence < threshold for high-stakes action", approval_required
        return checks, "PERMITTED", "Approved + confidence >= threshold", approval_required

    if confidence is None:
        return checks, "BLOCKED", "No confidence available", approval_required
    if confidence < policy.confidence_threshold:
        return checks, "BLOCKED", "Confidence < threshold", approval_required
    return checks, "PERMITTED", "Confidence >= threshold", approval_required
