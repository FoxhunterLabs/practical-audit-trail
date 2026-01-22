from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple, Optional

APP_NAME = "PAT v0.2"
LOG_PATH = "pat_log.jsonl"
KEYRING_PATH = "pat_keys.json"

DEFAULT_POLICY_ID = "PAT_DEMO_001"
DEFAULT_POLICY_VERSION = "0.2.0"

HIGH_STAKES_ACTIONS = {"LOCKDOWN", "DISPATCH_POLICE", "ESCALATE_INCIDENT"}
LOW_STAKES_ACTIONS = {"NOTIFY", "LOG_ONLY", "NOOP"}
ALL_ACTIONS = HIGH_STAKES_ACTIONS | LOW_STAKES_ACTIONS

CONFIDENCE_THRESHOLD = 0.85


@dataclass(frozen=True)
class PolicyRuleSet:
    policy_id: str
    version: str
    high_stakes_actions: Tuple[str, ...]
    confidence_threshold: float

    def as_text(self) -> str:
        # Deterministic serialization target for hashing
        import json
        return json.dumps(
            {
                "policy_id": self.policy_id,
                "version": self.version,
                "high_stakes_actions": list(self.high_stakes_actions),
                "confidence_threshold": self.confidence_threshold,
                "notes": "Demo policy: high-stakes require human approval; confidence threshold gate.",
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )


DEFAULT_POLICY = PolicyRuleSet(
    policy_id=DEFAULT_POLICY_ID,
    version=DEFAULT_POLICY_VERSION,
    high_stakes_actions=tuple(sorted(HIGH_STAKES_ACTIONS)),
    confidence_threshold=CONFIDENCE_THRESHOLD,
)


PRESETS: Dict[str, Dict[str, Any]] = {
    "low_notify_permit": {
        "name": "Low-stakes: NOTIFY @ 0.92 → PERMITTED",
        "prompt": "Simulated report: suspicious drone sighting near perimeter. Low stakes notification.",
        "model_output": "Recommendation: Notify site security. confidence: 0.92",
        "action_type": "NOTIFY",
        "action_target": "SITE_SECURITY",
        "action_params": {"channel": "radio"},
        "confidence": None,
    },
    "high_lockdown_block": {
        "name": "High-stakes: LOCKDOWN @ 0.62 → BLOCKED",
        "prompt": "Simulated report: unverified threat near school grounds. No confirmation from trusted sources.",
        "model_output": "Recommendation: Lock down the school immediately. confidence: 0.62",
        "action_type": "LOCKDOWN",
        "action_target": "SCHOOL_12",
        "action_params": {"duration_min": 30},
        "confidence": None,
    },
    "high_lockdown_ready": {
        "name": "High-stakes: LOCKDOWN @ 0.92 (needs approval) → SIGN to permit",
        "prompt": "Simulated report: credible threat indicator + corroboration pending. High-stakes action proposed.",
        "model_output": "Recommendation: Lock down the school and notify authorities. confidence: 0.92",
        "action_type": "LOCKDOWN",
        "action_target": "SCHOOL_12",
        "action_params": {"duration_min": 30},
        "confidence": None,
    },
}
