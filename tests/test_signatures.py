from __future__ import annotations

from pat.keys import ensure_demo_approver, verify_signature
from pat.receipt import build_new_receipt, build_approval_transition
from pat.config import DEFAULT_POLICY


def test_ed25519_signature_verifies(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    approver_id = ensure_demo_approver()

    r = build_new_receipt(
        prompt="x",
        model_output_raw="confidence: 0.92",
        proposed_action_type="LOCKDOWN",
        proposed_action_target="SCHOOL_12",
        proposed_action_params={},
        confidence_override=None,
        policy=DEFAULT_POLICY,
    )

    approved = build_approval_transition(r, approver_id=approver_id, policy=DEFAULT_POLICY)

    canonical_hash = approved["integrity"]["canonical_hash"]
    signature = approved["approval"]["signature"]

    assert verify_signature(approver_id, canonical_hash, signature) is True
