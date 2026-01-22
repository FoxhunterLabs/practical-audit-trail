from __future__ import annotations

from pat.receipt import build_new_receipt
from pat.replay import replay_and_compare
from pat.config import DEFAULT_POLICY


def test_replay_determinism_matches():
    r = build_new_receipt(
        prompt="test prompt",
        model_output_raw="Recommendation: Notify. confidence: 0.92",
        proposed_action_type="NOTIFY",
        proposed_action_target="X",
        proposed_action_params={},
        confidence_override=None,
        policy=DEFAULT_POLICY,
    )
    result = replay_and_compare(r, DEFAULT_POLICY)
    assert result["match"] is True
