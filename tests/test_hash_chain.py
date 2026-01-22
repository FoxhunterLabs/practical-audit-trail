from __future__ import annotations

import os

from pat.ledger import (
    append_receipt,
    read_all_receipts,
    reset_log,
    tamper_last_log_line,
    verify_chain,
)
from pat.receipt import build_new_receipt
from pat.config import DEFAULT_POLICY


def test_hash_chain_breaks_on_tamper(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    # ensure clean log
    reset_log()

    r1 = build_new_receipt(
        prompt="test",
        model_output_raw="confidence: 0.92",
        proposed_action_type="NOTIFY",
        proposed_action_target="X",
        proposed_action_params={},
        confidence_override=None,
        policy=DEFAULT_POLICY,
    )
    append_receipt(r1)

    receipts = read_all_receipts()
    ok, errors = verify_chain(receipts)
    assert ok, errors

    # Tamper last entry
    ok_t, _ = tamper_last_log_line()
    assert ok_t

    receipts2 = read_all_receipts()
    ok2, errors2 = verify_chain(receipts2)
    assert not ok2
    assert len(errors2) > 0
