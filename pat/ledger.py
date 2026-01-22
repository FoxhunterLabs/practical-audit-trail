from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, List, Optional, Tuple

from .config import LOG_PATH
from .hashing import canonical_json, compute_canonical_hash, compute_this_hash

_log_lock = threading.Lock()


def ensure_log_exists() -> None:
    if not os.path.exists(LOG_PATH):
        with open(LOG_PATH, "w", encoding="utf-8") as f:
            pass


def read_all_receipts() -> List[Dict[str, Any]]:
    ensure_log_exists()
    out: List[Dict[str, Any]] = []
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out


def get_last_hash(receipts: List[Dict[str, Any]]) -> str:
    if not receipts:
        return "sha256:" + "0" * 64
    integ = receipts[-1].get("integrity") or {}
    return integ.get("this_hash") or ("sha256:" + "0" * 64)


def append_receipt(receipt: Dict[str, Any]) -> None:
    ensure_log_exists()
    line = canonical_json(receipt)
    with _log_lock:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def find_latest_by_event_id(event_id: str) -> Optional[Dict[str, Any]]:
    receipts = read_all_receipts()
    for r in reversed(receipts):
        if r.get("event_id") == event_id:
            return r
    return None


def verify_chain(receipts: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    prev = "sha256:" + "0" * 64

    for idx, r in enumerate(receipts):
        integ = r.get("integrity") or {}
        stored_prev = integ.get("prev_hash")
        stored_this = integ.get("this_hash")
        stored_canon = integ.get("canonical_hash")

        if stored_prev != prev:
            errors.append(f"Line {idx+1}: prev_hash mismatch (expected {prev}, got {stored_prev})")

        recomputed_canon = compute_canonical_hash(r)
        if stored_canon != recomputed_canon:
            errors.append(f"Line {idx+1}: canonical_hash mismatch (expected {recomputed_canon}, got {stored_canon})")

        recomputed_this = compute_this_hash(prev, recomputed_canon)
        if stored_this != recomputed_this:
            errors.append(f"Line {idx+1}: this_hash mismatch (expected {recomputed_this}, got {stored_this})")

        prev = stored_this or recomputed_this

    return (len(errors) == 0), errors


def tamper_last_log_line(field_path: str = "decision.reason") -> Tuple[bool, str]:
    ensure_log_exists()
    with _log_lock:
        with open(LOG_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()
        if not lines:
            return False, "Log is empty; nothing to tamper."

        last = json.loads(lines[-1])

        try:
            if field_path == "decision.reason":
                last["decision"]["reason"] = (last["decision"].get("reason") or "") + " [TAMPERED]"
            elif field_path == "model_output.raw":
                last["model_output"]["raw"] = (last["model_output"].get("raw") or "") + "\n[TAMPERED]"
            else:
                last["tampered"] = True
        except Exception:
            last["tampered"] = True

        lines[-1] = canonical_json(last) + "\n"
        with open(LOG_PATH, "w", encoding="utf-8") as f:
            f.writelines(lines)

    return True, "Last log entry corrupted. Verification should now fail."


def reset_log() -> None:
    ensure_log_exists()
    with _log_lock:
        with open(LOG_PATH, "w", encoding="utf-8") as f:
            f.write("")
