from __future__ import annotations

import hashlib
import json
from typing import Any, Dict


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_rules_hash(policy_rules_text: str) -> str:
    return "sha256:" + sha256_hex(policy_rules_text.encode("utf-8"))


def receipt_canonical_payload(receipt: Dict[str, Any]) -> Dict[str, Any]:
    r = json.loads(canonical_json(receipt))  # deterministic deep copy
    if isinstance(r.get("integrity"), dict):
        r["integrity"].pop("this_hash", None)
        r["integrity"].pop("verified_at", None)
    if isinstance(r.get("approval"), dict):
        r["approval"].pop("signature", None)
    return r


def compute_canonical_hash(receipt: Dict[str, Any]) -> str:
    payload = receipt_canonical_payload(receipt)
    canon = canonical_json(payload).encode("utf-8")
    return "sha256:" + sha256_hex(canon)


def compute_this_hash(prev_hash: str, canonical_hash: str) -> str:
    msg = (prev_hash + "|" + canonical_hash).encode("utf-8")
    return "sha256:" + sha256_hex(msg)
