from __future__ import annotations

import base64
import datetime as dt
import json
import os
import threading
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from .config import KEYRING_PATH

_key_lock = threading.Lock()


def ensure_keyring_exists() -> None:
    if not os.path.exists(KEYRING_PATH):
        with open(KEYRING_PATH, "w", encoding="utf-8") as f:
            f.write(json.dumps({"keys": {}}, sort_keys=True, separators=(",", ":"), ensure_ascii=False))


def load_keyring() -> Dict[str, Any]:
    ensure_keyring_exists()
    with open(KEYRING_PATH, "r", encoding="utf-8") as f:
        return json.loads(f.read() or "{}") or {"keys": {}}


def save_keyring(data: Dict[str, Any]) -> None:
    with open(KEYRING_PATH, "w", encoding="utf-8") as f:
        f.write(json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False))


def _privkey_to_b64(priv: Ed25519PrivateKey) -> str:
    raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode("ascii")


def _pubkey_to_b64(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _b64_to_privkey(b64: str) -> Ed25519PrivateKey:
    raw = base64.b64decode(b64.encode("ascii"))
    return Ed25519PrivateKey.from_private_bytes(raw)


def _b64_to_pubkey(b64: str) -> Ed25519PublicKey:
    raw = base64.b64decode(b64.encode("ascii"))
    return Ed25519PublicKey.from_public_bytes(raw)


def ensure_demo_approver() -> str:
    with _key_lock:
        kr = load_keyring()
        keys = kr.get("keys", {})
        if keys:
            return sorted(keys.keys())[0]

        approver_id = "j.wells"
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()

        keys[approver_id] = {
            "alg": "ed25519",
            "private_key_b64": _privkey_to_b64(priv),  # demo convenience
            "public_key_b64": _pubkey_to_b64(pub),
            "created_utc": dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        }
        kr["keys"] = keys
        save_keyring(kr)
        return approver_id


def get_public_key_b64(approver_id: str) -> Optional[str]:
    kr = load_keyring()
    entry = (kr.get("keys") or {}).get(approver_id)
    if not entry:
        return None
    return entry.get("public_key_b64")


def sign_with_approver(approver_id: str, message: str) -> str:
    with _key_lock:
        kr = load_keyring()
        entry = (kr.get("keys") or {}).get(approver_id)
        if not entry:
            raise ValueError("Unknown approver_id")
        priv_b64 = entry.get("private_key_b64")
        if not priv_b64:
            raise ValueError("No private key available for approver")
        priv = _b64_to_privkey(priv_b64)

    sig = priv.sign(message.encode("utf-8"))
    return "ed25519:" + base64.b64encode(sig).decode("ascii")


def verify_signature(approver_id: str, message: str, signature: str) -> bool:
    if not signature or not signature.startswith("ed25519:"):
        return False
    sig_b64 = signature.split(":", 1)[1]
    try:
        sig = base64.b64decode(sig_b64.encode("ascii"))
    except Exception:
        return False

    pub_b64 = get_public_key_b64(approver_id)
    if not pub_b64:
        return False
    pub = _b64_to_pubkey(pub_b64)

    try:
        pub.verify(sig, message.encode("utf-8"))
        return True
    except Exception:
        return False


def new_approver_keypair(approver_id: str) -> None:
    approver_id = (approver_id or "").strip()
    if not approver_id:
        raise ValueError("approver_id required")

    with _key_lock:
        kr = load_keyring()
        keys = kr.get("keys") or {}
        if approver_id in keys:
            raise ValueError("approver_id already exists")

        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        keys[approver_id] = {
            "alg": "ed25519",
            "private_key_b64": _privkey_to_b64(priv),  # demo convenience
            "public_key_b64": _pubkey_to_b64(pub),
            "created_utc": dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        }
        kr["keys"] = keys
        save_keyring(kr)
