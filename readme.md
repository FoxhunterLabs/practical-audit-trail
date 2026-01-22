<img width="1236" height="947" alt="image" src="https://github.com/user-attachments/assets/c2483b93-6abb-4d1e-93ff-d64bdab97d29" />

````markdown
# Practical Audit Trail (PAT)

**PAT** is a tiny Python demo that turns a single AI output into a **courtroom-grade receipt**.

It captures:

- What was perceived (inputs)
- What was proposed (model output + action)
- What policy gates existed (rules + checks)
- What was permitted/blocked (decision + reason)
- Who approved (verifiable signature)
- What executed (actuation attempt stub)

Then it writes an **append-only, hash-chained ledger** and gives you a **Replay** button that reproduces the same outcome from the same record.

**Receipts, not vibes.**

---

## What this repo contains

- A 1-page Flask UI
- A deterministic policy engine
- Append-only JSONL ledger with **hash chaining**
- Human approval using **Ed25519 signatures** (public-key verifiable)
- Deterministic **replay verification**
- A built-in **tamper test** button (break the ledger on purpose)

---

## Quickstart

### 1) Install
```bash
pip install -r requirements.txt
````

### 2) Run the demo app

```bash
python app.py
```

Open:

```
http://127.0.0.1:5000
```

### 3) Run tests

```bash
pytest -q
```

---

## Demo flow (90 seconds)

1. **Click a preset**

   * `Low-stakes: NOTIFY @ 0.92 → PERMITTED`
   * `High-stakes: LOCKDOWN @ 0.62 → BLOCKED`
   * `High-stakes: LOCKDOWN @ 0.92 → SIGN to permit`

2. Go into the event → hit **Replay**

   * ✅ Hash chain verified
   * ✅ Replay match
   * ✅ Signature verified (if approved)

3. Click **Tamper last log entry**

   * Go to **Verify Log**
   * 💥 verification fails

That’s the money shot:
**edit history → chain breaks → receipts don’t lie.**

---

## Files created locally (not committed)

PAT generates demo artifacts locally:

* `pat_log.jsonl` — append-only ledger (JSONL)
* `pat_keys.json` — demo keyring (Ed25519 keypairs)

These are ignored by `.gitignore`.

---

## Ledger format

Receipts are stored as **one JSON object per line**:

Example fields (simplified):

```json
{
  "event_id": "2026-01-21T13:02:11Z_00041",
  "inputs": { "prompt": "..." },
  "model_output": { "raw": "...", "effective_confidence": 0.92 },
  "proposed_action": { "type": "LOCKDOWN", "target": "SCHOOL_12" },
  "policy_checks": [ ... ],
  "decision": { "result": "BLOCKED", "reason": "..." },
  "approval": { "approved": false, "signature": null },
  "integrity": {
    "prev_hash": "sha256:...",
    "canonical_hash": "sha256:...",
    "this_hash": "sha256:..."
  }
}
```

---

## Integrity model

Each receipt is chained to the previous:

* `canonical_hash = sha256(canonical_receipt_without_signature_and_this_hash)`
* `this_hash = sha256(prev_hash | canonical_hash)`

Edit any record → hashes break → verification fails.

This is not a blockchain.
It’s just **tamper-evidence** you can explain in one sentence.

---

## Signature model

High-stakes actions require human approval.

When approved:

* Receipt computes `canonical_hash`
* Approver signs it using **Ed25519**
* Signature verifies using the stored public key

This demo stores keys locally for convenience.
Real systems should keep private keys out of the application.

---

## Repo layout

```
practical-audit-trail/
  app.py
  requirements.txt
  pyproject.toml
  LICENSE
  .gitignore
  pat/
    config.py
    hashing.py
    policy.py
    ledger.py
    keys.py
    receipt.py
    replay.py
  tests/
    test_hash_chain.py
    test_replay.py
    test_signatures.py
```

---

## What PAT is (and isn’t)

✅ **Is**

* deterministic governance demo
* policy gating + audit receipt generator
* tamper-evident ledger + replay proof

❌ **Is not**

* a model alignment framework
* a replacement for safety engineering
* a “trust me bro” policy doc

PAT is just the **receipt layer**.

---

## License

MIT — do whatever you want.

```
```
