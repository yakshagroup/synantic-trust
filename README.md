# Audit seal public keys — the trust anchor of the evidence receipts

This directory is the **publication point** for the public keys that verify
the sealed audit-chain receipts (roadmap 19.12/D10). The GitHub repo's
commit history is the point: a key published here at a known commit has a
timestamp and content hash nobody — including the platform's owners — can
rewrite without the change being visible.

**Rule:** the private halves never live in this repo or any machine that
runs the platform's code. Only the public keys and the manifest are here.

## The manifest is the contract

`KEY_MANIFEST.json` lists every key that has ever signed a receipt: its id,
algorithm, creation date, and status (`active` / `retired` / `compromised`).
A receipt is verified against the key its `key_id` names — old keys stay
listed (and published) forever, because receipts signed under them must
remain verifiable for the life of the evidence.

## Files

| File | What it is |
|---|---|
| `KEY_MANIFEST.json` | The authoritative list of keys and their status |
| `ml-dsa-65/` | ML-DSA-65 public keys (DER, one file per key_id) |
| `slh-dsa-sha2-128s/` | SLH-DSA-SHA2-128s public keys (PEM, one per key_id) |
| `INCIDENT_PROCEDURE.md` | What to do if a private key is lost or leaks |

## How a stranger verifies a receipt with these files

1. Fetch the receipt JSONL from the audit-receipts bucket (or wherever it
   was presented to them), plus `verify_audit_receipt.py` from the
   bucket's `verify/` prefix.
2. Look up the receipt's `key_id` in `KEY_MANIFEST.json`, take the matching
   public key file from this repo.
3. Run: `python verify_audit_receipt.py RECEIPTS.jsonl <ml-dsa-public.der>
   --slh-pub <slh-public.pem>`
4. Exit code 0 = the round verifies. Nothing about this requires trusting
   the platform: only the key in this repo and the math in the script.

## Publishing a new key (rotation)

Run `core/backend/scripts/publish_audit_seal_keys.py` from the platform
side; it writes the new key files and rewrites the manifest with the old
key marked `retired` and dated. The commit that lands in this repo *is*
the publication — no other ceremony exists or is needed.