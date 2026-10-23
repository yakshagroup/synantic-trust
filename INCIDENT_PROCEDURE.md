# Incident procedure — audit seal key events

The seal's weakest point was never the math; it is the private keys. This
file is what to do when the thing nobody plans for happens. Read it before
you need it — during an incident is too late to discover a missing step.

## 1. A private key is suspected leaked (or the secret host is compromised)

A leaked seal key does not let anyone READ history — it lets them forge
receipts for rounds that never ran, which is worse: it poisons the
future, not the past. The response is rotation with disclosure, never
silence.

1. **Mint new keys immediately.** `python scripts/mint_audit_seal_keys.py
   --out-dir <new-secret-dir>` (on a machine you believe is clean).
2. **Mark the old key compromised in the manifest — do not delete it:**
   set its `"status": "compromised"` and `"retired_on"` to the date. Run
   `python scripts/publish_audit_seal_keys.py --keys <new-secret-dir>`,
   which records the new keys as active and the old as retired; edit the
   old rows to `compromised` before committing.
3. **Publish (commit + push).** The commit message says plainly:
   "audit-seal: key <id> compromised, rotated to <new id>, from <date>".
4. **Point the deployment at the new keys** (env `AUDIT_PQC_*_PATH`) and
   restart the scheduler. The first sealed round under the new keys is
   the start of the new trust period.
5. **Disclose the date range in writing.** Receipts signed by the
   compromised key between its mint date and the rotation are *still
   valid evidence of what the platform did* — the hash chain and the
   Bitcoin anchor stand — but they no longer prove the platform's
   authorship as strongly. State the window in the incident report so an
   auditor can weigh them honestly.

## 2. A private key is lost (no leak, just gone)

Lost is better than leaked: nobody can forge, the platform just cannot
sign. Response:

1. Mint new keys, publish, repoint the env — same as above minus the
   `compromised` marking (status stays `retired`).
2. Every receipt before the rotation verifies as before. Nothing about
   the past changes.

## 3. A signature stops verifying in production (no incident you know of)

This is what the `AIBrainAuditPQCSealStale` / `SlhStale` alerts are for.
Check the runbook first (key file readable, openssl version, key rotation
forgotten mid-deploy) before assuming compromise: 9 times out of 10 it
is a deploy that rotated keys without publishing them.

## What never to do

- **Never "re-sign" old receipts under a new key.** A receipt's proof is
  that it was signed when the round ran. Re-signing history is the exact
  attack the whole design exists to make visible.
- **Never delete a retired key's row or file from keys/.** Old receipts
  verify against old keys forever; removing one makes every receipt
  under it unverifiable — an unforced own goal.
- **Never rotate quietly as an incident fix.** A swap without a dated
  commit and a manifest entry makes every receipt after the swap look
  forged, because the verifier cannot tell your fix from an attacker's
  substitution. Rotation is an event, and events are recorded.