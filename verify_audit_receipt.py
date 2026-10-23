#!/usr/bin/env python3
"""Standalone verifier for sealed audit-chain receipts (roadmap 19.12/D10).

THIS FILE IS AN EVIDENCE ARTIFACT, NOT PART OF THE APPLICATION. It is
uploaded beside the receipts in object storage on purpose: the roadmap's
rule is that a verifier in the future must be able to check a round with
only (1) the receipt file, (2) the published public key, and (3) this
script — even if the company, the platform, and today's cryptography
libraries are all gone. It therefore runs on a bare Python 3.10+ with
NO third-party imports and must stay that way.

It verifies what the application verifies — the ML-DSA-65 signature over
the round's sealed payload — plus the Merkle root arithmetic that binds
the per-tenant head lines to the receipt. ML-DSA-65 signature checking in
pure Python is deliberately NOT reimplemented here (getting lattice
verification subtly wrong would give false confidence); this script
delegates that single step to the installed cryptography stack and checks
everything else itself. When the stack of the day changes, the receipt
format and the Merkle arithmetic below still hold — the part worth
pinning in a language that does not rot.

Usage:
    python verify_audit_receipt.py RECEIPTS.jsonl PUBLIC_KEY.der
    # optional second seal: --slh-pub public-slh.pem checks it too

Exit codes: 0 = all receipts verify, 1 = at least one fails or is
malformed, 2 = the files could not be read at all.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

ALGORITHM = "ML-DSA-65"
ALGORITHM_2 = "SLH-DSA-SHA2-128s"


def sealed_payload(merkle_root: str, round_started_at: str, tenant_count: int) -> str:
    """Byte-exact with app.modules.audit.pqc_seal.sealed_payload.

    Duplicated rather than imported: the point of this script is that the
    app package is not on the machine. If the app's payload format changes
    (append-only, by convention), this copy must be updated in the same
    commit and re-uploaded to object storage.
    """
    return json.dumps(
        {
            "algorithm": ALGORITHM,
            "merkle_root": merkle_root,
            "round_started_at": round_started_at,
            "tenant_count": tenant_count,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def merkle_root_of(leaves: list[str]) -> str:
    """SHA-256 Merkle root, duplicates kept, odd level promoted.

    Byte-exact with app.modules.audit.pqc_seal.merkle_root_of; the empty
    round is the hash of nothing, as Merkle defined it.
    """
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    level = [hashlib.sha256(leaf.encode()).hexdigest() for leaf in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(f"{level[i]}{level[i + 1]}".encode()).hexdigest()
            for i in range(0, len(level), 2)
        ]
    return level[0]


def _load_public_key(der_path: str):
    """Load the public key with whatever cryptography stack is installed.

    The receipts record FIPS 204 (ML-DSA-65); pyca/cryptography 47+ reads
    that. If the stack of the day needs another loader, change only this
    function — the receipt format does not change with it.
    """
    from cryptography.hazmat.primitives import serialization

    with open(der_path, "rb") as handle:
        return serialization.load_der_public_key(handle.read())


def _verify_signature(public_key, signature: bytes, payload: bytes) -> bool:
    try:
        public_key.verify(signature, payload)
        return True
    except Exception:  # noqa: BLE001 - a failed check is False, not a crash
        return False


def _is_anchor_line(parsed: dict) -> bool:
    # Phase 3's anchors block: {"anchors_attempted": true, ...} — carries no
    # "algorithm" and no "head"; recorded in the report, verified by its
    # own services (OpenTimestamps / TSA), never by this script's keys.
    return parsed.get("anchors_attempted") is True and "head" not in parsed


def _is_slh_line(parsed: dict) -> bool:
    return parsed.get("algorithm") == ALGORITHM_2 and "covers" in parsed


def verify_jsonl(path: str, public_key, slh_pub_path: str | None = None) -> tuple[int, int, list[str]]:
    """Verify a receipts JSONL file. Returns (ok_count, bad_count, reasons).

    The first line of each export object is the seal receipt; what follows
    is: optionally the second seal (SLH-DSA), the tenant head lines the
    Merkle root commits to, and optionally the anchors block. The head
    lines are identified by shape (they carry "head"), not by position —
    the anchors block's place in the file is not load-bearing.
    """
    ok = bad = 0
    reasons: list[str] = []
    with open(path, encoding="utf-8") as handle:
        lines = [line.strip() for line in handle if line.strip()]
    if not lines:
        return 0, 0, ["empty file"]
    receipt_line = lines[0]
    try:
        receipt = json.loads(receipt_line)
    except json.JSONDecodeError as exc:
        return 0, 1, [f"receipt is not JSON: {exc}"]
    if receipt.get("algorithm") != ALGORITHM:
        return 0, 1, [f"unknown algorithm: {receipt.get('algorithm')!r}"]
    parsed_rest: list[dict] = []
    slh_line: str | None = None
    for line in lines[1:]:
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            return 0, 1, [f"a line is not JSON: {exc}"]
        if _is_slh_line(parsed):
            slh_line = line
        elif _is_anchor_line(parsed):
            continue
        else:
            parsed_rest.append(parsed)
    head_jsons = parsed_rest
    leaves = sorted(str(h.get("head", "")) for h in head_jsons)
    root = merkle_root_of(leaves)
    tenant_count = receipt.get("tenant_count")
    problems: list[str] = []
    if root != receipt.get("merkle_root"):
        problems.append(
            "head lines do not match the receipt's merkle_root "
            "(lines were added, removed or edited after the round)"
        )
    if isinstance(tenant_count, int) and tenant_count != len(head_jsons):
        problems.append(
            f"tenant_count mismatch: receipt says {tenant_count}, file has {len(head_jsons)}"
        )
    try:
        signature = bytes.fromhex(str(receipt.get("signature", "")))
    except ValueError as exc:
        return 0, 1, [f"signature is not hex: {exc}"] + problems
    payload = sealed_payload(
        merkle_root=str(receipt.get("merkle_root", "")),
        round_started_at=str(receipt.get("round_started_at", "")),
        tenant_count=int(tenant_count or 0),
    ).encode()
    if not _verify_signature(public_key, signature, payload):
        problems.append("signature does not verify under the given public key")
    # Second seal: chained to the FIRST receipt line, so its presence
    # confirms seal 1 byte-for-byte under a hash-only assumption. Checked
    # only when the caller passed the SLH public key and the file carries
    # the line — a round exported before phase 3 is not a failure.
    if slh_line is not None and slh_pub_path is not None:
        slh = json.loads(slh_line)
        if hashlib.sha256(receipt_line.encode()).hexdigest() != slh.get("covers"):
            problems.append("SLH-DSA covers-hash does not match the first receipt")
        else:
            import subprocess
            import tempfile

            sig2 = bytes.fromhex(str(slh.get("signature", "")))
            payload2 = (ALGORITHM_2 + "\n" + receipt_line).encode()
            with (
                tempfile.NamedTemporaryFile() as input_file,
                tempfile.NamedTemporaryFile(suffix=".sig") as sig_file,
            ):
                input_file.write(payload2)
                input_file.flush()
                sig_file.write(sig2)
                sig_file.flush()
                proc = subprocess.run(  # noqa: S603 - fixed argv
                    [
                        "openssl",
                        "pkeyutl",
                        "-verify",
                        "-pubin",
                        "-inkey",
                        slh_pub_path,
                        "-in",
                        input_file.name,
                        "-rawin",
                        "-sigfile",
                        sig_file.name,
                    ],
                    capture_output=True,
                    check=False,
                )
                if proc.returncode != 0:
                    problems.append("SLH-DSA signature does not verify under the given key")
    elif slh_line is not None:
        reasons.append("note: file has an SLH-DSA line but no --slh-pub was given; unchecked")
    if problems:
        bad += 1
        reasons.extend(problems)
    else:
        ok += 1
    return ok, bad, reasons


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipts")
    parser.add_argument("public_key")
    parser.add_argument("--slh-pub", default=None, help="SLH-DSA public key (PEM) for the second seal")
    args = parser.parse_args(argv[1:])
    try:
        public_key = _load_public_key(args.public_key)
    except Exception as exc:  # noqa: BLE001
        print(f"could not load public key: {exc}", file=sys.stderr)
        return 2
    try:
        ok, bad, reasons = verify_jsonl(args.receipts, public_key, slh_pub_path=args.slh_pub)
    except OSError as exc:
        print(f"could not read receipts: {exc}", file=sys.stderr)
        return 2
    for reason in reasons:
        print(reason if reason.startswith("note:") else f"FAIL: {reason}")
    print(f"rounds ok: {ok}, bad: {bad}")
    return 0 if bad == 0 and ok > 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))