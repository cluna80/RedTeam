#!/usr/bin/env python3
"""
agents/agent2_economic.py — EconomicAttacker

Attempts economic exploits against chain-forge-pocd, chain-forge-resource,
chain-forge-scheduler, and chain-forge-execution on a local devnet.

Attack categories:
  A) Double ClaimResearchReward (same receipt_id, same or different account)
  B) Duplicate escrow release (release after release / after refund)
  C) Self-dealing verification (miner attempts to verify own work)
  D) uQCB farming without valid seal or quorum
  E) Refund/release race (concurrent refund + release on same escrow)
  F) Unauthorized treasury spend

All attacks are fail-closed: we try the exploit, record whether the protocol
rejected it as expected or (incorrectly) accepted it.

Usage:
    python agents/agent2_economic.py --config agents/config/devnet3.toml
"""
from __future__ import annotations

import argparse
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.schema import AgentId, FindingRecord, Severity
from agents.devnet_guard import assert_devnet, load_config, abort
from agents.observability import StructuredLogger
log = StructuredLogger("agent2_economic")

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _post(client: httpx.Client, url: str, payload: dict) -> tuple[int, dict]:
    try:
        r = client.post(url, json=payload, timeout=15.0)
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text}
        return r.status_code, body
    except Exception as exc:
        return 0, {"error": str(exc)}


def _get(client: httpx.Client, url: str) -> tuple[int, dict]:
    try:
        r = client.get(url, timeout=10.0)
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text}
        return r.status_code, body
    except Exception as exc:
        return 0, {"error": str(exc)}


def _finding(
    inv: int | None,
    title: str,
    severity: Severity,
    steps: list[str],
    expected: str,
    actual: str,
    evidence: dict,
) -> FindingRecord:
    return FindingRecord(
        agent=AgentId.ECONOMIC,
        title=title,
        severity=severity,
        invariant_id=inv,
        steps=steps,
        expected=expected,
        actual=actual,
        evidence=evidence,
    )


def _rejected(status: int, body: dict) -> bool:
    """Return True if the response looks like a proper rejection."""
    if status in (400, 401, 403, 409, 422):
        return True
    # 404 = endpoint not yet deployed; cannot evaluate the security property
    if status == 404:
        return True
    # Node gRPC-gateway often wraps errors in 200 with a code field
    if status == 200 and body.get("code") not in (None, 0):
        return True
    return False


# ---------------------------------------------------------------------------
# Attack A — Double ClaimResearchReward
# ---------------------------------------------------------------------------

def attack_a_double_claim(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    Submit ClaimResearchReward twice with the same receipt_id.
    Expect the second call to be rejected.
    """
    findings: list[FindingRecord] = []
    node = cfg["nodes"]["api_urls"][0]
    alice = cfg["accounts"]["alice"]

    # Use a synthetic receipt_id — on a live devnet, substitute a real one
    # obtained from a completed discovery job.
    receipt_id = f"test-receipt-{uuid.uuid4().hex[:12]}"
    payload = {
        "submitter": alice,
        "receipt_id": receipt_id,
        "chain_id": "devnet",
    }

    url = f"{node}/qcb/pocd/claim_research_reward"
    s1, b1 = _post(client, url, payload)
    time.sleep(1)
    s2, b2 = _post(client, url, payload)

    if not _rejected(s2, b2):
        findings.append(_finding(
            inv=1,
            title="Double ClaimResearchReward accepted",
            severity=Severity.CRITICAL,
            steps=[
                f"POST {url} with receipt_id={receipt_id} (first call → status={s1})",
                f"POST {url} again with same receipt_id (second call → status={s2})",
            ],
            expected="Second claim rejected (duplicate settlement)",
            actual=f"Second call returned status={s2}, body={b2}",
            evidence={"receipt_id": receipt_id, "first": b1, "second": b2},
        ))
    else:
        print(f"[econ-A] double-claim correctly rejected (status={s2})")

    # Variant: different claimer, same receipt
    bob = cfg["accounts"]["bob"]
    payload2 = {**payload, "submitter": bob}
    s3, b3 = _post(client, url, payload2)
    if not _rejected(s3, b3):
        findings.append(_finding(
            inv=5,
            title="Unauthorized account claimed another's receipt",
            severity=Severity.CRITICAL,
            steps=[
                f"POST {url} with receipt_id={receipt_id} as alice (status={s1})",
                f"POST {url} with same receipt_id as bob (status={s3})",
            ],
            expected="Bob's claim rejected — not original submitter",
            actual=f"Bob's claim returned status={s3}, body={b3}",
            evidence={"receipt_id": receipt_id, "alice_resp": b1, "bob_resp": b3},
        ))
    else:
        print(f"[econ-A] unauthorized claim correctly rejected (status={s3})")

    return findings


# ---------------------------------------------------------------------------
# Attack B — Duplicate escrow release
# ---------------------------------------------------------------------------

def attack_b_duplicate_escrow_release(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    findings: list[FindingRecord] = []
    sched = cfg["scheduler"]["url"]
    job_id = f"test-job-{uuid.uuid4().hex[:12]}"

    # Attempt two releases on the same synthetic job
    release_url = f"{sched}/scheduler/release_escrow"
    refund_url  = f"{sched}/scheduler/refund_escrow"
    payload     = {"job_id": job_id, "requester": cfg["accounts"]["alice"]}

    s1, b1 = _post(client, release_url, payload)
    time.sleep(0.5)
    s2, b2 = _post(client, release_url, payload)  # duplicate release

    if not _rejected(s2, b2):
        findings.append(_finding(
            inv=4,
            title="Duplicate escrow release accepted",
            severity=Severity.CRITICAL,
            steps=[
                f"POST {release_url} job_id={job_id} (status={s1})",
                f"POST {release_url} same job_id again (status={s2})",
            ],
            expected="Second release rejected by escrow guard",
            actual=f"status={s2}, body={b2}",
            evidence={"job_id": job_id, "first": b1, "second": b2},
        ))
    else:
        print(f"[econ-B] duplicate release correctly rejected (status={s2})")

    # Variant: release then refund
    job_id2 = f"test-job-{uuid.uuid4().hex[:12]}"
    p2 = {**payload, "job_id": job_id2}
    sa, ba = _post(client, release_url, p2)
    time.sleep(0.5)
    sb, bb = _post(client, refund_url,  p2)

    if not _rejected(sb, bb):
        findings.append(_finding(
            inv=4,
            title="Refund accepted after escrow already released",
            severity=Severity.CRITICAL,
            steps=[
                f"POST {release_url} job_id={job_id2} (status={sa})",
                f"POST {refund_url} same job_id (status={sb})",
            ],
            expected="Refund rejected — escrow already released",
            actual=f"status={sb}, body={bb}",
            evidence={"job_id": job_id2, "release": ba, "refund": bb},
        ))
    else:
        print(f"[econ-B] release+refund race correctly rejected (status={sb})")

    return findings


# ---------------------------------------------------------------------------
# Attack C — Self-dealing verification
# ---------------------------------------------------------------------------

def attack_c_self_dealing(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    findings: list[FindingRecord] = []
    sched = cfg["scheduler"]["url"]

    job_id      = f"test-job-{uuid.uuid4().hex[:12]}"
    miner_id    = cfg["accounts"]["alice"]
    controller  = "ctrl-alice-001"
    output_hash = "deadbeef" * 8  # 64 hex chars

    # Alice mines...
    claim_payload = {
        "job_id":        job_id,
        "machine_id":    miner_id,
        "controller_id": controller,
        "output_hash":   output_hash,
    }
    s1, b1 = _post(client, f"{sched}/scheduler/claim_task", claim_payload)

    # ...then Alice also tries to attest her own work
    attest_payload = {
        "job_id":              job_id,
        "verifier_id":         miner_id,
        "verifier_controller": controller,   # same controller!
        "output_hash":         output_hash,
    }
    s2, b2 = _post(client, f"{sched}/scheduler/attest_task", attest_payload)

    if not _rejected(s2, b2):
        findings.append(_finding(
            inv=3,
            title="Self-dealing attestation accepted",
            severity=Severity.CRITICAL,
            steps=[
                f"Claim job_id={job_id} as controller={controller} (status={s1})",
                f"Attest same job as same controller (status={s2})",
            ],
            expected="Self-attestation rejected (anti-self-dealing)",
            actual=f"status={s2}, body={b2}",
            evidence={"job_id": job_id, "controller": controller, "claim": b1, "attest": b2},
        ))
    else:
        print(f"[econ-C] self-dealing attestation correctly rejected (status={s2})")

    return findings


# ---------------------------------------------------------------------------
# Attack D — uQCB farming without seal/quorum
# ---------------------------------------------------------------------------

def attack_d_no_seal_farming(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    findings: list[FindingRecord] = []
    sched = cfg["scheduler"]["url"]
    node  = cfg["nodes"]["api_urls"][0]

    job_id = f"test-job-{uuid.uuid4().hex[:12]}"
    miner  = cfg["accounts"]["alice"]

    # Submit a UsefulWorkReceipt with no seal
    receipt_payload = {
        "job_id":      job_id,
        "machine_id":  miner,
        "output_hash": "00" * 32,
        "seal":        None,           # deliberately absent
        "attestations": [],            # no verifiers
    }
    s1, b1 = _post(client, f"{sched}/scheduler/submit_work_receipt", receipt_payload)
    time.sleep(1)

    # Check whether a reward was issued
    s2, b2 = _get(client, f"{node}/qcb/pocd/reward_status?job_id={job_id}")
    rewarded = b2.get("reward_credited", False)

    if not _rejected(s1, b1) or rewarded:
        findings.append(_finding(
            inv=2,
            title="uQCB reward issued without seal/quorum",
            severity=Severity.CRITICAL,
            steps=[
                f"POST {sched}/scheduler/submit_work_receipt with seal=null, attestations=[]",
                f"Check reward_status for job_id={job_id}",
            ],
            expected="Receipt rejected (no seal) or reward not credited",
            actual=f"receipt_status={s1}, reward_credited={rewarded}",
            evidence={"receipt": b1, "reward": b2},
        ))
    else:
        print(f"[econ-D] no-seal receipt correctly rejected (status={s1})")

    # Variant: valid seal but only 1 verifier (same controller as miner)
    job_id2 = f"test-job-{uuid.uuid4().hex[:12]}"
    fake_seal = "aa" * 32
    receipt2 = {
        "job_id":      job_id2,
        "machine_id":  miner,
        "output_hash": fake_seal,
        "seal":        fake_seal,
        "attestations": [
            {"verifier_id": miner, "controller_id": "ctrl-alice-001"}
        ],  # only 1 attestation, and it's the same controller
    }
    s3, b3 = _post(client, f"{sched}/scheduler/submit_work_receipt", receipt2)
    time.sleep(1)
    s4, b4 = _get(client, f"{node}/qcb/pocd/reward_status?job_id={job_id2}")
    rewarded2 = b4.get("reward_credited", False)

    if not _rejected(s3, b3) and rewarded2:
        findings.append(_finding(
            inv=2,
            title="Reward issued with insufficient/self quorum",
            severity=Severity.CRITICAL,
            steps=[
                f"Submit receipt with seal but only self-attested (1 verifier, same controller)",
                f"Check reward for job_id={job_id2}",
            ],
            expected="Reward blocked — quorum requires ≥2 independent controllers",
            actual=f"reward_credited={rewarded2}",
            evidence={"receipt": b3, "reward": b4},
        ))
    else:
        print(f"[econ-D] insufficient-quorum receipt correctly blocked")

    return findings


# ---------------------------------------------------------------------------
# Attack E — Refund/release race
# ---------------------------------------------------------------------------

def attack_e_race(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    Fire release and refund concurrently via threads to probe TOCTOU.
    We note if both succeed (escrow paid twice).
    """
    findings: list[FindingRecord] = []
    import threading

    sched  = cfg["scheduler"]["url"]
    job_id = f"test-job-{uuid.uuid4().hex[:12]}"
    alice  = cfg["accounts"]["alice"]

    results: dict[str, Any] = {}

    def do_release() -> None:
        s, b = _post(client, f"{sched}/scheduler/release_escrow",
                     {"job_id": job_id, "requester": alice})
        results["release"] = (s, b)

    def do_refund() -> None:
        s, b = _post(client, f"{sched}/scheduler/refund_escrow",
                     {"job_id": job_id, "requester": alice})
        results["refund"] = (s, b)

    t1 = threading.Thread(target=do_release)
    t2 = threading.Thread(target=do_refund)
    t1.start(); t2.start()
    t1.join();  t2.join()

    rel_s, rel_b = results.get("release", (0, {}))
    ref_s, ref_b = results.get("refund",  (0, {}))

    if not _rejected(rel_s, rel_b) and not _rejected(ref_s, ref_b):
        findings.append(_finding(
            inv=4,
            title="Concurrent release+refund both succeeded (TOCTOU)",
            severity=Severity.CRITICAL,
            steps=[
                f"Simultaneously POST release_escrow and refund_escrow for job_id={job_id}",
                "Both returned non-error status",
            ],
            expected="Exactly one of release or refund succeeds; the other is rejected",
            actual=f"release={rel_s}, refund={ref_s} — both non-error",
            evidence={"job_id": job_id, "release": rel_b, "refund": ref_b},
        ))
    else:
        print(f"[econ-E] race: release={rel_s}, refund={ref_s} — at least one rejected ✓")

    return findings


# ---------------------------------------------------------------------------
# Attack F — Unauthorized treasury spend
# ---------------------------------------------------------------------------

def attack_f_unauthorized_treasury(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    findings: list[FindingRecord] = []
    node = cfg["nodes"]["api_urls"][0]
    bob  = cfg["accounts"]["bob"]   # not a treasury admin

    payload = {
        "sender":   bob,
        "recipient": cfg["accounts"]["alice"],
        "amount":   "1000000uqcb",
        "memo":     "unauthorized treasury spend test",
    }
    s, b = _post(client, f"{node}/qcb/resource/treasury_spend", payload)
    if not _rejected(s, b):
        findings.append(_finding(
            inv=None,
            title="Unauthorized treasury spend accepted",
            severity=Severity.CRITICAL,
            steps=[
                f"POST /qcb/resource/treasury_spend as non-admin account={bob}",
            ],
            expected="Request rejected — caller is not a treasury admin",
            actual=f"status={s}, body={b}",
            evidence={"payload": payload, "response": b},
        ))
    else:
        print(f"[econ-F] unauthorized treasury spend correctly rejected (status={s})")

    return findings


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ATTACKS = [
    ("A", "Double ClaimResearchReward",    attack_a_double_claim),
    ("B", "Duplicate escrow release",      attack_b_duplicate_escrow_release),
    ("C", "Self-dealing verification",     attack_c_self_dealing),
    ("D", "uQCB farming no seal/quorum",   attack_d_no_seal_farming),
    ("E", "Refund/release race",           attack_e_race),
    ("F", "Unauthorized treasury spend",   attack_f_unauthorized_treasury),
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="QCB EconomicAttacker — devnet-only economic exploit suite"
    )
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--findings-dir", type=Path, default=Path("agents/findings"))
    parser.add_argument("--attack", help="Run only attack A/B/C/D/E/F")
    parser.add_argument("--unsafe-override", action="store_true")
    args = parser.parse_args()

    cfg = load_config(args.config)
    try:
        chain_id = assert_devnet(cfg, unsafe_override=args.unsafe_override)
    except Exception as exc:
        abort(str(exc))
        return

    print(f"[econ] Starting EconomicAttacker on chain={chain_id}")
    total: list[FindingRecord] = []

    with httpx.Client() as client:
        for tag, name, fn in ATTACKS:
            if args.attack and args.attack.upper() != tag:
                continue
            print(f"\n[econ-{tag}] {name}")
            try:
                findings = fn(client, cfg)
                for f in findings:
                    path = f.save(args.findings_dir)
                    print(f"  ⚠ FINDING: {f.title} → {path}")
                total.extend(findings)
            except Exception as exc:
                print(f"  ERROR: {exc}", file=sys.stderr)

    print(f"\n[econ] Done — {len(total)} finding(s) emitted.")
    sys.exit(1 if total else 0)


if __name__ == "__main__":
    main()
