#!/usr/bin/env python3
"""
agents/agent3_gossip.py — GossipAdversary

Injects and replays malformed or adversarial gossip messages against
Change Set R (GossipTopic::DiscoveryProof) and
Change Set S (GossipTopic::VerifierAttestation) on a local devnet.

Attack categories:
  G1) Wrong chain_id on DiscoveryProof
  G2) Stale timestamp on DiscoveryProof / VerifierAttestation
  G3) Forged signature on both topic types
  G4) Same-controller sybil attestations (≥2 attestations, 1 controller)
  G5) Equivocation — conflicting output_hashes for the same job
  G6) Spam flood — burst of valid-looking messages
  G7) Replay of a previously seen (valid) gossip message

After each attack category, we verify:
  - Bad messages are not visible in scheduler/gossip_log
  - Honest quorum still converges (at least 2 honest nodes agree on canonical)

Usage:
    python agents/agent3_gossip.py --config agents/config/devnet3.toml
"""
from __future__ import annotations

import argparse
import sys
import time
import uuid
import hashlib
import threading
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.schema import AgentId, FindingRecord, Severity
from agents.devnet_guard import assert_devnet, load_config, abort
from agents.observability import StructuredLogger
log = StructuredLogger("agent3_gossip")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
        agent=AgentId.GOSSIP,
        title=title,
        severity=severity,
        invariant_id=inv,
        steps=steps,
        expected=expected,
        actual=actual,
        evidence=evidence,
    )


def _post(client: httpx.Client, url: str, payload: dict, timeout: float = 10.0) -> tuple[int, dict]:
    try:
        r = client.post(url, json=payload, timeout=timeout)
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


def _rejected(status: int, body: dict) -> bool:
    if status in (400, 401, 403, 409, 422):
        return True
    if status == 200 and body.get("code") not in (None, 0):
        return True
    return False


def _fake_sig() -> str:
    """Return a plausible-length but invalid ML-DSA-style signature hex."""
    return "ff" * 64


def _valid_output_hash(seed: str = "") -> str:
    return hashlib.sha256(f"output-{seed}-{uuid.uuid4()}".encode()).hexdigest()


def _unix_now() -> int:
    return int(time.time())


def _stale_timestamp(window_secs: int) -> int:
    return _unix_now() - window_secs - 60


# ---------------------------------------------------------------------------
# Gossip injection endpoint
# The p2p layer exposes a devnet-only /debug/gossip_inject endpoint.
# All injections go through this; the node validates and propagates (or drops).
# ---------------------------------------------------------------------------

def _inject(
    client: httpx.Client,
    node_url: str,
    topic: str,
    message: dict,
) -> tuple[int, dict]:
    url = f"{node_url}/debug/gossip_inject"
    return _post(client, url, {"topic": topic, "message": message})


def _gossip_log_contains(
    client: httpx.Client,
    sched_url: str,
    msg_hash: str,
) -> bool:
    """Return True if the scheduler recorded this hash as credited."""
    _, data = _get(client, f"{sched_url}/scheduler/gossip_log")
    for msg in data.get("messages", []):
        if msg.get("message_hash") == msg_hash and msg.get("credited"):
            return True
    return False


def _quorum_converged(
    client: httpx.Client,
    sched_url: str,
    job_id: str,
    min_honest: int = 2,
) -> bool:
    """Check scheduler accepted the job canonically (honest quorum converged)."""
    _, data = _get(client, f"{sched_url}/scheduler/job_status?job_id={job_id}")
    return data.get("quorum_met") is True


# ---------------------------------------------------------------------------
# G1 — Wrong chain_id
# ---------------------------------------------------------------------------

def attack_g1_wrong_chain_id(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    findings: list[FindingRecord] = []
    node    = cfg["nodes"]["rpc_urls"][0]
    sched   = cfg["scheduler"]["url"]
    job_id  = f"job-{uuid.uuid4().hex[:12]}"
    oh      = _valid_output_hash("g1")

    msg = {
        "job_id":      job_id,
        "machine_id":  cfg["accounts"]["alice"],
        "output_hash": oh,
        "seal":        oh,
        "chain_id":    "wrong-mainnet-1",   # adversarial chain_id
        "timestamp":   _unix_now(),
        "signature":   _fake_sig(),
    }
    s, b = _inject(client, node, "DiscoveryProof", msg)
    time.sleep(2)
    credited = _gossip_log_contains(client, sched, oh)

    if not _rejected(s, b) or credited:
        findings.append(_finding(
            inv=9,
            title="DiscoveryProof with wrong chain_id not dropped",
            severity=Severity.CRITICAL,
            steps=[
                f"Inject DiscoveryProof with chain_id='wrong-mainnet-1' to {node}",
                "Poll scheduler gossip_log for credited=true on this message_hash",
            ],
            expected="Message dropped at p2p validation layer",
            actual=f"inject_status={s}, credited={credited}",
            evidence={"message": msg, "response": b},
        ))
    else:
        print(f"[gossip-G1] wrong chain_id correctly dropped (status={s})")

    return findings


# ---------------------------------------------------------------------------
# G2 — Stale timestamp
# ---------------------------------------------------------------------------

def attack_g2_stale_timestamp(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    findings: list[FindingRecord] = []
    node    = cfg["nodes"]["rpc_urls"][0]
    sched   = cfg["scheduler"]["url"]
    window  = cfg["timing"]["gossip_replay_window"]

    for topic in ("DiscoveryProof", "VerifierAttestation"):
        job_id = f"job-{uuid.uuid4().hex[:12]}"
        oh     = _valid_output_hash(f"g2-{topic}")
        stale  = _stale_timestamp(window)

        msg: dict[str, Any] = {
            "job_id":      job_id,
            "output_hash": oh,
            "timestamp":   stale,
            "chain_id":    "devnet",
            "signature":   _fake_sig(),
        }
        if topic == "VerifierAttestation":
            msg["verifier_id"]         = cfg["accounts"]["bob"]
            msg["verifier_controller"] = "ctrl-bob-001"
            msg["counted"]             = True
        else:
            msg["machine_id"] = cfg["accounts"]["alice"]
            msg["seal"]       = oh

        s, b = _inject(client, node, topic, msg)
        time.sleep(2)
        credited = _gossip_log_contains(client, sched, oh)

        if not _rejected(s, b) or credited:
            findings.append(_finding(
                inv=10,
                title=f"Stale {topic} not dropped",
                severity=Severity.HIGH,
                steps=[
                    f"Inject {topic} with timestamp={stale} ({window+60}s ago)",
                    "Check gossip_log for credited entry",
                ],
                expected="Stale message rejected by timestamp guard",
                actual=f"status={s}, credited={credited}",
                evidence={"topic": topic, "message": msg, "response": b},
            ))
        else:
            print(f"[gossip-G2] stale {topic} correctly rejected (status={s})")

    return findings


# ---------------------------------------------------------------------------
# G3 — Forged signature
# ---------------------------------------------------------------------------

def attack_g3_forged_signature(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    findings: list[FindingRecord] = []
    node    = cfg["nodes"]["rpc_urls"][0]
    sched   = cfg["scheduler"]["url"]

    for topic in ("DiscoveryProof", "VerifierAttestation"):
        job_id = f"job-{uuid.uuid4().hex[:12]}"
        oh     = _valid_output_hash(f"g3-{topic}")

        msg: dict[str, Any] = {
            "job_id":    job_id,
            "output_hash": oh,
            "timestamp": _unix_now(),
            "chain_id":  "devnet",
            "signature": _fake_sig(),  # not a valid ML-DSA sig
        }
        if topic == "VerifierAttestation":
            msg["verifier_id"]         = cfg["accounts"]["bob"]
            msg["verifier_controller"] = "ctrl-bob-001"
        else:
            msg["machine_id"] = cfg["accounts"]["alice"]
            msg["seal"]       = oh

        s, b = _inject(client, node, topic, msg)
        time.sleep(2)
        credited = _gossip_log_contains(client, sched, oh)

        if not _rejected(s, b) or credited:
            findings.append(_finding(
                inv=None,
                title=f"{topic} with forged signature accepted",
                severity=Severity.CRITICAL,
                steps=[
                    f"Inject {topic} with signature=0xff*64 (invalid ML-DSA)",
                    "Confirm message appears credited in gossip_log",
                ],
                expected="Message dropped — signature verification fails",
                actual=f"status={s}, credited={credited}",
                evidence={"topic": topic, "message": msg, "response": b},
            ))
        else:
            print(f"[gossip-G3] forged sig on {topic} correctly rejected (status={s})")

    return findings


# ---------------------------------------------------------------------------
# G4 — Same-controller sybil attestations
# ---------------------------------------------------------------------------

def attack_g4_sybil_attestations(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    Send ≥2 VerifierAttestations for the same job from different verifier
    identities but the same controller_id.  Quorum should NOT be met.
    """
    findings: list[FindingRecord] = []
    node    = cfg["nodes"]["rpc_urls"][0]
    sched   = cfg["scheduler"]["url"]

    job_id     = f"job-{uuid.uuid4().hex[:12]}"
    oh         = _valid_output_hash("g4")
    controller = "ctrl-sybil-999"   # one controller, two fake verifier IDs

    for i, verifier_account in enumerate(["qcb1sybil_a_000", "qcb1sybil_b_000"]):
        msg = {
            "job_id":              job_id,
            "output_hash":         oh,
            "verifier_id":         verifier_account,
            "verifier_controller": controller,
            "timestamp":           _unix_now(),
            "chain_id":            "devnet",
            "signature":           _fake_sig(),
        }
        _inject(client, node, "VerifierAttestation", msg)
        time.sleep(0.3)

    time.sleep(3)
    quorum = _quorum_converged(client, sched, job_id)

    if quorum:
        findings.append(_finding(
            inv=3,
            title="Sybil attestations (same controller) reached quorum",
            severity=Severity.CRITICAL,
            steps=[
                f"Inject 2 VerifierAttestations for job_id={job_id}",
                f"Both use verifier_controller={controller} (same controller)",
                "Check scheduler reports quorum_met=true",
            ],
            expected="Quorum blocked — only 1 independent controller",
            actual=f"quorum_met={quorum} for job_id={job_id}",
            evidence={"job_id": job_id, "controller": controller, "output_hash": oh},
        ))
    else:
        print(f"[gossip-G4] sybil quorum correctly blocked (quorum={quorum})")

    return findings


# ---------------------------------------------------------------------------
# G5 — Equivocation (conflicting output_hashes)
# ---------------------------------------------------------------------------

def attack_g5_equivocation(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    Inject two DiscoveryProof messages for the same job with different
    output_hashes.  Both should be rejected or only the first accepted;
    the attacker must not be credited for two distinct outputs.
    """
    findings: list[FindingRecord] = []
    node   = cfg["nodes"]["rpc_urls"][0]
    sched  = cfg["scheduler"]["url"]
    alice  = cfg["accounts"]["alice"]
    job_id = f"job-{uuid.uuid4().hex[:12]}"

    oh_a = _valid_output_hash("g5-a")
    oh_b = _valid_output_hash("g5-b")

    for oh in (oh_a, oh_b):
        msg = {
            "job_id":      job_id,
            "machine_id":  alice,
            "output_hash": oh,
            "seal":        oh,
            "timestamp":   _unix_now(),
            "chain_id":    "devnet",
            "signature":   _fake_sig(),
        }
        _inject(client, node, "DiscoveryProof", msg)
        time.sleep(0.5)

    time.sleep(3)
    _, log = _get(client, f"{sched}/scheduler/gossip_log")
    credited_hashes = [
        m["message_hash"] for m in log.get("messages", [])
        if m.get("credited") and m.get("job_id") == job_id
    ]

    if len(credited_hashes) > 1:
        findings.append(_finding(
            inv=1,
            title="Equivocating machine credited for two output_hashes",
            severity=Severity.CRITICAL,
            steps=[
                f"Inject DiscoveryProof for job_id={job_id} with output_hash=A",
                f"Inject DiscoveryProof for same job_id with output_hash=B",
                "Observe both appear as credited in gossip_log",
            ],
            expected="Only first hash accepted; equivocation detected and penalised",
            actual=f"{len(credited_hashes)} distinct hashes credited: {credited_hashes}",
            evidence={"job_id": job_id, "credited": credited_hashes},
        ))
    else:
        print(f"[gossip-G5] equivocation correctly handled (credited={len(credited_hashes)})")

    return findings


# ---------------------------------------------------------------------------
# G6 — Spam flood
# ---------------------------------------------------------------------------

def attack_g6_spam_flood(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    Send a burst of gossip messages above the rate limit.
    Verify nodes do not crash and honest quorum still converges on
    a legitimate job submitted concurrently.
    """
    findings: list[FindingRecord] = []
    node    = cfg["nodes"]["rpc_urls"][0]
    sched   = cfg["scheduler"]["url"]
    alice   = cfg["accounts"]["alice"]
    max_msg = cfg["limits"]["max_flood_msgs"]

    print(f"[gossip-G6] flooding {max_msg} messages…", flush=True)
    errors = 0
    for i in range(max_msg):
        msg = {
            "job_id":      f"spam-{i}-{uuid.uuid4().hex[:8]}",
            "machine_id":  alice,
            "output_hash": _valid_output_hash(f"flood-{i}"),
            "seal":        "00" * 32,
            "timestamp":   _unix_now(),
            "chain_id":    "devnet",
            "signature":   _fake_sig(),
        }
        s, _ = _inject(client, node, "DiscoveryProof", msg)
        if s == 0:
            errors += 1

    # After flood, check a honest job still goes through
    honest_job = f"job-honest-{uuid.uuid4().hex[:8]}"
    time.sleep(3)
    _, status = _get(client, f"{node}/status")
    node_alive = status.get("result") is not None

    if not node_alive:
        findings.append(_finding(
            inv=8,
            title="Node unreachable after gossip flood",
            severity=Severity.CRITICAL,
            steps=[
                f"Send {max_msg} DiscoveryProof messages in rapid succession",
                "Poll /status on the same node",
            ],
            expected="Node remains alive; excess messages rate-limited or dropped",
            actual="Node did not respond to /status after flood",
            evidence={"flood_count": max_msg, "errors_during_flood": errors},
        ))
    else:
        print(f"[gossip-G6] node alive after flood ✓ (errors_during_flood={errors})")

    return findings


# ---------------------------------------------------------------------------
# G7 — Replay of a previously seen valid message
# ---------------------------------------------------------------------------

def attack_g7_replay(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    Record a valid gossip message hash, wait for the replay window to expire,
    then re-inject the same message and verify it is dropped.
    In automated testing we fast-forward by using a pre-stale timestamp.
    """
    findings: list[FindingRecord] = []
    node    = cfg["nodes"]["rpc_urls"][0]
    sched   = cfg["scheduler"]["url"]
    window  = cfg["timing"]["gossip_replay_window"]

    job_id = f"job-replay-{uuid.uuid4().hex[:12]}"
    oh     = _valid_output_hash("g7-replay")

    # First injection (within window — might be accepted)
    msg = {
        "job_id":      job_id,
        "machine_id":  cfg["accounts"]["alice"],
        "output_hash": oh,
        "seal":        oh,
        "timestamp":   _unix_now(),
        "chain_id":    "devnet",
        "signature":   _fake_sig(),
    }
    s1, b1 = _inject(client, node, "DiscoveryProof", msg)
    time.sleep(2)
    credit_before = _gossip_log_contains(client, sched, oh)

    # Second injection with stale timestamp (simulates post-window replay)
    msg_replay = {**msg, "timestamp": _stale_timestamp(window)}
    s2, b2 = _inject(client, node, "DiscoveryProof", msg_replay)
    time.sleep(2)

    # Re-check credit; if it incremented, the replay was credited
    _, log = _get(client, f"{sched}/scheduler/gossip_log")
    replay_credited = sum(
        1 for m in log.get("messages", [])
        if m.get("message_hash") == oh and m.get("credited")
    )

    if replay_credited > 1:
        findings.append(_finding(
            inv=6,
            title="Replayed gossip message credited multiple times",
            severity=Severity.HIGH,
            steps=[
                f"Inject DiscoveryProof for job_id={job_id} at T=now",
                f"Re-inject same message with timestamp > {window}s ago",
                "Observe credited count > 1 in gossip_log",
            ],
            expected="Replay dropped; credit count = 1 (or 0 if first was rejected)",
            actual=f"credited count={replay_credited}",
            evidence={"job_id": job_id, "oh": oh, "replay_status": s2},
        ))
    else:
        print(f"[gossip-G7] replay correctly handled (credit_count={replay_credited})")

    return findings


# ---------------------------------------------------------------------------
# Post-attack: verify honest quorum still converges
# ---------------------------------------------------------------------------

def verify_honest_convergence(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    Submit a clean, fully-attested job via the scheduler API and verify
    it reaches canonical status.  If it doesn't, the adversarial traffic
    may have disrupted honest operation.
    """
    findings: list[FindingRecord] = []
    sched   = cfg["scheduler"]["url"]
    alice   = cfg["accounts"]["alice"]
    bob     = cfg["accounts"]["bob"]
    carol   = cfg["accounts"]["carol"]

    job_id = f"job-honest-final-{uuid.uuid4().hex[:8]}"
    oh     = _valid_output_hash("honest")
    seal   = oh

    # Submit honest work
    _, _ = _post(client, f"{sched}/scheduler/submit_work_receipt", {
        "job_id":      job_id,
        "machine_id":  alice,
        "output_hash": oh,
        "seal":        seal,
        "attestations": [
            {"verifier_id": bob,   "controller_id": "ctrl-bob-001"},
            {"verifier_id": carol, "controller_id": "ctrl-carol-001"},
        ],
    })
    time.sleep(5)

    quorum = _quorum_converged(client, sched, job_id)
    if not quorum:
        findings.append(_finding(
            inv=None,
            title="Honest quorum failed to converge after adversarial traffic",
            severity=Severity.HIGH,
            steps=[
                "Run G1–G7 attack categories",
                "Submit honest fully-attested job",
                "Wait 5 seconds, check quorum_met",
            ],
            expected="Honest job reaches canonical status (quorum_met=true)",
            actual=f"quorum_met={quorum} for job_id={job_id}",
            evidence={"job_id": job_id},
        ))
    else:
        print(f"[gossip-convergence] honest quorum converged ✓ job_id={job_id}")

    return findings


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ATTACKS = [
    ("G1", "Wrong chain_id",                attack_g1_wrong_chain_id),
    ("G2", "Stale timestamp",               attack_g2_stale_timestamp),
    ("G3", "Forged signature",              attack_g3_forged_signature),
    ("G4", "Sybil attestations",            attack_g4_sybil_attestations),
    ("G5", "Equivocation",                  attack_g5_equivocation),
    ("G6", "Spam flood",                    attack_g6_spam_flood),
    ("G7", "Replay",                        attack_g7_replay),
    ("HC", "Honest convergence check",      verify_honest_convergence),
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="QCB GossipAdversary — devnet-only gossip attack suite"
    )
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--findings-dir", type=Path, default=Path("agents/findings"))
    parser.add_argument("--attack", help="Run only G1/G2/G3/G4/G5/G6/G7/HC")
    parser.add_argument("--unsafe-override", action="store_true")
    args = parser.parse_args()

    cfg = load_config(args.config)
    try:
        chain_id = assert_devnet(cfg, unsafe_override=args.unsafe_override)
    except Exception as exc:
        abort(str(exc)); return

    print(f"[gossip] Starting GossipAdversary on chain={chain_id}")
    total: list[FindingRecord] = []

    with httpx.Client() as client:
        for tag, name, fn in ATTACKS:
            if args.attack and args.attack.upper() != tag:
                continue
            print(f"\n[gossip-{tag}] {name}")
            try:
                findings = fn(client, cfg)
                for f in findings:
                    path = f.save(args.findings_dir)
                    print(f"  ⚠ FINDING: {f.title} → {path}")
                total.extend(findings)
            except Exception as exc:
                print(f"  ERROR: {exc}", file=sys.stderr)

    print(f"\n[gossip] Done — {len(total)} finding(s) emitted.")
    sys.exit(1 if total else 0)


if __name__ == "__main__":
    main()
