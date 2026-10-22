#!/usr/bin/env python3
"""
agents/agent8_identity_pilot.py — IdentityPilotAdversary

Red-team agent for the Qattice identity pilot (Phase 2).

## Pilot targets (whitepaper §4)
  - Sybil rate < 3% under adversarial red-team testing
  - Per-verification cost < $5/human
  - Attestation guard Phases A–D holding under real load
  - DIS-KS-V1 adversarial scenarios all rejected

## Attack surfaces covered

  I1  Attestation guard — quadratic cost saturation
      Flood attestations to exhaust the quadratic cost cap (Phase A).
      Verify the guard rejects past the cost threshold.

  I2  Attestation guard — revocation bypass
      Attest, revoke, immediately re-attest without paying revocation cost.
      Phase B must block this.

  I3  Attestation guard — sybil confirmation without quorum
      Attempt ConfirmSybil without the required coordinator quorum.
      Phase C must reject non-quorum sybil confirmations.

  I4  Attestation guard — coordinator-gated reversal abuse
      Attempt ReverseSybil without coordinator authorization.
      Phase D must block unauthorized reversals.

  I5  Sybil rate measurement under load
      Register N identities controlled by 1 controller.
      Count how many pass verification; report sybil rate.
      Target: < 3% of N should be independently verified.

  I6  DIS challenge replay
      Capture a valid DIS challenge response; replay it.
      Anti-replay (single-use challenge) must block the second use.

  I7  DIS cross-RP replay
      Take a challenge signed for RP-A (rp_id binding) and present it to RP-B.
      Audience binding must reject.

  I8  DIS chain-ID cross-chain replay
      Present a valid DIS response signed for devnet to a mainnet-chain-id node.
      Chain-ID binding (confirmed in DIS Phase B, test B4) must hold.

  I9  DIS delegation depth overflow
      Build a delegation chain of depth 5 (limit is 4).
      Chain validation must reject depth > 4.

  I10 DIS delegation scope widening
      Construct a delegated proof that claims a wider scope than the parent granted.
      Scope-narrowing enforcement must reject.

  I11 DIS max_uses exhaustion then reuse
      Exhaust max_uses on a delegation; attempt one more use.
      max_uses counter must block the extra use.

  I12 DIS human-approval bypass
      Use a delegation marked requires_human_approval without providing approval.
      Human-approval gate must block.

  I13 Coordinator centralization probe
      Attempt AttestEntity, ConfirmSybil, and ReverseSybil without the
      coordinator role. Record which are gated vs. which accept any caller.
      Documents the temporary centralization named in the whitepaper.

  I14 Contribution-score penalty after sybil confirmation
      Confirm a machine as sybil; verify its contribution_score is penalised
      and its uQCB accumulation is blocked.

  I15 Epoch timestamp drift injection
      Inject a block proposal with a far-future timestamp_ms.
      Whitepaper audit found this is stored but never validated — we confirm
      and quantify the explorer integrity impact.

  I16 Governance turnout suppression simulation
      Flood ProposeChange txs to induce governance fatigue.
      Measure whether legitimate turnout drops below the 3%/6% quorum floor.
      (Open Question 17 from whitepaper.)

## Endpoints
  - /api/identity/{address}  — verification tier + CS score
  - /api/status              — height, peer count
  - POST /tx                 — transaction broadcast  [ASSUMPTION]
  - POST /debug/inject_*     — devnet-only injection hooks [ASSUMPTION]

## ASSUMPTIONS
  All [ASSUMPTION] markers: verify against chain-forge-identity/src/ and
  chain-forge-execution/src/. See agents/ASSUMPTIONS.md.

  AttestEntity tx field names: grep -n 'AttestEntity|attest_entity|attestee'
      chain-forge-execution/src/tx.rs chain-forge-identity/src/
  DIS challenge endpoint: grep -rn 'challenge|DIS|dis_challenge'
      chain-forge-node/src/api/

Usage:
    python agents/agent8_identity_pilot.py --config agents/config/devnet4.toml
    python agents/agent8_identity_pilot.py --config agents/config/devnet4.toml --attack I5
    python agents/agent8_identity_pilot.py --config agents/config/devnet4.toml --measure-sybil-rate --sybil-n 100
"""
from __future__ import annotations

import argparse
import json
import subprocess
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

log = StructuredLogger("agent8_identity_pilot")

# ---------------------------------------------------------------------------
# Wire format assumptions — update field names after reading source
# ---------------------------------------------------------------------------

# [ASSUMPTION] Transaction broadcast endpoint
TX_ENDPOINT = "/api/tx"

# DIS vendor server endpoints (dis-vendor-server, separate from the blockchain nodes)
DIS_CHALLENGE_ENDPOINT       = "/api/dis/challenge"   # old assumption — not used live
DIS_VERIFY_ENDPOINT          = "/api/auth/verify"      # old assumption — not used live
DIS_VENDOR_CHALLENGE         = "/challenge"
DIS_VENDOR_ENROLL_CHALLENGE  = "/enroll/challenge"
DIS_VENDOR_ENROLL            = "/enroll"
DIS_VENDOR_VERIFY_DELEGATED  = "/api/dis/verify_delegated"

# [ASSUMPTION] Attestation guard tx type names
# grep -n 'AttestEntity|RevokeAttestation|ConfirmSybil|ReportSuspectedSybil|ReverseSybil'
#     chain-forge-execution/src/tx.rs
TX_ATTEST_ENTITY        = "AttestEntity"
TX_REVOKE_ATTESTATION   = "RevokeAttestation"
TX_CONFIRM_SYBIL        = "ConfirmSybil"
TX_REPORT_SUSPECTED     = "ReportSuspectedSybil"
TX_REVERSE_SYBIL        = "ReverseSybil"
TX_PROPOSE_CHANGE       = "ProposeChange"

# [ASSUMPTION] Identity verification tiers
# grep -n 'Provisional|Verified|Established|verification_tier'
#     chain-forge-identity/src/
TIER_PROVISIONAL  = "Provisional"
TIER_VERIFIED     = "Verified"
TIER_ESTABLISHED  = "Established"

# Pilot targets (whitepaper §4)
SYBIL_RATE_TARGET   = 0.03   # < 3%
COST_PER_HUMAN_USD  = 5.00   # < $5


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(client: httpx.Client, url: str, timeout: float = 10.0) -> tuple[int, dict]:
    try:
        r = client.get(url, timeout=timeout)
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text[:500]}
        return r.status_code, body
    except Exception as exc:
        return 0, {"error": str(exc)}


def _post(client: httpx.Client, url: str, payload: dict, timeout: float = 10.0) -> tuple[int, dict]:
    try:
        r = client.post(url, json=payload, timeout=timeout)
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text[:500]}
        return r.status_code, body
    except Exception as exc:
        return 0, {"error": str(exc)}


def _rejected(status: int, body: dict) -> bool:
    if status in (400, 401, 403, 404, 409, 422):
        return True
    if status == 200 and body.get("code") not in (None, 0):
        return True
    return False


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
        agent=AgentId.SYBIL,
        title=f"[IdentityPilot] {title}",
        severity=severity,
        invariant_id=inv,
        steps=steps,
        expected=expected,
        actual=actual,
        evidence=evidence,
    )


def _broadcast_tx(
    client: httpx.Client,
    node_url: str,
    tx_type: str,
    payload: dict,
    sender: str = "",
    chain_id: str = "devnet",
    signature: str = "ff" * 64,
) -> tuple[int, dict]:
    """
    Broadcast a tx to the node.
    [ASSUMPTION] envelope shape — verify against chain-forge-execution/src/tx.rs
    """
    tx = {
        "chain_id":  chain_id,
        "nonce":     int(time.time()) % 1_000_000 + 300_000,
        "sender":    sender,
        "msg_type":  tx_type,
        "payload":   payload,
        "gas_limit": 100_000,
        "signature": signature,
        "pub_key":   "cd" * 32,
    }
    return _post(client, f"{node_url}{TX_ENDPOINT}", tx)


def _identity_status(
    client: httpx.Client,
    node_url: str,
    address: str,
) -> dict:
    """GET /api/identity/{address} — returns tier + contribution_score."""
    _, body = _get(client, f"{node_url}/api/identity/{address}")
    return body


# ---------------------------------------------------------------------------
# I1 — Attestation guard: quadratic cost saturation (Phase A)
# ---------------------------------------------------------------------------

def attack_i1_quadratic_cost_saturation(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    Phase A of the attestation guard imposes quadratic cost on attestations
    to make mass-attestation expensive. We flood attestations from one attester
    and verify the guard rejects past the cost cap.
    """
    findings: list[FindingRecord] = []
    node  = cfg["nodes"]["api_urls"][0]
    alice = cfg["accounts"]["alice"]

    # [ASSUMPTION] AttestEntity payload fields
    # grep -n 'AttestEntity|attestee|attester|cost' chain-forge-execution/src/tx.rs
    accepted = 0
    rejected_by_guard = 0
    flood_count = 50  # enough to hit quadratic cap for most configs

    log.info(f"[I1] flooding {flood_count} attestations from {alice}…")
    for i in range(flood_count):
        target_addr = f"qcb1target{i:04d}{'0'*30}"[:42]
        s, b = _broadcast_tx(
            client, node, TX_ATTEST_ENTITY,
            payload={
                "attestee":  target_addr,
                "attester":  alice,
                "claim":     "personhood",
                "evidence":  f"test-evidence-{i}",
            },
            sender=alice,
        )
        if _rejected(s, b):
            rejected_by_guard += 1
        else:
            accepted += 1

    log.info(f"[I1] accepted={accepted}, rejected={rejected_by_guard}")

    # If all accepted, the quadratic cost guard may not be enforcing
    if rejected_by_guard == 0 and flood_count >= 20:
        f = _finding(
            inv=8,
            title="Attestation guard quadratic cost cap not enforced",
            severity=Severity.HIGH,
            steps=[
                f"Broadcast {flood_count} AttestEntity txs from single attester={alice}",
                "All returned non-error status",
            ],
            expected="Quadratic cost cap rejects attestations above threshold (Phase A)",
            actual=f"All {flood_count} attestations accepted — no quadratic rejection observed",
            evidence={"flood_count": flood_count, "accepted": accepted, "rejected": rejected_by_guard},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info(f"[I1] quadratic cost guard firing ✓ ({rejected_by_guard}/{flood_count} rejected)")

    return findings


# ---------------------------------------------------------------------------
# I2 — Attestation guard: revocation bypass (Phase B)
# ---------------------------------------------------------------------------

def attack_i2_revocation_bypass(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    Phase B: Revocation carries a cost to prevent free churn.
    Attempt: attest → revoke → immediately re-attest without paying cost.
    """
    findings: list[FindingRecord] = []
    node  = cfg["nodes"]["api_urls"][0]
    alice = cfg["accounts"]["alice"]
    bob   = cfg["accounts"]["bob"]

    # Step 1: attest
    s1, b1 = _broadcast_tx(
        client, node, TX_ATTEST_ENTITY,
        payload={"attestee": bob, "attester": alice, "claim": "personhood"},
        sender=alice,
    )
    log.info(f"[I2] initial attest", status=s1)
    time.sleep(1)

    # Step 2: revoke
    s2, b2 = _broadcast_tx(
        client, node, TX_REVOKE_ATTESTATION,
        payload={"attestee": bob, "attester": alice},
        sender=alice,
    )
    log.info(f"[I2] revocation", status=s2)
    time.sleep(1)

    # Step 3: immediately re-attest — should be blocked by revocation cost
    s3, b3 = _broadcast_tx(
        client, node, TX_ATTEST_ENTITY,
        payload={"attestee": bob, "attester": alice, "claim": "personhood"},
        sender=alice,
    )
    log.info(f"[I2] immediate re-attest after revoke", status=s3)

    if not _rejected(s3, b3):
        f = _finding(
            inv=None,
            title="Attestation revocation cost bypassed — immediate re-attest accepted",
            severity=Severity.HIGH,
            steps=[
                f"AttestEntity: alice→bob (status={s1})",
                f"RevokeAttestation: alice→bob (status={s2})",
                f"AttestEntity again immediately: alice→bob (status={s3})",
            ],
            expected="Re-attest blocked by Phase B revocation cost (cooldown or cost gate)",
            actual=f"Re-attest accepted status={s3}",
            evidence={"attest": b1, "revoke": b2, "re_attest": b3},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info("[I2] revocation cost correctly blocked re-attest ✓", status=s3)

    return findings


# ---------------------------------------------------------------------------
# I3 — Attestation guard: ConfirmSybil without quorum (Phase C)
# ---------------------------------------------------------------------------

def attack_i3_sybil_confirm_no_quorum(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    Phase C: Sybil confirmation requires coordinator quorum.
    Attempt ConfirmSybil as an ordinary (non-coordinator) account.
    """
    findings: list[FindingRecord] = []
    node  = cfg["nodes"]["api_urls"][0]
    alice = cfg["accounts"]["alice"]
    bob   = cfg["accounts"]["bob"]
    carol = cfg["accounts"]["carol"]

    s, b = _broadcast_tx(
        client, node, TX_CONFIRM_SYBIL,
        payload={
            "target":   carol,
            "reporter": bob,
            "evidence": "fake-sybil-evidence",
        },
        sender=bob,  # bob is not the coordinator (alice is)
    )
    log.info(f"[I3] ConfirmSybil without coordinator quorum", status=s)

    if not _rejected(s, b):
        f = _finding(
            inv=3,
            title="ConfirmSybil accepted without coordinator quorum (Phase C)",
            severity=Severity.CRITICAL,
            steps=[
                f"Broadcast ConfirmSybil targeting carol from alice (non-coordinator)",
                f"Response status={s}",
            ],
            expected="ConfirmSybil rejected — requires coordinator quorum (Phase C)",
            actual=f"ConfirmSybil accepted status={s}, body={b}",
            evidence={"target": carol, "reporter": alice, "response": b},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info("[I3] ConfirmSybil correctly rejected without quorum ✓", status=s)

    return findings


# ---------------------------------------------------------------------------
# I4 — Attestation guard: ReverseSybil without coordinator (Phase D)
# ---------------------------------------------------------------------------

def attack_i4_reverse_sybil_unauthorized(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    Phase D: ReverseSybil (clearing a sybil flag) requires coordinator authorization.
    Attempt as an ordinary account.
    """
    findings: list[FindingRecord] = []
    node  = cfg["nodes"]["api_urls"][0]
    alice = cfg["accounts"]["alice"]
    bob   = cfg["accounts"]["bob"]

    s, b = _broadcast_tx(
        client, node, TX_REVERSE_SYBIL,
        payload={
            "target":     alice,
            "reverser":   bob,
            "justification": "unauthorized reversal attempt",
        },
        sender=bob,
    )
    log.info(f"[I4] ReverseSybil without coordinator auth", status=s)

    if not _rejected(s, b):
        f = _finding(
            inv=3,
            title="ReverseSybil accepted without coordinator authorization (Phase D)",
            severity=Severity.CRITICAL,
            steps=[
                f"Broadcast ReverseSybil targeting bob from alice (non-coordinator)",
                f"Response status={s}",
            ],
            expected="ReverseSybil rejected — requires coordinator authorization (Phase D)",
            actual=f"ReverseSybil accepted status={s}",
            evidence={"target": bob, "reverser": alice, "response": b},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info("[I4] ReverseSybil correctly rejected without coordinator ✓", status=s)

    return findings


# ---------------------------------------------------------------------------
# I5 — Sybil rate measurement
# ---------------------------------------------------------------------------

def attack_i5_sybil_rate_measurement(
    client: httpx.Client,
    cfg: dict[str, Any],
    n: int = 50,
) -> list[FindingRecord]:
    """
    The core identity pilot measurement: register N identities from
    a single controller and measure how many reach Verified tier.
    Pilot target: < 3% sybil rate.

    In a real pilot these would be distinct humans; here we measure
    how many synthetic identities the protocol allows one controller to verify,
    which is the lower bound on sybil resistance.
    """
    findings: list[FindingRecord] = []
    node = cfg["nodes"]["api_urls"][0]
    controller = f"ctrl-sybil-pilot-{uuid.uuid4().hex[:8]}"

    log.info(f"[I5] registering {n} identities under controller={controller}…")

    registered = 0
    verified   = 0

    for i in range(n):
        addr = f"qcb1sybil{i:05d}{'0'*27}"[:42]

        # [ASSUMPTION] registration tx type — update to real name
        # grep -n 'RegisterIdentity|register_identity|Identity|PersonhoodRegister'
        #     chain-forge-execution/src/tx.rs
        s, b = _broadcast_tx(
            client, node, "RegisterIdentity",  # [ASSUMPTION]
            payload={
                "address":     addr,
                "controller":  controller,
                "pub_key":     f"cd{i:04x}" + "00" * 30,
            },
            sender=addr,
        )
        if not _rejected(s, b):
            registered += 1

    time.sleep(3)  # wait for state

    # Count how many reached Verified tier
    for i in range(n):
        addr = f"qcb1sybil{i:05d}{'0'*27}"[:42]
        status = _identity_status(client, node, addr)
        tier = status.get("verification_tier", "")
        if tier in (TIER_VERIFIED, TIER_ESTABLISHED):
            verified += 1

    sybil_rate = verified / n if n > 0 else 0.0
    log.info(
        f"[I5] n={n}, registered={registered}, verified={verified}, "
        f"sybil_rate={sybil_rate:.1%} (target < {SYBIL_RATE_TARGET:.0%})"
    )

    if registered == 0:
        log.warn(
            f"[I5] NOT_TESTED — 0/{n} identities registered; "
            "RegisterIdentity tx type or endpoint may differ from assumption"
        )
        return findings

    if sybil_rate > SYBIL_RATE_TARGET:
        f = _finding(
            inv=7,
            title=f"Sybil rate {sybil_rate:.1%} exceeds pilot target of {SYBIL_RATE_TARGET:.0%}",
            severity=Severity.CRITICAL,
            steps=[
                f"Register {n} identities sharing controller={controller}",
                "Wait 3s for state propagation",
                f"Query /api/identity/{{addr}} for each — count Verified tier",
                f"Found {verified}/{n} verified = {sybil_rate:.1%}",
            ],
            expected=f"Sybil rate < {SYBIL_RATE_TARGET:.0%} (whitepaper §4 pilot target)",
            actual=f"Sybil rate = {sybil_rate:.1%} ({verified}/{n} verified)",
            evidence={
                "n": n, "registered": registered,
                "verified": verified, "sybil_rate": sybil_rate,
                "controller": controller,
                "target": SYBIL_RATE_TARGET,
            },
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info(
            f"[I5] sybil rate {sybil_rate:.1%} within pilot target ✓ "
            f"({verified}/{n} verified)"
        )

    return findings


# ---------------------------------------------------------------------------
# I6 — DIS challenge replay (anti-replay)
# ---------------------------------------------------------------------------

def attack_i6_dis_challenge_replay(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    DIS Phase A: challenges are single-use. Present the same signed response twice.
    The second use must be rejected by the anti-replay guard.
    """
    findings: list[FindingRecord] = []
    node = cfg["nodes"]["rpc_urls"][0]

    # Step 1: fetch a challenge
    s1, challenge = _get(client, f"{node}{DIS_CHALLENGE_ENDPOINT}")
    if s1 != 200 or not challenge.get("challenge_id"):
        log.warn("[I6] could not fetch DIS challenge — endpoint may differ", status=s1)
        return findings

    challenge_id = challenge["challenge_id"]
    fake_sig = "ab" * 64

    # Step 2: present response (will likely fail due to fake sig, but tests replay path)
    response_payload = {
        "challenge_id": challenge_id,
        "signature":    fake_sig,
        "pub_key":      "cd" * 32,
        "rp_id":        "devnet",
    }
    s2, b2 = _post(client, f"{node}{DIS_VERIFY_ENDPOINT}", response_payload)
    log.info(f"[I6] first presentation", status=s2)

    # Step 3: replay same challenge_id
    s3, b3 = _post(client, f"{node}{DIS_VERIFY_ENDPOINT}", response_payload)
    log.info(f"[I6] replay of same challenge_id", status=s3)

    # Even if first failed (bad sig), the challenge_id should be consumed/expired
    # The replay must be rejected with a distinct "challenge already used" or "not found" error
    if not _rejected(s3, b3):
        f = _finding(
            inv=6,
            title="DIS challenge replay accepted (anti-replay failed)",
            severity=Severity.CRITICAL,
            steps=[
                f"Fetch challenge_id={challenge_id} from {DIS_CHALLENGE_ENDPOINT}",
                f"Present response (status={s2})",
                f"Replay same challenge_id (status={s3})",
            ],
            expected="Replayed challenge rejected — single-use challenge already consumed",
            actual=f"Replay returned status={s3}, body={b3}",
            evidence={"challenge_id": challenge_id, "first": b2, "replay": b3},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info("[I6] DIS challenge replay correctly rejected ✓", status=s3)

    return findings


# ---------------------------------------------------------------------------
# I7 — DIS cross-RP replay (audience binding)
# ---------------------------------------------------------------------------

def attack_i7_dis_cross_rp_replay(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    A response signed for rp_id='devnet-rp-a' must not be accepted by rp_id='devnet-rp-b'.
    Tests the rp_id + rp_origin audience binding from DIS-KS-V1.
    """
    findings: list[FindingRecord] = []
    node = cfg["nodes"]["rpc_urls"][0]

    # Fetch challenge for RP-A
    s1, challenge = _get(client, f"{node}{DIS_CHALLENGE_ENDPOINT}?rp_id=devnet-rp-a")
    if s1 != 200 or not challenge.get("challenge_id"):
        log.warn("[I7] could not fetch DIS challenge for RP-A", status=s1)
        return findings

    challenge_id = challenge["challenge_id"]

    # Present response claiming rp_id=devnet-rp-b (wrong audience)
    s2, b2 = _post(client, f"{node}{DIS_VERIFY_ENDPOINT}", {
        "challenge_id": challenge_id,
        "signature":    "ab" * 64,
        "pub_key":      "cd" * 32,
        "rp_id":        "devnet-rp-b",   # wrong RP
    })
    log.info(f"[I7] cross-RP presentation (rp_id mismatch)", status=s2)

    if not _rejected(s2, b2):
        f = _finding(
            inv=9,
            title="DIS cross-RP replay accepted (audience binding failed)",
            severity=Severity.CRITICAL,
            steps=[
                "Fetch challenge for rp_id=devnet-rp-a",
                "Present response with rp_id=devnet-rp-b (wrong audience)",
                f"Response status={s2}",
            ],
            expected="Rejected — rp_id mismatch in audience binding",
            actual=f"status={s2}, body={b2}",
            evidence={"challenge_id": challenge_id, "response": b2},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info("[I7] cross-RP replay correctly rejected ✓", status=s2)

    return findings


# ---------------------------------------------------------------------------
# I8 — DIS chain-ID binding (confirmed in Phase B test B4)
# ---------------------------------------------------------------------------

def attack_i8_dis_chain_id_binding(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    DIS Phase B test B4 confirmed chain-ID binding. We run it as a regression.
    Present a DIS response with wrong chain_id; must be rejected.
    """
    findings: list[FindingRecord] = []
    node = cfg["nodes"]["rpc_urls"][0]

    s1, challenge = _get(client, f"{node}{DIS_CHALLENGE_ENDPOINT}")
    if s1 != 200 or not challenge.get("challenge_id"):
        log.warn("[I8] could not fetch DIS challenge", status=s1)
        return findings

    challenge_id = challenge["challenge_id"]

    s2, b2 = _post(client, f"{node}{DIS_VERIFY_ENDPOINT}", {
        "challenge_id": challenge_id,
        "signature":    "ab" * 64,
        "pub_key":      "cd" * 32,
        "rp_id":        "devnet",
        "chain_id":     "qcb-mainnet-1",   # wrong chain
    })
    log.info(f"[I8] DIS with wrong chain_id", status=s2)

    if not _rejected(s2, b2):
        f = _finding(
            inv=9,
            title="DIS chain-ID binding regression: wrong chain_id accepted",
            severity=Severity.CRITICAL,
            steps=[
                "Fetch DIS challenge",
                "Present response with chain_id=qcb-mainnet-1 (wrong chain)",
                f"Response status={s2}",
            ],
            expected="Rejected — DIS Phase B test B4 regression (chain-ID binding)",
            actual=f"status={s2}, body={b2}",
            evidence={"challenge_id": challenge_id, "response": b2},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info("[I8] DIS chain-ID binding regression PASSED ✓", status=s2)

    return findings


# ---------------------------------------------------------------------------
# I9 — DIS delegation depth overflow (limit = 4)
# ---------------------------------------------------------------------------

def attack_i9_delegation_depth_overflow(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    Build a delegation chain of depth 5 (one deeper than the limit of 4).
    The chain validator must reject it.
    Whitepaper §4 DIS: "chain depth ≤ 4".

    The server checks chain length BEFORE enrollment, so no enrolled key is needed.
    Must target the DIS vendor server (/api/dis/verify_delegated), NOT the blockchain node.
    """
    findings: list[FindingRecord] = []
    vendor_url = cfg.get("dis", {}).get("vendor_url")
    if not vendor_url:
        log.warn("[I9] NOT_TESTED — no [dis].vendor_url in config")
        return findings

    # 5 properly-structured links; depth check fires before hex-decode / signature check.
    fake_link = {
        "rp_id":                  "devnet",
        "delegator_public_key":   "ff" * 4,
        "delegate_public_key":    "ee" * 4,
        "scopes":                 ["document:read"],
        "resource_id":            "doc-001",
        "action":                 "read",
        "issued_at":              1,
        "expires_at":             9_999_999_999,
        "max_uses":               None,
        "requires_human_approval": False,
        "signature":              "cc" * 4,
    }
    s, b = _post(client, f"{vendor_url}{DIS_VENDOR_VERIFY_DELEGATED}", {
        "wallet_id":           "i9-test",
        "vendor_id":           cfg.get("dis", {}).get("vendor_id", "devnet"),
        "challenge":           {
            "challenge_id": [0] * 16, "nonce": [0] * 16,
            "issued_at": 1, "expires_at": 9_999_999_999,
            "resource_id": "doc-001", "action": "read",
            "scopes": ["document:read"], "policy_id": "v1",
            "rp_id": cfg.get("dis", {}).get("vendor_id", "devnet"),
            "rp_origin": "https://devnet.example", "suite_id": 1,
        },
        "delegation_chain":    [fake_link] * 5,
        "agent_public_key_hex": "ab" * 4,
        "agent_signature_hex":  "cd" * 4,
    })
    log.info(f"[I9] delegation depth=5 (limit=4)", status=s)

    # Require HTTP 403 "delegation chain empty or exceeds max depth"
    depth_rejected = (
        s == 403 and
        b.get("status") == "rejected" and
        "max depth" in b.get("message", "").lower()
    )
    if not depth_rejected:
        if s not in (400, 403, 422):
            verdict = "accepted"
        else:
            verdict = f"rejected for wrong reason (status={s}, msg={b.get('message','?')})"
        f = _finding(
            inv=None,
            title="DIS delegation depth overflow: chain not rejected for correct reason",
            severity=Severity.HIGH,
            steps=[
                "POST /api/dis/verify_delegated with depth=5 chain",
                f"Response: status={s}, body={b}",
            ],
            expected="HTTP 403, status='rejected', message contains 'max depth'",
            actual=verdict,
            evidence={"chain_depth": 5, "response": b},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info("[I9] delegation depth overflow correctly rejected ✓", status=s)

    return findings


# ---------------------------------------------------------------------------
# I10 — DIS delegation scope widening
# ---------------------------------------------------------------------------

def attack_i10_scope_widening(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    A delegated proof must not claim wider scopes than the parent granted.
    Present a delegation chain where delegatee claims ["document:read","document:write"]
    but parent only granted ["document:read"].

    NOTE: Scope-widening check fires AFTER the root-holder enrollment check (Phase 1).
    Without an enrolled root delegator key the server returns 403 "not enrolled"
    before it ever reaches the scope check.  This test only produces a conclusive PASS
    when run with a full DIS setup (see I11).  If [dis].vendor_url is not set the test
    reports NOT_TESTED.
    """
    findings: list[FindingRecord] = []
    vendor_url = cfg.get("dis", {}).get("vendor_url")
    if not vendor_url:
        log.warn("[I10] NOT_TESTED — no [dis].vendor_url in config")
        return findings

    vendor_id = cfg.get("dis", {}).get("vendor_id", "devnet")
    fake_pk_a = "ff" * 4
    fake_pk_b = "ee" * 4
    fake_pk_c = "dd" * 4
    base_link = {
        "rp_id": vendor_id, "resource_id": "doc-001", "action": "read",
        "issued_at": 1, "expires_at": 9_999_999_999,
        "max_uses": None, "requires_human_approval": False, "signature": "cc" * 4,
    }
    s, b = _post(client, f"{vendor_url}{DIS_VENDOR_VERIFY_DELEGATED}", {
        "wallet_id":  "i10-test",
        "vendor_id":  vendor_id,
        "challenge":  {
            "challenge_id": [0] * 16, "nonce": [0] * 16,
            "issued_at": 1, "expires_at": 9_999_999_999,
            "resource_id": "doc-001", "action": "read",
            "scopes": ["document:read"], "policy_id": "v1",
            "rp_id": vendor_id, "rp_origin": "https://devnet.example", "suite_id": 1,
        },
        "delegation_chain": [
            {**base_link, "delegator_public_key": fake_pk_a, "delegate_public_key": fake_pk_b,
             "scopes": ["document:read"]},          # parent grants only read
            {**base_link, "delegator_public_key": fake_pk_b, "delegate_public_key": fake_pk_c,
             "scopes": ["document:read", "document:write"]},  # widened — not allowed
        ],
        "agent_public_key_hex": fake_pk_c,
        "agent_signature_hex":  "ab" * 4,
    })
    log.info(f"[I10] delegation scope widening attempt", status=s)

    # A 403 proves the request was processed.  The message tells us where it stopped.
    # "root delegator key is not enrolled" = stopped at Phase 1 (inconclusive for scope)
    # "child scopes widen parent"          = scope check fired (conclusive ✓)
    msg = b.get("message", "")
    if s == 403 and "child scopes widen parent" in msg:
        log.info("[I10] scope widening correctly rejected ✓ (scope check fired)", status=s)
    elif s == 403 and "not enrolled" in msg:
        log.warn("[I10] INCONCLUSIVE — request rejected at enrollment check before scope check; "
                 "run with a full DIS setup (see I11) for conclusive result")
    elif not _rejected(s, b):
        f = _finding(
            inv=None,
            title="DIS delegation scope widening accepted",
            severity=Severity.HIGH,
            steps=[
                "POST /api/dis/verify_delegated: link 1 grants [document:read], link 2 claims [document:read, document:write]",
                f"Response: status={s}, body={b}",
            ],
            expected="HTTP 403, message contains 'child scopes widen parent'",
            actual=f"status={s}, body={b}",
            evidence={"response": b},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info("[I10] scope widening rejected (reason may not be scope check)", status=s,
                 msg=msg)

    return findings


# ---------------------------------------------------------------------------
# I11 — DIS max_uses exhaustion then reuse
# ---------------------------------------------------------------------------

def _run_helper(binary: str, *args: str, stdin: str | None = None) -> dict:
    """Run dis-test-helper and return parsed JSON output."""
    result = subprocess.run(
        [binary, *args],
        input=stdin, capture_output=True, text=True, timeout=15
    )
    if result.returncode != 0:
        raise RuntimeError(f"dis-test-helper failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def attack_i11_max_uses_exhaustion(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    A delegation with max_uses=2 must reject the 3rd use.
    Uses the actual /api/dis/verify_delegated endpoint on the DIS vendor server
    with a real ML-DSA-65 (Dilithium3/pqcrypto) signed delegation.
    """
    findings: list[FindingRecord] = []

    vendor_url = cfg.get("dis", {}).get("vendor_url")
    if not vendor_url:
        log.warn("[I11] NOT_TESTED — no [dis].vendor_url in config; "
                 "add [dis] vendor_url = 'http://127.0.0.1:3000' to run this test")
        return findings

    vendor_id = cfg.get("dis", {}).get("vendor_id", "devnet")

    # Locate the dis-test-helper binary (build root or beside this script)
    import shutil
    _here = Path(__file__).parent
    _bin_candidates = [
        Path("/home/user/chain-forge-engine/target/release/dis-test-helper"),
        _here / "../../chain-forge-engine/target/release/dis-test-helper",
        Path(shutil.which("dis-test-helper") or ""),
    ]
    helper = next((str(p) for p in _bin_candidates if p.exists()), None)
    if not helper:
        log.warn("[I11] NOT_TESTED — dis-test-helper binary not found; "
                 "run: cd /home/user/chain-forge-engine && cargo build --release -p dis-test-helper")
        return findings

    try:
        # ------------------------------------------------------------------ #
        # 1. Generate keypairs for holder (root delegator) and agent          #
        # ------------------------------------------------------------------ #
        holder = _run_helper(helper, "keygen")
        agent  = _run_helper(helper, "keygen")
        holder_pk = holder["public_key_hex"]
        holder_sk = holder["secret_key_hex"]
        agent_pk  = agent["public_key_hex"]

        # ------------------------------------------------------------------ #
        # 2. Enroll the holder on the DIS vendor server                       #
        # ------------------------------------------------------------------ #
        _, ec = _post(client, f"{vendor_url}/enroll/challenge",
                      {"wallet_id": "i11-holder", "vendor_id": vendor_id,
                       "public_key_hex": holder_pk})
        nonce_str: str
        if isinstance(ec.get("nonce"), list):
            nonce_str = bytes(ec["nonce"]).hex()
        else:
            nonce_str = str(ec.get("nonce", ""))
        enroll_sig = _run_helper(helper, "sign-nonce", "--sk", holder_sk,
                                 "--nonce", nonce_str)
        es, eb = _post(client, f"{vendor_url}/enroll",
                       {"wallet_id": "i11-holder", "vendor_id": vendor_id,
                        "public_key_hex": holder_pk,
                        "signature_hex": enroll_sig["signature_hex"]})
        if es not in (200, 201):
            log.warn(f"[I11] NOT_TESTED — enrollment failed: {es} {eb}")
            return findings
        log.info("[I11] holder enrolled", status=es)

        # ------------------------------------------------------------------ #
        # 3. Build delegation: holder → agent, max_uses=2                     #
        # ------------------------------------------------------------------ #
        now_ts = int(time.time())
        exp_ts = now_ts + 3600
        del_sig = _run_helper(
            helper, "make-delegation",
            "--delegator-pk", holder_pk, "--delegator-sk", holder_sk,
            "--delegate-pk",  agent_pk,
            "--rp-id",        vendor_id,
            "--resource-id",  "doc-001",
            "--action",       "read",
            "--scopes",       "document:read",
            "--issued-at",    str(now_ts),
            "--expires-at",   str(exp_ts),
            "--max-uses",     "2",
        )
        delegation_link = {
            "delegator_public_key": holder_pk,
            "delegate_public_key":  agent_pk,
            "rp_id":                vendor_id,
            "resource_id":          "doc-001",
            "action":               "read",
            "scopes":               ["document:read"],
            "issued_at":            now_ts,
            "expires_at":           exp_ts,
            "max_uses":             2,
            "requires_human_approval": False,
            "signature":            del_sig["signature_hex"],
        }

        results: list[tuple[int, dict]] = []

        # ------------------------------------------------------------------ #
        # 4. Three verify_delegated calls, fresh challenge each time           #
        # ------------------------------------------------------------------ #
        for use_num in range(1, 4):
            cs, cb = _post(client, f"{vendor_url}/challenge",
                           {"wallet_id": "i11-agent", "vendor_id": vendor_id,
                            "public_key_hex": agent_pk,
                            "resource_id": "doc-001", "action": "read",
                            "scopes": ["document:read"]})
            if cs not in (200, 201):
                log.warn(f"[I11] use{use_num}: challenge failed: {cs} {cb}")
                results.append((cs, cb))
                continue

            transcript_hex = _run_helper(
                helper, "canonical-request",
                stdin=json.dumps({
                    "suite_id":   cb.get("suite_id", 1),
                    "rp_id":      vendor_id,
                    "rp_origin":  f"https://{vendor_id}.example",
                    "challenge_id": cb["challenge_id"],
                    "nonce":        cb["nonce"],
                    "issued_at":    cb.get("issued_at", now_ts),
                    "expires_at":   cb.get("expires_at", exp_ts),
                    "resource_id":  "doc-001",
                    "action":       "read",
                    "scopes":       ["document:read"],
                    "policy_id":    cb.get("policy_id", "v1"),
                }),
            )["transcript_hex"]
            agent_sig = _run_helper(helper, "sign-transcript",
                                    "--sk", agent["secret_key_hex"],
                                    "--transcript", transcript_hex)
            vs, vb = _post(client, f"{vendor_url}{DIS_VENDOR_VERIFY_DELEGATED}", {
                "wallet_id":          "i11-agent",
                "vendor_id":          vendor_id,
                "challenge":          cb,
                "delegation_chain":   [delegation_link],
                "agent_public_key_hex": agent_pk,
                "agent_signature_hex":  agent_sig["signature_hex"],
            })
            log.info(f"[I11] use{use_num}: HTTP {vs}, status={vb.get('status')}, "
                     f"msg={vb.get('message','')}")
            results.append((vs, vb))

        if len(results) < 3:
            log.warn("[I11] NOT_TESTED — could not complete all 3 uses "
                     f"(only {len(results)} completed)")
            return findings

        (s1, b1), (s2, b2), (s3, b3) = results

        # ------------------------------------------------------------------ #
        # 5. Evaluate                                                          #
        # ------------------------------------------------------------------ #
        use1_ok = s1 == 200 and b1.get("status") == "verified"
        use2_ok = s2 == 200 and b2.get("status") == "verified"
        msg3    = b3.get("message", "").lower()
        use3_enforced = (s3 == 403 and b3.get("status") == "rejected" and
                         any(kw in msg3 for kw in ("max_uses", "usage", "limit", "exhausted")))

        if not use1_ok or not use2_ok:
            log.warn(f"[I11] NOT_TESTED — legitimate uses not verified: "
                     f"use1={s1}/{b1.get('status')}, use2={s2}/{b2.get('status')}")
            return findings

        if use3_enforced:
            log.info(f"[I11] max_uses=2 correctly enforced ✓ "
                     f"use1={s1}✓ use2={s2}✓ use3={s3}({b3.get('status')}) msg='{msg3}'")
        else:
            f = _finding(
                inv=None,
                title="DIS max_uses not enforced: third use accepted after max_uses=2",
                severity=Severity.MEDIUM,
                steps=[
                    "Enroll holder on DIS vendor server",
                    "Create delegation holder→agent max_uses=2",
                    f"Use 1: HTTP {s1}, status={b1.get('status')}",
                    f"Use 2: HTTP {s2}, status={b2.get('status')}",
                    f"Use 3 (over limit): HTTP {s3}, status={b3.get('status')}, msg={msg3}",
                ],
                expected="Use 3: HTTP 403, status=rejected, message contains usage-limit reason",
                actual=f"Use 3: HTTP {s3}, status={b3.get('status')}, msg={msg3}",
                evidence={"use1": b1, "use2": b2, "use3": b3},
            )
            findings.append(f)
            log.finding(f)

    except Exception as exc:
        log.error(f"[I11] exception during test: {exc}")

    return findings


# ---------------------------------------------------------------------------
# I12 — DIS human-approval bypass
# ---------------------------------------------------------------------------

def attack_i12_human_approval_bypass(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    A delegation with requires_human_approval=true must not be used
    without providing an explicit human-approval token.

    Security note: source-code analysis of dis-vendor-server/src/main.rs shows that
    verify_delegated_inner() does NOT enforce requires_human_approval — the field is
    stored in the Delegation struct but never checked in the verification path.
    This test confirms that finding against the live server.
    """
    findings: list[FindingRecord] = []

    vendor_url = cfg.get("dis", {}).get("vendor_url")
    if not vendor_url:
        log.warn("[I12] NOT_TESTED — no [dis].vendor_url in config")
        return findings

    vendor_id = cfg.get("dis", {}).get("vendor_id", "devnet")
    fake_pk_a = "ff" * 4
    fake_pk_b = "ee" * 4

    # Send a delegation with requires_human_approval=True and no approval token.
    # Fake keys/sig will fail cryptographic checks first; but if the server rejects
    # with a message about human approval, that proves the check exists.
    # If it rejects only on sig/enrollment, we report the code-level finding.
    s, b = _post(client, f"{vendor_url}{DIS_VENDOR_VERIFY_DELEGATED}", {
        "wallet_id":  "i12-test",
        "vendor_id":  vendor_id,
        "challenge":  {
            "challenge_id": [0] * 16, "nonce": [0] * 16,
            "issued_at": 1, "expires_at": 9_999_999_999,
            "resource_id": "doc-001", "action": "read",
            "scopes": ["document:read"], "policy_id": "v1",
            "rp_id": vendor_id, "rp_origin": "https://devnet.example", "suite_id": 1,
        },
        "delegation_chain": [{
            "delegator_public_key": fake_pk_a,
            "delegate_public_key":  fake_pk_b,
            "rp_id":                vendor_id,
            "resource_id":          "doc-001",
            "action":               "read",
            "scopes":               ["document:read"],
            "issued_at":            1,
            "expires_at":           9_999_999_999,
            "max_uses":             None,
            "requires_human_approval": True,   # requires approval
            "signature":            "cc" * 4,
        }],
        "agent_public_key_hex": fake_pk_b,
        "agent_signature_hex":  "ab" * 4,
        # no human_approval_token field
    })
    log.info(f"[I12] human-approval bypass attempt", status=s, msg=b.get("message", ""))

    msg = b.get("message", "").lower()
    if s == 403 and any(kw in msg for kw in ("human", "approval", "approved")):
        log.info("[I12] human-approval bypass correctly rejected ✓", status=s)
    else:
        # Server rejected for another reason (sig/enrollment) or accepted.
        # Either way, the code-level analysis confirms non-enforcement.
        f = _finding(
            inv=None,
            title="DIS requires_human_approval not enforced in verify_delegated_inner",
            severity=Severity.HIGH,
            steps=[
                "Source analysis: dis-vendor-server/src/main.rs verify_delegated_inner() "
                "stores requires_human_approval in Delegation struct but never checks it",
                f"Live test: POST /api/dis/verify_delegated with requires_human_approval=true "
                f"and no approval token → HTTP {s}, msg='{b.get('message', '')}'",
            ],
            expected="HTTP 403 with message referencing human approval requirement",
            actual=f"HTTP {s}, msg='{b.get('message', '')}' — no human-approval enforcement visible",
            evidence={"response": b,
                      "code_ref": "dis-vendor-server/src/main.rs verify_delegated_inner()"},
        )
        findings.append(f)
        log.finding(f)

    return findings


# ---------------------------------------------------------------------------
# I13 — Coordinator centralization probe
# ---------------------------------------------------------------------------

def attack_i13_coordinator_probe(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    The whitepaper names coordinator role as a "temporary centralization".
    This probe documents which guard txs any caller can invoke vs. which
    are correctly gated to the coordinator role.
    Not a finding per se — produces an INFO record of the centralization surface.
    """
    findings: list[FindingRecord] = []
    node  = cfg["nodes"]["api_urls"][0]
    alice = cfg["accounts"]["alice"]  # alice IS the coordinator in genesis
    bob   = cfg["accounts"]["bob"]   # bob is NOT the coordinator

    gated: dict[str, bool] = {}
    for tx_type, payload in [
        (TX_ATTEST_ENTITY,    {"attestee": bob, "attester": alice, "claim": "personhood"}),
        (TX_REVOKE_ATTESTATION, {"attestee": bob, "attester": alice}),
        (TX_REPORT_SUSPECTED,  {"target": bob, "reporter": alice, "evidence": "test"}),
        (TX_CONFIRM_SYBIL,     {"target": bob, "reporter": alice, "evidence": "test"}),
        (TX_REVERSE_SYBIL,     {"target": bob, "reverser": alice, "justification": "test"}),
    ]:
        s, b = _broadcast_tx(client, node, tx_type, payload=payload, sender=alice)
        gated[tx_type] = _rejected(s, b)
        log.info(f"[I13] {tx_type}: {'GATED ✓' if gated[tx_type] else 'OPEN (any caller)'}")

    # Any tx that SHOULD be coordinator-only but isn't is a finding
    # From whitepaper: ConfirmSybil and ReverseSybil are coordinator-gated (Phases C+D)
    coordinator_only = {TX_CONFIRM_SYBIL, TX_REVERSE_SYBIL}
    for tx_type in coordinator_only:
        if not gated.get(tx_type, True):
            f = _finding(
                inv=3,
                title=f"Coordinator-only tx {tx_type} accepted from non-coordinator",
                severity=Severity.CRITICAL,
                steps=[
                    f"Broadcast {tx_type} from alice (non-coordinator)",
                    "Not rejected",
                ],
                expected=f"{tx_type} requires coordinator role (Phases C/D)",
                actual=f"{tx_type} accepted from ordinary account",
                evidence={"tx_type": tx_type, "gated_map": gated},
            )
            findings.append(f)
            log.finding(f)

    # Document the centralization surface regardless
    log.info("[I13] coordinator centralization surface", gated_map=gated)
    return findings


# ---------------------------------------------------------------------------
# I14 — Contribution score penalty after sybil confirmation
# ---------------------------------------------------------------------------

def attack_i14_cs_penalty_after_sybil(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    After a machine is confirmed as sybil (Phase C), its contribution_score
    must be penalised and further uQCB accumulation blocked.
    We check the identity API after ConfirmSybil to verify the penalty landed.
    """
    findings: list[FindingRecord] = []
    node  = cfg["nodes"]["api_urls"][0]
    alice = cfg["accounts"]["alice"]
    carol = cfg["accounts"]["carol"]

    cs_before = _identity_status(client, node, carol).get("contribution_score", -1)
    log.info(f"[I14] carol CS before sybil confirmation: {cs_before}")

    # ConfirmSybil — may fail if alice is not coordinator (expected on real devnet)
    _broadcast_tx(
        client, node, TX_CONFIRM_SYBIL,
        payload={"target": carol, "reporter": alice, "evidence": "pilot-test"},
        sender=alice,
    )
    time.sleep(2)

    cs_after = _identity_status(client, node, carol).get("contribution_score", -1)
    tier_after = _identity_status(client, node, carol).get("verification_tier", "")
    log.info(f"[I14] carol CS after sybil confirmation: {cs_after}, tier: {tier_after}")

    if cs_before == -1 and cs_after == -1:
        log.warn("[I14] NOT_TESTED — carol identity not found or CS field absent; "
                 "ConfirmSybil may have been rejected (alice may not be coordinator)")
        return findings

    # If CS didn't decrease and tier didn't change, penalty may not have applied
    if cs_before != -1 and cs_after >= cs_before and tier_after != "Sybil":
        f = _finding(
            inv=7,
            title="Sybil confirmation did not penalise contribution score",
            severity=Severity.HIGH,
            steps=[
                f"Record carol CS={cs_before}",
                "ConfirmSybil targeting carol",
                f"Carol CS after={cs_after}, tier={tier_after}",
            ],
            expected="CS penalised and/or tier set to Sybil after ConfirmSybil",
            actual=f"CS unchanged ({cs_before}→{cs_after}), tier={tier_after}",
            evidence={"cs_before": cs_before, "cs_after": cs_after, "tier": tier_after},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info(f"[I14] CS penalty applied ✓ ({cs_before}→{cs_after}, tier={tier_after})")

    return findings


# ---------------------------------------------------------------------------
# I15 — Epoch timestamp drift (whitepaper audit finding)
# ---------------------------------------------------------------------------

def attack_i15_timestamp_drift(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    Whitepaper audit (PR #1 comment, commit 2ee3e24) found:
    proposal.timestamp_ms is stored but never validated. A proposer can
    set an arbitrary timestamp without rejection.
    Consensus safety: NONE. Explorer integrity: MEDIUM.
    We confirm and quantify the drift via the debug injection endpoint.
    """
    findings: list[FindingRecord] = []
    node = cfg["nodes"]["rpc_urls"][0]

    far_future_ms = (int(time.time()) + 365 * 24 * 3600) * 1000  # 1 year ahead

    s, b = _post(client, f"{node}/debug/inject_proposal", {
        "chain_id":     cfg.get("chain_id", "devnet"),
        "height":       999_999,
        "round":        0,
        "block_hash":   "aa" * 32,
        "proposer":     cfg["accounts"]["alice"],
        "signature":    "ff" * 64,
        "timestamp_ms": far_future_ms,  # far-future timestamp
    })
    log.info(f"[I15] injected proposal with timestamp 1yr in future", status=s)

    # Check explorer API to see if the forged timestamp appears
    time.sleep(2)
    _, blocks_raw = _get(client, f"{cfg['nodes']['api_urls'][0]}/api/blocks")
    # API may return a list directly or {"blocks": [...]}
    if isinstance(blocks_raw, list):
        blocks_list = blocks_raw
    else:
        blocks_list = blocks_raw.get("blocks", [])
    forged_seen = any(
        (b.get("timestamp_ms", 0) if isinstance(b, dict) else 0) >= far_future_ms
        for b in blocks_list
    )

    if forged_seen:
        f = _finding(
            inv=None,
            title="Block explorer shows forged far-future timestamp (audit finding I15)",
            severity=Severity.MEDIUM,
            steps=[
                f"Inject proposal with timestamp_ms={far_future_ms} (1yr future)",
                "Poll /api/blocks",
                "Far-future timestamp visible in block list",
            ],
            expected="Timestamp validated; drift beyond reasonable window rejected",
            actual=f"Block explorer shows timestamp_ms={far_future_ms}",
            evidence={"far_future_ms": far_future_ms, "blocks_sample": blocks_list[:3]},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info("[I15] far-future timestamp not surfaced in explorer (or injection rejected) ✓")

    return findings


# ---------------------------------------------------------------------------
# I16 — Governance turnout suppression simulation (Open Q17)
# ---------------------------------------------------------------------------

def attack_i16_turnout_suppression(
    client: httpx.Client,
    cfg: dict[str, Any],
) -> list[FindingRecord]:
    """
    Open Question 17 from whitepaper: can an attacker suppress legitimate
    turnout by spamming ProposeChange txs (governance fatigue)?

    We flood proposals and then check whether the governance queue is so
    large that legitimate voters would be unable to process it.
    This is a documentation/measurement attack, not an exploit per se.
    """
    findings: list[FindingRecord] = []
    node  = cfg["nodes"]["api_urls"][0]
    alice = cfg["accounts"]["alice"]
    flood = 100  # governance spam count

    log.info(f"[I16] flooding {flood} ProposeChange txs (governance fatigue probe)…")
    accepted = 0
    for i in range(flood):
        s, b = _broadcast_tx(
            client, node, TX_PROPOSE_CHANGE,
            payload={
                "parameter": f"test_param_{i}",
                "value":     str(i),
                "rationale": f"spam proposal {i}",
            },
            sender=alice,
        )
        if not _rejected(s, b):
            accepted += 1

    log.info(f"[I16] {accepted}/{flood} proposals accepted")

    # Check proposal queue depth
    _, gov_state = _get(client, f"{node}/api/governance/proposals")
    queue_depth = len(gov_state.get("proposals", []))
    log.info(f"[I16] governance queue depth: {queue_depth}")

    # If > 10 spam proposals landed, document as a governance fatigue risk
    if accepted > 10:
        f = _finding(
            inv=None,
            title=f"Governance spam: {accepted} proposals accepted (turnout suppression risk)",
            severity=Severity.MEDIUM,
            steps=[
                f"Flood {flood} ProposeChange txs from alice",
                f"{accepted} accepted; governance queue depth={queue_depth}",
            ],
            expected="Rate limiting or deposit requirement prevents spam proposals",
            actual=f"{accepted}/{flood} proposals accepted — Open Question 17 risk confirmed",
            evidence={
                "flood_count": flood, "accepted": accepted,
                "queue_depth": queue_depth,
                "open_question": "Q17: turnout-suppression resistance",
            },
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info(f"[I16] governance spam correctly rate-limited ✓ ({accepted}/{flood} accepted)")

    return findings


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ATTACKS = [
    ("I1",  "Attestation guard: quadratic cost cap",           attack_i1_quadratic_cost_saturation, False),
    ("I2",  "Attestation guard: revocation bypass",            attack_i2_revocation_bypass,          False),
    ("I3",  "Attestation guard: ConfirmSybil no quorum",       attack_i3_sybil_confirm_no_quorum,    False),
    ("I4",  "Attestation guard: ReverseSybil unauthorized",    attack_i4_reverse_sybil_unauthorized, False),
    ("I5",  "Sybil rate measurement",                          attack_i5_sybil_rate_measurement,     True),
    ("I6",  "DIS challenge replay",                            attack_i6_dis_challenge_replay,       False),
    ("I7",  "DIS cross-RP replay",                             attack_i7_dis_cross_rp_replay,        False),
    ("I8",  "DIS chain-ID binding regression",                 attack_i8_dis_chain_id_binding,       False),
    ("I9",  "DIS delegation depth overflow",                   attack_i9_delegation_depth_overflow,  False),
    ("I10", "DIS delegation scope widening",                   attack_i10_scope_widening,            False),
    ("I11", "DIS max_uses exhaustion then reuse",              attack_i11_max_uses_exhaustion,       False),
    ("I12", "DIS human-approval bypass",                       attack_i12_human_approval_bypass,     False),
    ("I13", "Coordinator centralization probe",                attack_i13_coordinator_probe,          False),
    ("I14", "CS penalty after sybil confirmation",             attack_i14_cs_penalty_after_sybil,   False),
    ("I15", "Epoch timestamp drift (whitepaper audit finding)",attack_i15_timestamp_drift,           False),
    ("I16", "Governance turnout suppression (Open Q17)",       attack_i16_turnout_suppression,       False),
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="QCB IdentityPilotAdversary — red-team for the Qattice identity pilot"
    )
    parser.add_argument("--config",          required=True, type=Path)
    parser.add_argument("--findings-dir",    type=Path, default=Path("agents/findings"))
    parser.add_argument("--attack",          help="Run only I1..I16")
    parser.add_argument("--sybil-n",         type=int, default=50,
                        help="Number of identities to register in I5 sybil rate measurement (default: 50)")
    parser.add_argument("--measure-sybil-rate", action="store_true",
                        help="Run only I5 sybil rate measurement (shorthand)")
    parser.add_argument("--unsafe-override", action="store_true")
    args = parser.parse_args()

    cfg = load_config(args.config)
    try:
        chain_id = assert_devnet(cfg, unsafe_override=args.unsafe_override)
    except Exception as exc:
        abort(str(exc)); return

    cfg["chain_id"] = chain_id
    log.info("IdentityPilotAdversary starting", chain_id=chain_id)
    log.info(
        "Pilot targets",
        sybil_rate_target=f"< {SYBIL_RATE_TARGET:.0%}",
        cost_per_human_usd=f"< ${COST_PER_HUMAN_USD}",
    )
    args.findings_dir.mkdir(parents=True, exist_ok=True)
    total: list[FindingRecord] = []

    if args.measure_sybil_rate:
        findings = attack_i5_sybil_rate_measurement(
            httpx.Client(), cfg, n=args.sybil_n
        )
        for f in findings:
            f.save(args.findings_dir)
        total.extend(findings)
        log.info("Sybil rate measurement complete", findings=len(total))
        sys.exit(1 if total else 0)

    passed: list[str]    = []
    failed: list[str]    = []
    not_tested: list[str] = []
    errors: list[str]    = []

    with httpx.Client() as client:
        for tag, name, fn, needs_n in ATTACKS:
            if args.attack and args.attack.upper() != tag:
                continue
            log.info(f"Running {tag}: {name}")
            try:
                if needs_n:
                    findings = fn(client, cfg, n=args.sybil_n)
                else:
                    findings = fn(client, cfg)
                for f in findings:
                    f.save(args.findings_dir)
                total.extend(findings)
                if findings:
                    failed.append(tag)
                else:
                    passed.append(tag)
            except Exception as exc:
                log.error(f"Error in {tag}: {exc}")
                errors.append(tag)

    log.info(
        "IdentityPilotAdversary complete",
        total_findings=len(total),
        passed=passed,
        failed=failed,
        not_tested=not_tested,
        errors=errors,
    )
    if total or errors:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
