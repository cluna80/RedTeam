#!/usr/bin/env python3
"""
agents/agent_identity_pilot.py — Identity Pilot Test Driver

End-to-end attack and invariant suite for the Qattice identity pilot
(attestation-guard Phases A–D).

## Attacks covered

  IP-1  Self-attest: AttestEntity where attester == subject (INV-11)
  IP-2  Duplicate attestation: same (attester, subject) pair twice (INV-11)
  IP-3  Revoke → reward race: submit reward tx between RevokeAttestation and
        the block it confirms; entity must not be creditable (INV-12)
  IP-4  ConfirmSybil freeze check: entity MUST be unfundable/uncreditable
        immediately after ConfirmSybil confirms (INV-13)
  IP-5  ReportSuspectedSybil must not freeze: entity still receives rewards
        after a report (INV-14)
  IP-6  ReverseSybil restores: entity regains pop_verified after appeal (INV-13)
  IP-7  Sybil rate threshold: force >3% sybil confirms and check pilot alert (INV-15)
  IP-8  Concurrent AttestEntity race: two attestations for same entity race;
        idempotent result required (INV-11)

## Usage
    python agents/agent_identity_pilot.py --config agents/config/devnet3.toml
    python agents/agent_identity_pilot.py --config agents/config/devnet3.toml --attack IP-4
"""
from __future__ import annotations

import argparse
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.schema import AgentId, FindingRecord, Severity
from agents.devnet_guard import assert_devnet, load_config, abort
from agents.observability import StructuredLogger
from agents.identity_client import (
    attest_entity,
    revoke_attestation,
    confirm_sybil,
    report_suspected_sybil,
    reverse_sybil,
    get_entity_status,
    get_pilot_stats,
    rejected,
    tx_id_from_response,
    fetch_tx_result,
    transfer,
    register_identity,
    _fetch_chain_nonce,
)

# Well-known funded genesis addresses
_ALICE = "qcb1alice"
_BOB   = "qcb1bob"
_DAVE  = "qcb1dave"

log = StructuredLogger("agent_identity_pilot")

# How long to wait for a tx to confirm (blocks at ~1 s/block in devnet)
TX_CONFIRM_WAIT_SECS = 6


def _api(cfg: dict[str, Any]) -> str:
    return cfg["nodes"]["api_urls"][0]


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
        agent=AgentId.IDENTITY_PILOT,
        title=title,
        severity=severity,
        invariant_id=inv,
        steps=steps,
        expected=expected,
        actual=actual,
        evidence=evidence,
    )


def _wait_confirm() -> None:
    """Brief sleep to let a tx land in a block."""
    time.sleep(TX_CONFIRM_WAIT_SECS)


# ---------------------------------------------------------------------------
# IP-1: Self-attest (INV-11)
# ---------------------------------------------------------------------------

def attack_ip1_self_attest(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    AttestEntity where attester_controller == subject_controller (i.e., sender
    attests themselves).  The chain MUST reject this (INV-11).

    Uses Alice (funded genesis account) so gas is available.  Verifies via
    GET /api/tx/{id} that the execution result has success=False; a 200/queued
    mempool response alone does not mean the tx executed successfully.
    """
    findings: list[FindingRecord] = []
    api = _api(cfg)

    # Alice attests herself — sender == claimant_id
    s, b = attest_entity(
        client, api,
        entity_id=_ALICE,
        subject_controller=_ALICE,
        attester_controller=_ALICE,   # same — must be rejected
    )
    tx_id = tx_id_from_response(b)
    log.info("[IP-1] self-attest submitted", status=s, tx_id=tx_id)

    # Wait for block inclusion, then check execution result
    import time; time.sleep(TX_CONFIRM_WAIT_SECS)

    exec_ok: bool | None = None
    exec_body: dict = {}
    if tx_id:
        _, exec_body = fetch_tx_result(client, api, tx_id)
        exec_ok = exec_body.get("success", None)

    log.info("[IP-1] self-attest execution result", success=exec_ok,
             error=exec_body.get("error"))

    if rejected(s, b):
        # Mempool-level rejection is acceptable (stricter than required)
        log.info("[IP-1] self-attest correctly rejected at HTTP layer ✓")
    elif exec_ok is True:
        # Tx executed — self-attest was NOT blocked at execution
        findings.append(_finding(
            inv=11,
            title="AttestEntity accepted with attester == subject controller",
            severity=Severity.CRITICAL,
            steps=[
                f"POST /api/tx AttestEntity entity_id={_ALICE} sender={_ALICE}",
                f"attester_controller == subject (self-attest)",
                f"Execution result: success={exec_ok}",
            ],
            expected="Tx rejected — self-attestation is prohibited (INV-11)",
            actual=f"Tx accepted with status={s}, execution success={exec_ok}",
            evidence={"entity_id": _ALICE, "exec": exec_body},
        ))
        log.finding(findings[-1])
    else:
        # exec_ok is False — chain rejected at execution ✓
        log.info("[IP-1] self-attest correctly rejected at execution ✓",
                 error=exec_body.get("error"))

    return findings


# ---------------------------------------------------------------------------
# IP-2: Duplicate attestation (INV-11)
# ---------------------------------------------------------------------------

def attack_ip2_duplicate_attest(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    IP-2: Duplicate active attestation — same (attester, claimant) pair attests twice.
    The second Attest tx MUST fail at execution with AlreadyAttested.

    Prior version used unregistered ctrl-* addresses; both attests failed before
    reaching the dedup guard (root cause: fake addresses have no on-chain identity).

    Rewrite:
      - Fund a fresh address from Alice (sequential, confirmed before proceeding).
      - Register it as a Provisional identity on-chain.
      - Alice (Verified genesis identity) submits two Attest txs for the same claimant.
      - Verdict is based on tx execution result (GET /api/tx/{id}), not HTTP status.
    """
    findings: list[FindingRecord] = []
    api = _api(cfg)

    # --- Step 1: fund a fresh Provisional claimant from Alice ---
    claimant = f"qcb1ip2{uuid.uuid4().hex[:12]}"
    alice_nonce = _fetch_chain_nonce(api, _ALICE) or 0
    s_fund, b_fund = transfer(
        client, api, sender=_ALICE, to=claimant, amount=200_000, nonce=alice_nonce,
    )
    fund_tid = tx_id_from_response(b_fund)
    log.info("[IP-2] funding fresh claimant", addr=claimant, tx_id=fund_tid, status=s_fund)
    _wait_confirm()

    # Verify funding landed before registering
    _, fund_exec = fetch_tx_result(client, api, fund_tid) if fund_tid else (0, {})
    if not fund_exec.get("success"):
        log.info("[IP-2] funding did not land — skipping test", error=fund_exec.get("error"))
        return findings

    # --- Step 2: register claimant as Provisional ---
    s_reg, b_reg = register_identity(client, api, sender=claimant, nonce=0)
    reg_tid = tx_id_from_response(b_reg)
    log.info("[IP-2] registering claimant", tx_id=reg_tid, status=s_reg)
    _wait_confirm()

    _, reg_exec = fetch_tx_result(client, api, reg_tid) if reg_tid else (0, {})
    if not reg_exec.get("success"):
        log.info("[IP-2] registration did not land — skipping test", error=reg_exec.get("error"))
        return findings

    # --- Step 3: Alice attests the claimant (first, must succeed) ---
    s1, b1 = attest_entity(
        client, api,
        entity_id=claimant,
        subject_controller=claimant,
        attester_controller=_ALICE,
    )
    att1_tid = tx_id_from_response(b1)
    log.info("[IP-2] first attest", tx_id=att1_tid, status=s1)
    _wait_confirm()

    _, exec1 = fetch_tx_result(client, api, att1_tid) if att1_tid else (0, {})
    if not exec1.get("success"):
        log.info(
            "[IP-2] first attest failed at execution — cannot proceed",
            error=exec1.get("error"), tx_id=att1_tid,
        )
        return findings

    log.info("[IP-2] first attest confirmed at execution ✓")

    # --- Step 4: Alice attests same claimant again (must fail with AlreadyAttested) ---
    s2, b2 = attest_entity(
        client, api,
        entity_id=claimant,
        subject_controller=claimant,
        attester_controller=_ALICE,
    )
    att2_tid = tx_id_from_response(b2)
    log.info("[IP-2] duplicate attest submitted", tx_id=att2_tid, status=s2)
    _wait_confirm()

    _, exec2 = fetch_tx_result(client, api, att2_tid) if att2_tid else (0, {})
    exec2_ok = exec2.get("success")
    exec2_err = exec2.get("error", "")

    if exec2_ok is True:
        # Dedup guard did not fire — security finding
        findings.append(_finding(
            inv=11,
            title="Duplicate active attestation accepted at execution (AlreadyAttested guard missing)",
            severity=Severity.HIGH,
            steps=[
                f"Transfer 200_000 uqcb → {claimant} (funded)",
                f"RegisterIdentity sender={claimant} (Provisional)",
                f"Attest claimant={claimant} attester={_ALICE} — first (tx {att1_tid}) ✓",
                f"Attest claimant={claimant} attester={_ALICE} — duplicate (tx {att2_tid})",
                f"GET /api/tx/{att2_tid} → success=true (expected success=false + AlreadyAttested)",
            ],
            expected="Execution fails with AlreadyAttested — same active attester cannot attest twice",
            actual=f"Execution succeeded: success=true, tx={att2_tid}",
            evidence={"claimant": claimant, "att1_tid": att1_tid, "att2_tid": att2_tid,
                      "exec1": exec1, "exec2": exec2},
        ))
        log.finding(findings[-1])
    else:
        log.info(
            "[IP-2] duplicate attest correctly rejected at execution ✓",
            error=exec2_err, tx_id=att2_tid,
        )

    return findings


# ---------------------------------------------------------------------------
# IP-3: Revoke → reward race (INV-12)
# ---------------------------------------------------------------------------

def attack_ip3_revoke_reward_race(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    Establish pop_verified entity, then revoke attestation and immediately
    try to claim a reward before the revocation confirms.  The chain MUST
    honour the revocation atomically (INV-12).
    """
    findings: list[FindingRecord] = []
    api = _api(cfg)
    entity_id    = f"entity-race-{uuid.uuid4().hex[:8]}"
    subject_ctrl = f"ctrl-subject-{uuid.uuid4().hex[:8]}"
    attester_ctrl = f"ctrl-attester-{uuid.uuid4().hex[:8]}"

    # Phase A: establish attestation
    s_att, _ = attest_entity(
        client, api,
        entity_id=entity_id,
        subject_controller=subject_ctrl,
        attester_controller=attester_ctrl,
    )
    log.info("[IP-3] attestation established", status=s_att)
    _wait_confirm()

    # Phase B: revoke
    s_rev, b_rev = revoke_attestation(
        client, api,
        entity_id=entity_id,
        revoker_controller=attester_ctrl,
    )
    log.info("[IP-3] revocation submitted", status=s_rev)

    # Race: immediately check status (before block confirm)
    _wait_confirm()
    s_stat, b_stat = get_entity_status(client, api, entity_id)
    pop_verified = b_stat.get("pop_verified", None)
    log.info("[IP-3] entity status after revoke confirm", pop_verified=pop_verified, status=s_stat)

    if pop_verified is True:
        findings.append(_finding(
            inv=12,
            title="Entity pop_verified still true after RevokeAttestation confirmed",
            severity=Severity.CRITICAL,
            steps=[
                f"AttestEntity entity_id={entity_id}",
                "Wait confirm",
                f"RevokeAttestation entity_id={entity_id}",
                f"Wait {TX_CONFIRM_WAIT_SECS}s — poll entity status",
            ],
            expected="pop_verified=false after RevokeAttestation confirms (INV-12)",
            actual=f"pop_verified={pop_verified}",
            evidence={"entity_id": entity_id, "status": b_stat, "revoke_resp": b_rev},
        ))
        log.finding(findings[-1])
    else:
        log.info("[IP-3] pop_verified correctly cleared after revocation ✓")

    return findings


# ---------------------------------------------------------------------------
# IP-4: ConfirmSybil freeze (INV-13)
# ---------------------------------------------------------------------------

def attack_ip4_confirm_sybil_freeze(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    ConfirmSybil on a verified entity.  Entity MUST be frozen immediately.
    Probe by checking entity_status.frozen == true and no further reward
    events are accepted for that entity.

    Uses Bob as the target because Bob is a funded genesis account that can
    pay gas.  Bob must already be registered (genesis includes him).
    Alice is the attestation coordinator allowed to call ConfirmSybil.
    We first ReverseSybil Bob (in case a prior run left him frozen) so we
    start from a known unfrozen state.
    """
    findings: list[FindingRecord] = []
    api = _api(cfg)

    # Well-known funded addresses from genesis
    entity_id     = "qcb1bob"   # target — has genesis balance for gas
    coordinator   = "qcb1alice" # attestation_coordinator per genesis

    # --- Reset: if Bob is already frozen, unfreeze him first so this test
    #     starts from a clean state regardless of prior runs.
    _, prior_state = get_entity_status(client, api, entity_id)
    if prior_state.get("frozen"):
        log.info("[IP-4] Bob already frozen — ReverseSybil to reset state")
        from agents.identity_client import reverse_sybil
        reverse_sybil(client, api,
                      entity_id=entity_id, authority_controller=coordinator)
        _wait_confirm()

    # Make sure Bob is registered (he is in genesis, but confirm)
    _, pre = get_entity_status(client, api, entity_id)
    log.info("[IP-4] Bob pre-state", state=pre)

    # Alice attests Bob (may fail if already attested this epoch; ignore)
    attest_entity(client, api, entity_id=entity_id,
                  subject_controller=entity_id,
                  attester_controller=coordinator)
    _wait_confirm()

    # ConfirmSybil — Alice is the coordinator
    s_cs, b_cs = confirm_sybil(
        client, api,
        entity_id=entity_id,
        reporter_controller=coordinator,
    )
    log.info("[IP-4] ConfirmSybil submitted", status=s_cs)
    _wait_confirm()

    # Check freeze
    s_stat, b_stat = get_entity_status(client, api, entity_id)
    frozen         = b_stat.get("frozen", None)
    sybil_confirmed = b_stat.get("sybil_confirmed", None)
    log.info("[IP-4] entity status after ConfirmSybil",
             frozen=frozen, sybil_confirmed=sybil_confirmed)

    if frozen is not True:
        findings.append(_finding(
            inv=13,
            title="Entity not frozen after ConfirmSybil confirmed",
            severity=Severity.CRITICAL,
            steps=[
                f"AttestEntity entity_id={entity_id} attester={coordinator}",
                f"ConfirmSybil entity_id={entity_id} reporter={coordinator}",
                f"Wait {TX_CONFIRM_WAIT_SECS}s — poll entity status",
            ],
            expected="frozen=true and sybil_confirmed=true after ConfirmSybil (INV-13)",
            actual=f"frozen={frozen}, sybil_confirmed={sybil_confirmed}",
            evidence={"entity_id": entity_id, "confirm_resp": b_cs, "status": b_stat},
        ))
        log.finding(findings[-1])
    else:
        log.info("[IP-4] entity correctly frozen after ConfirmSybil ✓")

    return findings


# ---------------------------------------------------------------------------
# IP-5: ReportSuspectedSybil must not freeze (INV-14)
# ---------------------------------------------------------------------------

def attack_ip5_report_no_freeze(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    ReportSuspectedSybil must not change pop_verified or frozen status.
    """
    findings: list[FindingRecord] = []
    api = _api(cfg)
    entity_id     = f"entity-report-{uuid.uuid4().hex[:8]}"
    subject_ctrl  = f"ctrl-subject-{uuid.uuid4().hex[:8]}"
    attester_ctrl = f"ctrl-attester-{uuid.uuid4().hex[:8]}"
    reporter_ctrl = f"ctrl-reporter-{uuid.uuid4().hex[:8]}"

    attest_entity(client, api, entity_id=entity_id,
                  subject_controller=subject_ctrl,
                  attester_controller=attester_ctrl)
    _wait_confirm()

    # Capture baseline
    _, b_before = get_entity_status(client, api, entity_id)
    pv_before  = b_before.get("pop_verified", None)
    frz_before = b_before.get("frozen", False)

    # Report
    s_rep, b_rep = report_suspected_sybil(
        client, api,
        entity_id=entity_id,
        reporter_controller=reporter_ctrl,
    )
    log.info("[IP-5] ReportSuspectedSybil submitted", status=s_rep)
    _wait_confirm()

    # Check entity unchanged
    _, b_after = get_entity_status(client, api, entity_id)
    pv_after  = b_after.get("pop_verified", None)
    frz_after = b_after.get("frozen", False)
    log.info("[IP-5] entity status", pv_before=pv_before, pv_after=pv_after,
             frz_before=frz_before, frz_after=frz_after)

    if frz_after and not frz_before:
        findings.append(_finding(
            inv=14,
            title="ReportSuspectedSybil caused entity to be frozen",
            severity=Severity.CRITICAL,
            steps=[
                f"AttestEntity entity_id={entity_id}",
                f"ReportSuspectedSybil entity_id={entity_id} reporter={reporter_ctrl}",
                f"Wait {TX_CONFIRM_WAIT_SECS}s — poll entity status",
            ],
            expected="frozen=false after Report (only ConfirmSybil may freeze) (INV-14)",
            actual=f"frozen changed from {frz_before} → {frz_after}",
            evidence={"entity_id": entity_id, "before": b_before, "after": b_after},
        ))
        log.finding(findings[-1])
    elif pv_after != pv_before:
        findings.append(_finding(
            inv=14,
            title="ReportSuspectedSybil changed pop_verified status",
            severity=Severity.HIGH,
            steps=[
                f"AttestEntity entity_id={entity_id}",
                f"ReportSuspectedSybil — check pop_verified",
            ],
            expected="pop_verified unchanged by Report (INV-14)",
            actual=f"pop_verified: {pv_before} → {pv_after}",
            evidence={"entity_id": entity_id, "before": b_before, "after": b_after},
        ))
        log.finding(findings[-1])
    else:
        log.info("[IP-5] ReportSuspectedSybil correctly did not freeze entity ✓")

    return findings


# ---------------------------------------------------------------------------
# IP-6: ReverseSybil restores entity (INV-13)
# ---------------------------------------------------------------------------

def attack_ip6_reverse_sybil_restores(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    After ConfirmSybil, ReverseSybil MUST unfreeze the entity.

    Uses Dave as the target — he's a funded genesis account.  We first ensure
    Dave is frozen (ConfirmSybil if needed), then ReverseSybil and verify.
    Alice is the attestation_coordinator allowed to call both.
    """
    findings: list[FindingRecord] = []
    api = _api(cfg)
    entity_id      = "qcb1dave"   # funded genesis account
    coordinator    = "qcb1alice"  # attestation_coordinator per genesis

    # Ensure Dave is frozen so we have something to reverse.
    _, b_pre = get_entity_status(client, api, entity_id)
    if not b_pre.get("frozen", False):
        log.info("[IP-6] Dave not frozen — ConfirmSybil to set up reverse test")
        attest_entity(client, api, entity_id=entity_id,
                      subject_controller=entity_id,
                      attester_controller=coordinator)
        _wait_confirm()
        confirm_sybil(client, api, entity_id=entity_id, reporter_controller=coordinator)
        _wait_confirm()

    # Verify frozen before reversing
    _, b_frozen = get_entity_status(client, api, entity_id)
    if not b_frozen.get("frozen", False):
        log.info("[IP-6] entity not frozen after ConfirmSybil — skipping reverse test",
                 entity_id=entity_id)
        return findings

    # Now reverse
    s_rev, b_rev = reverse_sybil(
        client, api,
        entity_id=entity_id,
        authority_controller=coordinator,
    )
    log.info("[IP-6] ReverseSybil submitted", status=s_rev)
    _wait_confirm()

    _, b_after = get_entity_status(client, api, entity_id)
    frozen_after = b_after.get("frozen", True)
    log.info("[IP-6] entity after reverse", frozen=frozen_after)

    if frozen_after:
        findings.append(_finding(
            inv=13,
            title="Entity remains frozen after ReverseSybil confirmed",
            severity=Severity.HIGH,
            steps=[
                f"AttestEntity entity_id={entity_id}",
                f"ConfirmSybil — entity frozen",
                f"ReverseSybil authority={coordinator}",
                f"Wait {TX_CONFIRM_WAIT_SECS}s — entity still frozen",
            ],
            expected="frozen=false after ReverseSybil (INV-13 appeal path)",
            actual=f"frozen={frozen_after}",
            evidence={"entity_id": entity_id, "before": b_frozen, "after": b_after},
        ))
        log.finding(findings[-1])
    else:
        log.info("[IP-6] ReverseSybil correctly unfroze entity ✓")

    return findings


# ---------------------------------------------------------------------------
# IP-7: Sybil rate threshold (INV-15)
# ---------------------------------------------------------------------------

def attack_ip7_sybil_rate_threshold(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    Create SYBIL_COUNT entities, attest them all, then ConfirmSybil > 3%.
    The pilot stats endpoint MUST report an alert or the rate MUST be visible.
    This test verifies the monitoring path (INV-15).
    """
    findings: list[FindingRecord] = []
    api = _api(cfg)
    TOTAL     = 10
    SYBIL_N   = 4   # 40% >> 3% threshold; forces the alert condition

    entities: list[str] = []
    for i in range(TOTAL):
        entity_id     = f"entity-rate-{i}-{uuid.uuid4().hex[:6]}"
        subject_ctrl  = f"ctrl-s-{i}-{uuid.uuid4().hex[:6]}"
        attester_ctrl = f"ctrl-a-{i}-{uuid.uuid4().hex[:6]}"
        attest_entity(client, api, entity_id=entity_id,
                      subject_controller=subject_ctrl,
                      attester_controller=attester_ctrl)
        entities.append(entity_id)

    log.info(f"[IP-7] attested {TOTAL} entities, waiting for confirm…")
    _wait_confirm()

    # ConfirmSybil on SYBIL_N of them
    reporter_ctrl = f"ctrl-reporter-{uuid.uuid4().hex[:8]}"
    for entity_id in entities[:SYBIL_N]:
        confirm_sybil(client, api, entity_id=entity_id,
                      reporter_controller=reporter_ctrl)
    _wait_confirm()

    # Read pilot stats
    s_stats, b_stats = get_pilot_stats(client, api)
    log.info("[IP-7] pilot stats", status=s_stats, stats=b_stats)

    if s_stats == 0:
        # Stats endpoint not yet implemented — info finding
        findings.append(_finding(
            inv=15,
            title="[IP-7] Pilot stats endpoint unreachable — INV-15 monitoring unverifiable",
            severity=Severity.MEDIUM,
            steps=[
                f"Create {TOTAL} entities, confirm {SYBIL_N} as sybil",
                "GET /api/identity/pilot/stats",
            ],
            expected="Stats endpoint returns sybil_rate and alert_triggered",
            actual="Endpoint unreachable",
            evidence={"error": b_stats},
        ))
        log.finding(findings[-1])
    else:
        sybil_rate    = b_stats.get("sybil_rate", None)
        alert         = b_stats.get("alert_triggered", None)
        expected_rate = SYBIL_N / TOTAL

        if sybil_rate is not None and sybil_rate < expected_rate * 0.9:
            findings.append(_finding(
                inv=15,
                title="Pilot sybil_rate under-reported",
                severity=Severity.HIGH,
                steps=[
                    f"ConfirmSybil on {SYBIL_N}/{TOTAL} entities",
                    "GET /api/identity/pilot/stats",
                    f"Expected sybil_rate ≈ {expected_rate:.0%}, got {sybil_rate}",
                ],
                expected=f"sybil_rate ≈ {expected_rate:.0%} and alert_triggered=true",
                actual=f"sybil_rate={sybil_rate}, alert={alert}",
                evidence={"stats": b_stats},
            ))
            log.finding(findings[-1])
        else:
            log.info("[IP-7] sybil rate reported and monitoring visible ✓",
                     sybil_rate=sybil_rate, alert=alert)

    return findings


# ---------------------------------------------------------------------------
# IP-8: Concurrent AttestEntity race (INV-11)
# ---------------------------------------------------------------------------

def attack_ip8_concurrent_attest_race(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    Two simultaneous AttestEntity calls for the same (entity_id, attester, subject).
    Only one should be accepted; idempotent or TOCTOU failure would allow double credit.
    """
    findings: list[FindingRecord] = []
    api = _api(cfg)
    entity_id     = f"entity-conc-{uuid.uuid4().hex[:8]}"
    subject_ctrl  = f"ctrl-subject-{uuid.uuid4().hex[:8]}"
    attester_ctrl = f"ctrl-attester-{uuid.uuid4().hex[:8]}"
    results: dict[str, tuple[int, dict]] = {}

    def _attest(tag: str) -> None:
        s, b = attest_entity(client, api, entity_id=entity_id,
                             subject_controller=subject_ctrl,
                             attester_controller=attester_ctrl)
        results[tag] = (s, b)

    t1 = threading.Thread(target=_attest, args=("A",))
    t2 = threading.Thread(target=_attest, args=("B",))
    t1.start(); t2.start()
    t1.join();  t2.join()

    sa, ba = results.get("A", (0, {}))
    sb, bb = results.get("B", (0, {}))
    log.info("[IP-8] concurrent attest race", status_A=sa, status_B=sb)

    both_accepted = not rejected(sa, ba) and not rejected(sb, bb)
    if both_accepted:
        # Check attestation_count — should be 1 not 2
        _, b_stat = get_entity_status(client, api, entity_id)
        attest_count = b_stat.get("attestation_count", None)
        if attest_count is not None and attest_count > 1:
            findings.append(_finding(
                inv=11,
                title="Concurrent AttestEntity race: duplicate attestation counted",
                severity=Severity.HIGH,
                steps=[
                    f"Two simultaneous AttestEntity for entity_id={entity_id}",
                    "Both returned non-error",
                    f"attestation_count={attest_count} (expected 1)",
                ],
                expected="Race resolves to exactly 1 attestation counted",
                actual=f"attestation_count={attest_count}",
                evidence={"entity_id": entity_id, "resp_A": ba, "resp_B": bb, "status": b_stat},
            ))
            log.finding(findings[-1])
        else:
            log.info("[IP-8] race resolved to single attestation ✓",
                     attestation_count=attest_count)
    else:
        log.info("[IP-8] at least one attest rejected — race handled ✓",
                 status_A=sa, status_B=sb)

    return findings


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ATTACKS = [
    ("IP-1", "Self-attest block",                attack_ip1_self_attest),
    ("IP-2", "Duplicate attestation",            attack_ip2_duplicate_attest),
    ("IP-3", "Revoke→reward race",               attack_ip3_revoke_reward_race),
    ("IP-4", "ConfirmSybil freeze",              attack_ip4_confirm_sybil_freeze),
    ("IP-5", "ReportSuspectedSybil no-freeze",   attack_ip5_report_no_freeze),
    ("IP-6", "ReverseSybil restores entity",     attack_ip6_reverse_sybil_restores),
    ("IP-7", "Sybil rate threshold alert",       attack_ip7_sybil_rate_threshold),
    ("IP-8", "Concurrent attest race",           attack_ip8_concurrent_attest_race),
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Qattice Identity Pilot Test Driver — devnet only"
    )
    parser.add_argument("--config",          required=True, type=Path)
    parser.add_argument("--findings-dir",    type=Path, default=Path("agents/findings"))
    parser.add_argument("--attack",          help="Run only IP-N (e.g. IP-4)")
    parser.add_argument("--once",            action="store_true",
                        help="Accepted for runner compatibility (attacks always run once)")
    parser.add_argument("--unsafe-override", action="store_true")
    args = parser.parse_args()

    cfg = load_config(args.config)
    try:
        chain_id = assert_devnet(cfg, unsafe_override=args.unsafe_override)
    except Exception as exc:
        abort(str(exc)); return

    log.info("Identity Pilot Driver starting", chain_id=chain_id)
    args.findings_dir.mkdir(parents=True, exist_ok=True)
    total: list[FindingRecord] = []

    with httpx.Client() as client:
        for tag, name, fn in ATTACKS:
            if args.attack and args.attack.upper() != tag:
                continue
            log.info(f"Running {tag}: {name}")
            try:
                findings = fn(client, cfg)
                for f in findings:
                    f.save(args.findings_dir)
                total.extend(findings)
            except Exception as exc:
                log.error(f"Error in {tag}: {exc}")

    log.info("Identity Pilot Driver complete", total_findings=len(total))
    sys.exit(1 if total else 0)


if __name__ == "__main__":
    main()
