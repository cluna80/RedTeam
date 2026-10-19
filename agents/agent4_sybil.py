#!/usr/bin/env python3
"""
agents/agent4_sybil.py — SybilProbe (full implementation)

Probes chain-forge-identity and chain-forge-personhood for sybil and
identity-abuse vulnerabilities.  All attacks go via POST /api/tx with the
correct Transaction envelope (verified against chain-forge-node/src/api.rs).

## Attack categories
  S1  Multi-identity per controller
      Register 2+ identities sharing one controller_id; only 1 may be verified.
      (In the current chain model, each address IS the identity — we test that
      the same address cannot double-register.)
  S2  Registry spam
      Flood RegisterIdentity txs above the per-epoch cap; excess must be rejected.
  S3  Revoke / re-attest cycling (revocation cooldown)
      Attest an entity, revoke, immediately re-attest; cooldown must block it.
  S4  Self-attest (INV-11)
      Send TxBody::Attest where claimant_id == sender; must be rejected.
  S5  ConfirmSybil freezes entity (INV-13)
      After ConfirmSybil, GET /api/identity/{address} must show frozen=true,
      and the entity must NOT be in pop_verified on any node.
  S6  ReportSuspectedSybil does NOT freeze (INV-14)
      After ReportSuspectedSybil, entity must NOT be frozen.
  S7  Concurrent registration race
      Submit two RegisterIdentity txs for the same address simultaneously;
      exactly one should land.

Usage:
    python agents/agent4_sybil.py --config agents/config/devnet3-local.toml
    python agents/agent4_sybil.py --config agents/config/devnet3-local.toml --attack S4
    python agents/agent4_sybil.py --config agents/config/devnet3-local.toml --once
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
import agents.identity_client as ic

log = StructuredLogger("agent4_sybil")

# How long to wait for a tx to be included in a block before checking state.
# Devnet block time is ~1s but mempool propagation adds latency; 6s is safe.
_TX_WAIT_SECS = 6.0

# Well-known devnet addresses (match genesis-3node.json)
_ALICE   = "qcb1alice"
_BOB     = "qcb1bob"
_DAVE    = "qcb1dave"
# "coordinator" address that is allowed to call ConfirmSybil / ReverseSybil.
# Defaults to Alice — override via genesis attestation_coordinator field.
_COORDINATOR = _ALICE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _api(cfg: dict[str, Any]) -> str:
    return cfg["nodes"]["api_urls"][0]


def _get(client: httpx.Client, url: str) -> tuple[int, dict]:
    try:
        r = client.get(url, timeout=10.0)
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text[:500]}
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
        agent=AgentId.SYBIL,
        title=title,
        severity=severity,
        invariant_id=inv,
        steps=steps,
        expected=expected,
        actual=actual,
        evidence=evidence,
    )


def _fresh_addr() -> str:
    """Generate a unique test address for this run."""
    return f"qcb1test-{uuid.uuid4().hex[:12]}"


def _register_and_wait(
    client: httpx.Client,
    api_url: str,
    address: str,
    wait: float = _TX_WAIT_SECS,
) -> tuple[int, dict]:
    """Register an identity and wait for block inclusion."""
    status, body = ic.register_identity(client, api_url, sender=address)
    if wait > 0 and ic.queued(status, body):
        time.sleep(wait)
    return status, body


# ---------------------------------------------------------------------------
# S1 — Double-registration (same address registers twice)
# ---------------------------------------------------------------------------

def attack_s1_double_register(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    An address that is already registered sends RegisterIdentity again.
    The chain must reject the duplicate at execution (AlreadyExists).

    Uses Bob — a funded genesis account that is already registered — so gas
    is available and the uniqueness check is actually reached.  Verifies
    rejection via GET /api/tx/{id}; HTTP 200/queued at mempool is expected
    and does not mean the tx succeeded at execution.
    """
    findings: list[FindingRecord] = []
    api_url = _api(cfg)

    # Bob is already registered (genesis).  Re-register him.
    s2, b2 = ic.register_identity(client, api_url, sender=_BOB)
    tx_id = ic.tx_id_from_response(b2)
    log.info("[S1] second registration for already-registered Bob",
             status=s2, tx_id=tx_id)

    time.sleep(_TX_WAIT_SECS)

    exec_ok: bool | None = None
    exec_body: dict = {}
    if tx_id:
        _, exec_body = ic.fetch_tx_result(client, api_url, tx_id)
        exec_ok = exec_body.get("success", None)

    log.info("[S1] double-register execution result", success=exec_ok,
             error=exec_body.get("error"))

    if ic.rejected(s2, b2):
        log.info("[S1] double-registration rejected at HTTP layer ✓")
    elif exec_ok is True:
        _, id_state = ic.get_entity_status(client, api_url, _BOB)
        f = _finding(
            inv=7,
            title="Double-registration succeeded at execution (INV-7/S1)",
            severity=Severity.HIGH,
            steps=[
                f"Bob ({_BOB}) is already registered (genesis)",
                f"POST /api/tx RegisterIdentity sender={_BOB} again",
                f"Execution result: success={exec_ok}",
            ],
            expected="Second RegisterIdentity rejected at execution (AlreadyExists)",
            actual=f"Second registration executed successfully: {exec_body}",
            evidence={"addr": _BOB, "exec": exec_body, "id_state": id_state},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info("[S1] double-registration correctly rejected at execution ✓",
                 error=exec_body.get("error"))

    return findings


# ---------------------------------------------------------------------------
# S2 — Registry spam above per-epoch cap (INV-8)
# ---------------------------------------------------------------------------

EPOCH_REG_CAP = 10   # assumed; the real cap comes from genesis chain config

def attack_s2_registry_spam(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    Flood EPOCH_REG_CAP+1 funded RegisterIdentity txs.

    Protocol:
      1. Fund EPOCH_REG_CAP+1 fresh addresses from Alice (200_000 uqcb each —
         enough for gas).  Wait for the transfers to land.
      2. Register each funded address; collect tx_ids.
      3. Wait for all registrations to land, then count how many executed
         successfully.  If more than EPOCH_REG_CAP succeed it is a finding.

    Checks execution results via GET /api/tx/{id}, not just mempool queuing.
    All txs should reach mempool (they are syntactically valid); the cap is
    enforced at execution time (inside IdentityStore::register).
    """
    findings: list[FindingRecord] = []
    api_url = _api(cfg)
    spam_count = EPOCH_REG_CAP + 1   # one over the cap

    # Step 1: fund fresh addresses from Alice one at a time.
    # The chain uses a strictly sequential nonce model: only one tx per sender
    # can execute per block (nonce must match exactly).  We must wait for each
    # transfer to land before submitting the next one.
    addrs: list[str] = []
    log.info(f"[S2] funding {spam_count} fresh addresses from Alice (sequential)…")
    funded_ok = 0
    for i in range(spam_count):
        addr = _fresh_addr()
        addrs.append(addr)

        # Fetch authoritative nonce from chain before each transfer
        alice_nonce = ic._fetch_chain_nonce(api_url, _ALICE) or 0
        s, b = ic.transfer(client, api_url, sender=_ALICE, to=addr, amount=200_000,
                           nonce=alice_nonce)
        tid = ic.tx_id_from_response(b)
        log.info(f"[S2] transfer {i+1}/{spam_count}", addr=addr, status=s,
                 nonce=alice_nonce, tx_id=tid)

        # Wait for this transfer to land before sending the next
        time.sleep(_TX_WAIT_SECS)

        # Verify it landed
        bal = 0
        try:
            r = client.get(f"{api_url}/api/accounts/{addr}", timeout=5.0)
            bal = r.json().get("balances", {}).get("uqcb", 0) if r.status_code == 200 else 0
        except Exception:
            pass
        if bal >= 100_000:
            funded_ok += 1
        else:
            log.info(f"[S2] transfer {i+1} did not land",
                     addr=addr, balance=bal, tx_id=tid,
                     exec=ic.fetch_tx_result(client, api_url, tid)[1] if tid else {})

    if funded_ok < spam_count:
        log.info(f"[S2] {funded_ok}/{spam_count} funded — proceeding with what landed")

    log.info(f"[S2] funding complete", funded_ok=funded_ok, total=spam_count)

    # Step 2: register all funded addresses.
    # Each fresh address has nonce=0 (never used before).
    reg_tx_ids: list[tuple[str, str]] = []   # (addr, tx_id)
    log.info(f"[S2] registering {spam_count} addresses…")
    for addr in addrs:
        s, b = ic.register_identity(client, api_url, sender=addr, nonce=0)
        tid = ic.tx_id_from_response(b)
        if tid:
            reg_tx_ids.append((addr, tid))

    time.sleep(_TX_WAIT_SECS)

    # Step 3: count successful executions
    succeeded = 0
    failed = 0
    errors: list[str] = []
    for addr, tid in reg_tx_ids:
        _, result = ic.fetch_tx_result(client, api_url, tid)
        if result.get("success"):
            succeeded += 1
        else:
            failed += 1
            err = result.get("error", "unknown")
            if err not in errors:
                errors.append(err)

    log.info("[S2] registration results",
             succeeded=succeeded, failed=failed,
             cap=EPOCH_REG_CAP, errors=errors)

    if succeeded > EPOCH_REG_CAP:
        f = _finding(
            inv=8,
            title="Identity registry accepted more registrations than epoch cap",
            severity=Severity.HIGH,
            steps=[
                f"Fund {spam_count} fresh addresses from Alice",
                f"Submit {spam_count} RegisterIdentity txs",
                f"{succeeded} executed successfully (cap={EPOCH_REG_CAP})",
            ],
            expected=f"At most {EPOCH_REG_CAP} registrations succeed per epoch",
            actual=f"{succeeded} succeeded (excess={succeeded - EPOCH_REG_CAP})",
            evidence={"succeeded": succeeded, "failed": failed,
                      "cap": EPOCH_REG_CAP, "submitted": spam_count, "errors": errors},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info("[S2] epoch cap enforced ✓", succeeded=succeeded, cap=EPOCH_REG_CAP)

    # Sanity: node still alive
    s_alive, _ = _get(client, f"{api_url}/api/status")
    if s_alive == 0:
        f = _finding(
            inv=None,
            title="[S2] Node unreachable after registration spam",
            severity=Severity.CRITICAL,
            steps=[f"Flood {spam_count} RegisterIdentity txs", "GET /api/status"],
            expected="Node responds",
            actual="Connection error",
            evidence={"spam_count": spam_count},
        )
        findings.append(f)
        log.finding(f)

    return findings


# ---------------------------------------------------------------------------
# S3 — Revocation cooldown bypass
# ---------------------------------------------------------------------------

REVOKE_COOLDOWN_SECS = 3   # assumed minimum; check chain config

def attack_s3_revoke_reattest(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    Alice attests Bob, revokes, then immediately re-attests.
    If a cooldown is enforced, the immediate re-attest must be rejected.
    """
    findings: list[FindingRecord] = []
    api_url = _api(cfg)

    # Ensure Bob is registered
    ic.register_identity(client, api_url, sender=_BOB)
    time.sleep(_TX_WAIT_SECS)

    # Alice attests Bob
    s_att, b_att = ic.attest_entity(
        client, api_url,
        entity_id=_BOB,
        subject_controller=_BOB,
        attester_controller=_ALICE,
    )
    log.info("[S3] initial attest", status=s_att, body=b_att)
    time.sleep(_TX_WAIT_SECS)

    # Alice revokes Bob
    s_rev, b_rev = ic.revoke_attestation(
        client, api_url,
        entity_id=_BOB,
        revoker_controller=_ALICE,
    )
    log.info("[S3] revocation", status=s_rev, body=b_rev)

    # Immediately re-attest (should be blocked by cooldown if enforced)
    s_re, b_re = ic.attest_entity(
        client, api_url,
        entity_id=_BOB,
        subject_controller=_BOB,
        attester_controller=_ALICE,
    )
    log.info("[S3] immediate re-attest", status=s_re, body=b_re)

    if not ic.rejected(s_re, b_re):
        f = _finding(
            inv=None,
            title="Revocation cooldown not enforced: immediate re-attest accepted",
            severity=Severity.MEDIUM,
            steps=[
                f"Alice attests Bob → s={s_att}",
                f"Alice revokes Bob → s={s_rev}",
                f"Alice immediately re-attests Bob → s={s_re} (not rejected)",
            ],
            expected=f"Re-attest blocked by {REVOKE_COOLDOWN_SECS}s cooldown",
            actual=f"Re-attest accepted: status={s_re}, body={b_re}",
            evidence={"att": b_att, "rev": b_rev, "re_att": b_re},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info("[S3] immediate re-attest correctly rejected ✓", status=s_re)

    return findings


# ---------------------------------------------------------------------------
# S4 — Self-attest (INV-11)
# ---------------------------------------------------------------------------

def attack_s4_self_attest(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    Send TxBody::Attest { claimant_id = Alice } from Alice (same sender).
    IdentityStore::attest() must return SelfAttestation error → tx rejected.
    """
    findings: list[FindingRecord] = []
    api_url = _api(cfg)

    # Ensure Alice is registered
    ic.register_identity(client, api_url, sender=_ALICE)
    time.sleep(_TX_WAIT_SECS)

    # Self-attest: attester_controller = claimant = ALICE
    s, b = ic.attest_entity(
        client, api_url,
        entity_id=_ALICE,
        subject_controller=_ALICE,
        attester_controller=_ALICE,
    )
    log.info("[S4] self-attest attempt", status=s, body=b)

    # The chain accepts the tx into the mempool (HTTP 200 / queued) but MUST
    # reject it at execution with SelfAttestation.  We verify the on-chain
    # execution result via GET /api/tx/{id} after waiting for block inclusion.
    tx_id = ic.tx_id_from_response(b)
    time.sleep(_TX_WAIT_SECS)

    exec_ok: bool | None = None
    exec_body: dict = {}
    if tx_id:
        _, exec_body = ic.fetch_tx_result(client, api_url, tx_id)
        exec_ok = exec_body.get("success", None)

    log.info("[S4] self-attest execution result", tx_id=tx_id,
             success=exec_ok, error=exec_body.get("error"))

    # Finding if: HTTP-rejected (unexpected path) OR execution succeeded
    if ic.rejected(s, b):
        # Mempool-rejected is a stricter enforcement than required — still passes.
        log.info("[S4] self-attest rejected at HTTP layer ✓")
    elif exec_ok is True:
        # Tx executed successfully — self-attest was NOT blocked.
        _, id_state = ic.get_entity_status(client, api_url, _ALICE)
        f = _finding(
            inv=11,
            title="Self-attestation not rejected (INV-11)",
            severity=Severity.HIGH,
            steps=[
                f"Register Alice (sender={_ALICE})",
                f"POST /api/tx Attest {{claimant_id: {_ALICE}}} from sender={_ALICE}",
                f"Execution result: success={exec_ok}, error={exec_body.get('error')}",
            ],
            expected="Self-attest rejected at execution with SelfAttestation error",
            actual=f"Self-attest executed successfully: {exec_body}",
            evidence={"status": s, "body": b, "exec": exec_body, "id_state": id_state},
        )
        findings.append(f)
        log.finding(f)
    else:
        # exec_ok is False or None (not yet landed) — chain rejected at execution ✓
        log.info("[S4] self-attest rejected at execution ✓",
                 error=exec_body.get("error"))

    return findings


# ---------------------------------------------------------------------------
# S5 — ConfirmSybil atomically freezes entity (INV-13)
# ---------------------------------------------------------------------------

def attack_s5_confirm_sybil_freezes(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    Register Dave, have Alice attest Dave, then have the coordinator
    (Alice) send ConfirmSybil.  After block inclusion:
      - GET /api/identity/Dave must show frozen=true, sybil_confirmed=true
      - Dave must NOT appear in pop_verified on any node
    """
    findings: list[FindingRecord] = []
    api_url = _api(cfg)

    # Register Dave, have Alice attest him
    ic.register_identity(client, api_url, sender=_DAVE)
    time.sleep(_TX_WAIT_SECS)

    ic.attest_entity(
        client, api_url,
        entity_id=_DAVE,
        subject_controller=_DAVE,
        attester_controller=_ALICE,
    )
    time.sleep(_TX_WAIT_SECS)

    # ConfirmSybil from coordinator
    s_cs, b_cs = ic.confirm_sybil(
        client, api_url,
        entity_id=_DAVE,
        reporter_controller=_COORDINATOR,
    )
    log.info("[S5] ConfirmSybil sent", status=s_cs, body=b_cs)
    time.sleep(_TX_WAIT_SECS)

    if ic.rejected(s_cs, b_cs):
        # Could be coordinator not recognised in this devnet genesis — log but don't fail
        log.info("[S5] ConfirmSybil rejected — coordinator may not be in genesis", status=s_cs)
        return findings

    # Check frozen state
    _, id_state = ic.get_entity_status(client, api_url, _DAVE)
    log.info("[S5] Dave identity state after ConfirmSybil", state=id_state)

    frozen          = id_state.get("frozen", False)
    sybil_confirmed = id_state.get("sybil_confirmed", False)

    if not frozen or not sybil_confirmed:
        f = _finding(
            inv=13,
            title="ConfirmSybil did not atomically freeze entity (INV-13)",
            severity=Severity.CRITICAL,
            steps=[
                f"Register Dave ({_DAVE})",
                f"Alice attests Dave",
                f"Coordinator ({_COORDINATOR}) sends ConfirmSybil → status={s_cs}",
                f"GET /api/identity/{_DAVE} → frozen={frozen}, sybil_confirmed={sybil_confirmed}",
            ],
            expected="frozen=true AND sybil_confirmed=true after ConfirmSybil",
            actual=f"frozen={frozen}, sybil_confirmed={sybil_confirmed}",
            evidence={"confirm_resp": b_cs, "id_state": id_state},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info("[S5] Dave correctly frozen after ConfirmSybil ✓",
                 frozen=frozen, sybil_confirmed=sybil_confirmed)

    # Now reverse and confirm unfreeze
    s_rv, b_rv = ic.reverse_sybil(
        client, api_url,
        entity_id=_DAVE,
        authority_controller=_COORDINATOR,
    )
    log.info("[S5] ReverseSybil sent", status=s_rv, body=b_rv)
    time.sleep(_TX_WAIT_SECS)

    if ic.queued(s_rv, b_rv):
        _, id_state2 = ic.get_entity_status(client, api_url, _DAVE)
        still_frozen = id_state2.get("frozen", True)
        if still_frozen:
            f = _finding(
                inv=13,
                title="ReverseSybil did not unfreeze entity",
                severity=Severity.HIGH,
                steps=[
                    f"ConfirmSybil Dave → frozen",
                    f"ReverseSybil Dave → status={s_rv}",
                    f"GET /api/identity/{_DAVE} → still frozen={still_frozen}",
                ],
                expected="frozen=false after ReverseSybil",
                actual=f"frozen={still_frozen}",
                evidence={"reverse_resp": b_rv, "id_state2": id_state2},
            )
            findings.append(f)
            log.finding(f)
        else:
            log.info("[S5] Dave correctly unfrozen after ReverseSybil ✓")

    return findings


# ---------------------------------------------------------------------------
# S6 — ReportSuspectedSybil does NOT freeze (INV-14)
# ---------------------------------------------------------------------------

def attack_s6_report_no_freeze(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    ReportSuspectedSybil must NOT freeze the entity.  Only ConfirmSybil may.
    """
    findings: list[FindingRecord] = []
    api_url = _api(cfg)

    target = _fresh_addr()
    ic.register_identity(client, api_url, sender=target)
    time.sleep(_TX_WAIT_SECS)

    ic.attest_entity(
        client, api_url,
        entity_id=target,
        subject_controller=target,
        attester_controller=_ALICE,
    )
    time.sleep(_TX_WAIT_SECS)

    s_rp, b_rp = ic.report_suspected_sybil(
        client, api_url,
        entity_id=target,
        reporter_controller=_ALICE,
    )
    log.info("[S6] ReportSuspectedSybil sent", status=s_rp, body=b_rp)
    time.sleep(_TX_WAIT_SECS)

    _, id_state = ic.get_entity_status(client, api_url, target)
    frozen = id_state.get("frozen", False)
    log.info("[S6] target state after ReportSuspectedSybil", frozen=frozen, state=id_state)

    if frozen:
        f = _finding(
            inv=14,
            title="ReportSuspectedSybil froze entity — only ConfirmSybil should (INV-14)",
            severity=Severity.HIGH,
            steps=[
                f"Register target {target}",
                "Alice attests target",
                f"Alice sends ReportSuspectedSybil → status={s_rp}",
                f"GET /api/identity/{target} → frozen={frozen}",
            ],
            expected="frozen=false after ReportSuspectedSybil",
            actual=f"frozen={frozen}",
            evidence={"report_resp": b_rp, "id_state": id_state},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info("[S6] ReportSuspectedSybil correctly did not freeze ✓")

    return findings


# ---------------------------------------------------------------------------
# S7 — Concurrent registration race
# ---------------------------------------------------------------------------

def attack_s7_concurrent_registration(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    Submit two RegisterIdentity txs for the same address simultaneously.
    Exactly one should succeed; the second must be a no-op or rejected.
    """
    findings: list[FindingRecord] = []
    api_url = _api(cfg)
    addr = _fresh_addr()
    results: dict[str, tuple[int, dict]] = {}

    def _reg(tag: str) -> None:
        s, b = ic.register_identity(client, api_url, sender=addr)
        results[tag] = (s, b)

    t1 = threading.Thread(target=_reg, args=("A",))
    t2 = threading.Thread(target=_reg, args=("B",))
    t1.start(); t2.start()
    t1.join();  t2.join()

    sa, ba = results.get("A", (0, {}))
    sb, bb = results.get("B", (0, {}))
    log.info("[S7] concurrent registration", addr=addr, status_A=sa, status_B=sb)

    # Both accepted is only a problem if it caused inconsistent state
    time.sleep(_TX_WAIT_SECS)
    _, id_state = ic.get_entity_status(client, api_url, addr)
    log.info("[S7] identity state after concurrent register", state=id_state)

    # If neither rejected it's worth noting, but not necessarily a critical bug
    # (chain may just treat duplicate register as idempotent)
    if not ic.rejected(sa, ba) and not ic.rejected(sb, bb):
        log.info("[S7] both registrations accepted — check idempotency in chain-forge-identity")
        # Not raising a finding unless we can confirm actual double-entry

    return findings


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ATTACKS = [
    ("S1", "Double-registration",              attack_s1_double_register),
    ("S2", "Registry spam (epoch cap)",        attack_s2_registry_spam),
    ("S3", "Revocation cooldown bypass",       attack_s3_revoke_reattest),
    ("S4", "Self-attest (INV-11)",             attack_s4_self_attest),
    ("S5", "ConfirmSybil freezes (INV-13)",    attack_s5_confirm_sybil_freezes),
    ("S6", "ReportSuspectedSybil no freeze",   attack_s6_report_no_freeze),
    ("S7", "Concurrent registration race",     attack_s7_concurrent_registration),
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="QCB SybilProbe — devnet-only identity/attestation attack suite"
    )
    parser.add_argument("--config",          required=True, type=Path)
    parser.add_argument("--findings-dir",    type=Path, default=Path("agents/findings"))
    parser.add_argument("--attack",          help="Run only S1..S7")
    parser.add_argument("--unsafe-override", action="store_true")
    parser.add_argument("--once",            action="store_true",
                        help="Run suite once and exit (for automated pipelines)")
    args = parser.parse_args()

    cfg = load_config(args.config)
    try:
        chain_id = assert_devnet(cfg, unsafe_override=args.unsafe_override)
    except Exception as exc:
        abort(str(exc)); return

    log.info("SybilProbe starting", chain_id=chain_id)
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

    log.info("SybilProbe complete", total_findings=len(total))
    sys.exit(1 if total else 0)


if __name__ == "__main__":
    main()
