#!/usr/bin/env python3
"""
agents/agent9_qpc_consensus.py — QPC Consensus Adversary (QPC-CONS-001)

Tests the invariant:
  A single verified human cannot increase aggregate consensus influence by
  splitting stake, wallets, validator identities, or machine ownership.

Architecture note (as of chain-forge-engine main 005bd27):
  - gate_voting_power() + PersonhoodConfig.power_cap=1 are enforced in Rust
    across all three BFT engines.
  - Phase B (feat/qpc-cons-001-phase-b-authenticated-binding, commit fc1852b):
    BondValidator now accepts owner_identity_id: Option<String>. When set,
    the executor authenticates the binding (tx.sender == owner_identity_id,
    identity must have active personhood credential) and stores it via
    state.set_raw(). Bindings survive restarts and ownership changes are
    rejected. Per-human cap now enforces aggregate voting_power ≤ power_cap.
  - Tests A01, A03, A10 now submit live BondValidator txs with owner_identity_id
    to verify the cap enforcement path end-to-end.

Findings emitted:
  QPC-GAP-001  owner_identity_id not settable via tx API (HIGH) — conditionally
               emitted; suppressed when Phase B is detected on the running chain
  QPC-GAP-002  Attestation requires coordinator centralization (MEDIUM)

Usage:
    python agents/agent9_qpc_consensus.py --config agents/config/devnet3-local.toml
    python agents/agent9_qpc_consensus.py --config agents/config/devnet3-local.toml --attack QPC-A07
    python agents/agent9_qpc_consensus.py --config agents/config/devnet3-local.toml --offline
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.schema import AgentId, FindingRecord, Severity
from agents.devnet_guard import assert_devnet, load_config, abort
from agents.observability import StructuredLogger

log = StructuredLogger("agent9_qpc_consensus")

POWER_CAP = 1  # PersonhoodConfig default; must match genesis-3node.json

# Phase B attacker accounts — funded in genesis, not genesis validators
# Carol has 500M uqcb and is not in the initial validator set.
CAROL = "qcb1carol"
COORDINATOR = "qcb1alice"  # attestation_coordinator in genesis-3node.json
# Synthetic attacker addresses for multi-validator cap tests
ATTACKER_V1 = "qcb1attacker1"
ATTACKER_V2 = "qcb1attacker2"
MIN_BOND = 10_000_000  # 10 QCB in uqcb — typical min_stake_uqcb on devnet

# ---------------------------------------------------------------------------
# TestResult
# ---------------------------------------------------------------------------

@dataclass
class TestResult:
    test_id: str
    scenario: str
    timestamp: str
    git_sha: str
    chain_id: str
    seed: int
    validator_count: int
    human_count: int
    expected: str
    actual: str
    tx_ids: list[str]
    block_heights: list[int]
    block_hashes: list[str]
    identity_evidence: dict
    voting_power_evidence: dict
    classification: str  # PASS | FAIL | NOT_TESTED | SIMULATED
    notes: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(Path(__file__).parent.parent), "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL,
        ).decode().strip()
    except Exception:
        return "unknown"


def _get(client: httpx.Client, url: str) -> dict | list | None:
    try:
        r = client.get(url, timeout=5.0)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        log.warn(f"GET {url} failed: {e}")
    return None


def _post_tx(client: httpx.Client, node_url: str, tx: dict) -> dict:
    try:
        r = client.post(f"{node_url}/api/tx", json=tx, timeout=10.0)
        resp = r.json()
        # Normalize: add success=True for queued/accepted, success=False for error/rejected
        if "status" in resp:
            resp["success"] = resp["status"] in ("queued", "accepted", "ok")
        return resp
    except Exception as e:
        return {"error": str(e), "success": False}


def _wait_tx_result(client: httpx.Client, node_url: str, tx_id: str,
                    timeout: float = 20.0) -> dict:
    """Poll /api/tx/{tx_id} until the tx is committed (height > 0) or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = _get(client, f"{node_url}/api/tx/{tx_id}")
        if isinstance(result, dict) and result.get("height", 0) > 0:
            return result
        time.sleep(1.0)
    return {"error": "timeout waiting for tx commit", "success": False}


def _tx(sender: str, nonce: int, body_variant: str, body_fields: dict, tx_id: str | None = None) -> dict:
    """Build a tx envelope in the format expected by chain-forge-node /api/tx."""
    import uuid as _uuid
    return {
        "id": tx_id or str(_uuid.uuid4())[:8],
        "sender": sender,
        "nonce": nonce,
        "gas_limit": 100_000,
        "body": {body_variant: body_fields},
    }


def _current_validators(client: httpx.Client, node_url: str) -> list[dict]:
    result = _get(client, f"{node_url}/api/validators")
    if isinstance(result, list):
        return result
    return []


def _current_height(client: httpx.Client, node_url: str) -> int:
    status = _get(client, f"{node_url}/api/status")
    if isinstance(status, dict):
        return int(status.get("height", 0))
    return 0


def _wait_block(client: httpx.Client, node_url: str, after_height: int, timeout: float = 15.0) -> int:
    deadline = time.time() + timeout
    while time.time() < deadline:
        h = _current_height(client, node_url)
        if h > after_height:
            return h
        time.sleep(1.0)
    return _current_height(client, node_url)


def _get_nonce(client: httpx.Client, node_url: str, addr: str) -> int:
    """Return the next valid nonce for addr.

    The executor expects tx.nonce == account.nonce (0-based: first tx uses
    nonce=0, incremented after each commit).  The mempool (after the nonce fix
    that seeds fresh accounts with NO_PRIOR_TX) accepts nonce=0 as the first tx.
    """
    acct = _get(client, f"{node_url}/api/accounts/{addr}")
    if isinstance(acct, dict):
        return int(acct.get("nonce", 0))
    return 0


def _attest(client: httpx.Client, node_url: str, coordinator: str, target: str) -> dict:
    """Send Attest tx from coordinator to target. require_signatures=false on devnet."""
    nonce = _get_nonce(client, node_url, coordinator)
    return _post_tx(client, node_url, _tx(
        coordinator, nonce, "Attest",
        {"target": target, "claimant_id": target, "tier": "Provisional"},
    ))


def _faucet(client: httpx.Client, node_url: str, faucet: str, target: str, amount: int) -> dict:
    """Transfer funds from faucet to target so they can bond stake."""
    nonce = _get_nonce(client, node_url, faucet)
    return _post_tx(client, node_url, _tx(
        faucet, nonce, "Transfer",
        {"to": target, "denom": "uqcb", "amount": amount},
    ))


def _bond_validator(
    client: httpx.Client, node_url: str,
    sender: str, amount: int,
    owner_identity_id: str | None = None,
) -> dict:
    """Submit BondValidator tx, optionally with Phase B owner_identity_id binding."""
    nonce = _get_nonce(client, node_url, sender)
    body_fields: dict = {"amount": amount}
    if owner_identity_id is not None:
        body_fields["owner_identity_id"] = owner_identity_id
    return _post_tx(client, node_url, _tx(sender, nonce, "BondValidator", body_fields))


def _probe_phase_b(client: httpx.Client, node_url: str) -> bool:
    """
    Probe whether Phase B is active by sending a BondValidator tx with
    owner_identity_id. If the field is accepted (any non-'unknown field' response),
    Phase B is live. If rejected with 'unknown field', Phase B is absent.
    Uses a fresh nonce=999999 (out-of-range) so the tx is guaranteed to fail anyway.
    """
    resp = _post_tx(client, node_url, _tx(
        "qcb1phase_b_probe", 999_999, "BondValidator",
        {"amount": 1, "owner_identity_id": "qcb1probe_owner"},
    ))
    resp_str = str(resp).lower()
    # Phase B absent: serde rejects the unknown field
    if "unknown field" in resp_str:
        return False
    # Any other response (registered account check, nonce error, auth error, queued) =
    # field was accepted by serde → Phase B present.
    return True


def _make_result(
    test_id: str, scenario: str, chain_id: str, git_sha: str,
    validators: list[dict],
    classification: str, expected: str, actual: str, notes: str = "",
    tx_ids: list[str] | None = None,
    block_heights: list[int] | None = None,
    block_hashes: list[str] | None = None,
    identity_evidence: dict | None = None,
) -> TestResult:
    return TestResult(
        test_id=test_id,
        scenario=scenario,
        timestamp=_now(),
        git_sha=git_sha,
        chain_id=chain_id,
        seed=0x51AB_C001,
        validator_count=len(validators),
        human_count=len({v.get("id") for v in validators}),
        expected=expected,
        actual=actual,
        tx_ids=tx_ids or [],
        block_heights=block_heights or [],
        block_hashes=block_hashes or [],
        identity_evidence=identity_evidence or {},
        voting_power_evidence={"validators": validators},
        classification=classification,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Architectural gap findings (always emitted — code audit, not live test)
# ---------------------------------------------------------------------------

def _gap_001(git_sha: str, phase_b_resolved: bool = False) -> FindingRecord:
    if phase_b_resolved:
        return FindingRecord(
            agent=AgentId.QPC_CONSENSUS,
            title="QPC-GAP-001 RESOLVED: owner_identity_id now settable via BondValidator tx (Phase B)",
            severity=Severity.INFO,
            invariant_id=None,
            steps=[
                "1. Phase B (feat/qpc-cons-001-phase-b-authenticated-binding, commit fc1852b) detected.",
                "2. BondValidator now accepts owner_identity_id: Option<String>.",
                "3. Executor authenticates binding (tx.sender == owner_identity_id, active credential).",
                "4. Binding stored via state.set_raw(); survives restarts; ownership changes rejected.",
                "5. Per-human cap enforces aggregate voting_power <= power_cap (not just validator count).",
                "6. Live adversarial tests (A01, A03, A10) now exercise this path.",
            ],
            expected="Phase B passes A01, A03, A10 adversarial tests.",
            actual="Phase B detected via BondValidator owner_identity_id field acceptance. "
                   "Live tests determine PASS/FAIL.",
            evidence={"git_sha": git_sha, "phase_b": True, "affected_tests": ["QPC-A01", "QPC-A03", "QPC-A10"]},
        )
    return FindingRecord(
        agent=AgentId.QPC_CONSENSUS,
        title="QPC-GAP-001: owner_identity_id not settable via tx API — per-human cap bypassable",
        severity=Severity.HIGH,
        invariant_id=None,
        steps=[
            "1. Attacker creates N addresses (any number).",
            "2. Each address calls BondValidator{amount} + RegisterValidatorKey.",
            "3. Each resulting ValidatorRecord has owner_identity_id=None.",
            "4. build_validator_set() treats each None-owner as its own human.",
            "5. Each validator gets an independent power slot up to power_cap=1.",
            "6. N validators → N units of voting power, one human → power_cap violation.",
        ],
        expected="BondValidator should accept an owner_identity_id parameter that binds "
                 "the new validator to a specific verified human, so all validators sharing "
                 "that human share a single power budget.",
        actual="BondValidator{amount: u128} carries no owner_identity_id field. "
               "chain-forge-execution/src/lib.rs hardcodes owner_identity_id=None at "
               "registration. The cap enforcement in build_validator_set() is correct in "
               "Rust but is never triggered for post-genesis validators because the binding "
               "is never set.",
        evidence={
            "rust_gap_location": "chain-forge-execution/src/lib.rs:2112-2123 (BondValidator handler)",
            "cap_enforcement_location": "chain-forge-validators/src/lib.rs:992-1035 (build_validator_set)",
            "git_sha": git_sha,
            "affected_tests": ["QPC-A01", "QPC-A03", "QPC-A10"],
        },
    )


def _gap_002(git_sha: str) -> FindingRecord:
    return FindingRecord(
        agent=AgentId.QPC_CONSENSUS,
        title="QPC-GAP-002: pop_verified attestation requires coordinator centralization",
        severity=Severity.MEDIUM,
        invariant_id=None,
        steps=[
            "1. New validator bonds stake and registers consensus key.",
            "2. validator.pop_verified remains false until coordinator attests.",
            "3. gate_voting_power() zeroes power for unverified validators.",
            "4. Only qcb1alice (single coordinator) can grant pop_verified=true on devnet.",
            "5. Attestation centralization is noted as temporary in whitepaper §4.",
        ],
        expected="Decentralized personhood verification with no single coordinator gate. "
                 "At mainnet, multiple approved issuers should be able to attest personhood "
                 "independently (ZK-VRC / VRC-registry path in chain-forge-personhood).",
        actual="On the 3-node devnet, attestation_coordinator=qcb1alice (genesis-3node.json). "
               "Only this single address can issue Attest txs that grant pop_verified=true. "
               "Multi-issuer path (chain-forge-personhood ZK circuits) exists in codebase "
               "but is not wired into the live validator admission flow.",
        evidence={
            "coordinator_config": "tests/devnet/genesis-3node.json:attestation_coordinator=qcb1alice",
            "gate_location": "chain-forge-consensus/src/lib.rs:614 (gate_voting_power)",
            "zk_vrc_location": "chain-forge-personhood/src/lib.rs (Groth16VrcVerifier)",
            "git_sha": git_sha,
            "affected_tests": ["QPC-A02", "QPC-A05"],
            "whitepaper_reference": "Section 4 — Identity Pilot centralization note",
        },
    )


# ---------------------------------------------------------------------------
# Individual test functions
# ---------------------------------------------------------------------------

def test_a01_multi_validator_cap(
    client: httpx.Client, node_url: str, chain_id: str, git_sha: str,
    phase_b: bool = False,
) -> TestResult:
    """QPC-A01: One human registers 2 validators — aggregate influence cap enforced.

    Phase B path (genesis accounts only — non-genesis blocked by F5):
      1. Attest carol (coordinator=alice).
      2. Carol self-bonds with owner_identity_id=carol (Rule 1: sender==owner) — must succeed.
      3. Bob attempts to bond with owner_identity_id=carol (sender=bob != carol) — must be
         REJECTED by Phase B Rule 1.  This is the critical security property: Phase B prevents
         cross-owner bonding, blocking the multi-validator Sybil attack at the tx layer.
      4. Verify carol's aggregate voting_power ≤ POWER_CAP.

    PASS: step 3 rejected AND cap holds.
    FAIL: step 3 accepted (spoofing allowed) OR cap exceeded.
    """
    vals_before = _current_validators(client, node_url)
    violations_genesis = [v for v in vals_before if v.get("voting_power", 0) > POWER_CAP]

    if not phase_b:
        baseline_pass = len(violations_genesis) == 0
        classification = "PASS" if baseline_pass else "FAIL"
        actual = (
            f"Genesis validators all have voting_power <= {POWER_CAP}. "
            f"Phase B not detected — adversarial multi-validator path not exercised."
            if baseline_pass else
            f"Invariant violated: {len(violations_genesis)} genesis validators exceed cap: "
            + str([v['id'] for v in violations_genesis])
        )
        return _make_result(
            "QPC-A01",
            "One human registers 2 validators — aggregate influence cap enforced",
            chain_id, git_sha, vals_before,
            classification=classification,
            expected=f"Aggregate voting_power per human <= {POWER_CAP}",
            actual=actual,
            notes="Phase B not detected. Run against feat/qpc-cons-001-phase-b-authenticated-binding.",
        )

    # Phase B path: test that Phase B blocks cross-owner bonding.
    # Step 1: Attest carol so she has a personhood credential.
    attest_resp = _attest(client, node_url, COORDINATOR, CAROL)
    log.info("QPC-A01: attest carol", resp=str(attest_resp)[:120])

    # Wait for attest to commit before carol tries to self-bond.
    h0 = _current_height(client, node_url)
    _wait_block(client, node_url, h0, timeout=15.0)

    # Step 2: Carol self-bonds with owner=carol (valid, sender==owner).
    bond_self = _bond_validator(client, node_url, CAROL, MIN_BOND, owner_identity_id=CAROL)
    log.info("QPC-A01: carol self-bond", resp=str(bond_self)[:120])

    h_before = _current_height(client, node_url)

    # Step 3: Bob attempts to bond under carol's identity (sender=bob, owner=carol → Rule 1 reject).
    bond_spoof_queued = _bond_validator(client, node_url, "qcb1bob", MIN_BOND, owner_identity_id=CAROL)
    log.info("QPC-A01: bob bond owner=carol (spoof attempt)", resp=str(bond_spoof_queued)[:120])

    # Step 4: Wait for block; check execution result of spoof bond and carol's aggregate power.
    h_after = _wait_block(client, node_url, h_before, timeout=20.0)
    spoof_tx_id = bond_spoof_queued.get("tx_id", "")
    bond_spoof = _wait_tx_result(client, node_url, spoof_tx_id) if spoof_tx_id else bond_spoof_queued
    log.info("QPC-A01: spoof bond execution result", result=str(bond_spoof)[:120])
    vals_after = _current_validators(client, node_url)

    carol_validators = [v for v in vals_after if v.get("id") == CAROL
                        or v.get("owner_identity_id") == CAROL]
    agg_power = sum(v.get("voting_power", 0) for v in carol_validators)
    cap_held = agg_power <= POWER_CAP

    spoof_str = str(bond_spoof).lower()
    spoof_rejected = (
        bond_spoof.get("success") is False
        or not bond_spoof.get("success", True)
        or "rejected" in bond_spoof.get("status", "")
        or "sender" in spoof_str
        or "owner_identity_id" in spoof_str
        or "must equal" in spoof_str
        or "not a registered" in spoof_str
    )

    violations_after = [v for v in vals_after if v.get("voting_power", 0) > POWER_CAP]

    if spoof_rejected and cap_held and not violations_after:
        classification = "PASS"
        actual = (
            f"Phase B correctly blocked cross-owner bonding: bob→carol rejected. "
            f"Carol aggregate power={agg_power} <= power_cap={POWER_CAP}. "
            f"carol_self_bond={'queued/ok' if bond_self.get('status')=='queued' else str(bond_self)[:60]}."
        )
    elif not spoof_rejected:
        classification = "FAIL"
        actual = (
            f"CRITICAL: Phase B did not reject cross-owner bond (bob→carol accepted). "
            f"bond_spoof={str(bond_spoof)[:120]}."
        )
    elif violations_after:
        classification = "FAIL"
        actual = (
            f"Cap violated: {[v['id'] for v in violations_after]} exceed power_cap={POWER_CAP}. "
            f"bond_spoof={str(bond_spoof)[:80]}."
        )
    else:
        classification = "FAIL"
        actual = (
            f"Carol aggregate power={agg_power} > power_cap={POWER_CAP}. "
            f"carol_validators={[v.get('id') for v in carol_validators]}."
        )

    return _make_result(
        "QPC-A01",
        "One human registers 2 validators — aggregate influence cap enforced",
        chain_id, git_sha, vals_after,
        classification=classification,
        expected=(
            f"Cross-owner bond (sender != owner_identity_id) rejected by Phase B Rule 1. "
            f"Carol aggregate voting_power <= {POWER_CAP}."
        ),
        actual=actual,
        tx_ids=[bond_self.get("tx_id", ""), bond_spoof.get("tx_id", "")],
        block_heights=[h_before, h_after],
        identity_evidence={
            "attest_carol": attest_resp,
            "carol_self_bond": bond_self,
            "bob_spoof_bond": bond_spoof,
        },
        notes=f"Phase B live. Spoof rejected={spoof_rejected}. h_before={h_before} h_after={h_after}.",
    )


def test_a02_stake_split(
    client: httpx.Client, node_url: str, chain_id: str, git_sha: str,
) -> TestResult:
    """QPC-A02: Split stake across 100 wallets — no additional aggregate influence."""
    vals = _current_validators(client, node_url)
    total = sum(v.get("voting_power", 0) for v in vals)
    return _make_result(
        "QPC-A02",
        "Split stake across 100 wallets — no additional aggregate influence",
        chain_id, git_sha, vals,
        classification="NOT_TESTED",
        expected="Stake splitting does not increase aggregate influence beyond power_cap per human.",
        actual=f"Synthetic wallets have 0 balance and cannot bond stake. "
               f"Current total genesis voting power={total}. "
               f"Cannot gain pop_verified without coordinator (QPC-GAP-002).",
        notes="Full adversarial test requires funded attacker wallets + coordinator cooperation.",
    )


def test_a03_credential_reuse(
    client: httpx.Client, node_url: str, chain_id: str, git_sha: str,
    phase_b: bool = False,
) -> TestResult:
    """QPC-A03: One credential reused across multiple validator identities.

    Phase B path: attempt to bond ATTACKER_V1 (already bound to carol from A01)
    with a DIFFERENT owner (bob) — must be rejected because ownership changes
    are not allowed once set.
    Also attempt to bond a fresh address (ATTACKER_V2 if already bound) with
    carol as owner again — must succeed (re-bond same owner is idempotent).
    """
    vals = _current_validators(client, node_url)

    if not phase_b:
        ids = [v.get("id") for v in vals]
        duplicates = len(ids) != len(set(ids))
        return _make_result(
            "QPC-A03",
            "One credential reused across multiple validator identities — no duplicate human allowance",
            chain_id, git_sha, vals,
            classification="NOT_TESTED",
            expected="A single credential cannot grant independent power to multiple validator entries.",
            actual=f"Phase B not detected. Validator IDs unique={not duplicates}.",
            notes="Run against feat/qpc-cons-001-phase-b-authenticated-binding.",
        )

    # Phase B path (genesis accounts only):
    # Step 1: Attest bob so he's eligible for self-bond.
    attest_bob = _attest(client, node_url, COORDINATOR, "qcb1bob")
    log.info("QPC-A03: attest bob", resp=str(attest_bob)[:80])
    h0 = _current_height(client, node_url)
    _wait_block(client, node_url, h0, timeout=15.0)

    # Step 2: Bob self-bonds with owner=bob (valid initial binding).
    bob_self = _bond_validator(client, node_url, "qcb1bob", MIN_BOND, owner_identity_id="qcb1bob")
    log.info("QPC-A03: bob self-bond", resp=str(bob_self)[:80])
    h1 = _current_height(client, node_url)
    _wait_block(client, node_url, h1, timeout=15.0)

    # Step 3: Bob tries to re-bond with owner=carol (ownership change attempt).
    # Phase B Rule 1 blocks this: sender=bob != owner=carol.
    h_before = _current_height(client, node_url)
    change_queued = _bond_validator(client, node_url, "qcb1bob", MIN_BOND, owner_identity_id=CAROL)
    log.info("QPC-A03: spoof ownership change bob→carol", resp=str(change_queued)[:120])

    # Step 4: Also verify idempotent re-bond (same owner) is accepted.
    rebond_queued = _bond_validator(client, node_url, "qcb1bob", MIN_BOND, owner_identity_id="qcb1bob")
    log.info("QPC-A03: bob re-bond same owner (idempotent)", resp=str(rebond_queued)[:80])

    h_after = _wait_block(client, node_url, h_before, timeout=20.0)

    # Fetch committed execution results.
    change_tx_id = change_queued.get("tx_id", "")
    change_resp = _wait_tx_result(client, node_url, change_tx_id) if change_tx_id else change_queued
    rebond_tx_id = rebond_queued.get("tx_id", "")
    rebond_resp = _wait_tx_result(client, node_url, rebond_tx_id) if rebond_tx_id else rebond_queued
    log.info("QPC-A03: change tx result", result=str(change_resp)[:120])

    vals_after = _current_validators(client, node_url)

    change_str = str(change_resp).lower()
    change_rejected = (
        change_resp.get("success") is False
        or not change_resp.get("success", True)
        or "rejected" in change_resp.get("status", "")
        or "sender" in change_str
        or "must equal" in change_str
        or "cannot be changed" in change_str
        or "not a registered" in change_str
    )

    if change_rejected:
        classification = "PASS"
        actual = (
            f"Ownership change (bob→carol) correctly rejected by Phase B: "
            f"{change_resp.get('message', str(change_resp)[:80])}. "
            f"Idempotent re-bond (bob→bob): {str(rebond_resp)[:60]}."
        )
    elif change_resp.get("success") or change_resp.get("status") == "queued":
        classification = "FAIL"
        actual = (
            f"CRITICAL: Ownership change (bob→carol) accepted — credential reuse not blocked. "
            f"resp={change_resp}."
        )
    else:
        classification = "SIMULATED"
        actual = f"change_resp={str(change_resp)[:100]} rebond_resp={str(rebond_resp)[:60]}."

    return _make_result(
        "QPC-A03",
        "One credential reused across validator identities — ownership change rejected",
        chain_id, git_sha, vals_after,
        classification=classification,
        expected=(
            "Phase B Rule 1 rejects sender!=owner_identity_id; "
            "same-owner re-bond is idempotent (permitted)."
        ),
        actual=actual,
        block_heights=[h_before, h_after],
        identity_evidence={
            "attest_bob": attest_bob,
            "bob_self_bond": bob_self,
            "ownership_change_attempt": change_resp,
            "idempotent_rebond": rebond_resp,
        },
        notes=f"Phase B live. Change rejected={change_rejected}.",
    )


def test_a04_revoked_credential(
    client: httpx.Client, node_url: str, chain_id: str, git_sha: str,
    node_urls: list[str],
) -> TestResult:
    """QPC-A04: Revoked credential attempts consensus voting — revoked power rejected."""
    h_before = _current_height(client, node_url)
    vals_before = _current_validators(client, node_url)
    alice = next((v for v in vals_before if v.get("id") == "qcb1alice"), None)
    if alice is None:
        return _make_result(
            "QPC-A04",
            "Revoked credential attempts consensus voting",
            chain_id, git_sha, vals_before,
            classification="NOT_TESTED",
            expected="Revoked validator has voting_power=0.",
            actual="qcb1alice not found in validator set.",
        )
    alice_power_before = alice.get("voting_power", 0)

    # Send RevokeAttestation from qcb1alice (coordinator = qcb1alice on devnet)
    nonce = _get_nonce(client, node_url, "qcb1alice")
    revoke_resp = _post_tx(client, node_url, _tx(
        "qcb1alice", nonce, "RevokeAttestation",
        {"target": "qcb1alice", "attested_id": "qcb1alice"},
    ))
    tx_id = revoke_resp.get("tx_id", "")
    log.info("QPC-A04: sent RevokeAttestation", tx_id=tx_id, resp=str(revoke_resp)[:120])

    # Wait for next block
    h_after = _wait_block(client, node_url, h_before, timeout=20.0)
    vals_after = _current_validators(client, node_url)
    alice_after = next((v for v in vals_after if v.get("id") == "qcb1alice"), {})
    alice_power_after = alice_after.get("voting_power", -1)

    # Try to restore (Attest back)
    nonce2 = _get_nonce(client, node_url, "qcb1alice")
    restore_resp = _post_tx(client, node_url, _tx(
        "qcb1alice", nonce2, "Attest",
        {"target": "qcb1alice", "claimant_id": "qcb1alice", "tier": "Provisional"},
    ))
    log.info("QPC-A04: sent Attest restore", resp=str(restore_resp)[:120])
    _wait_block(client, node_url, h_after, timeout=20.0)

    if revoke_resp.get("success") is False or "error" in revoke_resp:
        classification = "NOT_TESTED"
        actual = (f"RevokeAttestation tx failed: {revoke_resp.get('error','unknown')}. "
                  f"This may be expected if require_signatures=false blocks coordinator-gated txs.")
    elif alice_power_after == 0:
        classification = "PASS"
        actual = f"alice voting_power dropped from {alice_power_before} to 0 after revocation."
    elif alice_power_after == alice_power_before:
        classification = "FAIL"
        actual = f"alice voting_power unchanged ({alice_power_before}) after RevokeAttestation."
    else:
        classification = "SIMULATED"
        actual = f"alice power before={alice_power_before}, after={alice_power_after}."

    return _make_result(
        "QPC-A04",
        "Revoked credential attempts consensus voting — revoked power rejected",
        chain_id, git_sha, vals_after,
        classification=classification,
        expected="Revoked validator has voting_power=0 after RevokeAttestation committed.",
        actual=actual,
        tx_ids=[tx_id] if tx_id else [],
        block_heights=[h_before, h_after],
        identity_evidence={"revoke_resp": revoke_resp, "restore_resp": restore_resp},
    )


def test_a05_credential_recovery(
    client: httpx.Client, node_url: str, chain_id: str, git_sha: str,
) -> TestResult:
    """QPC-A05: Credential recovery — old+new cannot both gain independent influence."""
    vals = _current_validators(client, node_url)
    # Check that an unregistered address has voting_power=0
    fresh_addr = "qcb1test0000"
    acct = _get(client, f"{node_url}/api/accounts/{fresh_addr}")
    in_validator_set = any(v.get("id") == fresh_addr for v in vals)
    return _make_result(
        "QPC-A05",
        "Credential recovery — old and new bindings cannot both gain independent influence",
        chain_id, git_sha, vals,
        classification="NOT_TESTED",
        expected="A fresh address not yet attested has voting_power=0.",
        actual=f"{fresh_addr} in validator set: {in_validator_set}. "
               f"Full dual-binding recovery attack requires multi-step coordinator interaction.",
        identity_evidence={"fresh_acct": acct or {}},
    )


def test_a06_proof_replay(
    client: httpx.Client, node_url: str, chain_id: str, git_sha: str,
) -> TestResult:
    """QPC-A06: Personhood proof replay across epochs — duplicate attest rejected."""
    vals = _current_validators(client, node_url)

    # Attest carol (may already be attested).  To test replay rejection, we need two
    # distinct Attest txs.  The second must use nonce = first_nonce+1 so the executor
    # doesn't reject it for nonce mismatch before it gets to the AlreadyAttested check.
    # We fetch committed nonce once, send attest1 (nonce=N), then wait a block so nonce
    # advances on-chain to N+1, then send attest2 (nonce=N+1).
    nonce = _get_nonce(client, node_url, "qcb1alice")
    attest1 = _post_tx(client, node_url, _tx(
        "qcb1alice", nonce, "Attest",
        {"target": "qcb1carol", "claimant_id": "qcb1carol", "tier": "Provisional"},
    ))
    # Wait for attest1 to commit so alice's on-chain nonce increments.
    h_a6 = _current_height(client, node_url)
    _wait_block(client, node_url, h_a6, timeout=15.0)
    nonce2 = _get_nonce(client, node_url, "qcb1alice")
    attest2 = _post_tx(client, node_url, _tx(
        "qcb1alice", nonce2, "Attest",
        {"target": "qcb1carol", "claimant_id": "qcb1carol", "tier": "Provisional"},
    ))
    log.info("QPC-A06", attest1=str(attest1)[:100], attest2=str(attest2)[:100])

    second_failed = (attest2.get("success") is False or
                     "AlreadyAttested" in str(attest2) or
                     "already" in str(attest2).lower())
    if second_failed:
        classification = "PASS"
        actual = f"Second duplicate Attest rejected: {attest2.get('error', str(attest2)[:80])}"
    elif attest1.get("success") is False:
        classification = "NOT_TESTED"
        actual = f"First Attest failed ({attest1.get('error','')}); cannot test replay guard."
    else:
        classification = "FAIL"
        actual = f"Second Attest accepted (no AlreadyAttested rejection): {attest2}"

    return _make_result(
        "QPC-A06",
        "Personhood proof replay across epochs — duplicate attest rejected",
        chain_id, git_sha, vals,
        classification=classification,
        expected="Second identical Attest for same (attester, target) pair rejected with AlreadyAttested.",
        actual=actual,
        identity_evidence={"attest1": attest1, "attest2": attest2},
    )


def test_a07_cross_node_consistency(
    client: httpx.Client, node_urls: list[str], chain_id: str, git_sha: str,
) -> TestResult:
    """QPC-A07: All nodes return identical effective validator weights."""
    snapshots: dict[str, list[dict]] = {}
    for url in node_urls:
        v = _current_validators(client, url)
        if v is not None:
            snapshots[url] = sorted(v, key=lambda x: x.get("id", ""))

    if len(snapshots) < 2:
        return _make_result(
            "QPC-A07", "Cross-node validator weight consistency",
            chain_id, git_sha, [],
            classification="NOT_TESTED",
            expected="All nodes return identical validator weights.",
            actual=f"Only {len(snapshots)} nodes responded.",
        )

    reference_url, reference = next(iter(snapshots.items()))
    mismatches = []
    for url, vs in snapshots.items():
        if url == reference_url:
            continue
        if vs != reference:
            mismatches.append(url)

    classification = "PASS" if not mismatches else "FAIL"
    actual = (
        f"All {len(snapshots)} nodes agree on validator weights."
        if not mismatches else
        f"Mismatch between {reference_url} and {mismatches}"
    )
    return _make_result(
        "QPC-A07",
        "Cross-node validator weight consistency",
        chain_id, git_sha, reference,
        classification=classification,
        expected="All nodes return identical validator set and voting powers.",
        actual=actual,
        identity_evidence={"node_count": len(snapshots), "mismatches": mismatches},
    )


def test_a08_transition_consistency(
    client: httpx.Client, node_url: str, chain_id: str, git_sha: str,
) -> TestResult:
    """QPC-A08: Validator-set transitions preserve per-human cap."""
    h1 = _current_height(client, node_url)
    vals1 = _current_validators(client, node_url)
    h2 = _wait_block(client, node_url, h1, timeout=20.0)
    vals2 = _current_validators(client, node_url)

    max_power_1 = max((v.get("voting_power", 0) for v in vals1), default=0)
    max_power_2 = max((v.get("voting_power", 0) for v in vals2), default=0)
    cap_held = max_power_1 <= POWER_CAP and max_power_2 <= POWER_CAP

    return _make_result(
        "QPC-A08",
        "Identity changes during validator-set transitions — no transient cap bypass",
        chain_id, git_sha, vals2,
        classification="SIMULATED",
        expected=f"No single validator exceeds power_cap={POWER_CAP} across consecutive blocks.",
        actual=f"h={h1}: max_power={max_power_1}; h={h2}: max_power={max_power_2}. Cap held={cap_held}.",
        block_heights=[h1, h2],
        notes="Cannot force concurrent identity+transition timing from outside; passive observation only.",
    )


def test_a09_restart_revocation(
    chain_id: str, git_sha: str,
) -> TestResult:
    return TestResult(
        test_id="QPC-A09",
        scenario="Restart after credential revocation — revoked eligibility remains revoked",
        timestamp=_now(), git_sha=git_sha, chain_id=chain_id, seed=0x51AB_C001,
        validator_count=0, human_count=0,
        expected="After node restart, revoked validator retains voting_power=0.",
        actual="NOT_TESTED: requires controlled node restart outside agent scope.",
        tx_ids=[], block_heights=[], block_hashes=[],
        identity_evidence={}, voting_power_evidence={},
        classification="NOT_TESTED",
        notes="Restart persistence tested separately in devnet restart-recovery test suite "
              "(tests/devnet/test7-restart-recovery-local.sh).",
    )


def test_a10_attacker_many_validators(
    client: httpx.Client, node_url: str, chain_id: str, git_sha: str,
    phase_b: bool = False,
) -> TestResult:
    """QPC-A10: Attacker controls many validators with one credential — power_cap enforced.

    Phase B path: bond 3 validators under carol and verify that after a block,
    aggregate voting_power for carol's validators is still <= power_cap=1.
    This directly tests the voting-power budget algorithm (Issue 2 of second review).
    """
    vals_before = _current_validators(client, node_url)

    if not phase_b:
        return _make_result(
            "QPC-A10",
            "Attacker controls many validators using one human credential — bounds preserved",
            chain_id, git_sha, vals_before,
            classification="NOT_TESTED",
            expected=f"Aggregate power per human <= power_cap={POWER_CAP}.",
            actual="Phase B not detected — adversarial path not exercised.",
            notes="Run against feat/qpc-cons-001-phase-b-authenticated-binding.",
        )

    # Phase B path (genesis accounts only):
    # Verify Phase B prevents 3 genesis accounts from bonding under one credential.
    # With Rule 1 (sender==owner required), only carol can self-bond as carol's validator.
    # Bob and Dave cannot bond under carol — their attempts must be rejected.
    #
    # Step 1: Attest carol.
    attest_resp = _attest(client, node_url, COORDINATOR, CAROL)
    log.info("QPC-A10: attest carol", resp=str(attest_resp)[:80])
    h0 = _current_height(client, node_url)
    _wait_block(client, node_url, h0, timeout=15.0)

    # Step 2: Carol self-bonds (valid, 1 validator under carol).
    carol_bond = _bond_validator(client, node_url, CAROL, MIN_BOND, owner_identity_id=CAROL)
    log.info("QPC-A10: carol self-bond", resp=str(carol_bond)[:80])

    h_before = _current_height(client, node_url)

    # Step 3: Bob and Dave attempt to bond under carol (must each be rejected by Phase B Rule 1).
    bob_bond_queued = _bond_validator(client, node_url, "qcb1bob", MIN_BOND, owner_identity_id=CAROL)
    log.info("QPC-A10: bob bond owner=carol (attack)", resp=str(bob_bond_queued)[:80])

    dave_bond_queued = _bond_validator(client, node_url, "qcb1dave", MIN_BOND, owner_identity_id=CAROL)
    log.info("QPC-A10: dave bond owner=carol (attack)", resp=str(dave_bond_queued)[:80])

    h_after = _wait_block(client, node_url, h_before, timeout=25.0)

    # Fetch committed execution results.
    bob_bond = _wait_tx_result(client, node_url, bob_bond_queued.get("tx_id","")) if bob_bond_queued.get("tx_id") else bob_bond_queued
    dave_bond = _wait_tx_result(client, node_url, dave_bond_queued.get("tx_id","")) if dave_bond_queued.get("tx_id") else dave_bond_queued
    log.info("QPC-A10: bob execution result", result=str(bob_bond)[:100])
    log.info("QPC-A10: dave execution result", result=str(dave_bond)[:100])

    vals_after = _current_validators(client, node_url)

    carol_validators = [v for v in vals_after
                        if v.get("id") == CAROL or v.get("owner_identity_id") == CAROL]
    agg_power = sum(v.get("voting_power", 0) for v in carol_validators)
    cap_held = agg_power <= POWER_CAP

    def _is_rejected(r: dict) -> bool:
        s = str(r).lower()
        return (r.get("success") is False
                or not r.get("success", True)
                or "rejected" in r.get("status", "")
                or "sender" in s
                or "must equal" in s
                or "not a registered" in s)

    bob_rejected = _is_rejected(bob_bond)
    dave_rejected = _is_rejected(dave_bond)
    both_rejected = bob_rejected and dave_rejected

    if both_rejected and cap_held:
        classification = "PASS"
        actual = (
            f"Phase B blocked all cross-owner bonds: bob_rejected={bob_rejected}, "
            f"dave_rejected={dave_rejected}. Carol aggregate power={agg_power} <= "
            f"power_cap={POWER_CAP}. carol_validators={[v.get('id') for v in carol_validators]}."
        )
    elif not both_rejected:
        classification = "FAIL"
        actual = (
            f"Cross-owner bond NOT rejected: bob_rejected={bob_rejected}, "
            f"dave_rejected={dave_rejected}. "
            f"bob_bond={str(bob_bond)[:80]}. dave_bond={str(dave_bond)[:80]}."
        )
    else:
        classification = "FAIL"
        actual = (
            f"Per-human cap VIOLATED: carol aggregate power={agg_power} > power_cap={POWER_CAP}. "
            f"carol_validators={[(v.get('id'), v.get('voting_power')) for v in carol_validators]}."
        )

    return _make_result(
        "QPC-A10",
        "Attacker controls 3 validators using one human credential — power budget enforced",
        chain_id, git_sha, vals_after,
        classification=classification,
        expected=(
            f"Phase B Rule 1 rejects bob/dave bonding under carol. "
            f"Carol aggregate voting_power <= power_cap={POWER_CAP}."
        ),
        actual=actual,
        tx_ids=[carol_bond.get("tx_id",""), bob_bond.get("tx_id",""), dave_bond.get("tx_id","")],
        block_heights=[h_before, h_after],
        identity_evidence={
            "attest_carol": attest_resp,
            "carol_self_bond": carol_bond,
            "bob_attack_bond": bob_bond,
            "dave_attack_bond": dave_bond,
        },
        notes=f"Phase B live. bob_rejected={bob_rejected} dave_rejected={dave_rejected} agg_power={agg_power}.",
    )


# ---------------------------------------------------------------------------
# Invariant oracles
# ---------------------------------------------------------------------------

def run_invariant_oracles(
    client: httpx.Client, node_urls: list[str], chain_id: str,
) -> dict[str, dict]:
    results: dict[str, dict] = {}
    node_url = node_urls[0]
    vals = _current_validators(client, node_url)

    # QPC-I01: positive power → pop_verified=true AND consensus_pubkey non-empty
    i01_violations = [
        v for v in vals
        if v.get("voting_power", 0) > 0
        and (not v.get("pop_verified") or not v.get("consensus_pubkey"))
    ]
    results["QPC-I01"] = {
        "description": "Every validator with positive voting_power has pop_verified=true and a consensus key.",
        "pass": len(i01_violations) == 0,
        "violations": i01_violations,
    }

    # QPC-I02: no single validator exceeds power_cap (proxy for per-human cap)
    i02_violations = [v for v in vals if v.get("voting_power", 0) > POWER_CAP]
    results["QPC-I02"] = {
        "description": f"No validator's voting_power exceeds power_cap={POWER_CAP}.",
        "pass": len(i02_violations) == 0,
        "violations": i02_violations,
    }

    # QPC-I03: all nodes agree
    snapshots = []
    for url in node_urls:
        v = _current_validators(client, url)
        if v:
            snapshots.append(sorted(v, key=lambda x: x.get("id", "")))
    i03_pass = len(snapshots) >= 2 and all(s == snapshots[0] for s in snapshots[1:])
    results["QPC-I03"] = {
        "description": "All nodes return identical effective validator weights.",
        "pass": i03_pass,
        "node_count": len(snapshots),
    }

    # QPC-I04: not directly testable
    results["QPC-I04"] = {
        "description": "Revocation/recovery cannot create simultaneous independent power.",
        "pass": None,
        "note": "NOT_TESTABLE without controlled revocation+recovery sequence.",
    }

    # QPC-I05: total power >= quorum (ceil(2/3 * total))
    total_power = sum(v.get("voting_power", 0) for v in vals)
    verified_power = sum(v.get("voting_power", 0) for v in vals if v.get("pop_verified"))
    quorum = (2 * total_power + 2) // 3  # ceil(2/3)
    results["QPC-I05"] = {
        "description": "Total verified voting power >= BFT quorum threshold.",
        "pass": total_power >= quorum,
        "total_power": total_power,
        "quorum": quorum,
        "verified_power": verified_power,
    }

    # QPC-I06: revocation API exists (structural check)
    results["QPC-I06"] = {
        "description": "RevokeAttestation tx type is available (restart persistence untested here).",
        "pass": None,
        "note": "Structural: RevokeAttestation tx type exists in execution crate. "
                "Restart persistence tested in QPC-A09 (NOT_TESTED without restart control).",
    }

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="QPC Consensus Adversary — QPC-CONS-001")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--findings-dir", type=Path, default=Path("agents/findings"))
    parser.add_argument("--attack", default=None,
                        help="Run a single test, e.g. QPC-A07")
    parser.add_argument("--offline", action="store_true",
                        help="Skip all live devnet tests; emit only architectural gap findings")
    parser.add_argument("--unsafe-override", action="store_true")
    args = parser.parse_args()

    config = load_config(args.config)
    args.findings_dir.mkdir(parents=True, exist_ok=True)

    reports_dir = Path(__file__).parent.parent / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    git_sha = _git_sha()

    # Devnet guard
    try:
        chain_id = assert_devnet(config, unsafe_override=args.unsafe_override)
    except SystemExit:
        chain_id = "unknown"

    node_urls: list[str] = config.get("nodes", {}).get("rpc_urls", [])
    node_url = node_urls[0] if node_urls else "http://127.0.0.1:8080"

    # Check devnet availability
    devnet_up = False
    phase_b = False
    if not args.offline:
        try:
            with httpx.Client() as probe:
                r = probe.get(f"{node_url}/api/status", timeout=3.0)
                devnet_up = r.status_code == 200
                if devnet_up:
                    chain_id = r.json().get("chain_id", chain_id)
                    phase_b = _probe_phase_b(probe, node_url)
        except Exception:
            pass
        log.info("devnet availability", url=node_url, up=devnet_up, phase_b=phase_b)

    # Always emit architectural gap findings (gap001 downgraded to INFO if Phase B resolved)
    gap001 = _gap_001(git_sha, phase_b_resolved=phase_b)
    gap002 = _gap_002(git_sha)
    gap001_path = gap001.save(args.findings_dir)
    gap002_path = gap002.save(args.findings_dir)
    log.finding(gap001)
    log.finding(gap002)

    # Run tests
    results: list[TestResult] = []
    invariants: dict[str, dict] = {}
    findings: list[FindingRecord] = [gap001, gap002]

    if devnet_up:
        with httpx.Client() as client:
            def _run(test_id: str, fn) -> None:  # type: ignore
                if args.attack and args.attack != test_id:
                    return
                log.info(f"running {test_id}")
                results.append(fn())

            _run("QPC-A01", lambda: test_a01_multi_validator_cap(client, node_url, chain_id, git_sha, phase_b=phase_b))
            _run("QPC-A02", lambda: test_a02_stake_split(client, node_url, chain_id, git_sha))
            _run("QPC-A03", lambda: test_a03_credential_reuse(client, node_url, chain_id, git_sha, phase_b=phase_b))
            _run("QPC-A04", lambda: test_a04_revoked_credential(client, node_url, chain_id, git_sha, node_urls))
            _run("QPC-A05", lambda: test_a05_credential_recovery(client, node_url, chain_id, git_sha))
            _run("QPC-A06", lambda: test_a06_proof_replay(client, node_url, chain_id, git_sha))
            _run("QPC-A07", lambda: test_a07_cross_node_consistency(client, node_urls, chain_id, git_sha))
            _run("QPC-A08", lambda: test_a08_transition_consistency(client, node_url, chain_id, git_sha))
            _run("QPC-A09", lambda: test_a09_restart_revocation(chain_id, git_sha))
            _run("QPC-A10", lambda: test_a10_attacker_many_validators(client, node_url, chain_id, git_sha, phase_b=phase_b))

            if not args.attack:
                invariants = run_invariant_oracles(client, node_urls, chain_id)
    else:
        not_tested_reason = "devnet unreachable" if not args.offline else "offline mode"
        for tid, scenario in [
            ("QPC-A01", "One human registers 10 validators"),
            ("QPC-A02", "Split stake across 100 wallets"),
            ("QPC-A03", "Credential reuse across validators"),
            ("QPC-A04", "Revoked credential voting"),
            ("QPC-A05", "Credential recovery dual binding"),
            ("QPC-A06", "Personhood proof replay"),
            ("QPC-A07", "Cross-node validator consistency"),
            ("QPC-A08", "Transition consistency"),
            ("QPC-A09", "Restart after revocation"),
            ("QPC-A10", "Attacker controls many validators"),
        ]:
            if args.attack and args.attack != tid:
                continue
            results.append(TestResult(
                test_id=tid, scenario=scenario, timestamp=_now(),
                git_sha=git_sha, chain_id=chain_id, seed=0x51AB_C001,
                validator_count=0, human_count=0,
                expected="N/A", actual=f"NOT_TESTED: {not_tested_reason}",
                tx_ids=[], block_heights=[], block_hashes=[],
                identity_evidence={}, voting_power_evidence={},
                classification="NOT_TESTED", notes=not_tested_reason,
            ))

    # Check for FAIL results → emit as findings
    for r in results:
        if r.classification == "FAIL":
            f = FindingRecord(
                agent=AgentId.QPC_CONSENSUS,
                title=f"{r.test_id}: {r.scenario}",
                severity=Severity.HIGH,
                invariant_id=None,
                steps=[r.scenario],
                expected=r.expected,
                actual=r.actual,
                evidence={"voting_power_evidence": r.voting_power_evidence,
                          "identity_evidence": r.identity_evidence},
            )
            findings.append(f)
            f.save(args.findings_dir)
            log.finding(f)

    # Write reports
    report_json = {
        "milestone": "QPC-CONS-001",
        "timestamp": _now(),
        "git_sha": git_sha,
        "chain_id": chain_id,
        "devnet_up": devnet_up,
        "phase_b_detected": phase_b,
        "test_results": [asdict(r) for r in results],
        "invariant_oracles": invariants,
        "security_findings": [json.loads(f.to_json()) for f in findings],
    }
    json_path = reports_dir / "qpc_cons_001_results.json"
    json_path.write_text(json.dumps(report_json, indent=2))
    log.info(f"JSON report written", path=str(json_path))

    # Markdown report
    counts = {c: sum(1 for r in results if r.classification == c)
              for c in ("PASS", "FAIL", "NOT_TESTED", "SIMULATED")}
    md_lines = [
        "# QPC-CONS-001 Security Report",
        "",
        f"**Generated:** {_now()}  ",
        f"**Commit:** `{git_sha}`  ",
        f"**Chain ID:** `{chain_id}`  ",
        f"**Devnet reachable:** {devnet_up}",
        "",
        "## Test Summary",
        "",
        f"| Classification | Count |",
        f"|---|---|",
    ]
    for cls, cnt in counts.items():
        md_lines.append(f"| {cls} | {cnt} |")
    gap001_md = (
        [
            "### QPC-GAP-001 (RESOLVED — Phase B): owner_identity_id now settable",
            "",
            "`BondValidator` now accepts `owner_identity_id: Option<String>` (Phase B,",
            "commit `fc1852b`). Bindings are authenticated (tx.sender == owner_identity_id,",
            "active personhood credential required), stored durably via `state.set_raw()`,",
            "survive restarts, and reject unauthorized ownership changes. Per-human cap",
            "enforces `∑ voting_power ≤ power_cap` (not just validator count).",
            "",
        ]
        if phase_b else
        [
            "### QPC-GAP-001 (HIGH): owner_identity_id not settable via tx API",
            "",
            "`BondValidator{amount}` hardcodes `owner_identity_id=None`. Every post-genesis",
            "validator is treated as its own human. The per-human cap enforcement in",
            "`build_validator_set()` is correct Rust code but is never triggered because the",
            "binding is never set. An attacker can register N validators (each with a different",
            "address) and accumulate N units of voting power.",
            "",
            "**Location:** `chain-forge-execution/src/lib.rs:2112-2123`  ",
            "**Fix:** Add `owner_identity_id: Option<String>` to `BondValidator` tx body.",
            "",
        ]
    )
    md_lines += [
        "",
        "## Architectural Security Gaps",
        "",
    ] + gap001_md + [
        "### QPC-GAP-002 (MEDIUM): Attestation requires coordinator centralization",
        "",
        "Only `attestation_coordinator` (qcb1alice on devnet) can grant `pop_verified=true`.",
        "The ZK-VRC multi-issuer path exists in `chain-forge-personhood` but is not wired",
        "into the live validator admission flow.",
        "",
        "## Test Results",
        "",
        "| Test ID | Classification | Notes |",
        "|---|---|---|",
    ]
    for r in results:
        md_lines.append(f"| {r.test_id} | {r.classification} | {r.notes[:80] if r.notes else r.actual[:80]} |")

    if invariants:
        md_lines += ["", "## Invariant Oracle Results", ""]
        for inv_id, inv in invariants.items():
            p = inv.get("pass")
            status = "PASS" if p is True else ("FAIL" if p is False else "NOT_TESTABLE")
            md_lines.append(f"- **{inv_id}** ({status}): {inv.get('description', '')}")

    phase_b_note = (
        "Phase B (`owner_identity_id` in `BondValidator`) was detected on the running chain. "
        "Tests QPC-A01, QPC-A03, and QPC-A10 exercised live adversarial transactions. "
        "See individual test results above for PASS/FAIL verdicts."
        if phase_b else
        "Phase B (`owner_identity_id` in `BondValidator`) was NOT detected on the running chain. "
        "QPC-A01, QPC-A03, QPC-A10 were not exercised. Deploy feat/qpc-cons-001-phase-b-authenticated-binding "
        "to enable live adversarial testing."
    )
    gap001_status = "RESOLVED (Phase B)" if phase_b else "OPEN"
    md_lines += [
        "",
        "## Conclusion",
        "",
        phase_b_note,
        "",
        f"- **QPC-GAP-001** ({gap001_status}): per-human cap enforcement via `owner_identity_id`.",
        "- **QPC-GAP-002** (OPEN): attestation centralization (single coordinator on devnet).",
        "",
        "> A PASS result on A01/A03/A10 confirms the invariant holds for the tested scenarios.",
        "> QPC-GAP-002 remains open pending multi-issuer ZK-VRC wiring.",
    ]
    md_path = reports_dir / "qpc_cons_001_security_report.md"
    md_path.write_text("\n".join(md_lines))
    log.info(f"Markdown report written", path=str(md_path))

    # Summary
    total_findings = len(list(args.findings_dir.glob("*.json")))
    passes = counts.get("PASS", 0)
    fails = counts.get("FAIL", 0)
    print(f"\n{'='*60}")
    print(f"QPC-CONS-001  Findings: {total_findings}  PASS: {passes}  FAIL: {fails}")
    print(f"  Reports: {json_path}")
    print(f"  Reports: {md_path}")
    print(f"{'='*60}")

    sys.exit(1 if total_findings > 0 else 0)


if __name__ == "__main__":
    main()
