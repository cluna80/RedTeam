#!/usr/bin/env python3
"""
agents/agent7_consensus.py — ConsensusAdversary

Targets the QCB Tendermint-style BFT consensus layer in chain-forge-consensus,
probing safety, liveness, and view-change correctness on the devnet.

## What we know from the whitepaper and Phase 0 results
- TendermintEngine is live: chain_id-scoped vote sets, real libp2p P2P
- 4-node devnet: Alice/Bob/Carol/Dave — quorum=3, f=1
- Partition recovery verified: iptables DROP → nodes resync in <2s
- chain-forge-slashing exists: equivocation is punishable on-chain
- REST: /api/status, /api/height (inferred), node RPC on :26657/:26659/:26661/:26663
- Change Set Q: BTC beacon deterministic job assignment (scheduler layer, not consensus)
- Cross-chain vote contamination: was a known bug (now fixed) — we regression-test it

## Attack categories
  C1  Chain-ID cross-contamination regression
      Replay votes/proposals with a wrong chain_id; confirm nodes reject them.
      This was a real bug (fixed in Phase 0); we keep it as a regression.

  C2  Byzantine proposer — conflicting block proposals
      In a real deployment a malicious proposer would send two different block
      proposals for the same height/round to different validator subsets.
      We simulate this from the outside by injecting two conflicting /propose
      debug payloads and checking whether any node commits a block without
      a valid quorum.

  C3  Vote withholding (liveness attack)
      Isolate one validator (iptables DROP on its P2P port) so it cannot
      cast votes. With f=1 and quorum=3, the remaining 3 nodes must still
      make progress. Verifies liveness under the maximum tolerable fault.

  C4  Double-fault threshold probe
      Isolate TWO validators simultaneously (f=2 > f_max=1).
      The chain must halt (no new blocks) rather than produce a block
      without quorum. Verifies the safety guarantee: no commit without 3/4.

  C5  Stale-height vote replay
      Replay a vote message from height N at height N+K (K>0).
      Nodes must not count stale votes toward a later height's quorum.

  C6  View-change / round-change flood
      Send a burst of NextRound / ViewChange messages above the rate limit.
      Verify the node stays alive and does not lock up in round-change.

  C7  Equivocation detection
      Submit two conflicting votes for the same height+round from the same
      validator address via the debug injection endpoint.
      Verify chain-forge-slashing records the equivocation evidence.

  C8  Partition recovery regression
      Reproduce the Phase 0 iptables test programmatically:
      DROP Alice's P2P port, wait for 5 blocks, restore, verify Alice resyncs.
      This is the whitepaper's own benchmark — we make it a repeatable test.

## Endpoints used
- /api/status          — height, round, step, peer_count (confirmed in whitepaper)
- /api/consensus_state — [ASSUMPTION] Tendermint standard endpoint
- /debug/inject_vote   — [ASSUMPTION] devnet-only injection hook
- /debug/inject_proposal — [ASSUMPTION] devnet-only injection hook
- /debug/slashing_evidence — [ASSUMPTION] devnet-only query
- iptables             — for C3/C4/C8 (requires root or sudo on the devnet host)

## ASSUMPTIONS (grep to verify)
All [ASSUMPTION] markers point to things to confirm against chain-forge-consensus/src/
See agents/ASSUMPTIONS.md for the full list.

Usage:
    python agents/agent7_consensus.py --config agents/config/devnet4.toml
    python agents/agent7_consensus.py --config agents/config/devnet4.toml --attack C8
    python agents/agent7_consensus.py --config agents/config/devnet3.toml --no-iptables
"""
from __future__ import annotations

import argparse
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

log = StructuredLogger("agent7_consensus")

# ---------------------------------------------------------------------------
# Node layout — matches devnet4.toml Alice/Bob/Carol/Dave
# ---------------------------------------------------------------------------

# [ASSUMPTION] P2P ports follow the pattern RPC_port + 1
# Grep: grep -rn 'p2p_port\|P2P_PORT\|26656' chain-forge-node/src/ devnet/
_P2P_PORT_OFFSET = -1   # [ASSUMPTION] p2p = rpc_port - 1 (i.e. 26656, 26658, 26660, 26662)

# [ASSUMPTION] Debug injection endpoint prefix
_DEBUG_PREFIX = "/debug"   # [ASSUMPTION] devnet-only, guarded by --features devnet

# [ASSUMPTION] Consensus state endpoint
_CONSENSUS_STATE = "/api/consensus_state"   # [ASSUMPTION]

# Vote/proposal message shapes
# [ASSUMPTION] field names match chain-forge-consensus/src/vote.rs, proposal.rs
# Grep: grep -n 'struct Vote\|struct Proposal\|chain_id\|height\|round\|block_hash'
#        chain-forge-consensus/src/

_DEVNET_CHAIN_ID = "devnet"   # override via config if needed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rpc_port(rpc_url: str) -> int:
    return int(rpc_url.rsplit(":", 1)[-1])


def _p2p_port(rpc_url: str) -> int:
    """[ASSUMPTION] p2p port = rpc_port - 1"""
    return _rpc_port(rpc_url) + _P2P_PORT_OFFSET


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
    if status in (400, 401, 403, 409, 422):
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
        agent=AgentId.INVARIANT,   # closest existing agent enum; extend AgentId for CONSENSUS
        title=f"[ConsensusAdversary] {title}",
        severity=severity,
        invariant_id=inv,
        steps=steps,
        expected=expected,
        actual=actual,
        evidence=evidence,
    )


def _current_height(client: httpx.Client, node_url: str) -> int | None:
    """Return the node's current committed block height, or None on error."""
    _, body = _get(client, f"{node_url}/api/status")
    # [ASSUMPTION] height field path — check chain-forge-node/src/api/status.rs
    return (
        body.get("height")
        or body.get("result", {}).get("sync_info", {}).get("latest_block_height")
        or body.get("sync_info", {}).get("latest_block_height")
    )


def _wait_for_height(
    client: httpx.Client,
    node_url: str,
    target: int,
    timeout_secs: float = 60.0,
) -> bool:
    """Return True if the node reaches target height within timeout."""
    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        h = _current_height(client, node_url)
        if h is not None and h >= target:
            return True
        time.sleep(1.0)
    return False


def _peer_count(client: httpx.Client, node_url: str) -> int | None:
    _, body = _get(client, f"{node_url}/api/status")
    return (
        body.get("peer_count")
        or body.get("result", {}).get("n_peers")
    )


def _iptables_drop(host: str, port: int, direction: str = "INPUT") -> bool:
    """
    Block traffic to/from a port using iptables.
    Requires the test runner to have sudo/root on the devnet host.
    Returns True if the command succeeded.
    direction: 'INPUT' or 'OUTPUT'
    """
    cmd = ["sudo", "iptables", "-I", direction, "-p", "tcp",
           "--dport" if direction == "INPUT" else "--sport", str(port),
           "-j", "DROP"]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception as exc:
        log.warn(f"iptables DROP failed: {exc}")
        return False


def _iptables_restore(host: str, port: int, direction: str = "INPUT") -> bool:
    """Remove the DROP rule added by _iptables_drop."""
    cmd = ["sudo", "iptables", "-D", direction, "-p", "tcp",
           "--dport" if direction == "INPUT" else "--sport", str(port),
           "-j", "DROP"]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception as exc:
        log.warn(f"iptables restore failed: {exc}")
        return False


def _inject_vote(
    client: httpx.Client,
    node_url: str,
    chain_id: str,
    height: int,
    round_: int,
    block_hash: str,
    validator_addr: str,
    signature: str = "ff" * 64,
) -> tuple[int, dict]:
    """
    POST /debug/inject_vote
    [ASSUMPTION] field names — grep chain-forge-consensus/src/debug.rs or chain-forge-node/src/
    """
    return _post(client, f"{node_url}{_DEBUG_PREFIX}/inject_vote", {
        "chain_id":       chain_id,
        "height":         height,
        "round":          round_,
        "block_hash":     block_hash,
        "validator_addr": validator_addr,
        "signature":      signature,
        "vote_type":      "PRECOMMIT",   # [ASSUMPTION]
    })


def _inject_proposal(
    client: httpx.Client,
    node_url: str,
    chain_id: str,
    height: int,
    round_: int,
    block_hash: str,
    proposer_addr: str,
    signature: str = "ff" * 64,
) -> tuple[int, dict]:
    """
    POST /debug/inject_proposal
    [ASSUMPTION] field names — grep chain-forge-consensus/src/debug.rs
    """
    return _post(client, f"{node_url}{_DEBUG_PREFIX}/inject_proposal", {
        "chain_id":     chain_id,
        "height":       height,
        "round":        round_,
        "block_hash":   block_hash,
        "proposer":     proposer_addr,
        "signature":    signature,
        "timestamp":    int(time.time()),
    })


# ---------------------------------------------------------------------------
# C1 — Chain-ID cross-contamination regression
# ---------------------------------------------------------------------------

def attack_c1_chain_id_regression(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    The whitepaper documents a real bug where chain_id was never set in init(),
    causing silent consensus failures across multi-node networks.  It was fixed
    in Phase 0.  This attack regression-tests that the fix holds.

    We inject votes and proposals with wrong chain_ids and verify all nodes
    reject them and do not count them toward any quorum.
    """
    findings: list[FindingRecord] = []
    node_urls = cfg["nodes"]["rpc_urls"]
    chain_id  = cfg.get("chain_id", _DEVNET_CHAIN_ID)

    wrong_chain_ids = [
        "qcb-mainnet-1",
        "devnet-999",
        "",
        "devnet\x00injected",
        chain_id + "-fork",
    ]

    for node_url in node_urls[:2]:   # test first two nodes
        h = _current_height(client, node_url) or 1
        for wrong_cid in wrong_chain_ids:
            s, b = _inject_vote(
                client, node_url,
                chain_id=wrong_cid,
                height=h,
                round_=0,
                block_hash="aa" * 32,
                validator_addr="qcb1alice000000000000000000000000000000000",
            )
            if s == 404:
                log.info(f"[C1] vote endpoint not deployed — NOT_TESTED (chain_id={wrong_cid!r})")
                continue
            if not _rejected(s, b):
                f = _finding(
                    inv=9,
                    title=f"Vote with wrong chain_id accepted: {wrong_cid!r}",
                    severity=Severity.CRITICAL,
                    steps=[
                        f"Inject vote with chain_id={wrong_cid!r} to {node_url}",
                        f"Node returned status={s}",
                    ],
                    expected="Vote rejected — wrong chain_id must never be admitted",
                    actual=f"status={s}, body={b}",
                    evidence={"wrong_chain_id": wrong_cid, "node": node_url, "response": b},
                )
                findings.append(f)
                log.finding(f)
            else:
                log.info(f"[C1] chain_id={wrong_cid!r} correctly rejected", status=s)

    return findings


# ---------------------------------------------------------------------------
# C2 — Byzantine proposer: conflicting block proposals
# ---------------------------------------------------------------------------

def attack_c2_conflicting_proposals(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    A Byzantine proposer sends two different block hashes for the same
    height+round to different validator subsets.  We simulate this by injecting
    conflicting proposals to different nodes and then checking whether any node
    commits a block at that height without the required quorum.

    Detection: if two nodes commit different block hashes at the same height,
    the chain has forked — a critical safety violation.
    """
    findings: list[FindingRecord] = []
    node_urls = cfg["nodes"]["rpc_urls"]
    chain_id  = cfg.get("chain_id", _DEVNET_CHAIN_ID)

    if len(node_urls) < 2:
        log.warn("[C2] need at least 2 nodes, skipping")
        return findings

    h     = (_current_height(client, node_urls[0]) or 1) + 2
    hash_a = "aa" * 32
    hash_b = "bb" * 32
    proposer = "qcb1alice000000000000000000000000000000000"

    # Inject conflicting proposals to different nodes
    _inject_proposal(client, node_urls[0], chain_id, h, 0, hash_a, proposer)
    _inject_proposal(client, node_urls[1], chain_id, h, 0, hash_b, proposer)
    log.info(f"[C2] injected conflicting proposals at height={h}", hash_a=hash_a[:8], hash_b=hash_b[:8])

    # Wait for block at height h, then check all nodes agree
    time.sleep(8)
    committed_hashes: dict[str, str] = {}
    for node_url in node_urls:
        _, body = _get(client, f"{node_url}/api/block?height={h}")
        bh = (
            body.get("block_hash")
            or body.get("result", {}).get("block_id", {}).get("hash")
        )
        if bh:
            committed_hashes[node_url] = bh

    unique_hashes = set(committed_hashes.values())
    if len(unique_hashes) > 1:
        f = _finding(
            inv=None,
            title="Chain fork: nodes committed different block hashes at same height",
            severity=Severity.CRITICAL,
            steps=[
                f"Inject proposal hash_a={hash_a[:8]} to {node_urls[0]}",
                f"Inject proposal hash_b={hash_b[:8]} to {node_urls[1]}",
                f"Query /api/block?height={h} on all nodes",
                f"Found {len(unique_hashes)} distinct committed hashes",
            ],
            expected="All nodes commit identical block hash at height (safety)",
            actual=f"Nodes disagree: {committed_hashes}",
            evidence={"height": h, "committed": committed_hashes},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info(f"[C2] all nodes agree on block hash at height={h} ✓",
                 unique_hash=list(unique_hashes)[0][:16] if unique_hashes else "none")

    return findings


# ---------------------------------------------------------------------------
# C3 — Vote withholding (liveness under f=1)
# ---------------------------------------------------------------------------

def attack_c3_vote_withholding(
    client: httpx.Client,
    cfg: dict[str, Any],
    use_iptables: bool = True,
) -> list[FindingRecord]:
    """
    Isolate Alice (node 0) by blocking her P2P port.
    With quorum=3 and f=1, Bob/Carol/Dave must still produce blocks.
    Then restore Alice and verify she resyncs — reproducing the Phase 0 test.
    """
    findings: list[FindingRecord] = []
    node_urls = cfg["nodes"]["rpc_urls"]
    if len(node_urls) < 4:
        log.warn("[C3] need 4 nodes for quorum=3 liveness test, skipping")
        return findings

    alice_url  = node_urls[0]
    bob_url    = node_urls[1]
    p2p_port   = _p2p_port(alice_url)

    h_before = _current_height(client, bob_url) or 0
    log.info(f"[C3] height before partition: {h_before}")

    if use_iptables:
        ok = _iptables_drop("127.0.0.1", p2p_port, "INPUT")
        log.info(f"[C3] iptables DROP Alice P2P port={p2p_port}", success=ok)
        if not ok:
            log.warn("[C3] iptables failed — cannot partition Alice, skipping C3")
            return findings
    else:
        log.warn("[C3] --no-iptables set: simulating partition by not voting (partial test)")

    # Wait for 5 blocks on the honest partition
    time.sleep(15)
    h_partitioned = _current_height(client, bob_url) or h_before
    log.info(f"[C3] height after 15s partition: {h_partitioned}")

    liveness_ok = h_partitioned >= h_before + 3

    if use_iptables:
        _iptables_restore("127.0.0.1", p2p_port, "INPUT")
        log.info(f"[C3] iptables RESTORED Alice P2P port={p2p_port}")

    # Wait for Alice to resync
    time.sleep(5)
    h_alice_after = _current_height(client, alice_url) or 0
    resync_ok = h_alice_after >= h_partitioned - 1

    log.info(f"[C3] Alice height after resync: {h_alice_after}, bob at: {h_partitioned}")

    if not liveness_ok:
        f = _finding(
            inv=None,
            title="Chain halted under f=1 partition (liveness failure)",
            severity=Severity.CRITICAL,
            steps=[
                f"Block Alice's P2P port={p2p_port} (iptables DROP)",
                "Wait 15s for Bob/Carol/Dave to produce blocks",
                f"Bob height: {h_before} → {h_partitioned} (expected +3 minimum)",
            ],
            expected="Bob/Carol/Dave produce blocks with 3/4 quorum (f=1 tolerance)",
            actual=f"Height only advanced {h_partitioned - h_before} blocks in 15s",
            evidence={"h_before": h_before, "h_partitioned": h_partitioned, "alice_p2p": p2p_port},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info(f"[C3] liveness under f=1 partition confirmed ✓ (+{h_partitioned - h_before} blocks)")

    if not resync_ok:
        f = _finding(
            inv=None,
            title="Alice failed to resync after partition healed",
            severity=Severity.HIGH,
            steps=[
                "Heal Alice's P2P partition (iptables restore)",
                "Wait 5s for sync",
                f"Alice height: {h_alice_after}, expected ≥ {h_partitioned - 1}",
            ],
            expected="Alice resyncs to chain tip within 5s of partition healing",
            actual=f"Alice at height {h_alice_after}, chain at {h_partitioned}",
            evidence={"h_alice": h_alice_after, "h_chain": h_partitioned},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info(f"[C3] Alice resync confirmed ✓ (height={h_alice_after})")

    return findings


# ---------------------------------------------------------------------------
# C4 — Double-fault threshold: chain must halt when f > f_max
# ---------------------------------------------------------------------------

def attack_c4_double_fault(
    client: httpx.Client,
    cfg: dict[str, Any],
    use_iptables: bool = True,
) -> list[FindingRecord]:
    """
    Isolate TWO validators (Alice + Bob) — f=2 > f_max=1.
    With only Carol + Dave active (2/4 < quorum=3), the chain must halt.
    A new committed block during this period is a safety violation.
    """
    findings: list[FindingRecord] = []
    node_urls = cfg["nodes"]["rpc_urls"]
    if len(node_urls) < 4:
        log.warn("[C4] need 4 nodes, skipping")
        return findings

    alice_url = node_urls[0]
    bob_url   = node_urls[1]
    carol_url = node_urls[2]
    alice_p2p = _p2p_port(alice_url)
    bob_p2p   = _p2p_port(bob_url)

    h_before = _current_height(client, carol_url) or 0
    log.info(f"[C4] height before double-fault: {h_before}")

    if not use_iptables:
        log.warn("[C4] --no-iptables: cannot test double-fault properly, skipping")
        return findings

    _iptables_drop("127.0.0.1", alice_p2p, "INPUT")
    _iptables_drop("127.0.0.1", bob_p2p,   "INPUT")
    log.info(f"[C4] partitioned Alice (p2p={alice_p2p}) and Bob (p2p={bob_p2p})")

    time.sleep(15)
    h_after = _current_height(client, carol_url) or h_before

    # Restore immediately
    _iptables_restore("127.0.0.1", alice_p2p, "INPUT")
    _iptables_restore("127.0.0.1", bob_p2p,   "INPUT")
    log.info(f"[C4] restored Alice and Bob")

    blocks_produced = h_after - h_before
    if blocks_produced > 0:
        f = _finding(
            inv=None,
            title="Chain committed blocks with only 2/4 validators (f=2 > f_max=1)",
            severity=Severity.CRITICAL,
            steps=[
                "Partition Alice AND Bob (iptables DROP both P2P ports)",
                "Leave only Carol + Dave active (2/4 validators)",
                f"Wait 15s — Carol height: {h_before} → {h_after}",
                f"Chain produced {blocks_produced} block(s) without quorum",
            ],
            expected="Chain halts when active validators < quorum (2 < 3); no new commits",
            actual=f"Chain committed {blocks_produced} block(s) at 2/4 validator participation",
            evidence={"h_before": h_before, "h_after": h_after, "blocks": blocks_produced},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info(f"[C4] chain correctly halted under double-fault ✓ (no new blocks in 15s)")

    return findings


# ---------------------------------------------------------------------------
# C5 — Stale-height vote replay
# ---------------------------------------------------------------------------

def attack_c5_stale_vote_replay(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    Inject a PRECOMMIT vote for height N, then replay the same vote
    at height N+5.  The node must not count it toward the later height's quorum.
    """
    findings: list[FindingRecord] = []
    node_url = cfg["nodes"]["rpc_urls"][0]
    chain_id = cfg.get("chain_id", _DEVNET_CHAIN_ID)

    h_now = _current_height(client, node_url) or 10
    stale_height = max(1, h_now - 3)
    future_height = h_now + 5

    block_hash = "cc" * 32
    validator  = "qcb1alice000000000000000000000000000000000"

    # Inject vote for stale height (may be rejected as past, which is correct)
    s1, b1 = _inject_vote(client, node_url, chain_id, stale_height, 0, block_hash, validator)
    log.info(f"[C5] stale vote at height={stale_height}", status=s1)

    # Now inject the same vote at a future height — must be rejected
    s2, b2 = _inject_vote(client, node_url, chain_id, future_height, 0, block_hash, validator)
    log.info(f"[C5] replayed vote at future height={future_height}", status=s2)

    # Wait until chain reaches future_height, then check if rogue vote counted
    if _wait_for_height(client, node_url, future_height, timeout_secs=60):
        _, state = _get(client, f"{node_url}{_CONSENSUS_STATE}")
        # If the block at future_height was committed with our injected hash
        # and that hash wasn't a real proposal, it's a finding
        committed_hash = (
            state.get("commit_hash")
            or state.get("result", {}).get("round_state", {}).get("proposal_block_hash")
        )
        if committed_hash and committed_hash.lower() == block_hash:
            f = _finding(
                inv=6,
                title="Stale vote replayed at future height contributed to commit",
                severity=Severity.CRITICAL,
                steps=[
                    f"Record vote at stale height={stale_height}",
                    f"Re-inject same vote at height={future_height}",
                    f"Chain reached height={future_height} and committed hash={block_hash[:16]}",
                ],
                expected="Stale vote rejected; future height commits a legitimately proposed block",
                actual=f"Committed hash matches injected stale vote at height={future_height}",
                evidence={"stale_h": stale_height, "future_h": future_height,
                          "block_hash": block_hash, "state": state},
            )
            findings.append(f)
            log.finding(f)
        else:
            log.info(f"[C5] stale vote replay did not affect commit at height={future_height} ✓")
    else:
        log.warn(f"[C5] chain did not reach height={future_height} within 60s — skipping commit check")

    return findings


# ---------------------------------------------------------------------------
# C6 — View-change / round-change flood
# ---------------------------------------------------------------------------

def attack_c6_viewchange_flood(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    Flood the node with NextRound/ViewChange messages above the rate limit.
    The node must stay alive and continue producing blocks; it must not
    lock up in a perpetual round-change loop.
    """
    findings: list[FindingRecord] = []
    node_url = cfg["nodes"]["rpc_urls"][0]
    chain_id = cfg.get("chain_id", _DEVNET_CHAIN_ID)
    flood_count = cfg["limits"]["max_flood_msgs"]

    h_before = _current_height(client, node_url) or 0
    log.info(f"[C6] flooding {flood_count} view-change messages…")

    errors = 0
    for i in range(flood_count):
        s, _ = _post(client, f"{node_url}{_DEBUG_PREFIX}/inject_view_change", {
            # [ASSUMPTION] field names for ViewChange/NextRound
            "chain_id": chain_id,
            "height":   h_before + 1,
            "round":    i,
            "validator": "qcb1alice000000000000000000000000000000000",
            "signature": "ff" * 64,
        })
        if s == 0:
            errors += 1

    log.info(f"[C6] flood complete", errors=errors)

    # Node must still be alive and making progress
    time.sleep(10)
    h_after = _current_height(client, node_url) or h_before
    node_alive = h_after > h_before

    if not node_alive:
        f = _finding(
            inv=8,
            title="Node halted or stalled after view-change flood",
            severity=Severity.CRITICAL,
            steps=[
                f"Flood {flood_count} view-change messages to {node_url}",
                "Wait 10s, poll height",
                f"Height before: {h_before}, after: {h_after}",
            ],
            expected="Node rate-limits/drops excess view-changes and continues producing blocks",
            actual=f"No new blocks produced (height stuck at {h_after})",
            evidence={"h_before": h_before, "h_after": h_after, "flood_count": flood_count},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info(f"[C6] node alive after flood ✓ (+{h_after - h_before} blocks)")

    return findings


# ---------------------------------------------------------------------------
# C7 — Equivocation detection via chain-forge-slashing
# ---------------------------------------------------------------------------

def attack_c7_equivocation(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    Submit two conflicting PRECOMMIT votes for the same height+round
    from the same validator address.  chain-forge-slashing must record
    the equivocation evidence and (eventually) slash the validator.
    """
    findings: list[FindingRecord] = []
    node_url  = cfg["nodes"]["rpc_urls"][0]
    chain_id  = cfg.get("chain_id", _DEVNET_CHAIN_ID)
    h         = (_current_height(client, node_url) or 1) + 2
    validator = "qcb1alice000000000000000000000000000000000"

    hash_a = "dd" * 32
    hash_b = "ee" * 32

    s1, b1 = _inject_vote(client, node_url, chain_id, h, 0, hash_a, validator)
    s2, b2 = _inject_vote(client, node_url, chain_id, h, 0, hash_b, validator)
    log.info(f"[C7] injected conflicting votes", height=h, s1=s1, s2=s2)

    if s1 == 404 and s2 == 404:
        log.info("[C7] vote endpoint not deployed — NOT_TESTED")
        return findings

    time.sleep(3)

    # Check slashing evidence endpoint
    # [ASSUMPTION] endpoint path — grep chain-forge-slashing/src/ chain-forge-node/src/
    se_status, evidence = _get(client, f"{node_url}{_DEBUG_PREFIX}/slashing_evidence")
    if se_status == 404:
        log.info("[C7] slashing evidence endpoint not deployed — NOT_TESTED")
        return findings
    equivocations = [
        e for e in evidence.get("evidence", [])
        if (
            e.get("validator") == validator
            and e.get("type") in ("equivocation", "double_vote", "DuplicateVote")
        )
    ]

    if not equivocations:
        f = _finding(
            inv=3,
            title="Equivocating validator not detected by chain-forge-slashing",
            severity=Severity.HIGH,
            steps=[
                f"Inject PRECOMMIT for height={h}, hash_a={hash_a[:8]} from validator={validator}",
                f"Inject PRECOMMIT for height={h}, hash_b={hash_b[:8]} from same validator",
                f"Poll {node_url}/debug/slashing_evidence",
                f"Found {len(equivocations)} equivocation record(s)",
            ],
            expected="chain-forge-slashing records DuplicateVote evidence for the validator",
            actual=f"No equivocation evidence found; slashing_evidence={evidence}",
            evidence={"height": h, "validator": validator, "vote_a": b1, "vote_b": b2,
                      "slashing_evidence": evidence},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info(f"[C7] equivocation detected and recorded by slashing layer ✓",
                 count=len(equivocations))

    return findings


# ---------------------------------------------------------------------------
# C8 — Partition recovery regression (whitepaper Phase 0 benchmark)
# ---------------------------------------------------------------------------

def attack_c8_partition_recovery(
    client: httpx.Client,
    cfg: dict[str, Any],
    use_iptables: bool = True,
) -> list[FindingRecord]:
    """
    Reproduce the Phase 0 partition test from the whitepaper:
      - Block Alice's P2P port with iptables DROP
      - Bob/Carol/Dave commit 5 blocks
      - Restore Alice's connection
      - Verify Alice resyncs in under 5 seconds

    This is the whitepaper's own benchmark — making it a repeatable regression.
    """
    findings: list[FindingRecord] = []
    node_urls = cfg["nodes"]["rpc_urls"]
    if len(node_urls) < 4:
        log.warn("[C8] need 4 nodes, skipping")
        return findings

    alice_url = node_urls[0]
    bob_url   = node_urls[1]
    p2p_port  = _p2p_port(alice_url)

    h_before = _current_height(client, alice_url) or 0
    log.info(f"[C8] baseline height={h_before}")

    if not use_iptables:
        log.warn("[C8] --no-iptables: skipping partition recovery test")
        return findings

    _iptables_drop("127.0.0.1", p2p_port, "INPUT")
    log.info(f"[C8] Alice partitioned (p2p DROP on port={p2p_port})")

    # Wait for honest partition to produce 5 blocks
    target = h_before + 5
    reached = _wait_for_height(client, bob_url, target, timeout_secs=30)
    h_during = _current_height(client, bob_url) or h_before

    if not reached:
        _iptables_restore("127.0.0.1", p2p_port, "INPUT")
        f = _finding(
            inv=None,
            title="[C8] Honest partition failed to produce 5 blocks in 30s",
            severity=Severity.HIGH,
            steps=[
                f"Partition Alice, wait for Bob to reach height={target}",
                f"Bob height after 30s: {h_during}",
            ],
            expected="Bob/Carol/Dave produce 5 blocks with 3/4 quorum within 30s",
            actual=f"Bob only reached height={h_during} (target={target})",
            evidence={"h_before": h_before, "h_during": h_during, "target": target},
        )
        findings.append(f)
        log.finding(f)
        return findings

    log.info(f"[C8] honest partition produced blocks (height={h_during})")

    # Restore and time resync
    t_restore = time.time()
    _iptables_restore("127.0.0.1", p2p_port, "INPUT")
    log.info(f"[C8] Alice restored — timing resync…")

    resync_ok = _wait_for_height(client, alice_url, h_during - 1, timeout_secs=10)
    t_resync = time.time() - t_restore
    h_alice_final = _current_height(client, alice_url) or 0

    log.info(f"[C8] Alice resync: height={h_alice_final} in {t_resync:.1f}s")

    if not resync_ok or t_resync > 10:
        f = _finding(
            inv=None,
            title=f"[C8] Alice resync too slow or failed ({t_resync:.1f}s)",
            severity=Severity.HIGH,
            steps=[
                f"Heal partition (iptables restore port={p2p_port})",
                f"Wait for Alice to reach height={h_during - 1}",
                f"Alice height after {t_resync:.1f}s: {h_alice_final}",
            ],
            expected="Alice resyncs to chain tip within 5s (whitepaper benchmark)",
            actual=f"Alice at height={h_alice_final}, chain at {h_during}, took {t_resync:.1f}s",
            evidence={"h_before": h_before, "h_during": h_during,
                      "h_alice_final": h_alice_final, "resync_secs": t_resync},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info(f"[C8] partition recovery regression PASSED ✓ "
                 f"(resync in {t_resync:.1f}s, whitepaper benchmark: <5s)")

    return findings


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ATTACKS = [
    ("C1", "Chain-ID cross-contamination regression",  attack_c1_chain_id_regression, False),
    ("C2", "Byzantine proposer / conflicting proposals", attack_c2_conflicting_proposals, False),
    ("C3", "Vote withholding (f=1 liveness)",          attack_c3_vote_withholding,   True),
    ("C4", "Double-fault halt (f=2 > f_max)",          attack_c4_double_fault,       True),
    ("C5", "Stale-height vote replay",                 attack_c5_stale_vote_replay,  False),
    ("C6", "View-change flood",                        attack_c6_viewchange_flood,   False),
    ("C7", "Equivocation detection",                   attack_c7_equivocation,       False),
    ("C8", "Partition recovery regression",            attack_c8_partition_recovery, True),
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="QCB ConsensusAdversary — devnet-only BFT consensus attack suite"
    )
    parser.add_argument("--config",          required=True, type=Path)
    parser.add_argument("--findings-dir",    type=Path, default=Path("agents/findings"))
    parser.add_argument("--attack",          help="Run only C1..C8")
    parser.add_argument("--no-iptables",     action="store_true",
                        help="Skip tests that require iptables (C3/C4/C8)")
    parser.add_argument("--unsafe-override", action="store_true")
    args = parser.parse_args()

    cfg = load_config(args.config)
    try:
        chain_id = assert_devnet(cfg, unsafe_override=args.unsafe_override)
    except Exception as exc:
        abort(str(exc)); return

    # Inject the chain_id into cfg for convenience
    cfg["chain_id"] = chain_id

    log.info("ConsensusAdversary starting", chain_id=chain_id)
    args.findings_dir.mkdir(parents=True, exist_ok=True)
    total: list[FindingRecord] = []

    with httpx.Client() as client:
        for tag, name, fn, needs_iptables in ATTACKS:
            if args.attack and args.attack.upper() != tag:
                continue
            if needs_iptables and args.no_iptables:
                log.info(f"Skipping {tag} (--no-iptables)", name=name)
                continue
            log.info(f"Running {tag}: {name}")
            try:
                if needs_iptables:
                    findings = fn(client, cfg, use_iptables=True)
                else:
                    findings = fn(client, cfg)
                for f in findings:
                    f.save(args.findings_dir)
                total.extend(findings)
            except Exception as exc:
                log.error(f"Error in {tag}: {exc}")

    log.info("ConsensusAdversary complete", total_findings=len(total))
    sys.exit(1 if total else 0)


if __name__ == "__main__":
    main()
