#!/usr/bin/env python3
"""
agents/agent5_invariant.py — InvariantMonitor

Continuously polls node, scheduler, and identity APIs and asserts all
10 protocol invariants defined in agents/invariants.md.

On any violation it emits a FindingRecord JSON, prints an alert with a
state snapshot, and (optionally) writes a regression test stub.

Usage:
    python agents/agent5_invariant.py --config agents/config/devnet3.toml
    python agents/agent5_invariant.py --config agents/config/devnet4.toml --once

Run against devnet only.  Refuses to start if chain_id looks like mainnet.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

# ---------------------------------------------------------------------------
# local imports (agents/ is on sys.path when run from repo root)
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.schema import AgentId, FindingRecord, Severity
from agents.devnet_guard import assert_devnet, load_config, abort


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get(client: httpx.Client, url: str, **kw: Any) -> dict[str, Any] | None:
    """GET url, return parsed JSON or None on any error (logged to stderr)."""
    try:
        r = client.get(url, timeout=10.0, **kw)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        print(f"[monitor] WARN GET {url}: {exc}", file=sys.stderr)
        return None


def _emit(finding: FindingRecord, findings_dir: Path) -> None:
    path = finding.save(findings_dir)
    print(f"\n{'='*70}")
    print(f"[FINDING] {finding}")
    print(f"  saved → {path}")
    print(f"{'='*70}\n", flush=True)


# ---------------------------------------------------------------------------
# State accumulators — keyed by the identifiers the node exposes.
# We don't invent protocol details; every field name mirrors the scheduler
# and node REST paths visible in existing devnet scripts.
# ---------------------------------------------------------------------------

class MonitorState:
    """
    Mutable snapshot updated each poll cycle.
    We accumulate across cycles to detect cross-cycle double-pays, etc.
    """
    def __init__(self) -> None:
        # INV-1: receipt_id → list of payment/credit events seen
        self.payments_by_receipt: dict[str, list[dict]] = defaultdict(list)
        # INV-2 / INV-10: job_id → attestation list
        self.attestations_by_job: dict[str, list[dict]] = defaultdict(list)
        # INV-3: job_id → set of controller_ids that attested
        self.attesting_controllers: dict[str, set[str]] = defaultdict(set)
        # INV-6: seen gossip message hashes
        self.seen_gossip_hashes: set[str] = set()
        # INV-7: controller_id → reward count this epoch
        self.epoch_rewards: dict[str, int] = defaultdict(int)
        # INV-8: per-epoch submission count
        self.epoch_submissions: dict[str, int] = defaultdict(int)
        # track current epoch to reset counters
        self.current_epoch: int = -1


# ---------------------------------------------------------------------------
# Individual invariant checks
# ---------------------------------------------------------------------------

class InvariantChecker:
    def __init__(
        self,
        config: dict[str, Any],
        state: MonitorState,
        findings_dir: Path,
    ) -> None:
        self.cfg = config
        self.state = state
        self.findings_dir = findings_dir
        self.scheduler_url: str = config["scheduler"]["url"]
        self.node_urls: list[str] = config["nodes"]["api_urls"]
        self.replay_window: int = config["timing"]["gossip_replay_window"]

    # -- helpers ------------------------------------------------------------

    def _finding(
        self,
        inv: int,
        title: str,
        severity: Severity,
        steps: list[str],
        expected: str,
        actual: str,
        evidence: dict,
    ) -> FindingRecord:
        return FindingRecord(
            agent=AgentId.INVARIANT,
            title=title,
            severity=severity,
            invariant_id=inv,
            steps=steps,
            expected=expected,
            actual=actual,
            evidence=evidence,
        )

    def _node_get(self, client: httpx.Client, path: str) -> dict | None:
        for url in self.node_urls:
            result = _get(client, f"{url}{path}")
            if result is not None:
                return result
        return None

    def _sched_get(self, client: httpx.Client, path: str) -> dict | None:
        return _get(client, f"{self.scheduler_url}{path}")

    # -- INV-1: no double payment per receipt/job ---------------------------

    def check_inv1_no_double_payment(self, client: httpx.Client) -> list[FindingRecord]:
        findings: list[FindingRecord] = []
        data = self._sched_get(client, "/scheduler/completed_jobs")
        if data is None:
            return findings

        jobs: list[dict] = data.get("jobs", [])
        for job in jobs:
            rid = job.get("receipt_id") or job.get("job_id")
            if rid is None:
                continue
            self.state.payments_by_receipt[rid].append(job)
            entries = self.state.payments_by_receipt[rid]
            # count distinct credit events by looking at credited_at timestamps
            credited = [e for e in entries if e.get("reward_credited")]
            if len(credited) > 1:
                findings.append(self._finding(
                    inv=1,
                    title="Double payment detected for receipt",
                    severity=Severity.CRITICAL,
                    steps=[
                        "Poll /scheduler/completed_jobs",
                        f"Filter by receipt_id={rid}",
                        "Observe multiple reward_credited=true entries",
                    ],
                    expected="At most one reward credit per receipt",
                    actual=f"{len(credited)} credit events for receipt {rid}",
                    evidence={"receipt_id": rid, "entries": credited},
                ))
        return findings

    # -- INV-2: no reward without valid seal + quorum -----------------------

    def check_inv2_seal_quorum_required(self, client: httpx.Client) -> list[FindingRecord]:
        findings: list[FindingRecord] = []
        data = self._sched_get(client, "/scheduler/completed_jobs")
        if data is None:
            return findings

        for job in data.get("jobs", []):
            if not job.get("reward_credited"):
                continue
            job_id = job.get("job_id", "<unknown>")
            seal_ok   = bool(job.get("seal_verified"))
            quorum_ok = bool(job.get("quorum_met"))
            if not seal_ok or not quorum_ok:
                findings.append(self._finding(
                    inv=2,
                    title="Reward credited without seal or quorum",
                    severity=Severity.CRITICAL,
                    steps=[
                        "Poll /scheduler/completed_jobs",
                        f"Locate job_id={job_id} with reward_credited=true",
                        "Inspect seal_verified and quorum_met fields",
                    ],
                    expected="Both seal_verified=true and quorum_met=true before credit",
                    actual=f"seal_verified={seal_ok}, quorum_met={quorum_ok}",
                    evidence={"job": job},
                ))
        return findings

    # -- INV-3: self-controller attestation never counts --------------------

    def check_inv3_no_self_attestation(self, client: httpx.Client) -> list[FindingRecord]:
        findings: list[FindingRecord] = []
        data = self._sched_get(client, "/scheduler/attestations")
        if data is None:
            return findings

        for attest in data.get("attestations", []):
            job_id        = attest.get("job_id", "<unknown>")
            miner_ctrl    = attest.get("miner_controller_id", "")
            verifier_ctrl = attest.get("verifier_controller_id", "")
            counted       = attest.get("counted_toward_quorum", False)

            if miner_ctrl and verifier_ctrl and miner_ctrl == verifier_ctrl and counted:
                findings.append(self._finding(
                    inv=3,
                    title="Self-controller attestation counted toward quorum",
                    severity=Severity.CRITICAL,
                    steps=[
                        "Poll /scheduler/attestations",
                        f"Find attestation for job_id={job_id}",
                        "Observe miner_controller_id == verifier_controller_id and counted=true",
                    ],
                    expected="Self-attestation discarded (anti-self-dealing)",
                    actual=f"controller={miner_ctrl} self-attested and counted",
                    evidence={"attestation": attest},
                ))
        return findings

    # -- INV-4: escrow only releases on valid completion --------------------

    def check_inv4_escrow_valid_release(self, client: httpx.Client) -> list[FindingRecord]:
        findings: list[FindingRecord] = []
        data = self._sched_get(client, "/scheduler/escrow_events")
        if data is None:
            return findings

        for event in data.get("events", []):
            if event.get("event_type") != "release":
                continue
            job_id  = event.get("job_id", "<unknown>")
            reason  = event.get("release_reason", "")
            receipt = event.get("receipt_verified", False)
            if not receipt and reason not in ("refund", "cancellation", "expiry"):
                findings.append(self._finding(
                    inv=4,
                    title="Escrow released without verified receipt",
                    severity=Severity.CRITICAL,
                    steps=[
                        "Poll /scheduler/escrow_events",
                        f"Find release event for job_id={job_id}",
                        "Observe receipt_verified=false with reason not in {refund,cancellation,expiry}",
                    ],
                    expected="Escrow release only after receipt_verified=true or explicit refund/expiry",
                    actual=f"Release with receipt_verified=false, reason={reason!r}",
                    evidence={"event": event},
                ))
        return findings

    # -- INV-5: unauthorized research claims rejected -----------------------

    def check_inv5_unauthorized_claims(self, client: httpx.Client) -> list[FindingRecord]:
        findings: list[FindingRecord] = []
        data = self._node_get(client, "/qcb/pocd/research_claims")
        if data is None:
            return findings

        for claim in data.get("claims", []):
            submitter = claim.get("original_submitter", "")
            claimer   = claim.get("claimer", "")
            delegated = claim.get("delegated", False)
            status    = claim.get("status", "")
            if status == "credited" and claimer != submitter and not delegated:
                findings.append(self._finding(
                    inv=5,
                    title="Research reward claimed by non-submitter without delegation",
                    severity=Severity.HIGH,
                    steps=[
                        "Poll /qcb/pocd/research_claims",
                        f"Find claim receipt_id={claim.get('receipt_id')}",
                        "Observe claimer != original_submitter and delegated=false",
                    ],
                    expected="Only original submitter or delegate can claim reward",
                    actual=f"claimer={claimer} != submitter={submitter}, no delegation",
                    evidence={"claim": claim},
                ))
        return findings

    # -- INV-6: gossip replay does not re-credit ----------------------------

    def check_inv6_gossip_replay(self, client: httpx.Client) -> list[FindingRecord]:
        findings: list[FindingRecord] = []
        data = self._sched_get(client, "/scheduler/gossip_log")
        if data is None:
            return findings

        now_ts = time.time()
        for msg in data.get("messages", []):
            msg_hash  = msg.get("message_hash", "")
            credited  = msg.get("credited", False)
            received  = msg.get("received_at_unix", 0)
            age_secs  = now_ts - received

            if credited and age_secs > self.replay_window:
                if msg_hash in self.state.seen_gossip_hashes:
                    findings.append(self._finding(
                        inv=6,
                        title="Stale replayed gossip message credited",
                        severity=Severity.HIGH,
                        steps=[
                            "Observe gossip message first time (recorded hash)",
                            f"Re-observe same hash after {self.replay_window}s window",
                            "Note credited=true on second observation",
                        ],
                        expected="Replayed message dropped, no credit applied",
                        actual=f"msg_hash={msg_hash} credited after {age_secs:.0f}s",
                        evidence={"message": msg},
                    ))
            self.state.seen_gossip_hashes.add(msg_hash)
        return findings

    # -- INV-7: personhood influence caps hold ------------------------------

    def check_inv7_personhood_caps(self, client: httpx.Client) -> list[FindingRecord]:
        findings: list[FindingRecord] = []
        data = self._node_get(client, "/qcb/identity/epoch_stats")
        if data is None:
            return findings

        cap = data.get("influence_cap_per_epoch", None)
        if cap is None:
            return findings

        for entry in data.get("controller_stats", []):
            ctrl    = entry.get("controller_id", "<unknown>")
            rewards = entry.get("rewards_this_epoch", 0)
            if rewards > cap:
                findings.append(self._finding(
                    inv=7,
                    title="Controller exceeded per-epoch influence cap",
                    severity=Severity.HIGH,
                    steps=[
                        "Poll /qcb/identity/epoch_stats",
                        f"Find controller_id={ctrl}",
                        f"Observe rewards_this_epoch={rewards} > cap={cap}",
                    ],
                    expected=f"No controller earns more than {cap} rewards per epoch",
                    actual=f"controller={ctrl} has {rewards} rewards this epoch",
                    evidence={"entry": entry, "cap": cap},
                ))
        return findings

    # -- INV-8: epoch/resource caps not bypassable by spam ------------------

    def check_inv8_epoch_caps(self, client: httpx.Client) -> list[FindingRecord]:
        findings: list[FindingRecord] = []
        data = self._sched_get(client, "/scheduler/epoch_quota")
        if data is None:
            return findings

        quota = data.get("max_submissions_per_epoch", None)
        if quota is None:
            return findings

        for entry in data.get("machine_quotas", []):
            machine_id   = entry.get("machine_id", "<unknown>")
            submissions  = entry.get("submissions_this_epoch", 0)
            accepted     = entry.get("accepted_this_epoch", 0)
            if accepted > quota:
                findings.append(self._finding(
                    inv=8,
                    title="Machine accepted more submissions than epoch quota",
                    severity=Severity.HIGH,
                    steps=[
                        "Poll /scheduler/epoch_quota",
                        f"Find machine_id={machine_id}",
                        f"Observe accepted_this_epoch={accepted} > quota={quota}",
                    ],
                    expected=f"At most {quota} accepted submissions per machine per epoch",
                    actual=f"machine={machine_id} accepted={accepted} (submitted={submissions})",
                    evidence={"entry": entry, "quota": quota},
                ))
        return findings

    # -- INV-9: wrong chain_id always dropped -------------------------------

    def check_inv9_chain_id_binding(self, client: httpx.Client) -> list[FindingRecord]:
        findings: list[FindingRecord] = []
        # Check node mempool for any admitted tx whose chain_id doesn't match
        for node_url in self.node_urls:
            data = _get(client, f"{node_url}/num_unconfirmed_txs")
            status = _get(client, f"{node_url}/status")
            if data is None or status is None:
                continue
            expected_chain = status.get("result", {}).get("node_info", {}).get("network", "")
            # If the node exposes mempool tx details:
            txs_data = _get(client, f"{node_url}/unconfirmed_txs?limit=50")
            if txs_data is None:
                continue
            for tx_summary in txs_data.get("result", {}).get("txs", []):
                tx_chain = tx_summary.get("chain_id", expected_chain)
                if tx_chain and tx_chain != expected_chain:
                    findings.append(self._finding(
                        inv=9,
                        title="Wrong chain_id tx admitted to mempool",
                        severity=Severity.CRITICAL,
                        steps=[
                            f"Poll {node_url}/unconfirmed_txs",
                            f"Find tx with chain_id={tx_chain}",
                            f"Node's own chain_id is {expected_chain}",
                        ],
                        expected=f"Tx with wrong chain_id rejected before mempool admission",
                        actual=f"Tx chain_id={tx_chain} admitted to node chain_id={expected_chain}",
                        evidence={"tx": tx_summary, "node": node_url},
                    ))
        return findings

    # -- INV-10: stale attestations never reach quorum ----------------------

    def check_inv10_stale_attestations(self, client: httpx.Client) -> list[FindingRecord]:
        findings: list[FindingRecord] = []
        data = self._sched_get(client, "/scheduler/attestations")
        if data is None:
            return findings

        now_ts = time.time()
        for attest in data.get("attestations", []):
            if not attest.get("counted_toward_quorum", False):
                continue
            attest_ts = attest.get("timestamp_unix", now_ts)
            age = now_ts - attest_ts
            if age > self.replay_window:
                findings.append(self._finding(
                    inv=10,
                    title="Stale attestation counted toward quorum",
                    severity=Severity.HIGH,
                    steps=[
                        "Poll /scheduler/attestations",
                        f"Find attestation timestamp older than {self.replay_window}s",
                        "Observe counted_toward_quorum=true",
                    ],
                    expected=f"Attestations older than {self.replay_window}s discarded from quorum",
                    actual=f"Attestation age={age:.0f}s counted for job={attest.get('job_id')}",
                    evidence={"attestation": attest},
                ))
        return findings

    # -- run all checks in one pass ----------------------------------------

    def run_all(self, client: httpx.Client) -> list[FindingRecord]:
        all_findings: list[FindingRecord] = []
        checks = [
            self.check_inv1_no_double_payment,
            self.check_inv2_seal_quorum_required,
            self.check_inv3_no_self_attestation,
            self.check_inv4_escrow_valid_release,
            self.check_inv5_unauthorized_claims,
            self.check_inv6_gossip_replay,
            self.check_inv7_personhood_caps,
            self.check_inv8_epoch_caps,
            self.check_inv9_chain_id_binding,
            self.check_inv10_stale_attestations,
        ]
        for check in checks:
            try:
                results = check(client)
                all_findings.extend(results)
            except Exception as exc:
                print(f"[monitor] ERROR in {check.__name__}: {exc}", file=sys.stderr)
        return all_findings


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run_monitor(
    config: dict[str, Any],
    findings_dir: Path,
    poll_interval: int,
    run_once: bool,
) -> None:
    state   = MonitorState()
    checker = ExtendedInvariantChecker(config, state, findings_dir)
    total_findings = 0

    with httpx.Client() as client:
        while True:
            cycle_start = time.time()
            print(f"[monitor] {_now_iso()} — polling…", flush=True)

            findings = checker.run_all(client)
            for f in findings:
                _emit(f, findings_dir)
                total_findings += 1

            elapsed = time.time() - cycle_start
            print(
                f"[monitor] cycle done in {elapsed:.1f}s — "
                f"{len(findings)} new finding(s), {total_findings} total",
                flush=True,
            )

            if run_once:
                break
            sleep_for = max(0.0, poll_interval - elapsed)
            time.sleep(sleep_for)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="QCB InvariantMonitor — devnet-only continuous red-team check"
    )
    parser.add_argument(
        "--config",
        required=True,
        type=Path,
        help="Path to devnet TOML config (e.g. agents/config/devnet3.toml)",
    )
    parser.add_argument(
        "--findings-dir",
        type=Path,
        default=Path("agents/findings"),
        help="Directory to write JSON findings (default: agents/findings)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single poll cycle and exit (useful for CI)",
    )
    parser.add_argument(
        "--unsafe-override",
        action="store_true",
        help="Skip live chain_id check (unit tests without a node only)",
    )
    args = parser.parse_args()

    if not args.config.exists():
        abort(f"Config not found: {args.config}")

    cfg = load_config(args.config)

    try:
        chain_id = assert_devnet(cfg, unsafe_override=args.unsafe_override)
    except Exception as exc:
        abort(str(exc))

    print(f"[monitor] Starting InvariantMonitor on chain={chain_id}")
    print(f"[monitor] Findings → {args.findings_dir}")
    print(f"[monitor] Mode={'once' if args.once else 'continuous'}")

    poll_interval = cfg["timing"]["poll_interval_secs"]
    run_monitor(cfg, args.findings_dir, poll_interval, args.once)


if __name__ == "__main__":
    main()


# ===========================================================================
# Extended invariant checks — added per suggestion pass
# ===========================================================================

class ExtendedInvariantChecker(InvariantChecker):
    """
    Adds three new invariant groups to the base InvariantChecker:
      E1–E3  Economic conservation (supply, collateral, fees)
      G1–G3  Gossip/message uniqueness and ordering
      V1–V3  Validator/controller set transition safety
    """

    # -----------------------------------------------------------------------
    # Economic conservation invariants
    # -----------------------------------------------------------------------

    def check_econ1_total_supply_conserved(self, client: httpx.Client) -> list[FindingRecord]:
        """
        E1: Total circulating uQCB + escrowed uQCB + treasury balance must
        equal the genesis supply plus net newly-minted rewards.

        Detects: double-mint, phantom issuance, escrow balance leaks.
        """
        findings: list[FindingRecord] = []

        supply  = self._node_get(client, "/qcb/resource/total_supply")
        escrow  = self._sched_get(client, "/scheduler/escrow_total")
        treasury = self._node_get(client, "/qcb/resource/treasury_balance")
        rewards  = self._sched_get(client, "/scheduler/total_rewards_issued")

        if None in (supply, escrow, treasury, rewards):
            return findings

        circulating  = supply.get("circulating_uqcb", 0)
        escrowed_amt = escrow.get("total_locked_uqcb", 0)
        treasury_bal = treasury.get("balance_uqcb", 0)
        minted       = rewards.get("total_minted_uqcb", 0)
        genesis      = supply.get("genesis_supply_uqcb", 0)

        # Conservation: circulating + escrowed + treasury == genesis + minted
        lhs = circulating + escrowed_amt + treasury_bal
        rhs = genesis + minted
        # Allow a small tolerance for in-flight txs (< 1 QCB = 1_000_000 uQCB)
        if abs(lhs - rhs) > 1_000_000:
            findings.append(self._finding(
                inv=None,
                title="Total supply conservation violated",
                severity=Severity.CRITICAL,
                steps=[
                    "Poll /qcb/resource/total_supply",
                    "Poll /scheduler/escrow_total",
                    "Poll /qcb/resource/treasury_balance",
                    "Poll /scheduler/total_rewards_issued",
                    "Assert circulating + escrowed + treasury == genesis + minted",
                ],
                expected=f"LHS ≈ RHS (tolerance 1_000_000 uQCB)",
                actual=f"LHS={lhs}, RHS={rhs}, delta={lhs - rhs}",
                evidence={
                    "circulating": circulating, "escrowed": escrowed_amt,
                    "treasury": treasury_bal, "minted": minted,
                    "genesis": genesis,
                },
            ))
        return findings

    def check_econ2_collateral_backing(self, client: httpx.Client) -> list[FindingRecord]:
        """
        E2: Every active escrow entry must be backed by a real locked balance.
        Sum of individual escrow entries must match the aggregate lock total.

        Detects: phantom escrow entries, off-by-one on lock/release.
        """
        findings: list[FindingRecord] = []

        aggregate = self._sched_get(client, "/scheduler/escrow_total")
        entries   = self._sched_get(client, "/scheduler/escrow_entries")
        if aggregate is None or entries is None:
            return findings

        reported_total = aggregate.get("total_locked_uqcb", 0)
        computed_total = sum(
            e.get("locked_uqcb", 0)
            for e in entries.get("entries", [])
            if e.get("status") == "locked"
        )

        if abs(reported_total - computed_total) > 0:
            findings.append(self._finding(
                inv=4,
                title="Escrow aggregate total mismatches sum of entries",
                severity=Severity.HIGH,
                steps=[
                    "Poll /scheduler/escrow_total (aggregate)",
                    "Poll /scheduler/escrow_entries (per-entry)",
                    "Sum locked entries; compare to aggregate",
                ],
                expected="Aggregate total == sum of locked entries",
                actual=f"reported={reported_total}, computed={computed_total}, delta={reported_total - computed_total}",
                evidence={"reported": reported_total, "computed": computed_total},
            ))
        return findings

    def check_econ3_fee_accounting(self, client: httpx.Client) -> list[FindingRecord]:
        """
        E3: Fees collected in a block must match the sum of gas_used × gas_price
        for all txs in that block.  Checks the last finalised block only.

        Detects: fee bypass, incorrect gas accounting, fee skimming.
        """
        findings: list[FindingRecord] = []

        block_data = self._node_get(client, "/block")   # latest block
        if block_data is None:
            return findings

        block = block_data.get("result", {}).get("block", {})
        header = block.get("header", {})
        block_height = header.get("height", "?")

        fee_summary = self._node_get(client, f"/qcb/resource/block_fees?height={block_height}")
        if fee_summary is None:
            return findings

        reported_fees  = fee_summary.get("total_fees_uqcb", 0)
        tx_fee_total   = sum(
            t.get("gas_used", 0) * t.get("gas_price", 0)
            for t in fee_summary.get("txs", [])
        )

        if reported_fees != tx_fee_total and tx_fee_total > 0:
            findings.append(self._finding(
                inv=None,
                title="Block fee accounting mismatch",
                severity=Severity.HIGH,
                steps=[
                    f"Poll /block (latest height={block_height})",
                    f"Poll /qcb/resource/block_fees?height={block_height}",
                    "Compare reported_fees to sum(gas_used × gas_price)",
                ],
                expected="reported_fees == sum(gas_used × gas_price)",
                actual=f"reported={reported_fees}, computed={tx_fee_total}",
                evidence={"height": block_height, "reported": reported_fees, "computed": tx_fee_total},
            ))
        return findings

    # -----------------------------------------------------------------------
    # Gossip message uniqueness and ordering invariants
    # -----------------------------------------------------------------------

    def check_gossip1_message_uniqueness(self, client: httpx.Client) -> list[FindingRecord]:
        """
        G1: No two distinct gossip messages with the same (job_id, output_hash,
        topic) pair should both appear as credited in the gossip log.

        Detects: dedup failure, equivocation credit, hash collision admission.
        """
        findings: list[FindingRecord] = []
        data = self._sched_get(client, "/scheduler/gossip_log")
        if data is None:
            return findings

        seen: dict[tuple, list[dict]] = {}
        for msg in data.get("messages", []):
            if not msg.get("credited"):
                continue
            key = (msg.get("job_id"), msg.get("output_hash"), msg.get("topic"))
            seen.setdefault(key, []).append(msg)

        for key, msgs in seen.items():
            if len(msgs) > 1:
                findings.append(self._finding(
                    inv=6,
                    title="Duplicate (job_id, output_hash, topic) credited in gossip log",
                    severity=Severity.CRITICAL,
                    steps=[
                        "Poll /scheduler/gossip_log",
                        "Group credited messages by (job_id, output_hash, topic)",
                        f"Found {len(msgs)} entries for key={key}",
                    ],
                    expected="At most one credited entry per (job_id, output_hash, topic)",
                    actual=f"{len(msgs)} credited entries for key={key}",
                    evidence={"key": str(key), "entries": msgs},
                ))
        return findings

    def check_gossip2_causal_ordering(self, client: httpx.Client) -> list[FindingRecord]:
        """
        G2: A VerifierAttestation must not be credited before the corresponding
        DiscoveryProof appears in the gossip log for the same job_id.

        Detects: out-of-order credit, missing discovery receipt.
        """
        findings: list[FindingRecord] = []
        data = self._sched_get(client, "/scheduler/gossip_log")
        if data is None:
            return findings

        msgs = data.get("messages", [])
        discovery_jobs: set[str] = {
            m["job_id"] for m in msgs
            if m.get("topic") == "DiscoveryProof" and m.get("credited")
        }
        for msg in msgs:
            if (
                msg.get("topic") == "VerifierAttestation"
                and msg.get("counted_toward_quorum")
                and msg.get("job_id") not in discovery_jobs
            ):
                findings.append(self._finding(
                    inv=2,
                    title="VerifierAttestation counted with no prior DiscoveryProof",
                    severity=Severity.HIGH,
                    steps=[
                        "Poll /scheduler/gossip_log",
                        f"Find VerifierAttestation for job_id={msg.get('job_id')} with no DiscoveryProof",
                    ],
                    expected="DiscoveryProof must precede any VerifierAttestation credit",
                    actual=f"job_id={msg.get('job_id')} has attestation but no discovery proof",
                    evidence={"attestation": msg},
                ))
        return findings

    def check_gossip3_no_equivocation_credit(self, client: httpx.Client) -> list[FindingRecord]:
        """
        G3: For a given job_id, at most one distinct output_hash may be credited
        across all DiscoveryProof messages.  Multiple credited output_hashes for
        the same job indicates equivocation was not penalised.
        """
        findings: list[FindingRecord] = []
        data = self._sched_get(client, "/scheduler/gossip_log")
        if data is None:
            return findings

        job_hashes: dict[str, set[str]] = {}
        for msg in data.get("messages", []):
            if msg.get("topic") != "DiscoveryProof" or not msg.get("credited"):
                continue
            jid = msg.get("job_id", "")
            oh  = msg.get("output_hash", "")
            job_hashes.setdefault(jid, set()).add(oh)

        for job_id, hashes in job_hashes.items():
            if len(hashes) > 1:
                findings.append(self._finding(
                    inv=1,
                    title="Equivocating machine credited for multiple output_hashes",
                    severity=Severity.CRITICAL,
                    steps=[
                        "Poll /scheduler/gossip_log",
                        f"Filter DiscoveryProof messages for job_id={job_id}",
                        "Count distinct credited output_hashes",
                    ],
                    expected="At most one output_hash credited per job",
                    actual=f"{len(hashes)} hashes credited for job_id={job_id}: {hashes}",
                    evidence={"job_id": job_id, "credited_hashes": list(hashes)},
                ))
        return findings

    # -----------------------------------------------------------------------
    # Validator / controller set transition invariants
    # -----------------------------------------------------------------------

    def check_validator1_set_continuity(self, client: httpx.Client) -> list[FindingRecord]:
        """
        V1: The active validator set must not change by more than 1/3 between
        consecutive blocks (safety threshold for BFT).

        Detects: sudden validator set replacement, eclipse-style attacks.
        """
        findings: list[FindingRecord] = []

        cur  = self._node_get(client, "/validators")
        prev = getattr(self, "_prev_validators", None)

        validators = cur.get("result", {}).get("validators", []) if cur else []
        cur_set    = {v.get("address") for v in validators}

        if prev is not None and len(prev) > 0:
            removed = len(prev - cur_set)
            frac    = removed / len(prev)
            if frac > 1 / 3:
                findings.append(self._finding(
                    inv=None,
                    title="Validator set changed by > 1/3 between polls",
                    severity=Severity.CRITICAL,
                    steps=[
                        "Poll /validators at time T",
                        "Poll /validators at time T+poll_interval",
                        f"Compute fraction removed = {removed}/{len(prev)} = {frac:.2f}",
                    ],
                    expected="≤ 1/3 of validator set replaced per epoch boundary",
                    actual=f"{removed} of {len(prev)} validators removed ({frac:.0%})",
                    evidence={"removed": list(prev - cur_set), "remaining": list(cur_set)},
                ))

        self._prev_validators = cur_set
        return findings

    def check_validator2_no_unbonded_signing(self, client: httpx.Client) -> list[FindingRecord]:
        """
        V2: A controller that has been deregistered or whose bond has expired
        must not appear as a signer or verifier in any recent attestation.

        Detects: stale-key signing, bond-expiry bypass.
        """
        findings: list[FindingRecord] = []

        unbonded = self._node_get(client, "/qcb/identity/unbonded_controllers")
        attests  = self._sched_get(client, "/scheduler/attestations")
        if unbonded is None or attests is None:
            return findings

        unbonded_ids: set[str] = {
            c.get("controller_id", "")
            for c in unbonded.get("controllers", [])
        }

        for attest in attests.get("attestations", []):
            ctrl = attest.get("verifier_controller_id", "")
            if ctrl in unbonded_ids and attest.get("counted_toward_quorum"):
                findings.append(self._finding(
                    inv=None,
                    title="Unbonded controller counted in quorum",
                    severity=Severity.CRITICAL,
                    steps=[
                        "Poll /qcb/identity/unbonded_controllers",
                        "Poll /scheduler/attestations",
                        f"Find attestation from unbonded controller={ctrl}",
                    ],
                    expected="Unbonded controllers cannot contribute to quorum",
                    actual=f"controller={ctrl} is unbonded but counted",
                    evidence={"controller": ctrl, "attestation": attest},
                ))
        return findings

    def check_validator3_quorum_threshold(self, client: httpx.Client) -> list[FindingRecord]:
        """
        V3: A job accepted as canonical (quorum_met=true) must have accumulated
        attestations from at least 2 distinct controllers.
        No quorum should be declared with fewer than 2 independent controllers
        regardless of the number of individual attestations.
        """
        findings: list[FindingRecord] = []

        jobs    = self._sched_get(client, "/scheduler/completed_jobs")
        attests = self._sched_get(client, "/scheduler/attestations")
        if jobs is None or attests is None:
            return findings

        # Build: job_id → set of distinct controllers that attested
        job_controllers: dict[str, set[str]] = {}
        for a in attests.get("attestations", []):
            if not a.get("counted_toward_quorum"):
                continue
            jid  = a.get("job_id", "")
            ctrl = a.get("verifier_controller_id", "")
            job_controllers.setdefault(jid, set()).add(ctrl)

        for job in jobs.get("jobs", []):
            if not job.get("quorum_met"):
                continue
            jid         = job.get("job_id", "")
            controllers = job_controllers.get(jid, set())
            if len(controllers) < 2:
                findings.append(self._finding(
                    inv=2,
                    title="Quorum declared with fewer than 2 independent controllers",
                    severity=Severity.CRITICAL,
                    steps=[
                        f"Poll /scheduler/completed_jobs — find job_id={jid} with quorum_met=true",
                        "Poll /scheduler/attestations — count distinct verifier_controller_ids",
                    ],
                    expected="quorum requires ≥ 2 distinct controller IDs",
                    actual=f"Only {len(controllers)} distinct controller(s): {controllers}",
                    evidence={"job_id": jid, "controllers": list(controllers)},
                ))
        return findings

    # -----------------------------------------------------------------------
    # Extend run_all to include the new checks
    # -----------------------------------------------------------------------

    def run_all(self, client: httpx.Client) -> list[FindingRecord]:  # type: ignore[override]
        all_findings = super().run_all(client)
        extended_checks = [
            self.check_econ1_total_supply_conserved,
            self.check_econ2_collateral_backing,
            self.check_econ3_fee_accounting,
            self.check_gossip1_message_uniqueness,
            self.check_gossip2_causal_ordering,
            self.check_gossip3_no_equivocation_credit,
            self.check_validator1_set_continuity,
            self.check_validator2_no_unbonded_signing,
            self.check_validator3_quorum_threshold,
        ]
        for check in extended_checks:
            try:
                all_findings.extend(check(client))
            except Exception as exc:
                print(f"[monitor] ERROR in {check.__name__}: {exc}", file=sys.stderr)
        return all_findings
