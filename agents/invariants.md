# QCB Chain Red-Team — Invariant Definitions

These 10 invariants are monitored continuously by Agent 5 (InvariantMonitor)
and referenced in all finding records via `invariant_id`.

---

## INV-1: No double payment per receipt/job

A given `receipt_id` or `job_id` MUST result in at most one successful
reward emission, escrow release, or research-claim credit.

**Source**: `chain-forge-execution` duplicate-settlement rejection;
`chain-forge-pocd` DiscoveryReceipt dedup.

---

## INV-2: No reward without valid seal + quorum

`$QCB` / `uQCB` rewards MUST NOT be credited unless:
- A SHA-256 Useful Hash Commitment (seal) is present and verifies against
  the submitted output hash, AND
- A quorum of ≥ 2 independent verifiers (distinct controllers) has attested
  the seal.

**Source**: Change Set S `GossipTopic::VerifierAttestation`; scheduler
`accept_task_canonical` gate.

---

## INV-3: Self-controller verification never counts

An attestation from a verifier whose `controller_id` matches the miner's
`controller_id` MUST be discarded and MUST NOT count toward quorum.

**Source**: Change Set S anti-self-dealing check.

---

## INV-4: Escrow only releases on valid completion

Escrow funds MUST remain locked until `accept_task_canonical` is called with
a verified receipt. Neither timeout nor manual call bypasses verification.
Refund path MUST only activate on explicit cancellation or expiry, not
"completion".

**Source**: `chain-forge-resource` escrow lock/release/refund negative paths.

---

## INV-5: Unauthorized research claims rejected

Only the account that submitted the original `DiscoveryReceipt` (or a
delegated claimer) MAY call `ClaimResearchReward` for that receipt.

**Source**: `chain-forge-pocd` spend limits and auth guard.

---

## INV-6: Gossip replay does not re-credit

A `GossipTopic::DiscoveryProof` or `GossipTopic::VerifierAttestation`
replayed after the anti-replay window (see `gossip_replay_window`) MUST
be dropped by all nodes; no additional credit MAY accrue.

**Source**: Change Sets R and S anti-replay guards.

---

## INV-7: Personhood influence caps hold

No single identity (verified person / controller) may accumulate reward
influence beyond the configured epoch cap, even by submitting many receipts
quickly.

**Source**: `chain-forge-identity` epoch/resource caps.

---

## INV-8: Epoch/resource caps not bypassable by spam

Submitting a burst of tasks, receipts, or attestations in excess of the
per-epoch quota MUST result in the excess being rejected, not silently
admitted after queue drain.

**Source**: `chain-forge-scheduler` + `chain-forge-resource` rate limits.

---

## INV-9: Wrong chain_id always dropped

Any transaction, gossip message, or API call carrying a `chain_id` that
does not match the node's configured chain MUST be rejected before state
mutation. No partial application.

**Source**: `chain-forge-consensus` chain-ID binding; `chain-forge-p2p`
message validation.

---

## INV-10: Stale attestations never reach quorum

A `VerifierAttestation` whose timestamp precedes `now - gossip_replay_window`
MUST be rejected during quorum counting, even if it passed initial gossip
validation.

**Source**: Change Set S timestamp guard + scheduler quorum gate.

---

## INV-11: AttestEntity requires unique, non-self controller

A Phase-A `AttestEntity` on-chain transaction MUST be rejected if the
`attester_controller` matches the `subject_controller`.  A controller cannot
attest its own identity.  Each `(attester, subject)` pair MAY attest at most
once per epoch; a second submission for the same pair MUST be rejected.

**Source**: Attestation guard Phase A on-chain validation.

---

## INV-12: RevokeAttestation cannot re-verify without fresh Phase A

Once a `RevokeAttestation` tx is confirmed for an `entity_id`, that entity's
`pop_verified` flag MUST become false.  A subsequent `ConfirmSybil` or reward
event for that entity MUST be rejected until a new `AttestEntity` tx completes
the full Phase A cycle again.

**Source**: Attestation guard Phase B + personhood module revocation path.

---

## INV-13: ConfirmSybil freezes entity before any further reward

A `ConfirmSybil` on-chain transaction (Phase C) MUST atomically freeze the
target entity so that no reward emission, escrow release, or influence event
can occur for that entity from the moment the tx is included in a block.
The freeze MUST persist until `ReverseSybil` is confirmed (Phase D reverse
path).

**Source**: Attestation guard Phase C freeze gate.

---

## INV-14: ReportSuspectedSybil cannot be abused to grief honest nodes

`ReportSuspectedSybil` MUST NOT immediately freeze or penalise the target.
The target's `pop_verified` status and reward eligibility MUST remain
unchanged until a `ConfirmSybil` is issued.  An entity MUST NOT be frozen
solely on the basis of unconfirmed reports.

**Source**: Attestation guard Phase D report handling.

---

## INV-15: Identity pilot sybil rate stays below 3 %

Across all active `pop_verified` entities tracked by the identity pilot, the
fraction that are subsequently flagged by `ConfirmSybil` MUST remain below
3 % per epoch.  Exceeding this threshold indicates the attestation guard
is insufficiently screening entrants and MUST trigger an alert.

**Source**: Identity pilot target: `<3 % sybil rate` (ROADMAP Q1 provisional).
