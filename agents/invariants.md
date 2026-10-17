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
