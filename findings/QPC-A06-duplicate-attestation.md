# QPC-A06: Duplicate Attestation — AlreadyAttested Guard Confirmed

**ID**: QPC-A06  
**Severity**: NONE (not a vulnerability — guard correctly enforced)  
**Status**: CLOSED — properly defended  
**Discovered**: 2026-10-23 via Agent 9 live devnet run (commit 890b060)  
**Component**: `chain-forge-identity`

---

## Summary

Duplicate `Attest` transactions (same attester, same target) are idempotent at the
identity layer. The `identity.attest()` function returns `Err(AlreadyAttested)` if the
attester has an existing active record for the target, the executor propagates this as
a tx execution failure, and no additional quorum count or voting influence is created.

**Duplicate attestations cannot increase credential confidence, voting eligibility, or
effective influence.**

---

## Code Confirmation

`chain_forge_identity::IdentityStore::attest()` (identity/src/lib.rs ~L1117):

```rust
if claimant.attestation_ledger.has_attested(attester_id) {
    return Err(IdentityError::AlreadyAttested(attester_id.to_string()));
}
```

This check runs before any ledger mutation, before any quorum check, and before the
`AttestationRecord` is written. A second call from the same `(attester_id, claimant_id)`
pair fails immediately.

---

## Previous FAIL Cause

The earlier A06 FAIL was a **test infrastructure bug**, not a protocol bug:

1. Agent 9 sent two `Attest` txs with the same nonce (both fetched `alice.nonce` before
   either committed → same nonce value).
2. The mempool rejected attest2 for nonce mismatch (not `AlreadyAttested`).
3. Agent 9 classified the mempool's queued/rejected response as the verdict without
   waiting for execution — so the error detail was lost in noise.

The nonce race was fixed by waiting for attest1 to commit before fetching the nonce for
attest2. The test now uses `_wait_tx_result()` to confirm the execution-level result.

---

## Test Status

Agent 9 test `test_a06_proof_replay` now:

1. Sends `Attest alice→carol` (nonce=N), waits for block commit.
2. Fetches fresh nonce (N+1), sends second `Attest alice→carol`.
3. Calls `_wait_tx_result()` to get the execution result (not just mempool queue status).
4. Classifies `PASS` when the execution result shows rejection with `AlreadyAttested`.

Expected outcome on a clean devnet run: **PASS**.

---

## References

- `chain-forge-identity/src/lib.rs` L1117–1119 (`AlreadyAttested` guard)
- Agent 9 test: `test_a06_proof_replay` in `redteam/agents/agent9_qpc_consensus.py`
- PR #10: `feat/qpc-cons-001-phase-b-authenticated-binding`
