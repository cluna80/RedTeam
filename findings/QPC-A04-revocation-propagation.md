# QPC-A04: Revocation Propagation — Phase A Gap

**ID**: QPC-A04  
**Severity**: MEDIUM (Phase A documented gap; becomes HIGH when Phase C is not implemented before mainnet)  
**Status**: OPEN — Phase C not yet implemented  
**Discovered**: 2026-10-23 via Agent 9 live devnet run (commit 890b060)  
**Component**: `chain-forge-identity` + `chain-forge-execution`

---

## Summary

`RevokeAttestation` removes an attester's entry from the identity's attestation ledger
but does **not** downgrade the identity's verification tier or reduce their consensus
voting power. A validator who was verified via web-of-trust quorum retains full voting
power even after enough attestations are revoked to drop the count below quorum.

---

## Root Cause

`chain_forge_identity::IdentityStore::revoke_attestation()` (identity/src/lib.rs ~L1210):

```rust
if let Some(identity) = self.records.get_mut(attested_id) {
    identity.attestation_ledger.attesters.retain(|a| a != attester_id);
    // If removing this attestation drops the count below quorum AND
    // the identity is currently Verified solely because of this
    // quorum, it should be re-evaluated. For Phase A, we flag it
    // in the record only — full tier re-evaluation is Phase C scope.
}
```

The comment explicitly defers tier re-evaluation to Phase C. The function returns a
`RevocationCost` signal, but the executor (`chain-forge-execution/src/lib.rs` ~L2551)
only emits a CS cost event and never syncs the charm/tier back to the account state:

```rust
TxBody::RevokeAttestation { attested_id } => {
    identity.revoke_attestation(&tx.sender, attested_id)
        .map(|cost| {
            // Phase 0 / pilot: we emit the cost as an event …
            // Full CS deduction from the state store is wired up in a later phase.
            events.push(format!("revoke_attestation: … (cs_cost_bps={})"));
        })
        .map_err(|e| e.to_string())
}
```

Compare with `TxBody::Attest`, which **does** sync the charm:
```rust
if let (Ok(record), Ok(acct)) = (identity.get(claimant_id), state.get_account_mut(claimant_id)) {
    acct.attach_charm(record.charm.clone());
}
state.refresh_leaf(claimant_id);
```

`RevokeAttestation` has no equivalent `attach_charm` / `refresh_leaf` call.

---

## Security Impact

- An attester who is later found to have made a fraudulent attestation can have their
  attestation revoked, but the attested identity retains its Verified tier and full
  voting power.
- If `ATTESTATION_QUORUM = 3` and an identity accumulated exactly 3 attestations, any
  single revocation should drop them below quorum. With the current Phase A code, the
  identity remains Verified indefinitely.
- For Sybil resistance this matters: a human who obtained a Verified credential via a
  compromised or colluding attester set cannot have that credential revoked by revoking
  individual attestations.

---

## Reproduction (devnet)

```bash
# 1. Attest carol from alice (alice = coordinator)
POST /api/tx  {"sender":"qcb1alice","nonce":N,"body":{"Attest":{"claimant_id":"qcb1carol"}}}
# 2. Observe carol's tier (Provisional or Verified depending on prior state)
GET /api/identity/qcb1carol
# 3. Revoke alice's attestation of carol
POST /api/tx  {"sender":"qcb1alice","nonce":N+1,"body":{"RevokeAttestation":{"attested_id":"qcb1carol"}}}
# Wait for commit via GET /api/tx/{tx_id} until height > 0
# 4. Check carol's tier — unchanged despite revocation
GET /api/identity/qcb1carol
```

Agent 9 test QPC-A04 automates this sequence and emits `FINDING` on detection.

---

## Remediation

**Phase C implementation required** before mainnet:

1. After `revoke_attestation()` removes an attester from the ledger, check if
   `attestation_ledger.count() < ATTESTATION_QUORUM`.
2. If so, and the identity is `Verified` solely through the web-of-trust path
   (not via `verify_identity()` bypass), downgrade the charm to `Provisional`.
3. In the executor, after `RevokeAttestation` commits successfully, add:
   ```rust
   if let (Ok(record), Ok(acct)) = (identity.get(attested_id), state.get_account_mut(attested_id)) {
       acct.attach_charm(record.charm.clone());
   }
   state.refresh_leaf(attested_id);
   ```
4. Update `gate_voting_power()` to re-evaluate eligibility after charm downgrade.

**Do not merge into mainnet** with the Phase A limitation unaddressed.

---

## References

- `chain-forge-identity/src/lib.rs` L1192–1272 (`revoke_attestation`)
- `chain-forge-execution/src/lib.rs` L2551–2569 (`TxBody::RevokeAttestation`)
- Agent 9 test: `test_a04_revoked_credential` in `redteam/agents/agent9_qpc_consensus.py`
- PR #10: `feat/qpc-cons-001-phase-b-authenticated-binding`
