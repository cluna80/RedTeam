# QPC-CONS-001 Security Report

**Generated:** 2026-10-23T12:19:52.254828+00:00  
**Commit:** `c3a508a`  
**Chain ID:** `qcb-devnet-3node`  
**Devnet reachable:** True

## Test Summary

| Classification | Count |
|---|---|
| PASS | 4 |
| FAIL | 2 |
| NOT_TESTED | 3 |
| SIMULATED | 1 |

## Architectural Security Gaps

### QPC-GAP-001 (RESOLVED — Phase B): owner_identity_id now settable

`BondValidator` now accepts `owner_identity_id: Option<String>` (Phase B,
commit `fc1852b`). Bindings are authenticated (tx.sender == owner_identity_id,
active personhood credential required), stored durably via `state.set_raw()`,
survive restarts, and reject unauthorized ownership changes. Per-human cap
enforces `∑ voting_power ≤ power_cap` (not just validator count).

### QPC-GAP-002 (MEDIUM): Attestation requires coordinator centralization

Only `attestation_coordinator` (qcb1alice on devnet) can grant `pop_verified=true`.
The ZK-VRC multi-issuer path exists in `chain-forge-personhood` but is not wired
into the live validator admission flow.

## Test Results

| Test ID | Classification | Notes |
|---|---|---|
| QPC-A01 | PASS | Phase B live. Spoof rejected=True. h_before=4 h_after=5. |
| QPC-A02 | NOT_TESTED | Full adversarial test requires funded attacker wallets + coordinator cooperation |
| QPC-A03 | PASS | Phase B live. Change rejected=True. |
| QPC-A04 | FAIL | alice voting_power unchanged (1) after RevokeAttestation. |
| QPC-A05 | NOT_TESTED | qcb1test0000 in validator set: False. Full dual-binding recovery attack requires |
| QPC-A06 | FAIL | Second Attest accepted (no AlreadyAttested rejection): {'status': 'queued', 'tx_ |
| QPC-A07 | PASS | All 3 nodes agree on validator weights. |
| QPC-A08 | SIMULATED | Cannot force concurrent identity+transition timing from outside; passive observa |
| QPC-A09 | NOT_TESTED | Restart persistence tested separately in devnet restart-recovery test suite (tes |
| QPC-A10 | PASS | Phase B live. bob_rejected=True dave_rejected=True agg_power=0. |

## Invariant Oracle Results

- **QPC-I01** (PASS): Every validator with positive voting_power has pop_verified=true and a consensus key.
- **QPC-I02** (PASS): No validator's voting_power exceeds power_cap=1.
- **QPC-I03** (PASS): All nodes return identical effective validator weights.
- **QPC-I04** (NOT_TESTABLE): Revocation/recovery cannot create simultaneous independent power.
- **QPC-I05** (PASS): Total verified voting power >= BFT quorum threshold.
- **QPC-I06** (NOT_TESTABLE): RevokeAttestation tx type is available (restart persistence untested here).

## Conclusion

Phase B (`owner_identity_id` in `BondValidator`) was detected on the running chain. Tests QPC-A01, QPC-A03, and QPC-A10 exercised live adversarial transactions. See individual test results above for PASS/FAIL verdicts.

- **QPC-GAP-001** (RESOLVED (Phase B)): per-human cap enforcement via `owner_identity_id`.
- **QPC-GAP-002** (OPEN): attestation centralization (single coordinator on devnet).

> A PASS result on A01/A03/A10 confirms the invariant holds for the tested scenarios.
> QPC-GAP-002 remains open pending multi-issuer ZK-VRC wiring.