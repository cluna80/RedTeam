# QPC-CONS-001 Security Report

**Generated:** 2026-10-23T10:59:52.368445+00:00  
**Commit:** `e7fbd5a`  
**Chain ID:** `localnet-unsafe-override`  
**Devnet reachable:** False

## Test Summary

| Classification | Count |
|---|---|
| PASS | 0 |
| FAIL | 0 |
| NOT_TESTED | 10 |
| SIMULATED | 0 |

## Architectural Security Gaps

### QPC-GAP-001 (HIGH): owner_identity_id not settable via tx API

`BondValidator{amount}` hardcodes `owner_identity_id=None`. Every post-genesis
validator is treated as its own human. The per-human cap enforcement in
`build_validator_set()` is correct Rust code but is never triggered because the
binding is never set. An attacker can register N validators (each with a different
address) and accumulate N units of voting power.

**Location:** `chain-forge-execution/src/lib.rs:2112-2123`  
**Fix:** Add `owner_identity_id: Option<String>` to `BondValidator` tx body.

### QPC-GAP-002 (MEDIUM): Attestation requires coordinator centralization

Only `attestation_coordinator` (qcb1alice on devnet) can grant `pop_verified=true`.
The ZK-VRC multi-issuer path exists in `chain-forge-personhood` but is not wired
into the live validator admission flow.

## Test Results

| Test ID | Classification | Notes |
|---|---|---|
| QPC-A01 | NOT_TESTED | devnet unreachable |
| QPC-A02 | NOT_TESTED | devnet unreachable |
| QPC-A03 | NOT_TESTED | devnet unreachable |
| QPC-A04 | NOT_TESTED | devnet unreachable |
| QPC-A05 | NOT_TESTED | devnet unreachable |
| QPC-A06 | NOT_TESTED | devnet unreachable |
| QPC-A07 | NOT_TESTED | devnet unreachable |
| QPC-A08 | NOT_TESTED | devnet unreachable |
| QPC-A09 | NOT_TESTED | devnet unreachable |
| QPC-A10 | NOT_TESTED | devnet unreachable |

## Conclusion

The protocol's per-human voting-power cap is correctly implemented in Rust but
the wire path (`owner_identity_id` in `BondValidator`) required to activate it
for post-genesis validators is absent. This is the primary security gap.
Genesis validators (alice/bob/dave) each carry `voting_power=1` as expected.

> A zero-findings report does not imply complete security coverage.
> QPC-GAP-001 and QPC-GAP-002 remain open items.