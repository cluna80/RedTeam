# Identity Pilot — Phase 2 Status Report
**Date:** 2026-10-22  
**Chain:** qcb-devnet-3node  
**Red-team suite:** github.com/cluna80/RedTeam (agent8_identity_pilot.py)

---

## What was demonstrated

### Security hardening (confirmed)
- Attestation guard Phases A–D: passing (65 tests in chain-forge-identity)
- ConfirmSybil coordinator gate: enforced — non-coordinator txs rejected at mempool ingress
- ReverseSybil coordinator gate: enforced
- Tx ingress (check_tx): 0 findings across F1–F8 after 6 fix rounds (27 → 0 stateless findings)
- Governance rate limiting: enforced (100 spam proposals → 0 accepted)
- DIS chain-ID binding regression (Phase B test B4): passing
- DIS challenge anti-replay: not testable (endpoint not yet on node)

### Bulk registration attack (I5)
- 100 identities submitted under a single controller
- 0 reached Verified tier
- Sybil rate: 0.0% against target < 3%

**Qualification:** `registered=0` — the RegisterIdentity tx path is not yet wired  
into execution. The 0/100 verified result reflects that no identity was admitted,  
not that 100 were admitted and all rejected at verification. This distinction matters.

---

## What is NOT yet demonstrated

| Gap | Blocker |
|-----|---------|
| Successful legitimate registration | RegisterIdentity not wired in execution |
| End-to-end sybil resistance | Needs legitimate registration to compare against |
| Verification cost < $5 | Needs real verification ceremony |
| Legitimate human verification flow | End-to-end not tested |
| DIS delegation validation | /api/dis/verify_delegated not implemented (Phase C) |
| Durable max_uses counter | In-memory only (Phase C) |

---

## Open red-team findings (4, all Phase C)

| ID | Finding | Severity | Blocker |
|----|---------|----------|---------|
| I9 | Delegation depth overflow (depth=5) | HIGH | /api/dis/verify_delegated missing |
| I10 | Delegation scope widening | HIGH | /api/dis/verify_delegated missing |
| I11 | max_uses not enforced durably | MEDIUM | In-memory only |
| I12 | Human-approval bypass | HIGH | /api/dis/verify_delegated missing |

---

## Recommended sequence before advancing to QPC-CONS-001

1. Wire RegisterIdentity into tx execution — confirm registration, state  
   persistence, and /api/identity/{address} queries across all 3 nodes
2. Implement /api/dis/verify_delegated — closes I9, I10, I12
3. Implement durable max_uses counter — closes I11
4. Rerun identity pilot — demonstrate legitimate enrollment succeeds while  
   duplicate/fraudulent identities fail for the expected reasons
5. Measure verification cost — run real ceremony, record cost per human
6. Only then: QPC-CONS-001 — personhood-to-consensus integration

---

## Classification

**Phase 2 partial gate result.**  
Security hardening confirmed. Registration and end-to-end pilot not yet complete.  
Do not advance to QPC-CONS-001 until steps 1–5 above are complete.
