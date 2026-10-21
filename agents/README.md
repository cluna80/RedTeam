# QCB Chain — AI Red-Team Suite

Continuous, reproducible security probing for the `chain-forge-engine` devnet.

**Devnet only.** All agents refuse to start if the chain_id does not match
a recognised `devnet*` / `testnet*` / `localnet*` prefix.

---

## Directory layout

```
agents/
├── README.md                    ← you are here
├── run_suite.py                 ← top-level CLI runner
├── schema.py                    ← FindingRecord dataclass + JSON schema
├── devnet_guard.py              ← fail-closed devnet safety check
├── invariants.md                ← prose definitions of INV-1 … INV-10
│
├── agent1_tx_fuzzer.py          ← TxFuzzer            (stub)
├── agent2_economic.py           ← EconomicAttacker     (full)
├── agent3_gossip.py             ← GossipAdversary      (full)
├── agent4_sybil.py              ← SybilProbe           (stub)
├── agent5_invariant.py          ← InvariantMonitor     (full)
├── agent6_patch.py              ← PatchProposer        (stub → generates files)
│
├── config/
│   ├── devnet3.toml             ← Alice / Bob / Carol
│   └── devnet4.toml             ← Alice / Bob / Carol / Dave
│
├── findings/                    ← emitted JSON findings  (git-ignored in CI)
└── regressions/                 ← auto-generated failing tests (human review)
    └── test_regression_template.py
```

---

## Prerequisites

```bash
pip install httpx pytest
```

Python ≥ 3.11 (for `tomllib`).

---

## Quick start — 3-node devnet

### 1. Start the devnet

```bash
# From repo root — adapt to the actual devnet launch script:
./scripts/start_devnet3.sh
# or
cargo run -p chain-forge-node -- --devnet --nodes 3
```

Verify nodes are up:
```bash
curl http://127.0.0.1:26657/status | jq .result.node_info.network
# → "devnet-1" (or similar)
```

### 2. Run InvariantMonitor (continuous)

```bash
python agents/run_suite.py \
    --config agents/config/devnet3.toml \
    --agents 5
```

Or a single poll cycle for CI:
```bash
python agents/run_suite.py \
    --config agents/config/devnet3.toml \
    --agents 5 \
    --once
```

### 3. Run EconomicAttacker + GossipAdversary

```bash
python agents/run_suite.py \
    --config agents/config/devnet3.toml \
    --agents 2,3
```

### 4. Run the full suite

```bash
python agents/run_suite.py \
    --config agents/config/devnet3.toml \
    --agents 5,2,3,1,4 \
    --propose-patches
```

Findings land in `agents/findings/`; regression stubs in `agents/regressions/`.

---

## Quick start — 4-node devnet

Same commands, substituting `devnet4.toml`:

```bash
python agents/run_suite.py \
    --config agents/config/devnet4.toml \
    --agents 5,2,3
```

---

## Running regression tests

After findings are confirmed and regression stubs have been reviewed/adjusted:

```bash
# All devnet regressions:
pytest agents/regressions/ -m devnet -v

# Specific regression:
pytest agents/regressions/test_<slug>.py -v
```

Regressions **must fail** on an unpatched devnet and **pass** after a fix is applied.

---

## Finding format

Every finding is a JSON file in `agents/findings/` with this schema:

```json
{
  "finding_id":      "uuid4",
  "timestamp":       "2025-01-01T00:00:00+00:00",
  "agent":           "agent2_economic",
  "title":           "Double ClaimResearchReward accepted",
  "severity":        "critical",
  "invariant_id":    1,
  "steps":           ["step 1 …", "step 2 …"],
  "expected":        "Second claim rejected (duplicate settlement)",
  "actual":          "Second call returned status=200",
  "evidence":        { "receipt_id": "…", "first": {}, "second": {} },
  "regression_path": null
}
```

Severity levels: `critical` · `high` · `medium` · `low` · `info`

---

## Running individual agents

```bash
# Single economic attack category:
python agents/agent2_economic.py \
    --config agents/config/devnet3.toml \
    --attack A

# Single gossip attack:
python agents/agent3_gossip.py \
    --config agents/config/devnet3.toml \
    --attack G4

# InvariantMonitor — once:
python agents/agent5_invariant.py \
    --config agents/config/devnet3.toml \
    --once

# Generate patch proposals from all findings:
python agents/agent6_patch.py \
    --all-findings agents/findings/
```

---

## Implementing the stubs

### Agent 1 — TxFuzzer

Before coding, read:
- `chain-forge-execution/src/tx.rs` (tx envelope format)
- `chain-forge-execution/src/mempool.rs` (validation pipeline)
- `scripts/keys/` (devnet key fixtures for signing)

Use `broadcast_tx_sync` on the node RPC; check the `check_tx` result code.

### Agent 4 — SybilProbe

Before coding, read:
- `chain-forge-identity/src/registry.rs`
- `chain-forge-identity/src/attestation_guard.rs` (Phases A–D)

Use the testnet-hook endpoints only — guarded behind the `testnet-hooks`
feature flag in `chain-forge-identity/Cargo.toml`.

---

## Safety rules

1. **Never run against mainnet or any chain_id that looks like production.**
   `devnet_guard.py` enforces this at startup.

2. **Never weaken auth, identity, or quorum rules to make tests pass.**
   If a test fails because a rule is correct, the test needs updating.

3. **Never auto-merge PatchProposer output.**
   All files in `agents/regressions/` require human review before merge.

4. **Never commit `agents/findings/` to the main branch.**
   Add it to `.gitignore`; share findings via the issue tracker instead.

---

## CI integration

Add to your CI pipeline (after devnet launch):

```yaml
- name: InvariantMonitor (single cycle)
  run: |
    python agents/run_suite.py \
      --config agents/config/devnet3.toml \
      --agents 5 --once
  # Fails CI if any invariant is violated
```

---

## First live devnet red-team run — 2026-10-21

### Environment
- 3-node devnet: Alice/Bob/Dave, `chain-forge-node` v0.1.0
- chain_id: `qcb-devnet-3node`
- Agent 1 (TxFuzzer) against `POST /api/tx`

### Results: 27 findings → 14 remaining after fix

| Category | Initial | After fix | Status |
|----------|---------|-----------|--------|
| F2 field validation | 8 | 4 | Partially fixed |
| F3 gas cap | 4 | 1 | Mostly fixed |
| F4 body variants | 1 | 0 | ✅ Closed |
| F5 signature | 8 | 3 | Partially fixed |
| F1 nonce | 4 | 4 | Needs execution-layer state |
| F7 replay | 1 | 1 | Needs tx hash dedup in state |
| F8 unicode bomb | 1 | 1 | Open |

### Root cause (fixed)
`require_signatures: false` in devnet genesis caused the entire
ingress path to skip all validation — not just sig crypto.

### Fix applied to chain-forge-engine
`check_tx()` added to `chain-forge-execution/src/lib.rs`.
Runs unconditionally before any other gate. Enforces:
- sender non-empty
- gas_limit > 0 and <= block_gas_limit
- Ed25519 signature, if present, exactly 64 bytes
- ML-DSA-65 pq_signatures, if present, exactly 6586 hex chars
- Transfer: amount > 0, to non-empty with qcb1 prefix, denom non-empty
- Payload within max_tx_bytes (65536)

### Remaining 14 findings
All require account state and belong at execution layer:
nonce ordering, balance checks, tx replay dedup, sender→pubkey binding,
known denom validation, unicode denom handling.

### Round 3 results (after commit b7ecd22)

27 → 8 findings across 3 fix rounds. 19 closed.

| Category | R1 | R2 | R3 | Status |
|----------|----|----|----|--------|
| F3 Gas   | 4  | 1  | 0  | ✅ Clean |
| F4 Body  | 1  | 0  | 0  | ✅ Clean |
| F6       | 0  | 0  | 0  | ✅ Clean |
| F7 Replay| 1  | 1  | 0  | ✅ Clean |
| F8 Exhaustion | 1 | 1 | 0 | ✅ Clean |
| F2 Balance | 8 | 4 | 2 | Stateful — execution layer |
| F1 Nonce | 4  | 4  | 3  | Stateful — nonce tracking |
| F5 Sig/pubkey | 8 | 3 | 3 | Stateful — key binding |

Remaining 8 require account state and belong at execution layer.
Next: run agent5 (invariants) and agent7 (consensus) against live devnet.
