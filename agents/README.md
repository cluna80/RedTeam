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
