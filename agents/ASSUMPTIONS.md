# Wire-format assumptions for Agent 1 and Agent 4

All assumptions below are marked **[ASSUMPTION]**.
When you're back at a laptop, grep the repo and fix any that are wrong.
Everything else in the agents is derived from the repo structure and whitepaper.

---

## Agent 1 — TxFuzzer

### Tx serialization  [ASSUMPTION: JSON over HTTP]
Inferred from: existing `scripts/pocd_miner.py` uses `requests.post(..., json=payload)`;
no `.proto` files visible in `chain-forge-execution/` at the top level.
If the real format is borsh or protobuf, update `TxEnvelope.encode()` only.

### Broadcast endpoint  [ASSUMPTION: POST /broadcast_tx_sync]
Standard Tendermint-compatible path. If QCB uses a custom path, update
`BROADCAST_ENDPOINT` in agent1_tx_fuzzer.py.

### Tx fields  [ASSUMPTION]
```
chain_id   : str
nonce      : u64
sender     : str   (bech32 qcb1...)
msg_type   : str   ("Transfer" | "ClaimResearchReward" | ...)
payload    : dict
gas_limit  : u64
signature  : hex str   (ML-DSA-65, 3293 bytes → 6586 hex chars)
pub_key    : hex str   (ML-DSA-65 public key, 1952 bytes → 3904 hex chars)
```
Grep to verify: `grep -n "struct.*Tx\|pub chain_id\|pub nonce\|pub sender" chain-forge-execution/src/tx.rs`

### ML-DSA variant  [ASSUMPTION: ML-DSA-65 (Dilithium3)]
Inferred from crate name `chain-forge-vca-pq` (post-quantum) and `chain-forge-wallet`.
Grep: `grep -rn "ml_dsa\|dilithium\|Dilithium" chain-forge-wallet/src/`

### Rejection signal  [ASSUMPTION: check_tx.code != 0 in 200 response]
Standard Tendermint pattern. If QCB wraps errors differently, update `_check_tx_rejected()`.

---

## Agent 4 — SybilProbe

### Identity registration endpoint  [ASSUMPTION: POST /identity/register]
Inferred from crate `chain-forge-identity` and REST pattern in other agents.
Grep: `grep -rn "route\|post\|Router\|register" chain-forge-identity/src/`

### Controller binding  [ASSUMPTION: controller_id field on IdentityRecord]
Grep: `grep -n "controller\|Controller" chain-forge-identity/src/registry.rs`

### Attestation guard phases A–D  [ASSUMPTION: function names phase_a..phase_d or guard_phase]
Inferred from system context doc ("attestation guard Phases A–D").
Grep: `grep -n "phase\|Phase\|guard" chain-forge-identity/src/attestation_guard.rs`

### Revocation cooldown  [ASSUMPTION: 1 epoch = configurable, default 10 blocks]
Grep: `grep -n "cooldown\|COOLDOWN\|revoke_delay" chain-forge-identity/src/`

### Testnet hooks feature flag  [ASSUMPTION: feature = "testnet-hooks" in Cargo.toml]
Grep: `grep -n "testnet\|hooks\|feature" chain-forge-identity/Cargo.toml`

### Personhood / identity registry endpoint  [ASSUMPTION: /identity/... REST prefix]
May be /personhood/... based on crate `chain-forge-personhood`.
Grep: `grep -rn "Router\|route\|axum\|actix" chain-forge-identity/src/main.rs chain-forge-personhood/src/`
