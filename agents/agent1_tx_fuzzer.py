#!/usr/bin/env python3
"""
agents/agent1_tx_fuzzer.py — TxFuzzer (full implementation)

Broadcasts malformed and borderline transactions against the QCB node
execution layer on a local devnet.

## Wire-format
JSON envelope over HTTP POST /broadcast_tx_sync, matching the pattern
in scripts/pocd_miner.py.  See ASSUMPTIONS.md for substitution points
if the real format differs.

## Attack categories
  F1  Nonce       — zero, max-u64, gap, negative, wrong type, replay
  F2  Balance     — overspend, zero, negative, self-send, bad recipient
  F3  Gas         — zero, one, u64_max, above block cap, null, float
  F4  Chain-ID    — empty, wrong, numeric, null, unicode injection, huge
  F5  Signature   — truncated, zeroed, bit-flip, wrong key, null, non-hex
  F6  Tx variant  — unknown msg_type, null payload, extra fields, deeply nested
  F7  Replay      — broadcast, wait for confirm, resubmit identical tx
  F8  Exhaustion  — 1 MB memo, 10 k-key payload, depth-500 nesting

Liveness is checked before and after all attacks; a crash is itself a finding.

Usage:
    python agents/agent1_tx_fuzzer.py --config agents/config/devnet3.toml
    python agents/agent1_tx_fuzzer.py --config agents/config/devnet3.toml --attack F5
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
import time
import uuid
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.schema import AgentId, FindingRecord, Severity
from agents.devnet_guard import assert_devnet, load_config, abort
from agents.observability import StructuredLogger

log = StructuredLogger("agent1_tx_fuzzer")

# ---------------------------------------------------------------------------
# Constants
# [ASSUMPTION] Update these if the real values differ — see ASSUMPTIONS.md
# ---------------------------------------------------------------------------

U64_MAX = 2**64 - 1

# [ASSUMPTION] Tendermint-compatible broadcast endpoint
BROADCAST_ENDPOINT = "/broadcast_tx_sync"

# [ASSUMPTION] Block gas cap — read from genesis or node config if exposed
BLOCK_GAS_CAP = 10_000_000

# [ASSUMPTION] ML-DSA-65 sizes in bytes → hex chars
# Real sig len: 3293 bytes = 6586 hex chars
# Real pubkey:  1952 bytes = 3904 hex chars
# Using shorter placeholders here; the node rejects on structural grounds
# regardless of exact length once the hex is invalid.
_VALID_SIG_HEX_LEN  = 6586   # [ASSUMPTION] adjust to actual param set
_VALID_KEY_HEX_LEN  = 3904   # [ASSUMPTION] adjust to actual param set

_PLACEHOLDER_SIG = "ab" * (_VALID_SIG_HEX_LEN // 2)
_PLACEHOLDER_KEY = "cd" * (_VALID_KEY_HEX_LEN // 2)
_ZERO_SIG        = "00" * (_VALID_SIG_HEX_LEN // 2)
_ZERO_KEY        = "00" * (_VALID_KEY_HEX_LEN // 2)
_WRONG_KEY_SIG   = "ef" * (_VALID_SIG_HEX_LEN // 2)   # signed with a different key
_WRONG_KEY       = "fe" * (_VALID_KEY_HEX_LEN // 2)

# ---------------------------------------------------------------------------
# TxEnvelope
# [ASSUMPTION] Field names match chain-forge-execution/src/tx.rs
# ---------------------------------------------------------------------------

@dataclass
class TxEnvelope:
    chain_id:  Any = "devnet"          # str normally
    nonce:     Any = 1                 # u64 normally
    sender:    Any = ""                # bech32 qcb1... normally
    msg_type:  Any = "Transfer"        # str normally
    payload:   Any = field(default_factory=dict)
    gas_limit: Any = 100_000           # u64 normally
    signature: Any = _PLACEHOLDER_SIG  # hex str normally
    pub_key:   Any = _PLACEHOLDER_KEY  # hex str normally

    def as_dict(self) -> dict:
        return {
            "chain_id":  self.chain_id,
            "nonce":     self.nonce,
            "sender":    self.sender,
            "msg_type":  self.msg_type,
            "payload":   self.payload,
            "gas_limit": self.gas_limit,
            "signature": self.signature,
            "pub_key":   self.pub_key,
        }

    def encode(self) -> dict:
        """
        Return the HTTP request body for broadcast_tx_sync.

        [ASSUMPTION] JSON body.  If borsh/protobuf:
            raw = borsh_serialize(self.as_dict())
            return {"tx": base64.b64encode(raw).decode()}
        """
        return {"tx": self.as_dict()}

    def mutate(self, **overrides: Any) -> "TxEnvelope":
        d = self.as_dict()
        d.update(overrides)
        return TxEnvelope(**d)


def _base_tx(cfg: dict[str, Any]) -> TxEnvelope:
    return TxEnvelope(
        chain_id  = "devnet",
        nonce     = 1,
        sender    = cfg["accounts"]["alice"],
        msg_type  = "Transfer",
        payload   = {"recipient": cfg["accounts"]["bob"], "amount": 1},
        gas_limit = 100_000,
        signature = _PLACEHOLDER_SIG,
        pub_key   = _PLACEHOLDER_KEY,
    )


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _broadcast(
    client: httpx.Client,
    node_url: str,
    tx: TxEnvelope,
    timeout: float = 15.0,
) -> tuple[int, dict]:
    try:
        r = client.post(
            f"{node_url}{BROADCAST_ENDPOINT}",
            json=tx.encode(),
            timeout=timeout,
        )
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text[:500]}
        return r.status_code, body
    except httpx.TimeoutException:
        return 0, {"error": "timeout"}
    except Exception as exc:
        return 0, {"error": str(exc)}


def _check_tx_rejected(status: int, body: dict) -> bool:
    """
    Return True if the node correctly rejected the tx.

    [ASSUMPTION] Tendermint pattern: 200 + check_tx.code != 0, or HTTP 4xx.
    If QCB uses a different rejection signal, update here only.
    """
    if status in (400, 401, 403, 422):
        return True
    if status == 200:
        code = (
            body.get("check_tx", {}).get("code")
            or body.get("result", {}).get("check_tx", {}).get("code")
            or body.get("code")
        )
        if code not in (None, 0):
            return True
    return False


def _node_alive(client: httpx.Client, node_url: str, timeout: float = 5.0) -> bool:
    try:
        r = client.get(f"{node_url}/status", timeout=timeout)
        return r.status_code == 200
    except Exception:
        return False


def _finding(
    inv: int | None,
    title: str,
    severity: Severity,
    steps: list[str],
    expected: str,
    actual: str,
    evidence: dict,
) -> FindingRecord:
    return FindingRecord(
        agent=AgentId.TX_FUZZER,
        title=title,
        severity=severity,
        invariant_id=inv,
        steps=steps,
        expected=expected,
        actual=actual,
        evidence=evidence,
    )


def _fuzz_matrix(
    client: httpx.Client,
    node_url: str,
    category: str,
    cases: list[tuple[str, TxEnvelope]],
    inv: int | None = None,
) -> list[FindingRecord]:
    """Run all (label, tx) cases; emit a finding for each that isn't rejected."""
    findings: list[FindingRecord] = []
    for label, tx in cases:
        s, b = _broadcast(client, node_url, tx)
        rejected = _check_tx_rejected(s, b)
        if rejected:
            log.info(f"[{category}] {label}: rejected ✓")
        else:
            log.warn(f"[{category}] {label}: ACCEPTED — status={s}")
            f = _finding(
                inv=inv,
                title=f"[{category}] Bad tx accepted: {label}",
                severity=Severity.CRITICAL,
                steps=[
                    f"Construct tx with mutation: {label}",
                    f"POST {node_url}{BROADCAST_ENDPOINT}",
                    f"Response status={s}",
                ],
                expected="Node rejects malformed/invalid tx at check_tx",
                actual=f"status={s}, body={json.dumps(b)[:400]}",
                evidence={"label": label, "tx": tx.as_dict(), "response": b},
            )
            findings.append(f)
            log.finding(f)
    return findings


# ---------------------------------------------------------------------------
# F1 — Nonce edge cases
# ---------------------------------------------------------------------------

def attack_f1_nonce(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    node = cfg["nodes"]["rpc_urls"][0]
    base = _base_tx(cfg)

    cases: list[tuple[str, TxEnvelope]] = [
        ("nonce=0",          base.mutate(nonce=0)),
        ("nonce=U64_MAX",    base.mutate(nonce=U64_MAX)),
        ("nonce=-1",         base.mutate(nonce=-1)),
        ("nonce=gap+1000",   base.mutate(nonce=1_001)),   # gap: current is 1
        ("nonce=float",      base.mutate(nonce=1.5)),
        ("nonce=str",        base.mutate(nonce="one")),
        ("nonce=null",       base.mutate(nonce=None)),
    ]
    findings = _fuzz_matrix(client, node, "F1-nonce", cases)

    # Replay: broadcast, wait for block, resubmit identical bytes
    log.info("[F1-nonce] testing replay after confirm…")
    unique_nonce = (int(time.time()) % 50_000) + 100_000
    replay_tx = base.mutate(nonce=unique_nonce)
    s1, b1 = _broadcast(client, node, replay_tx)
    log.info(f"[F1-nonce] first broadcast", status=s1)
    time.sleep(4)   # wait for inclusion
    s2, b2 = _broadcast(client, node, replay_tx)   # identical
    if not _check_tx_rejected(s2, b2):
        f = _finding(
            inv=1,
            title="[F1] Replay of confirmed tx accepted",
            severity=Severity.CRITICAL,
            steps=[
                f"Broadcast tx nonce={unique_nonce}, wait 4 s for block inclusion",
                "Resubmit identical tx bytes",
            ],
            expected="Replay rejected (tx hash / nonce already in state)",
            actual=f"status={s2}, body={json.dumps(b2)[:300]}",
            evidence={"nonce": unique_nonce, "first_resp": b1, "replay_resp": b2},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info("[F1-nonce] replay correctly rejected ✓", status=s2)

    return findings


# ---------------------------------------------------------------------------
# F2 — Balance edge cases
# ---------------------------------------------------------------------------

def attack_f2_balance(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    node = cfg["nodes"]["rpc_urls"][0]
    base = _base_tx(cfg)
    alice = cfg["accounts"]["alice"]
    bob   = cfg["accounts"]["bob"]

    # Best-effort balance query; fall back to a safe large value
    # [ASSUMPTION] balance query endpoint
    try:
        r = client.get(
            f"{cfg['nodes']['api_urls'][0]}/qcb/resource/balance?account={alice}",
            timeout=5.0,
        )
        balance = r.json().get("balance", 10_000_000)
    except Exception:
        balance = 10_000_000

    cases: list[tuple[str, TxEnvelope]] = [
        ("amount=0",              base.mutate(payload={"recipient": bob, "amount": 0})),
        ("amount=balance+1",      base.mutate(payload={"recipient": bob, "amount": balance + 1})),
        ("amount=U64_MAX",        base.mutate(payload={"recipient": bob, "amount": U64_MAX})),
        ("amount=-1",             base.mutate(payload={"recipient": bob, "amount": -1})),
        ("amount=float",          base.mutate(payload={"recipient": bob, "amount": 0.5})),
        ("recipient=sender",      base.mutate(payload={"recipient": alice, "amount": 1})),
        ("recipient=empty",       base.mutate(payload={"recipient": "", "amount": 1})),
        ("recipient=not-bech32",  base.mutate(payload={"recipient": "0xdeadbeef", "amount": 1})),
        ("recipient=null",        base.mutate(payload={"recipient": None, "amount": 1})),
        ("no-recipient-field",    base.mutate(payload={"amount": 1})),
    ]
    return _fuzz_matrix(client, node, "F2-balance", cases)


# ---------------------------------------------------------------------------
# F3 — Gas edge cases
# ---------------------------------------------------------------------------

def attack_f3_gas(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    node = cfg["nodes"]["rpc_urls"][0]
    base = _base_tx(cfg)

    cases: list[tuple[str, TxEnvelope]] = [
        ("gas=0",              base.mutate(gas_limit=0)),
        ("gas=1",              base.mutate(gas_limit=1)),
        ("gas=U64_MAX",        base.mutate(gas_limit=U64_MAX)),
        ("gas=block_cap+1",    base.mutate(gas_limit=BLOCK_GAS_CAP + 1)),
        ("gas=-1",             base.mutate(gas_limit=-1)),
        ("gas=float",          base.mutate(gas_limit=1.5)),
        ("gas=null",           base.mutate(gas_limit=None)),
        ("gas=string",         base.mutate(gas_limit="infinite")),
    ]
    return _fuzz_matrix(client, node, "F3-gas", cases)


# ---------------------------------------------------------------------------
# F4 — Chain-ID mutations  (INV-9)
# ---------------------------------------------------------------------------

def attack_f4_chain_id(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    node = cfg["nodes"]["rpc_urls"][0]
    base = _base_tx(cfg)

    cases: list[tuple[str, TxEnvelope]] = [
        ("chain_id=empty",        base.mutate(chain_id="")),
        ("chain_id=mainnet",      base.mutate(chain_id="qcb-mainnet-1")),
        ("chain_id=other-devnet", base.mutate(chain_id="devnet-999")),
        ("chain_id=integer",      base.mutate(chain_id=12345)),
        ("chain_id=null",         base.mutate(chain_id=None)),
        ("chain_id=nul-inject",   base.mutate(chain_id="devnet\x00injected")),
        ("chain_id=256-chars",    base.mutate(chain_id="x" * 256)),
        ("chain_id=array",        base.mutate(chain_id=["devnet"])),
    ]
    findings = _fuzz_matrix(client, node, "F4-chain-id", cases, inv=9)

    if not _node_alive(client, node):
        f = _finding(
            inv=None,
            title="[F4] Node unresponsive after chain_id fuzz",
            severity=Severity.CRITICAL,
            steps=["Send 8 txs with malformed chain_id", f"GET {node}/status"],
            expected="Node remains alive and responsive",
            actual="/status returned no response",
            evidence={"node": node},
        )
        findings.append(f)
        log.finding(f)

    return findings


# ---------------------------------------------------------------------------
# F5 — Signature / public key mutations  (ML-DSA)
# ---------------------------------------------------------------------------

def attack_f5_signature(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    node = cfg["nodes"]["rpc_urls"][0]
    base = _base_tx(cfg)

    # One-byte bit flip at position 0
    _bitflip = format(0xab ^ 0x01, "02x") + _PLACEHOLDER_SIG[2:]
    # Truncated to half length
    _truncated_sig = _PLACEHOLDER_SIG[: _VALID_SIG_HEX_LEN // 2]
    _truncated_key = _PLACEHOLDER_KEY[: _VALID_KEY_HEX_LEN // 2]
    # Double length (appended garbage)
    _double_sig = _PLACEHOLDER_SIG + "cc" * (_VALID_SIG_HEX_LEN // 2)

    cases: list[tuple[str, TxEnvelope]] = [
        ("sig=zeroed",         base.mutate(signature=_ZERO_SIG)),
        ("sig=truncated-half", base.mutate(signature=_truncated_sig)),
        ("sig=double-length",  base.mutate(signature=_double_sig)),
        ("sig=bit-flip-byte0", base.mutate(signature=_bitflip)),
        ("sig=wrong-key-pair", base.mutate(signature=_WRONG_KEY_SIG, pub_key=_WRONG_KEY)),
        ("sig=empty-string",   base.mutate(signature="")),
        ("sig=null",           base.mutate(signature=None)),
        ("sig=non-hex",        base.mutate(signature="GGGG" * 100)),
        ("sig=integer",        base.mutate(signature=12345)),
        ("pubkey=zeroed",      base.mutate(pub_key=_ZERO_KEY)),
        ("pubkey=truncated",   base.mutate(pub_key=_truncated_key)),
        ("pubkey=null",        base.mutate(pub_key=None)),
        ("pubkey=mismatch",    base.mutate(pub_key=_WRONG_KEY)),   # key doesn't match sig
        # Sender/pubkey mismatch: pubkey is valid-length but derives to a different address
        ("sender-pubkey-mismatch", base.mutate(
            sender=cfg["accounts"]["bob"],    # bob's address
            pub_key=_PLACEHOLDER_KEY,          # alice's key (mismatched)
        )),
    ]
    return _fuzz_matrix(client, node, "F5-signature", cases)


# ---------------------------------------------------------------------------
# F6 — Unknown / malformed tx variant
# ---------------------------------------------------------------------------

class _ExtraFieldTx(TxEnvelope):
    """Injects unexpected top-level fields into the encoded tx."""
    def encode(self) -> dict:
        d = super().encode()
        d["tx"]["__proto__"]       = {"polluted": True}
        d["tx"]["admin_override"]  = True
        d["tx"]["_class"]          = "exploit"
        return d


def attack_f6_unknown_variant(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    node = cfg["nodes"]["rpc_urls"][0]
    base = _base_tx(cfg)

    def _deep(depth: int) -> dict:
        d: dict = {"v": "leaf"}
        for _ in range(depth):
            d = {"c": d}
        return d

    cases: list[tuple[str, TxEnvelope]] = [
        ("msg_type=unknown",       base.mutate(msg_type="ExplodeChain")),
        ("msg_type=empty",         base.mutate(msg_type="")),
        ("msg_type=null",          base.mutate(msg_type=None)),
        ("msg_type=integer",       base.mutate(msg_type=42)),
        ("payload=null",           base.mutate(payload=None)),
        ("payload=empty-dict",     base.mutate(payload={})),
        ("payload=list",           base.mutate(payload=[1, 2, 3])),
        ("payload=string",         base.mutate(payload="not-a-dict")),
        ("payload=depth-500",      base.mutate(payload=_deep(500))),
        ("payload=10k-keys",       base.mutate(payload={f"k{i}": "v" for i in range(10_000)})),
        ("extra-top-level-fields", _ExtraFieldTx(**base.as_dict())),
    ]
    return _fuzz_matrix(client, node, "F6-variant", cases)


# ---------------------------------------------------------------------------
# F7 — Replay after confirmation
# ---------------------------------------------------------------------------

def attack_f7_replay(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    findings: list[FindingRecord] = []
    node = cfg["nodes"]["rpc_urls"][0]
    base = _base_tx(cfg)

    nonce = (int(time.time()) % 50_000) + 200_000
    tx    = base.mutate(nonce=nonce)

    s1, b1 = _broadcast(client, node, tx)
    log.info("[F7] first broadcast", status=s1, nonce=nonce)
    time.sleep(5)
    s2, b2 = _broadcast(client, node, tx)
    log.info("[F7] replay broadcast", status=s2)

    if not _check_tx_rejected(s2, b2):
        f = _finding(
            inv=1,
            title="[F7] Replay tx accepted after block inclusion",
            severity=Severity.CRITICAL,
            steps=[
                f"Broadcast Transfer tx with nonce={nonce}",
                "Wait 5 seconds for block inclusion",
                "Rebroadcast identical tx bytes",
                f"Second broadcast returned status={s2}",
            ],
            expected="Replay rejected — nonce/hash already committed",
            actual=f"status={s2}, body={json.dumps(b2)[:300]}",
            evidence={"nonce": nonce, "first": b1, "replay": b2},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info("[F7] replay correctly rejected ✓", status=s2)

    return findings


# ---------------------------------------------------------------------------
# F8 — Resource exhaustion
# ---------------------------------------------------------------------------

def attack_f8_exhaustion(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    findings: list[FindingRecord] = []
    node = cfg["nodes"]["rpc_urls"][0]
    base = _base_tx(cfg)
    bob  = cfg["accounts"]["bob"]

    cases: list[tuple[str, TxEnvelope]] = [
        ("memo=1MB",        base.mutate(payload={"recipient": bob, "amount": 1, "memo": "A" * 1_000_000})),
        ("payload=10k-keys", base.mutate(payload={f"key_{i}": "v" for i in range(10_000)})),
        ("memo=unicode-bomb", base.mutate(payload={"recipient": bob, "amount": 1, "memo": "\u0000" * 50_000})),
        ("sig=10MB",        base.mutate(signature="ab" * 5_000_000)),
    ]
    findings.extend(_fuzz_matrix(client, node, "F8-exhaustion", cases, inv=8))

    if not _node_alive(client, node):
        f = _finding(
            inv=None,
            title="[F8] Node crashed under resource exhaustion",
            severity=Severity.CRITICAL,
            steps=["Send oversized payload / signature txs", f"GET {node}/status"],
            expected="Node rejects oversized fields and stays alive",
            actual="/status unreachable after exhaustion attempts",
            evidence={"node": node},
        )
        findings.append(f)
        log.finding(f)

    return findings


# ---------------------------------------------------------------------------
# Liveness gate
# ---------------------------------------------------------------------------

def check_liveness(
    client: httpx.Client,
    cfg: dict[str, Any],
    phase: str,
) -> list[FindingRecord]:
    findings: list[FindingRecord] = []
    for url in cfg["nodes"]["rpc_urls"]:
        alive = _node_alive(client, url)
        log.info(f"liveness/{phase}", node=url, alive=alive)
        if not alive:
            f = _finding(
                inv=None,
                title=f"Node unreachable ({phase})",
                severity=Severity.CRITICAL,
                steps=[f"GET {url}/status ({phase} phase)"],
                expected="Node responds with 200",
                actual="No response / connection error",
                evidence={"node": url, "phase": phase},
            )
            findings.append(f)
            log.finding(f)
    return findings


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ATTACKS = [
    ("F1", "Nonce edge cases",       attack_f1_nonce),
    ("F2", "Balance edge cases",     attack_f2_balance),
    ("F3", "Gas edge cases",         attack_f3_gas),
    ("F4", "Chain-ID mutations",     attack_f4_chain_id),
    ("F5", "Signature mutations",    attack_f5_signature),
    ("F6", "Unknown tx variant",     attack_f6_unknown_variant),
    ("F7", "Replay after confirm",   attack_f7_replay),
    ("F8", "Resource exhaustion",    attack_f8_exhaustion),
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="QCB TxFuzzer — devnet-only tx-level fuzzing"
    )
    parser.add_argument("--config",          required=True, type=Path)
    parser.add_argument("--findings-dir",    type=Path, default=Path("agents/findings"))
    parser.add_argument("--attack",          help="Run only F1..F8")
    parser.add_argument("--unsafe-override", action="store_true")
    args = parser.parse_args()

    cfg = load_config(args.config)
    try:
        chain_id = assert_devnet(cfg, unsafe_override=args.unsafe_override)
    except Exception as exc:
        abort(str(exc)); return

    log.info(f"TxFuzzer starting", chain_id=chain_id)
    args.findings_dir.mkdir(parents=True, exist_ok=True)
    total: list[FindingRecord] = []

    with httpx.Client() as client:
        total.extend(check_liveness(client, cfg, "pre"))

        for tag, name, fn in ATTACKS:
            if args.attack and args.attack.upper() != tag:
                continue
            log.info(f"Running {tag}: {name}")
            try:
                findings = fn(client, cfg)
                for f in findings:
                    f.save(args.findings_dir)
                total.extend(findings)
            except Exception as exc:
                log.error(f"Error in {tag}: {exc}")

        total.extend(check_liveness(client, cfg, "post"))

    log.info("TxFuzzer complete", total_findings=len(total))
    sys.exit(1 if total else 0)


if __name__ == "__main__":
    main()
