"""
agents/fixtures/qpc_human_fixtures.py — deterministic synthetic identity fixtures
for QPC-CONS-001 adversarial testing.

ALL identifiers, addresses, and keys here are SYNTHETIC TEST-ONLY values.
No real personal information, biometrics, or production credentials.

Use FIXTURE_SEED for reproducible test runs.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Sequence

FIXTURE_SEED: int = 0x51AB_C001

_STATUSES = ["Verified", "Provisional", "Revoked", "Expired", "Recovered",
             "Verified", "Verified", "Provisional", "Revoked", "Verified"]


def _det_hex(tag: str, n: int, length: int = 32) -> str:
    """Deterministic hex string derived from tag + index."""
    raw = hashlib.sha256(f"{FIXTURE_SEED}:{tag}:{n}".encode()).digest()
    # Extend if needed
    out = raw
    while len(out) < length:
        out += hashlib.sha256(out).digest()
    return out[:length].hex()


@dataclass
class SimulatedWallet:
    address: str
    human_id: str
    seed_hex: str


@dataclass
class SimulatedValidator:
    validator_id: str
    address: str
    owner_human_id: str
    consensus_pubkey: str   # 32-byte deterministic fake hex


@dataclass
class SimulatedHuman:
    human_id: str
    seed: int
    status: str
    wallets: list[str]       # wallet addresses
    validators: list[str]    # validator_ids


def build_fixtures() -> tuple[
    list[SimulatedHuman],
    list[SimulatedWallet],
    list[SimulatedValidator],
]:
    rng_state = FIXTURE_SEED

    def _next() -> int:
        nonlocal rng_state
        rng_state = (rng_state * 6364136223846793005 + 1442695040888963407) & 0xFFFF_FFFF_FFFF_FFFF
        return rng_state

    # 10 humans
    humans: list[SimulatedHuman] = []
    for i in range(10):
        humans.append(SimulatedHuman(
            human_id=f"human-{i:02d}",
            seed=_next() & 0xFFFF_FFFF,
            status=_STATUSES[i],
            wallets=[],
            validators=[],
        ))

    # 100 wallets — distribute among humans (10 each)
    wallets: list[SimulatedWallet] = []
    for i in range(100):
        human_idx = i // 10
        h = humans[human_idx]
        addr = f"qcb1test{i:04d}"
        w = SimulatedWallet(
            address=addr,
            human_id=h.human_id,
            seed_hex=_det_hex("wallet", i),
        )
        wallets.append(w)
        h.wallets.append(addr)

    # 30 validators — 3 per human
    validators: list[SimulatedValidator] = []
    for i in range(30):
        human_idx = i // 3
        h = humans[human_idx]
        v = SimulatedValidator(
            validator_id=f"val-test-{i:02d}",
            address=f"qcb1test{i:04d}",
            owner_human_id=h.human_id,
            consensus_pubkey=_det_hex("valkey", i, 32),
        )
        validators.append(v)
        h.validators.append(v.validator_id)

    return humans, wallets, validators


HUMANS, WALLETS, VALIDATORS = build_fixtures()

# Lookup maps
HUMAN_BY_ID: dict[str, SimulatedHuman]     = {h.human_id: h for h in HUMANS}
WALLET_BY_ADDR: dict[str, SimulatedWallet] = {w.address: w for w in WALLETS}
VAL_BY_ID: dict[str, SimulatedValidator]   = {v.validator_id: v for v in VALIDATORS}
