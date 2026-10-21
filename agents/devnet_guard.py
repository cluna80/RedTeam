"""
agents/devnet_guard.py — fail-closed devnet safety check.

Every agent MUST call assert_devnet() before touching any endpoint.
The check is intentionally conservative: if we cannot confirm devnet
from multiple independent signals, we abort.
"""
from __future__ import annotations
import os
import sys
import tomllib
from pathlib import Path
from typing import Any

import httpx


# Known mainnet chain IDs — extend as QCB mainnet launches
_MAINNET_CHAIN_IDS: set[str] = {
    "qcb-mainnet-1",
}

# Endpoints that must NEVER be targeted
_FORBIDDEN_PREFIXES: list[str] = [
    "https://rpc.qcb.network",
    "https://node.qcb.network",
]


class MainnetGuardError(RuntimeError):
    """Raised when a mainnet signal is detected; exits the process."""


def _check_forbidden_url(url: str) -> None:
    for prefix in _FORBIDDEN_PREFIXES:
        if url.startswith(prefix):
            raise MainnetGuardError(
                f"Refusing to connect: URL {url!r} matches mainnet prefix {prefix!r}."
            )


def _check_chain_id(node_url: str, timeout: float = 5.0) -> str:
    """Query /status and return chain_id; raise if mainnet."""
    try:
        r = httpx.get(f"{node_url}/api/status", timeout=timeout)
        r.raise_for_status()
        chain_id: str = r.json().get("chain_id") or r.json()["result"]["node_info"]["network"]
    except Exception as exc:
        raise MainnetGuardError(
            f"Could not verify chain_id from {node_url}: {exc}"
        ) from exc

    if chain_id in _MAINNET_CHAIN_IDS:
        raise MainnetGuardError(
            f"Chain ID {chain_id!r} is a mainnet identifier. Aborting."
        )
    if not (chain_id.startswith("devnet") or chain_id.startswith("testnet") or chain_id.startswith("localnet") or chain_id.startswith("qcb-devnet")):
        raise MainnetGuardError(
            f"Chain ID {chain_id!r} is not a recognised devnet/testnet prefix. "
            "Add --unsafe-override only if you are absolutely sure this is a test network."
        )
    return chain_id


def _check_env() -> None:
    if os.getenv("QCB_ALLOW_MAINNET"):
        raise MainnetGuardError(
            "QCB_ALLOW_MAINNET is set but this suite must never run against mainnet."
        )


def load_config(config_path: Path) -> dict[str, Any]:
    with open(config_path, "rb") as f:
        return tomllib.load(f)


def assert_devnet(config: dict[str, Any], unsafe_override: bool = False) -> str:
    """
    Perform all safety checks and return the validated chain_id.

    Raises MainnetGuardError (and exits 2) if any check fails.
    unsafe_override=True skips the chain_id network check — only for
    unit tests that don't have a live node.
    """
    _check_env()

    node_urls: list[str] = config.get("nodes", {}).get("rpc_urls", [])
    if not node_urls:
        raise MainnetGuardError("No node RPC URLs in config — cannot verify devnet.")

    for url in node_urls:
        _check_forbidden_url(url)

    if unsafe_override:
        return "localnet-unsafe-override"

    # Verify at least the first node
    chain_id = _check_chain_id(node_urls[0])
    print(f"[devnet_guard] chain_id={chain_id!r} ✓", flush=True)
    return chain_id


def abort(msg: str) -> None:
    print(f"[devnet_guard] ABORT: {msg}", file=sys.stderr)
    sys.exit(2)
