#!/usr/bin/env python3
"""
agents/run_suite.py — top-level CLI runner for the QCB red-team suite.

Runs agents in dependency order and wires findings to the PatchProposer.

Usage:
    # Run all agents against the 3-node devnet:
    python agents/run_suite.py --config agents/config/devnet3.toml

    # Run specific agents:
    python agents/run_suite.py --config agents/config/devnet3.toml --agents 5,2,3

    # Single-cycle InvariantMonitor (CI-friendly):
    python agents/run_suite.py --config agents/config/devnet3.toml --agents 5 --once

    # After agents run, generate regression stubs from any findings:
    python agents/run_suite.py --config agents/config/devnet3.toml --propose-patches
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

AGENTS_DIR = Path(__file__).parent
REPO_ROOT  = AGENTS_DIR.parent

_AGENT_SCRIPTS = {
    1: "agent1_tx_fuzzer.py",
    2: "agent2_economic.py",
    3: "agent3_gossip.py",
    4: "agent4_sybil.py",
    5: "agent5_invariant.py",
    7: "agent7_consensus.py",
    6: "agent6_patch.py",
    8: "agent_identity_pilot.py",    # Phase A–D attestation-guard / identity pilot
}

_DEFAULT_ORDER = [5, 7, 8, 2, 3, 1, 4, 8]   # 6 runs separately via --propose-patches; 8=identity pilot


def _run_agent(
    agent_num: int,
    config: Path,
    findings_dir: Path,
    extra_args: list[str],
) -> int:
    script = AGENTS_DIR / _AGENT_SCRIPTS[agent_num]
    cmd = [
        sys.executable, str(script),
        "--config",       str(config),
        "--findings-dir", str(findings_dir),
    ] + extra_args
    print(f"\n{'='*60}")
    print(f"Running Agent {agent_num}: {script.name}")
    print(f"  cmd: {' '.join(cmd)}")
    print(f"{'='*60}")
    result = subprocess.run(cmd)
    return result.returncode


def main() -> None:
    parser = argparse.ArgumentParser(
        description="QCB red-team suite runner — devnet only"
    )
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument(
        "--agents",
        default=",".join(str(a) for a in _DEFAULT_ORDER),
        help="Comma-separated agent numbers to run (default: 5,2,3,1,4)",
    )
    parser.add_argument(
        "--findings-dir",
        type=Path,
        default=AGENTS_DIR / "findings",
    )
    parser.add_argument(
        "--regressions-dir",
        type=Path,
        default=AGENTS_DIR / "regressions",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Pass --once to InvariantMonitor (single poll cycle)",
    )
    parser.add_argument(
        "--propose-patches",
        action="store_true",
        help="After running agents, run PatchProposer on all findings",
    )
    parser.add_argument(
        "--unsafe-override",
        action="store_true",
        help="Skip live chain_id check (unit tests only)",
    )
    args = parser.parse_args()

    args.findings_dir.mkdir(parents=True, exist_ok=True)
    args.regressions_dir.mkdir(parents=True, exist_ok=True)

    try:
        agents = [int(x.strip()) for x in args.agents.split(",")]
    except ValueError:
        parser.error("--agents must be comma-separated integers (e.g. 5,2,3)")

    extra: list[str] = []
    if args.once:
        extra.append("--once")
    if args.unsafe_override:
        extra.append("--unsafe-override")

    exit_codes: dict[int, int] = {}
    for agent_num in agents:
        if agent_num not in _AGENT_SCRIPTS:
            print(f"WARNING: Unknown agent {agent_num}, skipping")
            continue
        if agent_num == 6:
            continue   # PatchProposer runs only via --propose-patches
        if agent_num not in _AGENT_SCRIPTS:
            print(f"WARNING: Unknown agent {agent_num}, skipping")
            continue
        rc = _run_agent(agent_num, args.config, args.findings_dir, extra)
        exit_codes[agent_num] = rc

    if args.propose_patches:
        findings = list(args.findings_dir.glob("*.json"))
        if findings:
            script = AGENTS_DIR / _AGENT_SCRIPTS[6]
            cmd = [
                sys.executable, str(script),
                "--all-findings",    str(args.findings_dir),
                "--regressions-dir", str(args.regressions_dir),
            ]
            print(f"\n[runner] PatchProposer on {len(findings)} finding(s)…")
            subprocess.run(cmd)
        else:
            print("\n[runner] No findings to propose patches for.")

    # Summary
    total_findings = len(list(args.findings_dir.glob("*.json")))
    print(f"\n{'='*60}")
    print(f"Suite complete.  Findings: {total_findings}")
    for agent_num, rc in exit_codes.items():
        status = "FINDINGS" if rc != 0 else "clean"
        print(f"  Agent {agent_num}: {status} (exit={rc})")
    print(f"  Findings dir:     {args.findings_dir}")
    print(f"  Regressions dir:  {args.regressions_dir}")
    print(f"{'='*60}")

    # Exit non-zero if any agent found something
    sys.exit(1 if any(rc != 0 for rc in exit_codes.values()) else 0)


if __name__ == "__main__":
    main()
