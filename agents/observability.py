#!/usr/bin/env python3
"""
agents/observability.py — Structured logging + findings dashboard

Two components:

1. StructuredLogger
   Drop-in replacement for print() in all agents.  Emits JSON-L lines to
   stderr (machine-readable) and formatted lines to stdout (human-readable).
   Use by instantiating with the agent name; it is not a singleton.

2. dashboard()
   Reads agents/findings/*.json and renders a compact terminal summary.
   Run at any time to see signal vs noise across agents.

Usage:
    # In an agent:
    from agents.observability import StructuredLogger
    log = StructuredLogger("agent5_invariant")
    log.info("cycle done", cycles=3, findings=1)
    log.finding(finding_record)

    # Standalone dashboard:
    python agents/observability.py --findings-dir agents/findings/
    python agents/observability.py --findings-dir agents/findings/ --watch
"""
from __future__ import annotations

import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# agents.schema is importable from the repo root
sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.schema import FindingRecord, Severity


# ---------------------------------------------------------------------------
# ANSI colours — degrade gracefully when stdout is not a tty
# ---------------------------------------------------------------------------

def _tty() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_RESET  = "\033[0m"  if _tty() else ""
_BOLD   = "\033[1m"  if _tty() else ""
_RED    = "\033[31m" if _tty() else ""
_YELLOW = "\033[33m" if _tty() else ""
_GREEN  = "\033[32m" if _tty() else ""
_CYAN   = "\033[36m" if _tty() else ""
_GRAY   = "\033[90m" if _tty() else ""

_SEV_COLOUR = {
    "critical": _RED    + _BOLD,
    "high":     _RED,
    "medium":   _YELLOW,
    "low":      _CYAN,
    "info":     _GRAY,
}


# ---------------------------------------------------------------------------
# StructuredLogger
# ---------------------------------------------------------------------------

class StructuredLogger:
    """
    Emits structured JSON-L to stderr and human-readable text to stdout.

    Every log call writes one JSON object to stderr:
        {"ts": "…iso…", "agent": "agent5_invariant", "level": "info",
         "msg": "cycle done", "cycles": 3, "findings": 1}

    Use log.finding(f) to emit a finding alert on both channels.
    """

    def __init__(self, agent: str, json_out: Path | None = None) -> None:
        self.agent    = agent
        self._json_fh = open(json_out, "a") if json_out else None

    def _emit(self, level: str, msg: str, **kw: Any) -> None:
        record = {
            "ts":    datetime.now(timezone.utc).isoformat(),
            "agent": self.agent,
            "level": level,
            "msg":   msg,
            **kw,
        }
        line = json.dumps(record)

        # Machine-readable → stderr
        print(line, file=sys.stderr, flush=True)

        # Optional JSON file sink
        if self._json_fh:
            self._json_fh.write(line + "\n")
            self._json_fh.flush()

    def debug(self, msg: str, **kw: Any) -> None:
        self._emit("debug", msg, **kw)
        # debug suppressed from stdout by default

    def info(self, msg: str, **kw: Any) -> None:
        self._emit("info", msg, **kw)
        kv = "  ".join(f"{k}={v}" for k, v in kw.items())
        print(f"{_GRAY}[{self.agent}]{_RESET} {msg}" + (f"  {_GRAY}{kv}{_RESET}" if kv else ""),
              flush=True)

    def warn(self, msg: str, **kw: Any) -> None:
        self._emit("warn", msg, **kw)
        kv = "  ".join(f"{k}={v}" for k, v in kw.items())
        print(f"{_YELLOW}[{self.agent}] WARN {msg}{_RESET}" + (f"  {kv}" if kv else ""),
              flush=True)

    def error(self, msg: str, **kw: Any) -> None:
        self._emit("error", msg, **kw)
        print(f"{_RED}[{self.agent}] ERROR {msg}{_RESET}", file=sys.stderr, flush=True)

    def finding(self, f: FindingRecord) -> None:
        """Log a confirmed finding on both channels with full context."""
        self._emit(
            "finding",
            f.title,
            finding_id=f.finding_id,
            severity=f.severity.value,
            invariant_id=f.invariant_id,
            agent=f.agent.value,
        )
        colour = _SEV_COLOUR.get(f.severity.value, "")
        bar    = "=" * 68
        print(f"\n{colour}{bar}{_RESET}")
        print(f"{colour}[FINDING] [{f.severity.value.upper()}] {f.title}{_RESET}")
        print(f"  id={f.finding_id}  inv={f.invariant_id}  agent={f.agent.value}")
        print(f"  expected: {f.expected}")
        print(f"  actual  : {f.actual}")
        print(f"{colour}{bar}{_RESET}\n", flush=True)

    def __del__(self) -> None:
        if self._json_fh:
            try:
                self._json_fh.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

def _load_findings(findings_dir: Path) -> list[FindingRecord]:
    findings: list[FindingRecord] = []
    for p in sorted(findings_dir.glob("*.json")):
        try:
            findings.append(FindingRecord.load(p))
        except Exception:
            pass
    return findings


def _render_dashboard(findings: list[FindingRecord]) -> None:
    if not findings:
        print(f"{_GRAY}No findings yet.{_RESET}")
        return

    # Header
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"\n{_BOLD}QCB Red-Team Findings Dashboard{_RESET}  {_GRAY}{ts}{_RESET}")
    print("─" * 72)

    # Summary counts by severity
    by_sev: Counter[str] = Counter(f.severity.value for f in findings)
    parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        n = by_sev.get(sev, 0)
        if n:
            c = _SEV_COLOUR.get(sev, "")
            parts.append(f"{c}{n} {sev}{_RESET}")
    print("  " + "  |  ".join(parts))
    print()

    # Per-agent breakdown
    by_agent: dict[str, list[FindingRecord]] = {}
    for f in findings:
        by_agent.setdefault(f.agent.value, []).append(f)

    agent_labels = {
        "agent1_tx_fuzzer":      "Agent 1  TxFuzzer",
        "agent2_economic":       "Agent 2  EconomicAttacker",
        "agent3_gossip":         "Agent 3  GossipAdversary",
        "agent4_sybil":          "Agent 4  SybilProbe",
        "agent5_invariant":      "Agent 5  InvariantMonitor",
        "agent6_patch":          "Agent 6  PatchProposer",
        "agent_identity_pilot":  "Agent 8  IdentityPilot",
    }

    for agent_id, afindings in sorted(by_agent.items()):
        label = agent_labels.get(agent_id, agent_id)
        sev_counts = Counter(f.severity.value for f in afindings)
        sev_str = "  ".join(
            f"{_SEV_COLOUR.get(s,'')}{sev_counts[s]} {s}{_RESET}"
            for s in ("critical", "high", "medium", "low", "info")
            if sev_counts.get(s)
        )
        print(f"  {_BOLD}{label}{_RESET}  ({len(afindings)} total)  {sev_str}")

        # Show up to 5 most severe findings per agent
        shown = sorted(afindings, key=lambda f: _SEVERITY_RANK_DASH[f.severity], reverse=True)[:5]
        for f in shown:
            c     = _SEV_COLOUR.get(f.severity.value, "")
            inv   = f"INV-{f.invariant_id}" if f.invariant_id else "    "
            ts_short = f.timestamp[:19].replace("T", " ")
            has_reg  = "✓" if f.regression_path else " "
            print(f"    [{c}{f.severity.value:8s}{_RESET}] {inv}  {has_reg}  {f.title[:50]}  {_GRAY}{ts_short}{_RESET}")
        if len(afindings) > 5:
            print(f"    {_GRAY}… and {len(afindings) - 5} more{_RESET}")
        print()

    # Invariant heat map
    inv_hits: Counter[int] = Counter(
        f.invariant_id for f in findings if f.invariant_id is not None
    )
    if inv_hits:
        print(f"  {_BOLD}Invariant hit counts{_RESET}  (higher = more attack surface)")
        for inv_id in sorted(inv_hits, key=inv_hits.get, reverse=True):  # type: ignore
            bar_len = min(inv_hits[inv_id], 40)
            bar     = "█" * bar_len
            print(f"    INV-{inv_id:2d}  {bar}  {inv_hits[inv_id]}")
        print()

    # Regression coverage
    total       = len(findings)
    with_reg    = sum(1 for f in findings if f.regression_path)
    crit_high   = sum(1 for f in findings if f.severity.value in ("critical", "high"))
    print(f"  {_BOLD}Regression coverage{_RESET}  {with_reg}/{total} findings have test stubs")
    if crit_high > 0:
        uncovered = crit_high - sum(
            1 for f in findings
            if f.severity.value in ("critical", "high") and f.regression_path
        )
        if uncovered:
            print(f"  {_RED}{uncovered} CRITICAL/HIGH finding(s) without regression stubs{_RESET}")
    print()


_SEVERITY_RANK_DASH = {
    Severity.CRITICAL: 4,
    Severity.HIGH:     3,
    Severity.MEDIUM:   2,
    Severity.LOW:      1,
    Severity.INFO:     0,
}


def dashboard(findings_dir: Path, watch: bool = False, interval: int = 30) -> None:
    while True:
        if watch:
            # Clear screen (ANSI) then redraw
            print("\033[2J\033[H", end="")
        findings = _load_findings(findings_dir)
        _render_dashboard(findings)
        if not watch:
            break
        print(f"{_GRAY}Refreshing every {interval}s — Ctrl-C to exit{_RESET}", flush=True)
        time.sleep(interval)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        description="QCB red-team findings dashboard"
    )
    parser.add_argument(
        "--findings-dir",
        type=Path,
        default=Path("agents/findings"),
        help="Directory containing finding JSON files",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Refresh the dashboard every --interval seconds",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=30,
        help="Refresh interval in seconds when --watch is set (default: 30)",
    )
    args = parser.parse_args()
    dashboard(args.findings_dir, args.watch, args.interval)


if __name__ == "__main__":
    main()
