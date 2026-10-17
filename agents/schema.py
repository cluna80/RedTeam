"""
agents/schema.py — canonical finding record for the QCB red-team suite.
All agents emit findings in this format; the runner and PatchProposer consume it.
"""
from __future__ import annotations
import json
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"   # loss of funds, double-spend, quorum bypass
    HIGH     = "high"       # invariant violation without direct fund loss
    MEDIUM   = "medium"     # protocol deviation, degraded liveness
    LOW      = "low"        # unexpected-but-benign edge case
    INFO     = "info"       # noteworthy behaviour, no security impact


class AgentId(str, Enum):
    TX_FUZZER      = "agent1_tx_fuzzer"
    ECONOMIC       = "agent2_economic"
    GOSSIP         = "agent3_gossip"
    SYBIL          = "agent4_sybil"
    INVARIANT      = "agent5_invariant"
    PATCH_PROPOSER = "agent6_patch"


@dataclass
class FindingRecord:
    """
    One confirmed exploit or invariant violation.

    Fields map 1-to-1 with the JSON schema used by run_suite.py,
    regressions/, and PatchProposer.
    """
    agent:        AgentId
    title:        str
    severity:     Severity
    invariant_id: int | None        # 1-10 per invariants.md, None if N/A
    steps:        list[str]         # ordered reproduction steps
    expected:     str               # what the protocol should have done
    actual:       str               # what actually happened
    evidence:     dict[str, Any]    # raw API responses / state snapshots
    timestamp:    str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finding_id:   str = field(default_factory=lambda: str(uuid.uuid4()))
    regression_path: str | None = None  # set after test is written

    # ------------------------------------------------------------------
    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    def save(self, findings_dir: Path = Path("agents/findings")) -> Path:
        findings_dir.mkdir(parents=True, exist_ok=True)
        slug = self.title.lower().replace(" ", "_")[:40]
        path = findings_dir / f"{self.agent.value}_{slug}_{self.finding_id[:8]}.json"
        path.write_text(self.to_json())
        return path

    @classmethod
    def load(cls, path: Path) -> "FindingRecord":
        data = json.loads(path.read_text())
        data["agent"]    = AgentId(data["agent"])
        data["severity"] = Severity(data["severity"])
        return cls(**data)

    def __str__(self) -> str:
        return (
            f"[{self.severity.upper()}] {self.title}\n"
            f"  agent={self.agent.value}  invariant={self.invariant_id}\n"
            f"  expected: {self.expected}\n"
            f"  actual:   {self.actual}"
        )
