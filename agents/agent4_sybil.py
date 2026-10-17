#!/usr/bin/env python3
"""
agents/agent4_sybil.py — SybilProbe (full implementation)

Probes chain-forge-identity and chain-forge-personhood for sybil and
identity-abuse vulnerabilities.  All attacks use testnet-hook endpoints
that are only compiled in under the "testnet-hooks" feature flag.

## Attack categories
  S1  Multi-identity per controller
      Register 2+ identities sharing one controller_id; only 1 may be verified.
  S2  Registry spam
      Flood registrations above the per-epoch cap; excess must be rejected cleanly.
  S3  Revoke / re-register cycling
      Revoke an identity, immediately re-register with same key; cooldown must block.
  S4  Self-verify via identity API
      Register miner + verifier under same controller; attestation guard must block.
  S5  Cross-epoch quota re-use
      Exhaust epoch quota, then probe the epoch boundary reset path for off-by-ones.
  S6  Privilege escalation via re-registration
      Revoke a non-admin identity; re-register with an admin-role claim; must be rejected.
  S7  Concurrent registration race
      Submit 2 registrations for the same controller_id simultaneously; only 1 may land.

## Assumption markers
All [ASSUMPTION] comments flag items to verify against the real source.
See ASSUMPTIONS.md for grep commands.

Usage:
    python agents/agent4_sybil.py --config agents/config/devnet3.toml
    python agents/agent4_sybil.py --config agents/config/devnet3.toml --attack S3
"""
from __future__ import annotations

import argparse
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.schema import AgentId, FindingRecord, Severity
from agents.devnet_guard import assert_devnet, load_config, abort
from agents.observability import StructuredLogger

log = StructuredLogger("agent4_sybil")

# ---------------------------------------------------------------------------
# [ASSUMPTION] Identity API endpoint prefix
# Real value: grep -rn 'Router|route|post|get' chain-forge-identity/src/
# May be /personhood/... based on crate chain-forge-personhood
# ---------------------------------------------------------------------------
IDENTITY_PREFIX = "/identity"       # [ASSUMPTION]
PERSONHOOD_PREFIX = "/personhood"   # [ASSUMPTION]

# [ASSUMPTION] Revocation cooldown in blocks / seconds
REVOKE_COOLDOWN_SECS = 30           # [ASSUMPTION] read from chain config

# [ASSUMPTION] Per-epoch registration cap
EPOCH_REG_CAP = 10                  # [ASSUMPTION]


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _post(client: httpx.Client, url: str, payload: dict, timeout: float = 10.0) -> tuple[int, dict]:
    try:
        r = client.post(url, json=payload, timeout=timeout)
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text[:500]}
        return r.status_code, body
    except Exception as exc:
        return 0, {"error": str(exc)}


def _get(client: httpx.Client, url: str) -> tuple[int, dict]:
    try:
        r = client.get(url, timeout=10.0)
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text[:500]}
        return r.status_code, body
    except Exception as exc:
        return 0, {"error": str(exc)}


def _rejected(status: int, body: dict) -> bool:
    if status in (400, 401, 403, 409, 422):
        return True
    if status == 200 and body.get("code") not in (None, 0):
        return True
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
        agent=AgentId.SYBIL,
        title=title,
        severity=severity,
        invariant_id=inv,
        steps=steps,
        expected=expected,
        actual=actual,
        evidence=evidence,
    )


def _identity_url(cfg: dict[str, Any]) -> str:
    return cfg["identity"]["url"]


def _api_url(cfg: dict[str, Any]) -> str:
    return cfg["nodes"]["api_urls"][0]


# ---------------------------------------------------------------------------
# Registration / revocation helpers
# [ASSUMPTION] request shapes — update field names to match registry.rs structs
# ---------------------------------------------------------------------------

def _register(
    client: httpx.Client,
    base_url: str,
    identity_id: str,
    controller_id: str,
    pub_key_hex: str = "cd" * 32,
    role: str = "miner",            # [ASSUMPTION] role field exists
) -> tuple[int, dict]:
    """
    POST /identity/register
    [ASSUMPTION] field names: identity_id, controller_id, pub_key, role
    Real names: grep 'struct.*Register|pub identity_id|pub controller' chain-forge-identity/src/registry.rs
    """
    return _post(client, f"{base_url}{IDENTITY_PREFIX}/register", {
        "identity_id":   identity_id,
        "controller_id": controller_id,
        "pub_key":        pub_key_hex,
        "role":           role,
    })


def _revoke(
    client: httpx.Client,
    base_url: str,
    identity_id: str,
    controller_id: str,
) -> tuple[int, dict]:
    """
    POST /identity/revoke
    [ASSUMPTION] field names
    """
    return _post(client, f"{base_url}{IDENTITY_PREFIX}/revoke", {
        "identity_id":   identity_id,
        "controller_id": controller_id,
    })


def _lookup(
    client: httpx.Client,
    base_url: str,
    controller_id: str,
) -> tuple[int, dict]:
    """
    GET /identity/by_controller?controller_id=...
    [ASSUMPTION] endpoint path
    """
    return _get(client, f"{base_url}{IDENTITY_PREFIX}/by_controller?controller_id={controller_id}")


def _epoch_stats(
    client: httpx.Client,
    api_url: str,
) -> tuple[int, dict]:
    """
    GET /qcb/identity/epoch_stats
    [ASSUMPTION] endpoint — update if different
    """
    return _get(client, f"{api_url}/qcb/identity/epoch_stats")


# ---------------------------------------------------------------------------
# S1 — Multiple identities per controller
# ---------------------------------------------------------------------------

def attack_s1_multi_identity(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    Register identity_A and identity_B both with controller_id=ctrl-sybil-s1.
    The second registration must be rejected OR only one may be marked verified.
    """
    findings: list[FindingRecord] = []
    base_url    = _identity_url(cfg)
    controller  = f"ctrl-sybil-s1-{uuid.uuid4().hex[:8]}"
    id_a        = f"identity-a-{uuid.uuid4().hex[:8]}"
    id_b        = f"identity-b-{uuid.uuid4().hex[:8]}"

    s1, b1 = _register(client, base_url, id_a, controller)
    log.info("[S1] first registration", status=s1, identity=id_a, controller=controller)

    s2, b2 = _register(client, base_url, id_b, controller)  # same controller
    log.info("[S1] second registration (same controller)", status=s2, identity=id_b)

    if not _rejected(s2, b2):
        # Also check: are both marked verified?
        _, lookup = _lookup(client, base_url, controller)
        identities = lookup.get("identities", [])
        verified_count = sum(1 for i in identities if i.get("verified"))

        if verified_count > 1:
            f = _finding(
                inv=7,
                title="Two identities registered and verified under one controller",
                severity=Severity.CRITICAL,
                steps=[
                    f"POST {base_url}{IDENTITY_PREFIX}/register identity_id={id_a}, controller={controller}",
                    f"POST {base_url}{IDENTITY_PREFIX}/register identity_id={id_b}, same controller",
                    f"GET by_controller — found {verified_count} verified identities",
                ],
                expected="Second registration rejected or second identity not verified",
                actual=f"Both identities verified under controller={controller}",
                evidence={"controller": controller, "id_a": b1, "id_b": b2, "lookup": lookup},
            )
            findings.append(f)
            log.finding(f)
        else:
            log.info("[S1] second identity not verified — protocol correct ✓",
                     verified_count=verified_count)
    else:
        log.info("[S1] second registration correctly rejected ✓", status=s2)

    return findings


# ---------------------------------------------------------------------------
# S2 — Registry spam above epoch cap
# ---------------------------------------------------------------------------

def attack_s2_registry_spam(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    Submit EPOCH_REG_CAP + 10 registrations; all excess must be rejected,
    not silently queued or accepted.  Node must stay alive.
    """
    findings: list[FindingRecord] = []
    base_url   = _identity_url(cfg)
    api_url    = _api_url(cfg)
    spam_count = EPOCH_REG_CAP + 10
    accepted   = 0
    errors     = 0

    log.info(f"[S2] spamming {spam_count} identity registrations…")
    for i in range(spam_count):
        ctrl = f"ctrl-spam-{i}-{uuid.uuid4().hex[:6]}"
        iid  = f"identity-spam-{i}-{uuid.uuid4().hex[:6]}"
        s, b = _register(client, base_url, iid, ctrl)
        if not _rejected(s, b):
            accepted += 1
        if s == 0:
            errors += 1

    log.info("[S2] spam complete", accepted=accepted, spam_count=spam_count, errors=errors)

    if accepted > EPOCH_REG_CAP:
        f = _finding(
            inv=8,
            title="Identity registry accepted more registrations than epoch cap",
            severity=Severity.HIGH,
            steps=[
                f"Submit {spam_count} identity registrations in rapid succession",
                f"Count non-rejected responses",
            ],
            expected=f"At most {EPOCH_REG_CAP} registrations accepted per epoch",
            actual=f"{accepted} registrations accepted (cap={EPOCH_REG_CAP})",
            evidence={"accepted": accepted, "cap": EPOCH_REG_CAP, "submitted": spam_count},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info("[S2] epoch cap enforced correctly ✓", accepted=accepted, cap=EPOCH_REG_CAP)

    # Node must still be alive
    s_alive, _ = _get(client, f"{api_url}/health")
    if s_alive == 0:
        f = _finding(
            inv=None,
            title="[S2] Identity service unreachable after registration spam",
            severity=Severity.CRITICAL,
            steps=[f"Flood {spam_count} registrations", "GET /health"],
            expected="Service remains alive",
            actual="No response after spam",
            evidence={"spam_count": spam_count},
        )
        findings.append(f)
        log.finding(f)

    return findings


# ---------------------------------------------------------------------------
# S3 — Revoke / re-register cycling (cooldown bypass)
# ---------------------------------------------------------------------------

def attack_s3_revoke_reregister(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    Revoke an identity then immediately re-register with the same key material.
    The cooldown must block re-registration until the window expires.
    Also checks: re-registration must not inherit the revoked identity's history.
    """
    findings: list[FindingRecord] = []
    base_url   = _identity_url(cfg)
    controller = f"ctrl-cycle-{uuid.uuid4().hex[:8]}"
    iid        = f"identity-cycle-{uuid.uuid4().hex[:8]}"

    # Register
    s_reg, b_reg = _register(client, base_url, iid, controller)
    log.info("[S3] initial registration", status=s_reg)

    # Revoke immediately
    s_rev, b_rev = _revoke(client, base_url, iid, controller)
    log.info("[S3] revocation", status=s_rev)

    # Immediately re-register (should be blocked by cooldown)
    s_re, b_re = _register(client, base_url, iid, controller)
    log.info("[S3] immediate re-registration", status=s_re)

    if not _rejected(s_re, b_re):
        f = _finding(
            inv=None,
            title="Identity re-registered immediately after revocation (cooldown bypass)",
            severity=Severity.HIGH,
            steps=[
                f"Register identity_id={iid}, controller={controller}",
                "Revoke immediately",
                "Re-register immediately with same identity_id+controller",
                f"Re-registration returned status={s_re}",
            ],
            expected=f"Re-registration blocked by {REVOKE_COOLDOWN_SECS}s cooldown",
            actual=f"Re-registration accepted status={s_re}",
            evidence={
                "controller": controller,
                "reg": b_reg, "revoke": b_rev, "re_reg": b_re,
            },
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info("[S3] immediate re-registration correctly rejected ✓", status=s_re)

    # Wait for cooldown, then re-register — should succeed (positive path)
    log.info(f"[S3] waiting {REVOKE_COOLDOWN_SECS}s for cooldown…")
    time.sleep(REVOKE_COOLDOWN_SECS)
    iid2 = f"identity-cycle2-{uuid.uuid4().hex[:8]}"  # new identity_id post-cooldown
    s_after, b_after = _register(client, base_url, iid2, controller)
    log.info("[S3] post-cooldown re-registration", status=s_after)

    # Check it doesn't inherit the revoked identity's reward history
    _, lookup = _lookup(client, base_url, controller)
    for entry in lookup.get("identities", []):
        if entry.get("identity_id") == iid2:
            prior_rewards = entry.get("lifetime_rewards", 0)
            if prior_rewards != 0:
                f = _finding(
                    inv=7,
                    title="Re-registered identity inherited revoked identity's reward history",
                    severity=Severity.HIGH,
                    steps=[
                        "Register, revoke, wait cooldown, re-register",
                        f"Check lifetime_rewards on new identity_id={iid2}",
                    ],
                    expected="New registration starts with zero reward history",
                    actual=f"lifetime_rewards={prior_rewards} (inherited from revoked identity)",
                    evidence={"controller": controller, "new_identity": entry},
                )
                findings.append(f)
                log.finding(f)

    return findings


# ---------------------------------------------------------------------------
# S4 — Self-verify via identity API  (INV-3)
# ---------------------------------------------------------------------------

def attack_s4_self_verify(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    Register both a miner identity and a verifier identity under the same
    controller_id, then attempt to use the verifier to attest the miner's work.
    The attestation guard Phase C must block this at the scheduler layer.
    """
    findings: list[FindingRecord] = []
    base_url   = _identity_url(cfg)
    sched_url  = cfg["scheduler"]["url"]
    controller = f"ctrl-selfverify-{uuid.uuid4().hex[:8]}"
    miner_id   = f"miner-sv-{uuid.uuid4().hex[:8]}"
    verifier_id = f"verifier-sv-{uuid.uuid4().hex[:8]}"

    # Register both under the same controller
    s_m, b_m = _register(client, base_url, miner_id,    controller, role="miner")
    s_v, b_v = _register(client, base_url, verifier_id, controller, role="verifier")
    log.info("[S4] registered miner+verifier under same controller",
             miner_status=s_m, verifier_status=s_v, controller=controller)

    # Submit a job as miner
    job_id     = f"job-sv-{uuid.uuid4().hex[:8]}"
    output_hash = "aa" * 32
    _, b_claim = _post(client, f"{sched_url}/scheduler/claim_task", {
        "job_id":        job_id,
        "machine_id":    miner_id,
        "controller_id": controller,
        "output_hash":   output_hash,
    })
    log.info("[S4] miner claimed job", job_id=job_id)

    # Attempt self-attestation via the verifier (same controller)
    s_attest, b_attest = _post(client, f"{sched_url}/scheduler/attest_task", {
        "job_id":              job_id,
        "verifier_id":         verifier_id,
        "verifier_controller": controller,   # same controller as miner
        "output_hash":         output_hash,
    })
    log.info("[S4] self-attestation attempt", status=s_attest, controller=controller)

    if not _rejected(s_attest, b_attest):
        # Check if attestation was counted toward quorum
        _, attest_data = _get(client, f"{sched_url}/scheduler/attestations")
        self_counted = any(
            a.get("job_id") == job_id
            and a.get("verifier_controller_id") == controller
            and a.get("counted_toward_quorum")
            for a in attest_data.get("attestations", [])
        )
        if self_counted:
            f = _finding(
                inv=3,
                title="Self-verify via identity API: same-controller attestation counted",
                severity=Severity.CRITICAL,
                steps=[
                    f"Register miner identity_id={miner_id}, controller={controller}",
                    f"Register verifier identity_id={verifier_id}, same controller",
                    f"Miner claims job_id={job_id}",
                    "Verifier attests same job — same controller_id",
                    "Attestation counted toward quorum",
                ],
                expected="Attestation guard Phase C blocks same-controller attestation",
                actual=f"Self-attestation counted for job_id={job_id}",
                evidence={
                    "controller": controller,
                    "miner": miner_id, "verifier": verifier_id,
                    "attest_resp": b_attest,
                },
            )
            findings.append(f)
            log.finding(f)
        else:
            log.info("[S4] attestation accepted at HTTP layer but not counted ✓ (Phase C held)")
    else:
        log.info("[S4] self-attestation correctly rejected ✓", status=s_attest)

    return findings


# ---------------------------------------------------------------------------
# S5 — Cross-epoch quota re-use
# ---------------------------------------------------------------------------

def attack_s5_cross_epoch(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    Exhaust the per-epoch submission quota for a controller, then probe
    whether the epoch boundary resets atomically or has an off-by-one
    window where submissions can slip through.
    """
    findings: list[FindingRecord] = []
    api_url    = _api_url(cfg)
    sched_url  = cfg["scheduler"]["url"]
    controller = f"ctrl-epoch-{uuid.uuid4().hex[:8]}"
    base_url   = _identity_url(cfg)

    # Register a fresh identity
    iid = f"identity-epoch-{uuid.uuid4().hex[:8]}"
    _register(client, base_url, iid, controller)

    # Exhaust epoch quota
    log.info(f"[S5] exhausting epoch quota ({EPOCH_REG_CAP} submissions)…")
    for i in range(EPOCH_REG_CAP):
        job_id = f"job-epoch-{i}-{uuid.uuid4().hex[:6]}"
        _post(client, f"{sched_url}/scheduler/submit_work_receipt", {
            "job_id":        job_id,
            "machine_id":    iid,
            "controller_id": controller,
            "output_hash":   "bb" * 32,
            "seal":          "bb" * 32,
            "attestations":  [],
        })

    # One more submission — must be rejected
    extra_job = f"job-epoch-extra-{uuid.uuid4().hex[:8]}"
    s_extra, b_extra = _post(client, f"{sched_url}/scheduler/submit_work_receipt", {
        "job_id":        extra_job,
        "machine_id":    iid,
        "controller_id": controller,
        "output_hash":   "cc" * 32,
        "seal":          "cc" * 32,
        "attestations":  [],
    })
    if not _rejected(s_extra, b_extra):
        f = _finding(
            inv=8,
            title="Epoch quota exceeded — extra submission accepted",
            severity=Severity.HIGH,
            steps=[
                f"Submit {EPOCH_REG_CAP} work receipts for controller={controller}",
                f"Submit one more (job_id={extra_job})",
                f"Extra submission returned status={s_extra}",
            ],
            expected=f"Submission rejected — controller at epoch cap ({EPOCH_REG_CAP})",
            actual=f"status={s_extra}, body={b_extra}",
            evidence={"controller": controller, "cap": EPOCH_REG_CAP, "extra_resp": b_extra},
        )
        findings.append(f)
        log.finding(f)
    else:
        log.info("[S5] quota cap enforced correctly ✓", status=s_extra)

    # Probe epoch boundary: check the stats endpoint for off-by-one
    _, stats = _epoch_stats(client, api_url)
    for entry in stats.get("controller_stats", []):
        if entry.get("controller_id") == controller:
            actual_submissions = entry.get("submissions_this_epoch", 0)
            if actual_submissions > EPOCH_REG_CAP:
                f = _finding(
                    inv=8,
                    title="Epoch stats show submissions above cap",
                    severity=Severity.HIGH,
                    steps=[
                        f"Exhaust quota, probe epoch_stats for controller={controller}",
                    ],
                    expected=f"submissions_this_epoch <= {EPOCH_REG_CAP}",
                    actual=f"submissions_this_epoch={actual_submissions}",
                    evidence={"entry": entry, "cap": EPOCH_REG_CAP},
                )
                findings.append(f)
                log.finding(f)

    return findings


# ---------------------------------------------------------------------------
# S6 — Privilege escalation via re-registration
# ---------------------------------------------------------------------------

def attack_s6_privilege_escalation(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    Revoke a standard (miner) identity, then re-register with role=admin.
    The registry must not allow self-assigned admin roles.
    """
    findings: list[FindingRecord] = []
    base_url   = _identity_url(cfg)
    controller = f"ctrl-privesc-{uuid.uuid4().hex[:8]}"
    iid        = f"identity-privesc-{uuid.uuid4().hex[:8]}"

    _register(client, base_url, iid, controller, role="miner")
    _revoke(client, base_url, iid, controller)
    time.sleep(REVOKE_COOLDOWN_SECS)

    # Re-register with admin role claim
    iid2     = f"identity-privesc2-{uuid.uuid4().hex[:8]}"
    s, b = _register(client, base_url, iid2, controller, role="admin")
    log.info("[S6] admin role re-registration", status=s)

    if not _rejected(s, b):
        # Check the actual role assigned
        _, lookup = _lookup(client, base_url, controller)
        for entry in lookup.get("identities", []):
            if entry.get("identity_id") == iid2:
                actual_role = entry.get("role", "")
                if actual_role == "admin":
                    f = _finding(
                        inv=None,
                        title="Self-assigned admin role accepted via re-registration",
                        severity=Severity.CRITICAL,
                        steps=[
                            f"Register as miner, controller={controller}",
                            "Revoke, wait cooldown",
                            "Re-register with role=admin",
                            f"Lookup shows role={actual_role}",
                        ],
                        expected="Admin role claim rejected or ignored (role assigned by governance only)",
                        actual=f"role={actual_role} for identity={iid2}",
                        evidence={"controller": controller, "entry": entry},
                    )
                    findings.append(f)
                    log.finding(f)
                else:
                    log.info("[S6] admin claim ignored — role assigned correctly ✓",
                             actual_role=actual_role)
    else:
        log.info("[S6] admin re-registration correctly rejected ✓", status=s)

    return findings


# ---------------------------------------------------------------------------
# S7 — Concurrent registration race
# ---------------------------------------------------------------------------

def attack_s7_concurrent_registration(client: httpx.Client, cfg: dict[str, Any]) -> list[FindingRecord]:
    """
    Submit two registrations for the same controller_id simultaneously.
    Only one should be accepted; duplicate identity under one controller
    must not sneak through due to a TOCTOU in the registry.
    """
    findings: list[FindingRecord] = []
    base_url   = _identity_url(cfg)
    controller = f"ctrl-race-{uuid.uuid4().hex[:8]}"
    results: dict[str, tuple[int, dict]] = {}

    def _reg(tag: str) -> None:
        iid = f"identity-race-{tag}-{uuid.uuid4().hex[:6]}"
        s, b = _register(client, base_url, iid, controller)
        results[tag] = (s, b)

    t1 = threading.Thread(target=_reg, args=("A",))
    t2 = threading.Thread(target=_reg, args=("B",))
    t1.start(); t2.start()
    t1.join();  t2.join()

    sa, ba = results.get("A", (0, {}))
    sb, bb = results.get("B", (0, {}))
    log.info("[S7] concurrent registration", status_A=sa, status_B=sb, controller=controller)

    if not _rejected(sa, ba) and not _rejected(sb, bb):
        # Both accepted — check how many are verified
        _, lookup = _lookup(client, base_url, controller)
        verified = [i for i in lookup.get("identities", []) if i.get("verified")]
        if len(verified) > 1:
            f = _finding(
                inv=7,
                title="Concurrent registrations: two identities verified under one controller",
                severity=Severity.CRITICAL,
                steps=[
                    f"Simultaneously POST register for controller={controller} (two threads)",
                    f"Both returned non-error; lookup shows {len(verified)} verified identities",
                ],
                expected="Race resolved: exactly one identity verified per controller",
                actual=f"{len(verified)} verified identities under controller={controller}",
                evidence={
                    "controller": controller,
                    "resp_A": ba, "resp_B": bb,
                    "verified": verified,
                },
            )
            findings.append(f)
            log.finding(f)
        else:
            log.info("[S7] race resolved correctly ✓", verified_count=len(verified))
    else:
        log.info("[S7] at least one registration rejected ✓", status_A=sa, status_B=sb)

    return findings


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ATTACKS = [
    ("S1", "Multi-identity per controller",    attack_s1_multi_identity),
    ("S2", "Registry spam",                    attack_s2_registry_spam),
    ("S3", "Revoke/re-register cycling",       attack_s3_revoke_reregister),
    ("S4", "Self-verify via identity API",     attack_s4_self_verify),
    ("S5", "Cross-epoch quota re-use",         attack_s5_cross_epoch),
    ("S6", "Privilege escalation",             attack_s6_privilege_escalation),
    ("S7", "Concurrent registration race",     attack_s7_concurrent_registration),
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="QCB SybilProbe — devnet-only identity/attestation attack suite"
    )
    parser.add_argument("--config",          required=True, type=Path)
    parser.add_argument("--findings-dir",    type=Path, default=Path("agents/findings"))
    parser.add_argument("--attack",          help="Run only S1..S7")
    parser.add_argument("--unsafe-override", action="store_true")
    args = parser.parse_args()

    cfg = load_config(args.config)
    try:
        chain_id = assert_devnet(cfg, unsafe_override=args.unsafe_override)
    except Exception as exc:
        abort(str(exc)); return

    log.info("SybilProbe starting", chain_id=chain_id)
    args.findings_dir.mkdir(parents=True, exist_ok=True)
    total: list[FindingRecord] = []

    with httpx.Client() as client:
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

    log.info("SybilProbe complete", total_findings=len(total))
    sys.exit(1 if total else 0)


if __name__ == "__main__":
    main()