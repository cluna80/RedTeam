"""
agents/regressions/test_regression_template.py

Template for red-team regression tests.
Copy this file, rename it test_<finding_id>_<slug>.py, and fill in the TODOs.

Conventions (mirror existing phase0/phase1 negative-path tests):
  - pytest.mark.devnet     — only runs with a live devnet (CI gate)
  - pytest.mark.regression — marks a confirmed-exploit regression
  - Each test is SELF-CONTAINED: it sets up, attacks, and asserts in one function.
  - Use httpx.Client for HTTP; do not share state between tests.
  - Assert the *rejection*, not the absence of a response.
  - Include the finding_id in the docstring so it traces back to the finding JSON.

To run:
    # All devnet regressions:
    pytest agents/regressions/ -m devnet -v

    # Single test:
    pytest agents/regressions/test_<slug>.py -v
"""
from __future__ import annotations

import time

import httpx
import pytest

# ---------------------------------------------------------------------------
# Config — override with environment or conftest.py fixtures as needed
# ---------------------------------------------------------------------------
ALICE_API   = "http://127.0.0.1:1317"
BOB_API     = "http://127.0.0.1:1318"
SCHED_URL   = "http://127.0.0.1:8080"
DEVNET_CHAIN = "devnet"


# ---------------------------------------------------------------------------
# Example: INV-1 double-claim regression
# Replace the body with the actual finding's reproduction steps.
# ---------------------------------------------------------------------------

@pytest.mark.devnet
@pytest.mark.regression
def test_double_claim_research_reward_rejected() -> None:
    """
    Regression for INV-1: No double payment per receipt/job.

    Finding: agent2_economic — Double ClaimResearchReward accepted
    Severity: CRITICAL
    Finding ID: <replace with actual finding_id from the JSON>

    Steps:
      1. POST /qcb/pocd/claim_research_reward with a receipt_id (first claim)
      2. POST same endpoint with the same receipt_id (second claim)
      3. Assert second call is rejected (4xx or non-zero code)
    """
    receipt_id = "regression-test-receipt-inv1"
    payload = {
        "submitter": "qcb1alice000000000000000000000000000000000",
        "receipt_id": receipt_id,
        "chain_id": DEVNET_CHAIN,
    }
    url = f"{ALICE_API}/qcb/pocd/claim_research_reward"

    with httpx.Client() as client:
        r1 = client.post(url, json=payload, timeout=10)
        # First call: may succeed or fail depending on whether the receipt
        # exists on this devnet.  We don't assert on it.

        time.sleep(1)

        r2 = client.post(url, json=payload, timeout=10)
        # Second call MUST be rejected.
        assert r2.status_code in (400, 401, 403, 409, 422) or (
            r2.status_code == 200 and r2.json().get("code") not in (None, 0)
        ), (
            f"Expected second claim to be rejected, got {r2.status_code}: {r2.text}"
        )


@pytest.mark.devnet
@pytest.mark.regression
def test_self_dealing_attestation_rejected() -> None:
    """
    Regression for INV-3: Self-controller verification never counts.

    Steps:
      1. Claim a task as controller=ctrl-alice-001
      2. Attempt to attest the same task as the same controller
      3. Assert attestation is rejected
    """
    import uuid
    job_id     = f"regression-self-attest-{uuid.uuid4().hex[:8]}"
    controller = "ctrl-alice-001"
    alice      = "qcb1alice000000000000000000000000000000000"
    output_hash = "aa" * 32

    with httpx.Client() as client:
        # Step 1: claim
        client.post(f"{SCHED_URL}/scheduler/claim_task", json={
            "job_id":        job_id,
            "machine_id":    alice,
            "controller_id": controller,
            "output_hash":   output_hash,
        }, timeout=10)

        # Step 2: self-attest
        r = client.post(f"{SCHED_URL}/scheduler/attest_task", json={
            "job_id":              job_id,
            "verifier_id":         alice,
            "verifier_controller": controller,   # same as miner's controller
            "output_hash":         output_hash,
        }, timeout=10)

        # Step 3: must be rejected
        assert r.status_code in (400, 401, 403, 409, 422) or (
            r.status_code == 200 and r.json().get("code") not in (None, 0)
        ), (
            f"Expected self-attestation rejection, got {r.status_code}: {r.text}"
        )


@pytest.mark.devnet
@pytest.mark.regression
def test_wrong_chain_id_gossip_dropped() -> None:
    """
    Regression for INV-9: Wrong chain_id always dropped.

    Steps:
      1. Inject a DiscoveryProof with chain_id='wrong-mainnet-1'
      2. Assert the node rejects it at the gossip layer
    """
    import uuid, hashlib

    node_rpc = "http://127.0.0.1:26657"
    job_id   = f"regression-chain-id-{uuid.uuid4().hex[:8]}"
    oh       = hashlib.sha256(b"regression-chain-id").hexdigest()

    msg = {
        "job_id":      job_id,
        "machine_id":  "qcb1alice000000000000000000000000000000000",
        "output_hash": oh,
        "seal":        oh,
        "chain_id":    "wrong-mainnet-1",
        "timestamp":   int(time.time()),
        "signature":   "ff" * 64,
    }

    with httpx.Client() as client:
        r = client.post(
            f"{node_rpc}/debug/gossip_inject",
            json={"topic": "DiscoveryProof", "message": msg},
            timeout=10,
        )
        assert r.status_code in (400, 401, 403, 409, 422) or (
            r.status_code == 200 and r.json().get("code") not in (None, 0)
        ), (
            f"Expected wrong chain_id to be dropped, got {r.status_code}: {r.text}"
        )
