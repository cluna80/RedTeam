"""
agents/identity_client.py — thin client for the 5 attestation-guard on-chain
tx types used by the identity pilot.

All transactions are submitted via POST /api/tx (the chain-forge-node REST
endpoint).  The caller is responsible for signing; this module constructs the
payload shapes and returns (status_code, body) tuples so attack scripts can
assert on the results without coupling to httpx directly.

Tx types (per Qattice attestation guard spec):
  Phase A — AttestEntity         : bind a human attestation to an entity
  Phase B — RevokeAttestation    : revoke a previously issued attestation
  Phase C — ConfirmSybil         : confirm an entity is a sybil (freezes it)
  Phase D — ReportSuspectedSybil : flag an entity for review (no immediate freeze)
  Phase D — ReverseSybil         : undo a ConfirmSybil after a successful appeal

[ASSUMPTION] All field names below mirror the on-chain structs.
Real names: grep -rn 'AttestEntity\|RevokeAttestation\|ConfirmSybil' chain-forge-node/src/
"""
from __future__ import annotations

import uuid
from typing import Any

import httpx

# ---------------------------------------------------------------------------
# Tx-type string constants — [ASSUMPTION] must match on-chain enum variants
# ---------------------------------------------------------------------------
TX_ATTEST_ENTITY           = "AttestEntity"
TX_REVOKE_ATTESTATION      = "RevokeAttestation"
TX_CONFIRM_SYBIL           = "ConfirmSybil"
TX_REPORT_SUSPECTED_SYBIL  = "ReportSuspectedSybil"
TX_REVERSE_SYBIL           = "ReverseSybil"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _post_tx(
    client: httpx.Client,
    api_url: str,
    tx_type: str,
    payload: dict[str, Any],
    timeout: float = 10.0,
) -> tuple[int, dict[str, Any]]:
    """
    Wrap a tx payload in the standard envelope and POST to /api/tx.
    Returns (http_status, parsed_body).
    """
    envelope = {
        "type":    tx_type,
        "payload": payload,
        # [ASSUMPTION] nonce field name; may be "seq" or "sequence"
        "nonce":   payload.pop("_nonce", str(uuid.uuid4())),
    }
    try:
        r = client.post(f"{api_url}/api/tx", json=envelope, timeout=timeout)
        try:
            body: dict[str, Any] = r.json()
        except Exception:
            body = {"raw": r.text[:500]}
        return r.status_code, body
    except Exception as exc:
        return 0, {"error": str(exc)}


def rejected(status: int, body: dict[str, Any]) -> bool:
    """Return True when the node rejected the transaction."""
    if status in (400, 401, 403, 409, 422):
        return True
    # Some nodes return 200 with an error code in the body
    if status == 200 and body.get("code") not in (None, 0):
        return True
    return False


# ---------------------------------------------------------------------------
# Phase A — AttestEntity
# ---------------------------------------------------------------------------

def attest_entity(
    client: httpx.Client,
    api_url: str,
    *,
    entity_id: str,
    subject_controller: str,
    attester_controller: str,
    attestation_proof: str = "aa" * 32,   # [ASSUMPTION] hash / ZK proof
    nonce: str | None = None,
) -> tuple[int, dict[str, Any]]:
    """
    Submit a Phase-A AttestEntity transaction.

    The attestation guard MUST reject if attester_controller == subject_controller
    (INV-11) or if the same pair has already attested this epoch.

    [ASSUMPTION] field names: entity_id, subject_controller, attester_controller,
    attestation_proof
    Real names: grep 'struct AttestEntity' chain-forge-node/src/
    """
    payload: dict[str, Any] = {
        "entity_id":           entity_id,
        "subject_controller":  subject_controller,
        "attester_controller": attester_controller,
        "attestation_proof":   attestation_proof,
    }
    if nonce:
        payload["_nonce"] = nonce
    return _post_tx(client, api_url, TX_ATTEST_ENTITY, payload)


# ---------------------------------------------------------------------------
# Phase B — RevokeAttestation
# ---------------------------------------------------------------------------

def revoke_attestation(
    client: httpx.Client,
    api_url: str,
    *,
    entity_id: str,
    revoker_controller: str,
    reason: str = "manual_revocation",
    nonce: str | None = None,
) -> tuple[int, dict[str, Any]]:
    """
    Submit a Phase-B RevokeAttestation transaction.

    After confirmation the entity's pop_verified MUST become false (INV-12).

    [ASSUMPTION] field names: entity_id, revoker_controller, reason
    """
    payload: dict[str, Any] = {
        "entity_id":          entity_id,
        "revoker_controller": revoker_controller,
        "reason":             reason,
    }
    if nonce:
        payload["_nonce"] = nonce
    return _post_tx(client, api_url, TX_REVOKE_ATTESTATION, payload)


# ---------------------------------------------------------------------------
# Phase C — ConfirmSybil
# ---------------------------------------------------------------------------

def confirm_sybil(
    client: httpx.Client,
    api_url: str,
    *,
    entity_id: str,
    reporter_controller: str,
    evidence_hash: str = "bb" * 32,
    nonce: str | None = None,
) -> tuple[int, dict[str, Any]]:
    """
    Submit a Phase-C ConfirmSybil transaction.

    The chain MUST atomically freeze the entity on block inclusion (INV-13).
    No reward or influence event may target the entity after this tx confirms.

    [ASSUMPTION] field names: entity_id, reporter_controller, evidence_hash
    """
    payload: dict[str, Any] = {
        "entity_id":          entity_id,
        "reporter_controller": reporter_controller,
        "evidence_hash":      evidence_hash,
    }
    if nonce:
        payload["_nonce"] = nonce
    return _post_tx(client, api_url, TX_CONFIRM_SYBIL, payload)


# ---------------------------------------------------------------------------
# Phase D — ReportSuspectedSybil
# ---------------------------------------------------------------------------

def report_suspected_sybil(
    client: httpx.Client,
    api_url: str,
    *,
    entity_id: str,
    reporter_controller: str,
    suspicion_reason: str = "unusual_attestation_pattern",
    nonce: str | None = None,
) -> tuple[int, dict[str, Any]]:
    """
    Submit a Phase-D ReportSuspectedSybil transaction.

    MUST NOT freeze the entity or affect pop_verified (INV-14).
    Only ConfirmSybil may freeze.

    [ASSUMPTION] field names: entity_id, reporter_controller, suspicion_reason
    """
    payload: dict[str, Any] = {
        "entity_id":          entity_id,
        "reporter_controller": reporter_controller,
        "suspicion_reason":   suspicion_reason,
    }
    if nonce:
        payload["_nonce"] = nonce
    return _post_tx(client, api_url, TX_REPORT_SUSPECTED_SYBIL, payload)


# ---------------------------------------------------------------------------
# Phase D — ReverseSybil
# ---------------------------------------------------------------------------

def reverse_sybil(
    client: httpx.Client,
    api_url: str,
    *,
    entity_id: str,
    authority_controller: str,
    appeal_proof: str = "cc" * 32,
    nonce: str | None = None,
) -> tuple[int, dict[str, Any]]:
    """
    Submit a Phase-D ReverseSybil transaction (appeal / undo ConfirmSybil).

    MUST unfreeze the entity and restore pop_verified to its pre-freeze state.
    The entity MUST NOT remain frozen after this tx confirms.

    [ASSUMPTION] field names: entity_id, authority_controller, appeal_proof
    """
    payload: dict[str, Any] = {
        "entity_id":           entity_id,
        "authority_controller": authority_controller,
        "appeal_proof":        appeal_proof,
    }
    if nonce:
        payload["_nonce"] = nonce
    return _post_tx(client, api_url, TX_REVERSE_SYBIL, payload)


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def get_entity_status(
    client: httpx.Client,
    api_url: str,
    entity_id: str,
) -> tuple[int, dict[str, Any]]:
    """
    GET /api/identity/entity/{entity_id} — fetch current pop_verified,
    frozen, sybil_confirmed, and attestation_count fields.

    [ASSUMPTION] endpoint path
    Real path: grep 'entity\|pop_verified' chain-forge-node/src/api/
    """
    try:
        r = client.get(f"{api_url}/api/identity/entity/{entity_id}", timeout=10.0)
        try:
            body: dict[str, Any] = r.json()
        except Exception:
            body = {"raw": r.text[:500]}
        return r.status_code, body
    except Exception as exc:
        return 0, {"error": str(exc)}


def get_pilot_stats(
    client: httpx.Client,
    api_url: str,
) -> tuple[int, dict[str, Any]]:
    """
    GET /api/identity/pilot/stats — fetch sybil_rate, total_verified,
    total_confirmed_sybil, and cost_per_verification metrics.

    [ASSUMPTION] endpoint path
    Real path: grep 'pilot.*stats\|sybil_rate' chain-forge-node/src/api/
    """
    try:
        r = client.get(f"{api_url}/api/identity/pilot/stats", timeout=10.0)
        try:
            body: dict[str, Any] = r.json()
        except Exception:
            body = {"raw": r.text[:500]}
        return r.status_code, body
    except Exception as exc:
        return 0, {"error": str(exc)}
