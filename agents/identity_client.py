"""
agents/identity_client.py — thin client for the 5 attestation-guard on-chain
tx types used by the identity pilot.

All transactions are submitted via POST /api/tx using the chain-forge-node
Transaction envelope format:
    {
        "id":        "<uuid>",
        "sender":    "<caller address>",
        "nonce":     <u64>,
        "gas_limit": <u64>,
        "body":      { "<TxVariant>": { <fields> } }
    }

Tx types (per Qattice attestation guard spec):
  Phase A — Attest              : bind a human attestation to an entity
                                  (chain TxBody::Attest { claimant_id })
  Phase B — RevokeAttestation   : revoke a previously issued attestation
                                  (chain TxBody::RevokeAttestation { attested_id })
  Phase C — ConfirmSybil        : confirm an entity is a sybil (freezes it)
                                  (chain TxBody::ConfirmSybil { sybil_id })
  Phase D — ReportSuspectedSybil: flag an entity for review (no immediate freeze)
                                  (chain TxBody::ReportSuspectedSybil { suspected_id })
  Phase D — ReverseSybil        : undo a ConfirmSybil after a successful appeal
                                  (chain TxBody::ReverseSybil { sybil_id })

Identity lookup:
  GET /api/identity/{address} — returns registered, tier, frozen, sybil_confirmed

Verified against chain-forge-node/src/api.rs and chain-forge-execution/src/lib.rs.
"""
from __future__ import annotations

import uuid
from typing import Any

import httpx

# ---------------------------------------------------------------------------
# Tx-type constants — match TxBody enum variant names in chain-forge-execution
# ---------------------------------------------------------------------------
TX_ATTEST_ENTITY           = "Attest"               # Phase A: TxBody::Attest { claimant_id }
TX_REVOKE_ATTESTATION      = "RevokeAttestation"    # Phase B: TxBody::RevokeAttestation { attested_id }
TX_CONFIRM_SYBIL           = "ConfirmSybil"         # Phase C: TxBody::ConfirmSybil { sybil_id }
TX_REPORT_SUSPECTED_SYBIL  = "ReportSuspectedSybil" # Phase D: TxBody::ReportSuspectedSybil { suspected_id }
TX_REVERSE_SYBIL           = "ReverseSybil"         # Phase D: TxBody::ReverseSybil { sybil_id }
TX_REGISTER_IDENTITY       = "RegisterIdentity"     # Phase 0: TxBody::RegisterIdentity (no fields)

# Default gas limit for identity-pilot transactions.
_DEFAULT_GAS = 50_000

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_nonce_counter: dict[str, int] = {}

def _fetch_chain_nonce(api_url: str, sender: str, timeout: float = 5.0) -> int | None:
    """
    Query GET /api/accounts/{sender} and return the on-chain nonce.
    The chain's nonce field is the *next expected* nonce for that sender.
    Returns None if the endpoint is unavailable or the address is not found.
    """
    try:
        r = httpx.get(f"{api_url}/api/accounts/{sender}", timeout=timeout)
        if r.status_code == 200:
            return int(r.json().get("nonce", 0))
    except Exception:
        pass
    return None


def _next_nonce(sender: str, api_url: str | None = None) -> int:
    """
    Return the next nonce for sender.

    If api_url is provided and the chain is reachable, fetch the authoritative
    nonce from the chain (avoids mismatch when prior txs failed).  Falls back
    to the local counter if the chain is not reachable.
    """
    if api_url is not None:
        chain_nonce = _fetch_chain_nonce(api_url, sender)
        if chain_nonce is not None:
            # Ensure local counter is at least as high as the chain nonce
            _nonce_counter[sender] = max(_nonce_counter.get(sender, 0), chain_nonce) + 1
            return chain_nonce
    n = _nonce_counter.get(sender, 0)
    _nonce_counter[sender] = n + 1
    return n


def _post_tx(
    client: httpx.Client,
    api_url: str,
    sender: str,
    body_variant: str,
    body_fields: dict[str, Any],
    timeout: float = 10.0,
    nonce: int | None = None,
) -> tuple[int, dict[str, Any]]:
    """
    Wrap a tx payload in the chain-forge Transaction envelope and POST to /api/tx.
    Returns (http_status, parsed_body).

    The envelope format is:
        {
            "id":        "<uuid>",
            "sender":    "<sender address>",
            "nonce":     <u64>,
            "gas_limit": <u64>,
            "body":      { "<TxVariant>": <fields or null> }
        }

    For unit variants (RegisterIdentity) body_fields should be {}.
    The server serialises TxBody as an externally-tagged enum:
        {"RegisterIdentity": null}  or  {"ConfirmSybil": {"sybil_id": "..."}}
    """
    if nonce is None:
        nonce = _next_nonce(sender, api_url=api_url)

    # Externally-tagged serde enum:
    #   unit variant  -> {"RegisterIdentity": null}
    #   struct variant -> {"ConfirmSybil": {"sybil_id": "..."}}
    if body_fields:
        body_value: Any = body_fields
    else:
        body_value = None

    tx = {
        "id":        str(uuid.uuid4()),
        "sender":    sender,
        "nonce":     nonce,
        "gas_limit": _DEFAULT_GAS,
        "body":      {body_variant: body_value},
    }
    try:
        r = client.post(f"{api_url}/api/tx", json=tx, timeout=timeout)
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


def queued(status: int, body: dict[str, Any]) -> bool:
    """Return True when the node accepted the transaction into the mempool."""
    return status == 200 and body.get("status") == "queued"


# ---------------------------------------------------------------------------
# Phase 0 — RegisterIdentity
# ---------------------------------------------------------------------------

def register_identity(
    client: httpx.Client,
    api_url: str,
    *,
    sender: str,
    nonce: int | None = None,
) -> tuple[int, dict[str, Any]]:
    """
    Submit a RegisterIdentity tx.  The sender registers themselves as a
    Provisional identity.  No fields beyond sender are required.

    TxBody::RegisterIdentity (unit variant — serialises as {"RegisterIdentity": null}).
    """
    return _post_tx(client, api_url, sender, TX_REGISTER_IDENTITY, {}, nonce=nonce)


# ---------------------------------------------------------------------------
# Phase A — Attest (maps to AttestEntity in the pilot spec)
# ---------------------------------------------------------------------------

def attest_entity(
    client: httpx.Client,
    api_url: str,
    *,
    entity_id: str,           # claimant being attested (must != attester)
    subject_controller: str,  # unused by chain — kept for test-script symmetry
    attester_controller: str, # the sender / attesting address
    attestation_proof: str = "aa" * 32,  # unused in Phase 0; kept for API compat
    nonce: int | None = None,
) -> tuple[int, dict[str, Any]]:
    """
    Submit a Phase-A Attest transaction.

    The attestation guard rejects if attester_controller == entity_id
    (self-attestation, INV-11) or if the same pair has already attested
    this epoch.

    TxBody::Attest { claimant_id } — sender is the attester.
    Self-attest rejection: IdentityStore::attest() returns SelfAttestation
    when claimant_id == sender; the executor returns an error which the
    node maps to a 200 with success=false (queued but fails at execution).
    """
    return _post_tx(
        client, api_url, attester_controller,
        TX_ATTEST_ENTITY, {"claimant_id": entity_id},
        nonce=nonce,
    )


# ---------------------------------------------------------------------------
# Phase B — RevokeAttestation
# ---------------------------------------------------------------------------

def revoke_attestation(
    client: httpx.Client,
    api_url: str,
    *,
    entity_id: str,           # attested_id — the identity whose attestation is revoked
    revoker_controller: str,  # sender — the attester who is revoking
    reason: str = "manual_revocation",  # informational only; not sent on-chain
    nonce: int | None = None,
) -> tuple[int, dict[str, Any]]:
    """
    Submit a Phase-B RevokeAttestation transaction.

    After confirmation the entity's pop_verified MUST become false (INV-12)
    unless other attesters still meet quorum.

    TxBody::RevokeAttestation { attested_id } — sender is the revoker.
    """
    return _post_tx(
        client, api_url, revoker_controller,
        TX_REVOKE_ATTESTATION, {"attested_id": entity_id},
        nonce=nonce,
    )


# ---------------------------------------------------------------------------
# Phase C — ConfirmSybil
# ---------------------------------------------------------------------------

def confirm_sybil(
    client: httpx.Client,
    api_url: str,
    *,
    entity_id: str,              # sybil_id — the identity being confirmed
    reporter_controller: str,    # sender — must be the attestation coordinator
    evidence_hash: str = "bb" * 32,  # informational; not sent on-chain in Phase 0
    nonce: int | None = None,
) -> tuple[int, dict[str, Any]]:
    """
    Submit a Phase-C ConfirmSybil transaction.

    The chain MUST atomically freeze the entity on block inclusion (INV-13).
    Caller must be the attestation_coordinator from genesis.

    TxBody::ConfirmSybil { sybil_id } — sender is the coordinator.
    """
    return _post_tx(
        client, api_url, reporter_controller,
        TX_CONFIRM_SYBIL, {"sybil_id": entity_id},
        nonce=nonce,
    )


# ---------------------------------------------------------------------------
# Phase D — ReportSuspectedSybil
# ---------------------------------------------------------------------------

def report_suspected_sybil(
    client: httpx.Client,
    api_url: str,
    *,
    entity_id: str,              # suspected_id
    reporter_controller: str,    # sender — must have an active attestation for entity_id
    suspicion_reason: str = "unusual_attestation_pattern",  # informational
    nonce: int | None = None,
) -> tuple[int, dict[str, Any]]:
    """
    Submit a Phase-D ReportSuspectedSybil transaction.

    MUST NOT freeze the entity or affect pop_verified (INV-14).
    Only ConfirmSybil may freeze.

    TxBody::ReportSuspectedSybil { suspected_id } — sender is the reporter.
    """
    return _post_tx(
        client, api_url, reporter_controller,
        TX_REPORT_SUSPECTED_SYBIL, {"suspected_id": entity_id},
        nonce=nonce,
    )


# ---------------------------------------------------------------------------
# Phase D — ReverseSybil
# ---------------------------------------------------------------------------

def reverse_sybil(
    client: httpx.Client,
    api_url: str,
    *,
    entity_id: str,               # sybil_id — the identity being un-frozen
    authority_controller: str,    # sender — must be the attestation coordinator
    appeal_proof: str = "cc" * 32,  # informational; not sent on-chain in Phase 0
    nonce: int | None = None,
) -> tuple[int, dict[str, Any]]:
    """
    Submit a Phase-D ReverseSybil transaction (appeal / undo ConfirmSybil).

    MUST unfreeze the entity and restore pop_verified to its pre-freeze state.

    TxBody::ReverseSybil { sybil_id } — sender is the coordinator.
    """
    return _post_tx(
        client, api_url, authority_controller,
        TX_REVERSE_SYBIL, {"sybil_id": entity_id},
        nonce=nonce,
    )


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def get_entity_status(
    client: httpx.Client,
    api_url: str,
    entity_id: str,
) -> tuple[int, dict[str, Any]]:
    """
    GET /api/identity/{entity_id} — fetch current identity state.

    Returns fields: address, registered, tier, exemption_days,
                    frozen, sybil_confirmed.

    frozen and sybil_confirmed are the INV-13 fields added in this patch.
    """
    try:
        r = client.get(f"{api_url}/api/identity/{entity_id}", timeout=10.0)
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
    GET /api/identity/pilot/stats — fetch sybil-rate metrics.

    Note: this endpoint is not yet implemented in chain-forge-node (INV-15
    medium finding). Returns 200 with the address-lookup fallback response
    until the endpoint is added to api.rs.
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
