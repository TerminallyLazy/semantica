"""Bounded application service for Mae's structural shadow operations."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .contracts import (
    DecisionRecord,
    EventBatchRequest,
    RetrievalRequest,
    RevocationRequest,
    ScopeReferences,
    WireAuthorization,
)
from .storage import TenantPartitionedShadowStore


class MaeShadowService:
    """Maps strict contracts to a tenant-partitioned store without content access."""

    def __init__(self, store: TenantPartitionedShadowStore) -> None:
        self._store = store

    def ready(self) -> bool:
        return self._store.ready()

    def apply_events(self, request: EventBatchRequest) -> dict[str, Any]:
        results = self._store.apply_events(request.authorization.scope, request.events)
        status = "complete"
        if any(
            result["disposition"] not in {"applied", "duplicate"}
            for result in results
        ):
            status = "partial"
        return {
            "schemaVersion": 1,
            "authorization": authorization_wire(request.authorization),
            "status": status,
            "results": results,
        }

    def retrieve(self, request: RetrievalRequest) -> dict[str, Any]:
        result = self._store.retrieve(request)
        return {
            "schemaVersion": 1,
            "requestRef": request.request_ref,
            "authorization": authorization_wire(request.authorization),
            **result,
        }

    def record_decision(self, decision: DecisionRecord) -> dict[str, Any]:
        disposition = self._store.record_decision(decision)
        return {
            "schemaVersion": 1,
            "decisionRef": decision.decision_ref,
            "authorization": authorization_wire(decision.authorization),
            "status": "complete",
            "disposition": disposition,
        }

    def provenance(
        self,
        authorization: WireAuthorization,
        memory_ref: str,
    ) -> dict[str, Any]:
        result = self._store.provenance(authorization.scope, memory_ref)
        return {
            "schemaVersion": 1,
            "memoryRef": memory_ref,
            "authorization": authorization_wire(authorization),
            **result,
        }

    def revoke(self, request: RevocationRequest) -> dict[str, Any]:
        self._store.revoke(request.revocation)
        return {
            "schemaVersion": 1,
            "authorization": authorization_wire(request.authorization),
            "revocationRef": request.revocation.revocation_ref,
            "status": "complete",
            "pending": False,
        }

    def revocation_status(
        self,
        authorization: WireAuthorization,
        revocation_ref: str,
    ) -> dict[str, Any]:
        record = self._store.revocation_status(authorization.scope, revocation_ref)
        return {
            "schemaVersion": 1,
            "authorization": authorization_wire(authorization),
            "revocationRef": revocation_ref,
            "status": "complete" if record is not None else "complete_empty",
            "pending": False,
        }


def scope_wire(scope: ScopeReferences) -> dict[str, str]:
    result = {"accountRef": scope.account_ref, "familyRef": scope.family_ref}
    if scope.member_ref is not None:
        result["memberRef"] = scope.member_ref
    return result


def authorization_wire(authorization: WireAuthorization) -> dict[str, Any]:
    return {
        "scope": scope_wire(authorization.scope),
        "authorizationGeneration": authorization.authorization_generation,
        "sessionBindingRef": authorization.session_binding_ref,
        "issuedAt": timestamp_wire(authorization.issued_at),
        "expiresAt": timestamp_wire(authorization.expires_at),
    }


def timestamp_wire(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )
