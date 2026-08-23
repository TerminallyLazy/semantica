"""Tenant-partitioned structural store interfaces and synthetic reference store."""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol

from .contracts import (
    MAX_PROVENANCE_ENTRIES,
    DecisionRecord,
    EventProjection,
    RetrievalRequest,
    RevocationRecord,
    ScopeReferences,
)


class IdempotencyConflict(RuntimeError):
    pass


class StoreUnavailable(RuntimeError):
    pass


class OperationDeadlineExceeded(RuntimeError):
    pass


@dataclass(frozen=True)
class OperationFence:
    """Request fence that a production transaction must check before commit."""

    request_ref: str
    deadline_monotonic: float

    def remaining(self) -> float:
        return max(0.0, self.deadline_monotonic - time.monotonic())

    def ensure_active(self) -> None:
        if time.monotonic() >= self.deadline_monotonic:
            raise OperationDeadlineExceeded("operation deadline exceeded")


class TenantPartitionedShadowStore(Protocol):
    """Production seam; every operation receives an exact pseudonymous partition.

    A production mutation must carry the fence into its database transaction,
    validate it immediately before the durable commit, and roll back rather
    than commit when the fence is expired or the coroutine is cancelled.
    """

    production_ready: bool

    def ready(self) -> bool: ...

    async def apply_events(
        self,
        scope: ScopeReferences,
        events: tuple[EventProjection, ...],
        fence: OperationFence,
    ) -> list[dict[str, Any]]: ...

    async def retrieve(
        self, request: RetrievalRequest, fence: OperationFence
    ) -> dict[str, Any]: ...

    async def record_decision(
        self, decision: DecisionRecord, fence: OperationFence
    ) -> str: ...

    async def provenance(
        self, scope: ScopeReferences, memory_ref: str, fence: OperationFence
    ) -> dict[str, Any]: ...

    async def revoke(self, revocation: RevocationRecord, fence: OperationFence) -> str: ...

    async def revocation_status(
        self,
        scope: ScopeReferences,
        revocation_ref: str,
        fence: OperationFence,
    ) -> RevocationRecord | None: ...


@dataclass(frozen=True)
class _StoredEvent:
    projection: EventProjection
    payload_digest: str


@dataclass(frozen=True)
class _StoredDecision:
    decision: DecisionRecord
    payload_digest: str


@dataclass(frozen=True)
class _StoredRevocation:
    revocation: RevocationRecord
    payload_digest: str


@dataclass
class _TenantState:
    events_by_memory: dict[str, _StoredEvent] = field(default_factory=dict)
    event_idempotency: dict[str, tuple[str, str, str, str | None]] = field(
        default_factory=dict
    )
    decisions: dict[str, _StoredDecision] = field(default_factory=dict)
    tombstones: dict[str, _StoredRevocation] = field(default_factory=dict)
    revocation_idempotency: dict[str, tuple[str, str]] = field(default_factory=dict)
    revocations_by_ref: dict[str, _StoredRevocation] = field(default_factory=dict)
    adjacency: dict[str, set[str]] = field(default_factory=dict)


class InMemoryTenantPartitionedShadowStore:
    """Bounded synthetic/local reference store; never suitable for real ePHI."""

    production_ready = False

    def __init__(
        self,
        *,
        available: bool = True,
        max_graph_visits: int = 200,
        mutation_delay_seconds: float = 0.0,
    ) -> None:
        self._available = available
        self._max_graph_visits = max_graph_visits
        self._mutation_delay_seconds = mutation_delay_seconds
        self._states: dict[tuple[str, str, str | None], _TenantState] = {}
        self._lock = threading.RLock()

    def ready(self) -> bool:
        return self._available

    def set_available(self, available: bool) -> None:
        self._available = available

    async def apply_events(
        self,
        scope: ScopeReferences,
        events: tuple[EventProjection, ...],
        fence: OperationFence,
    ) -> list[dict[str, Any]]:
        if self._mutation_delay_seconds:
            await asyncio.sleep(self._mutation_delay_seconds)
        prepared = [(event, _payload_digest(event.canonical_payload)) for event in events]
        with self._lock:
            fence.ensure_active()
            state = self._state(scope, create=True)
            for event, digest in prepared:
                existing = state.event_idempotency.get(event.idempotency_ref)
                if existing is not None and existing[:2] != (event.event_ref, digest):
                    raise IdempotencyConflict("event idempotency conflict")

            fence.ensure_active()
            results: list[dict[str, Any]] = []
            for event, digest in prepared:
                existing = state.event_idempotency.get(event.idempotency_ref)
                if existing is not None:
                    if existing[2] == "applied":
                        disposition = "duplicate"
                        error_code = None
                    else:
                        disposition = existing[2]
                        error_code = existing[3]
                elif event.memory_ref in state.tombstones or any(
                    link.target_ref in state.tombstones for link in event.links
                ):
                    disposition = "permanent"
                    error_code = "permanent_rejection"
                    state.event_idempotency[event.idempotency_ref] = (
                        event.event_ref,
                        digest,
                        disposition,
                        error_code,
                    )
                else:
                    disposition = "applied"
                    error_code = None
                    state.event_idempotency[event.idempotency_ref] = (
                        event.event_ref,
                        digest,
                        disposition,
                        error_code,
                    )
                    state.events_by_memory[event.memory_ref] = _StoredEvent(event, digest)
                    self._replace_edges(state, event)
                results.append(
                    {
                        "eventRef": event.event_ref,
                        "idempotencyRef": event.idempotency_ref,
                        "disposition": disposition,
                        "errorCode": error_code,
                    }
                )
            return results

    async def retrieve(
        self, request: RetrievalRequest, fence: OperationFence
    ) -> dict[str, Any]:
        with self._lock:
            fence.ensure_active()
            state = self._state(request.authorization.scope, create=False)
            eligible = []
            omitted: set[str] = set()
            for mapping in request.candidate_mappings:
                if mapping.candidate_ref in state.tombstones:
                    omitted.add("revoked")
                    continue
                stored = state.events_by_memory.get(mapping.candidate_ref)
                if stored is None:
                    omitted.add("unhydrated")
                    continue
                eligible.append((mapping, stored.projection))

            distances, budget_exhausted = self._distances(
                state,
                request.anchor_refs,
                request.max_hops,
            )
            ranked = []
            for mapping, projection in eligible:
                if request.anchor_refs:
                    distance = distances.get(mapping.candidate_ref)
                    if distance is None:
                        continue
                else:
                    distance = 0
                ranked.append((distance, mapping.candidate_ref, mapping.mapping_ref, mapping, projection))
            ranked.sort(key=lambda item: item[:3])
            selected = ranked[: request.candidate_limit]
            if request.candidate_limit > 0 and len(ranked) > request.candidate_limit:
                omitted.add("result_budget")

            candidates = []
            for distance, _, _, mapping, projection in selected:
                reasons = ["lifecycle_match", "freshness_match"]
                if request.anchor_refs:
                    reasons.insert(0, "structural_proximity")
                if projection.lineage_refs:
                    reasons.append("provenance_match")
                candidates.append(
                    {
                        "memoryRef": mapping.candidate_ref,
                        "mappingRef": mapping.mapping_ref,
                        "scope": _scope_wire(mapping.scope),
                        "reasons": reasons,
                        "graphHops": distance,
                        "lifecycle": projection.lifecycle,
                        "freshness": projection.freshness,
                    }
                )

            if budget_exhausted:
                omitted.add("result_budget")
                status = "partial" if candidates else "unavailable"
            elif candidates and omitted:
                status = "partial"
            elif candidates:
                status = "complete"
            else:
                status = "complete_empty"
            return {
                "status": status,
                "candidates": candidates,
                "omissionCodes": sorted(omitted),
            }

    async def record_decision(
        self, decision: DecisionRecord, fence: OperationFence
    ) -> str:
        if self._mutation_delay_seconds:
            await asyncio.sleep(self._mutation_delay_seconds)
        with self._lock:
            fence.ensure_active()
            state = self._state(decision.authorization.scope, create=True)
            digest = _payload_digest(decision.canonical_payload)
            existing = state.decisions.get(decision.idempotency_ref)
            if existing is not None:
                if existing.payload_digest != digest:
                    raise IdempotencyConflict("decision idempotency conflict")
                return "duplicate"
            fence.ensure_active()
            state.decisions[decision.idempotency_ref] = _StoredDecision(decision, digest)
            return "applied"

    async def provenance(
        self,
        scope: ScopeReferences,
        memory_ref: str,
        fence: OperationFence,
    ) -> dict[str, Any]:
        with self._lock:
            fence.ensure_active()
            state = self._state(scope, create=False)
            if memory_ref in state.tombstones:
                return {"status": "complete_empty", "entries": [], "omissionCodes": ["revoked"]}
            stored = state.events_by_memory.get(memory_ref)
            if stored is None:
                return {"status": "complete_empty", "entries": [], "omissionCodes": []}
            projection = stored.projection
            entries = [
                {
                    "kind": "event",
                    "referenceRef": projection.event_ref,
                    "occurredAt": projection.occurred_at,
                    "lifecycle": projection.lifecycle,
                },
                {
                    "kind": "integrity",
                    "referenceRef": projection.integrity_ref,
                    "occurredAt": projection.occurred_at,
                    "lifecycle": projection.lifecycle,
                },
            ]
            entries.extend(
                {
                    "kind": "lineage",
                    "referenceRef": reference,
                    "occurredAt": projection.occurred_at,
                    "lifecycle": projection.lifecycle,
                }
                for reference in projection.lineage_refs
            )
            entries.extend(
                {
                    "kind": link.kind,
                    "referenceRef": link.target_ref,
                    "occurredAt": projection.occurred_at,
                    "lifecycle": projection.lifecycle,
                }
                for link in projection.links
            )
            entries.sort(key=lambda item: (item["kind"], item["referenceRef"]))
            omitted = []
            if len(entries) > MAX_PROVENANCE_ENTRIES:
                entries = entries[:MAX_PROVENANCE_ENTRIES]
                omitted = ["result_budget"]
            return {
                "status": "partial" if omitted else "complete",
                "entries": entries,
                "omissionCodes": omitted,
            }

    async def revoke(self, revocation: RevocationRecord, fence: OperationFence) -> str:
        if self._mutation_delay_seconds:
            await asyncio.sleep(self._mutation_delay_seconds)
        with self._lock:
            fence.ensure_active()
            state = self._state(revocation.scope, create=True)
            digest = _payload_digest(revocation.canonical_payload)
            existing = state.revocation_idempotency.get(revocation.idempotency_ref)
            if existing is not None:
                if existing != (revocation.revocation_ref, digest):
                    raise IdempotencyConflict("revocation idempotency conflict")
                return "duplicate"
            fence.ensure_active()
            stored = _StoredRevocation(revocation, digest)
            state.revocation_idempotency[revocation.idempotency_ref] = (
                revocation.revocation_ref,
                digest,
            )
            state.revocations_by_ref[revocation.revocation_ref] = stored
            state.tombstones[revocation.memory_ref] = stored
            state.events_by_memory.pop(revocation.memory_ref, None)
            state.adjacency.pop(revocation.memory_ref, None)
            for neighbors in state.adjacency.values():
                neighbors.discard(revocation.memory_ref)
            return "applied"

    async def revocation_status(
        self,
        scope: ScopeReferences,
        revocation_ref: str,
        fence: OperationFence,
    ) -> RevocationRecord | None:
        with self._lock:
            fence.ensure_active()
            stored = self._state(scope, create=False).revocations_by_ref.get(
                revocation_ref
            )
            return stored.revocation if stored is not None else None

    def _state(self, scope: ScopeReferences, *, create: bool) -> _TenantState:
        if not self._available:
            raise StoreUnavailable("shadow store unavailable")
        if create:
            return self._states.setdefault(scope.partition, _TenantState())
        return self._states.get(scope.partition, _TenantState())

    def _replace_edges(self, state: _TenantState, event: EventProjection) -> None:
        for neighbors in state.adjacency.values():
            neighbors.discard(event.memory_ref)
        state.adjacency[event.memory_ref] = set()
        for link in event.links:
            state.adjacency[event.memory_ref].add(link.target_ref)
            state.adjacency.setdefault(link.target_ref, set()).add(event.memory_ref)

    def _distances(
        self,
        state: _TenantState,
        anchors: tuple[str, ...],
        max_hops: int,
    ) -> tuple[dict[str, int], bool]:
        distances = {anchor: 0 for anchor in sorted(set(anchors))}
        queue = deque(sorted(distances))
        visits = 0
        while queue:
            current = queue.popleft()
            visits += 1
            if visits > self._max_graph_visits:
                return distances, True
            distance = distances[current]
            if distance >= max_hops:
                continue
            for neighbor in sorted(state.adjacency.get(current, set())):
                if neighbor not in distances:
                    distances[neighbor] = distance + 1
                    queue.append(neighbor)
        return distances, False


def _payload_digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _scope_wire(scope: ScopeReferences) -> dict[str, str]:
    result = {"accountRef": scope.account_ref, "familyRef": scope.family_ref}
    if scope.member_ref is not None:
        result["memberRef"] = scope.member_ref
    return result
