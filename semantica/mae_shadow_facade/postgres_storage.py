"""Durable PostgreSQL implementation of Mae's bounded shadow store."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections import deque
from datetime import datetime
from typing import Any, Mapping

from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from .contracts import (
    MAX_PROVENANCE_ENTRIES,
    DecisionRecord,
    EventProjection,
    RetrievalRequest,
    RevocationRecord,
    ScopeReferences,
)
from .storage import (
    IdempotencyConflict,
    OperationDeadlineExceeded,
    OperationFence,
    StoreUnavailable,
)


def _tenant(scope: ScopeReferences) -> tuple[str, str, str]:
    return scope.account_ref, scope.family_ref, scope.member_ref or ""


def _digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _scope_wire(scope: ScopeReferences) -> dict[str, str]:
    result = {"accountRef": scope.account_ref, "familyRef": scope.family_ref}
    if scope.member_ref is not None:
        result["memberRef"] = scope.member_ref
    return result


class PostgresTenantPartitionedShadowStore:
    production_ready = True

    def __init__(self, pool: ConnectionPool, *, max_graph_visits: int = 200) -> None:
        self._pool = pool
        self._max_graph_visits = max_graph_visits

    def ready(self) -> bool:
        try:
            with self._pool.connection(timeout=1) as connection:
                row = connection.execute(
                    "SELECT version FROM mae_shadow.schema_version WHERE singleton = true"
                ).fetchone()
                return row is not None and row[0] == 3
        except Exception:
            return False

    async def apply_events(
        self,
        scope: ScopeReferences,
        events: tuple[EventProjection, ...],
        fence: OperationFence,
    ) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._apply_events, scope, events, fence)

    def _apply_events(
        self,
        scope: ScopeReferences,
        events: tuple[EventProjection, ...],
        fence: OperationFence,
    ) -> list[dict[str, Any]]:
        tenant = _tenant(scope)
        try:
            with self._pool.connection() as connection, connection.transaction():
                results = []
                for event in events:
                    fence.ensure_active()
                    digest = _digest(event.canonical_payload)
                    prior = connection.execute(
                        """SELECT event_ref, payload_digest, disposition, error_code
                           FROM mae_shadow.event_idempotency
                           WHERE account_ref=%s AND family_ref=%s AND member_ref=%s
                             AND idempotency_ref=%s FOR UPDATE""",
                        (*tenant, event.idempotency_ref),
                    ).fetchone()
                    if prior:
                        if prior[0] != event.event_ref or prior[1] != digest:
                            raise IdempotencyConflict("event idempotency conflict")
                        disposition = "duplicate" if prior[2] == "applied" else prior[2]
                        results.append(
                            {
                                "eventRef": event.event_ref,
                                "idempotencyRef": event.idempotency_ref,
                                "disposition": disposition,
                                "errorCode": prior[3],
                            }
                        )
                        continue
                    targets = [
                        event.memory_ref,
                        *(link.target_ref for link in event.links),
                    ]
                    tombstone = connection.execute(
                        """SELECT 1 FROM mae_shadow.revocations
                           WHERE account_ref=%s AND family_ref=%s AND member_ref=%s
                             AND memory_ref = ANY(%s) LIMIT 1""",
                        (*tenant, targets),
                    ).fetchone()
                    disposition = "permanent" if tombstone else "applied"
                    error_code = "permanent_rejection" if tombstone else None
                    connection.execute(
                        """INSERT INTO mae_shadow.event_idempotency
                           (account_ref,family_ref,member_ref,idempotency_ref,event_ref,payload_digest,disposition,error_code)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (
                            *tenant,
                            event.idempotency_ref,
                            event.event_ref,
                            digest,
                            disposition,
                            error_code,
                        ),
                    )
                    if not tombstone:
                        connection.execute(
                            """INSERT INTO mae_shadow.projections
                               (account_ref,family_ref,member_ref,memory_ref,event_ref,facet,authority,
                                sensitivity,retention,lifecycle,freshness,occurred_at,integrity_ref,
                                lineage_refs,links,payload_digest,canonical_payload)
                               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                               ON CONFLICT (account_ref,family_ref,member_ref,memory_ref) DO UPDATE SET
                                 event_ref=EXCLUDED.event_ref, facet=EXCLUDED.facet,
                                 authority=EXCLUDED.authority, sensitivity=EXCLUDED.sensitivity,
                                 retention=EXCLUDED.retention, lifecycle=EXCLUDED.lifecycle,
                                 freshness=EXCLUDED.freshness, occurred_at=EXCLUDED.occurred_at,
                                 integrity_ref=EXCLUDED.integrity_ref, lineage_refs=EXCLUDED.lineage_refs,
                                 links=EXCLUDED.links, payload_digest=EXCLUDED.payload_digest,
                                 canonical_payload=EXCLUDED.canonical_payload, updated_at=now()""",
                            (
                                *tenant,
                                event.memory_ref,
                                event.event_ref,
                                event.facet,
                                event.authority,
                                event.sensitivity,
                                event.retention,
                                event.lifecycle,
                                event.freshness,
                                event.occurred_at,
                                event.integrity_ref,
                                list(event.lineage_refs),
                                Jsonb(
                                    [
                                        {
                                            "kind": link.kind,
                                            "targetRef": link.target_ref,
                                        }
                                        for link in event.links
                                    ]
                                ),
                                digest,
                                Jsonb(dict(event.canonical_payload)),
                            ),
                        )
                    results.append(
                        {
                            "eventRef": event.event_ref,
                            "idempotencyRef": event.idempotency_ref,
                            "disposition": disposition,
                            "errorCode": error_code,
                        }
                    )
                fence.ensure_active()
                return results
        except (IdempotencyConflict, OperationDeadlineExceeded):
            raise
        except Exception as error:
            raise StoreUnavailable("shadow mutation unavailable") from error

    async def retrieve(
        self, request: RetrievalRequest, fence: OperationFence
    ) -> dict[str, Any]:
        return await asyncio.to_thread(self._retrieve, request, fence)

    def _retrieve(
        self, request: RetrievalRequest, fence: OperationFence
    ) -> dict[str, Any]:
        tenant = _tenant(request.authorization.scope)
        try:
            with self._pool.connection() as connection:
                fence.ensure_active()
                rows = connection.execute(
                    """SELECT memory_ref,event_ref,lifecycle,freshness,occurred_at,integrity_ref,lineage_refs,links
                       FROM mae_shadow.projections
                       WHERE account_ref=%s AND family_ref=%s AND member_ref=%s""",
                    tenant,
                ).fetchall()
                revoked = {
                    row[0]
                    for row in connection.execute(
                        """SELECT memory_ref FROM mae_shadow.revocations
                           WHERE account_ref=%s AND family_ref=%s AND member_ref=%s""",
                        tenant,
                    ).fetchall()
                }
            projections = {row[0]: row for row in rows}
            adjacency: dict[str, set[str]] = {}
            for row in rows:
                adjacency.setdefault(row[0], set())
                for link in row[7] or []:
                    target = link["targetRef"]
                    adjacency[row[0]].add(target)
                    adjacency.setdefault(target, set()).add(row[0])
            distances, exhausted = self._distances(
                adjacency, request.anchor_refs, request.max_hops
            )
            eligible = []
            omitted: set[str] = set()
            for mapping in request.candidate_mappings:
                if mapping.candidate_ref in revoked:
                    omitted.add("revoked")
                    continue
                projection = projections.get(mapping.candidate_ref)
                if projection is None:
                    omitted.add("unhydrated")
                    continue
                distance = (
                    distances.get(mapping.candidate_ref) if request.anchor_refs else 0
                )
                if distance is None:
                    continue
                eligible.append(
                    (
                        distance,
                        mapping.candidate_ref,
                        mapping.mapping_ref,
                        mapping,
                        projection,
                    )
                )
            eligible.sort(key=lambda item: item[:3])
            selected = eligible[: request.candidate_limit]
            if request.candidate_limit > 0 and len(eligible) > request.candidate_limit:
                omitted.add("result_budget")
            candidates = []
            for distance, _, _, mapping, projection in selected:
                reasons = ["lifecycle_match", "freshness_match"]
                if request.anchor_refs:
                    reasons.insert(0, "structural_proximity")
                if projection[6]:
                    reasons.append("provenance_match")
                candidates.append(
                    {
                        "memoryRef": mapping.candidate_ref,
                        "mappingRef": mapping.mapping_ref,
                        "scope": _scope_wire(mapping.scope),
                        "reasons": reasons,
                        "graphHops": distance,
                        "lifecycle": projection[2],
                        "freshness": projection[3],
                    }
                )
            if exhausted:
                omitted.add("result_budget")
                status = "partial" if candidates else "unavailable"
            elif candidates and omitted:
                status = "partial"
            elif candidates:
                status = "complete"
            else:
                status = "complete_empty"
            fence.ensure_active()
            return {
                "status": status,
                "candidates": candidates,
                "omissionCodes": sorted(omitted),
            }
        except OperationDeadlineExceeded:
            raise
        except Exception as error:
            raise StoreUnavailable("shadow retrieval unavailable") from error

    async def record_decision(
        self, decision: DecisionRecord, fence: OperationFence
    ) -> str:
        return await asyncio.to_thread(self._record_decision, decision, fence)

    def _record_decision(self, decision: DecisionRecord, fence: OperationFence) -> str:
        tenant = _tenant(decision.authorization.scope)
        digest = _digest(decision.canonical_payload)
        try:
            with self._pool.connection() as connection, connection.transaction():
                prior = connection.execute(
                    """SELECT decision_ref,payload_digest FROM mae_shadow.decisions
                       WHERE account_ref=%s AND family_ref=%s AND member_ref=%s
                         AND idempotency_ref=%s FOR UPDATE""",
                    (*tenant, decision.idempotency_ref),
                ).fetchone()
                if prior:
                    if prior != (decision.decision_ref, digest):
                        raise IdempotencyConflict("decision idempotency conflict")
                    return "duplicate"
                fence.ensure_active()
                connection.execute(
                    """INSERT INTO mae_shadow.decisions
                       (account_ref,family_ref,member_ref,idempotency_ref,decision_ref,request_ref,
                        native_receipt_ref,integrity_ref,status,candidate_refs,selected_candidate_refs,
                        reason_codes,observed_at,payload_digest,canonical_payload)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        *tenant,
                        decision.idempotency_ref,
                        decision.decision_ref,
                        decision.request_ref,
                        decision.native_receipt_ref,
                        decision.integrity_ref,
                        decision.status,
                        list(decision.candidate_refs),
                        list(decision.selected_candidate_refs),
                        list(decision.reason_codes),
                        decision.observed_at,
                        digest,
                        Jsonb(dict(decision.canonical_payload)),
                    ),
                )
                fence.ensure_active()
                return "applied"
        except (IdempotencyConflict, OperationDeadlineExceeded):
            raise
        except Exception as error:
            raise StoreUnavailable("shadow decision unavailable") from error

    async def provenance(
        self, scope: ScopeReferences, memory_ref: str, fence: OperationFence
    ) -> dict[str, Any]:
        return await asyncio.to_thread(self._provenance, scope, memory_ref, fence)

    def _provenance(
        self, scope: ScopeReferences, memory_ref: str, fence: OperationFence
    ) -> dict[str, Any]:
        tenant = _tenant(scope)
        try:
            with self._pool.connection() as connection:
                fence.ensure_active()
                if connection.execute(
                    """SELECT 1 FROM mae_shadow.revocations
                       WHERE account_ref=%s AND family_ref=%s AND member_ref=%s AND memory_ref=%s""",
                    (*tenant, memory_ref),
                ).fetchone():
                    return {
                        "status": "complete_empty",
                        "entries": [],
                        "omissionCodes": ["revoked"],
                    }
                row = connection.execute(
                    """SELECT event_ref,lifecycle,occurred_at,integrity_ref,lineage_refs,links
                       FROM mae_shadow.projections
                       WHERE account_ref=%s AND family_ref=%s AND member_ref=%s AND memory_ref=%s""",
                    (*tenant, memory_ref),
                ).fetchone()
            if not row:
                return {"status": "complete_empty", "entries": [], "omissionCodes": []}
            entries = [
                {
                    "kind": "event",
                    "referenceRef": row[0],
                    "occurredAt": row[2],
                    "lifecycle": row[1],
                },
                {
                    "kind": "integrity",
                    "referenceRef": row[3],
                    "occurredAt": row[2],
                    "lifecycle": row[1],
                },
            ]
            entries.extend(
                {
                    "kind": "lineage",
                    "referenceRef": ref,
                    "occurredAt": row[2],
                    "lifecycle": row[1],
                }
                for ref in row[4] or []
            )
            entries.extend(
                {
                    "kind": link["kind"],
                    "referenceRef": link["targetRef"],
                    "occurredAt": row[2],
                    "lifecycle": row[1],
                }
                for link in row[5] or []
            )
            entries.sort(key=lambda item: (item["kind"], item["referenceRef"]))
            omitted = []
            if len(entries) > MAX_PROVENANCE_ENTRIES:
                entries = entries[:MAX_PROVENANCE_ENTRIES]
                omitted = ["result_budget"]
            fence.ensure_active()
            return {
                "status": "partial" if omitted else "complete",
                "entries": entries,
                "omissionCodes": omitted,
            }
        except OperationDeadlineExceeded:
            raise
        except Exception as error:
            raise StoreUnavailable("shadow provenance unavailable") from error

    async def revoke(self, revocation: RevocationRecord, fence: OperationFence) -> str:
        return await asyncio.to_thread(self._revoke, revocation, fence)

    def _revoke(self, revocation: RevocationRecord, fence: OperationFence) -> str:
        tenant = _tenant(revocation.scope)
        digest = _digest(revocation.canonical_payload)
        try:
            with self._pool.connection() as connection, connection.transaction():
                prior = connection.execute(
                    """SELECT revocation_ref,payload_digest FROM mae_shadow.revocations
                       WHERE account_ref=%s AND family_ref=%s AND member_ref=%s
                         AND idempotency_ref=%s FOR UPDATE""",
                    (*tenant, revocation.idempotency_ref),
                ).fetchone()
                if prior:
                    if prior != (revocation.revocation_ref, digest):
                        raise IdempotencyConflict("revocation idempotency conflict")
                    return "duplicate"
                fence.ensure_active()
                connection.execute(
                    """INSERT INTO mae_shadow.revocations
                       (account_ref,family_ref,member_ref,idempotency_ref,revocation_ref,memory_ref,
                        lifecycle,occurred_at,payload_digest,canonical_payload)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        *tenant,
                        revocation.idempotency_ref,
                        revocation.revocation_ref,
                        revocation.memory_ref,
                        revocation.lifecycle,
                        revocation.occurred_at,
                        digest,
                        Jsonb(dict(revocation.canonical_payload)),
                    ),
                )
                connection.execute(
                    """DELETE FROM mae_shadow.projections
                       WHERE account_ref=%s AND family_ref=%s AND member_ref=%s AND memory_ref=%s""",
                    (*tenant, revocation.memory_ref),
                )
                fence.ensure_active()
                return "applied"
        except (IdempotencyConflict, OperationDeadlineExceeded):
            raise
        except Exception as error:
            raise StoreUnavailable("shadow revocation unavailable") from error

    async def revocation_status(
        self, scope: ScopeReferences, revocation_ref: str, fence: OperationFence
    ) -> RevocationRecord | None:
        return await asyncio.to_thread(
            self._revocation_status, scope, revocation_ref, fence
        )

    def _revocation_status(
        self, scope: ScopeReferences, revocation_ref: str, fence: OperationFence
    ) -> RevocationRecord | None:
        tenant = _tenant(scope)
        try:
            with self._pool.connection() as connection:
                fence.ensure_active()
                row = connection.execute(
                    """SELECT idempotency_ref,memory_ref,lifecycle,occurred_at,canonical_payload
                       FROM mae_shadow.revocations
                       WHERE account_ref=%s AND family_ref=%s AND member_ref=%s AND revocation_ref=%s""",
                    (*tenant, revocation_ref),
                ).fetchone()
            if not row:
                return None
            return RevocationRecord(
                revocation_ref=revocation_ref,
                idempotency_ref=row[0],
                memory_ref=row[1],
                scope=scope,
                lifecycle=row[2],
                occurred_at=row[3],
                canonical_payload=row[4],
            )
        except OperationDeadlineExceeded:
            raise
        except Exception as error:
            raise StoreUnavailable("shadow revocation status unavailable") from error

    def _distances(
        self, adjacency: dict[str, set[str]], anchors: tuple[str, ...], max_hops: int
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
            for neighbor in sorted(adjacency.get(current, set())):
                if neighbor not in distances:
                    distances[neighbor] = distance + 1
                    queue.append(neighbor)
        return distances, False


class PostgresAccountAttemptLimiter:
    production_ready = True

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def ready(self) -> bool:
        try:
            with self._pool.connection(timeout=1) as connection:
                connection.execute("SELECT 1 FROM mae_shadow.rate_limits LIMIT 0")
            return True
        except Exception:
            return False

    async def consume(
        self, account_ref: str, bucket: str, limit: int, fence: OperationFence
    ) -> bool:
        def operation() -> bool:
            with self._pool.connection() as connection, connection.transaction():
                fence.ensure_active()
                row = connection.execute(
                    """INSERT INTO mae_shadow.rate_limits (account_ref,bucket,window_start,attempts)
                       VALUES (%s,%s,date_trunc('minute',now()),1)
                       ON CONFLICT (account_ref,bucket,window_start) DO UPDATE
                         SET attempts=mae_shadow.rate_limits.attempts+1
                       RETURNING attempts""",
                    (account_ref, bucket),
                ).fetchone()
                fence.ensure_active()
                return bool(row and row[0] <= limit)

        try:
            return await asyncio.to_thread(operation)
        except OperationDeadlineExceeded:
            raise
        except Exception as error:
            raise StoreUnavailable("rate limiter unavailable") from error
