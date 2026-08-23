from __future__ import annotations

import copy
import time

from semantica.mae_shadow_facade.app import FacadeSettings
from semantica.mae_shadow_facade.storage import InMemoryTenantPartitionedShadowStore

from .helpers import (
    authorization,
    call_app,
    decision,
    event_batch,
    ref,
    retrieval,
    revocation,
    synthetic_app,
    token,
)


def post(app, path, body, permission, nonce):
    return call_app(
        app,
        "POST",
        path,
        body=body,
        bearer=token(body["authorization"], permission, nonce=nonce),
    )


def test_exact_idempotency_duplicate_and_conflict():
    auth = authorization()
    app = synthetic_app()
    request = event_batch(auth)
    assert post(app, "/v1/shadow/events:batch", request, "shadow.events:write", "first")[1]["status"] == "complete"
    duplicate = post(app, "/v1/shadow/events:batch", request, "shadow.events:write", "duplicate")
    assert duplicate[1]["results"][0]["disposition"] == "duplicate"

    conflict = copy.deepcopy(request)
    conflict["events"][0]["freshness"] = "partial"
    status, response = post(
        app, "/v1/shadow/events:batch", conflict, "shadow.events:write", "conflict"
    )
    assert (status, response) == (409, {"error": "idempotency_conflict"})


def test_deterministic_bounded_retrieval_and_family_isolation():
    auth_a = authorization(family="family-a")
    auth_b = authorization(family="family-b")
    app = synthetic_app()
    post(app, "/v1/shadow/events:batch", event_batch(auth_a), "shadow.events:write", "seed-a")

    request_a = retrieval(auth_a)
    _, first = post(app, "/v1/shadow/retrievals", request_a, "shadow.retrievals:read", "retrieve-a-1")
    _, second = post(app, "/v1/shadow/retrievals", request_a, "shadow.retrievals:read", "retrieve-a-2")
    assert first == second
    assert first["status"] == "complete"
    assert first["candidates"][0]["memoryRef"] == ref("memory")

    request_b = retrieval(auth_b)
    _, isolated = post(app, "/v1/shadow/retrievals", request_b, "shadow.retrievals:read", "retrieve-b")
    assert isolated["status"] == "complete_empty"
    assert isolated["candidates"] == []
    assert isolated["omissionCodes"] == ["unhydrated"]


def test_revocation_tombstone_prevents_resurrection_and_has_status():
    auth = authorization()
    app = synthetic_app()
    seed = event_batch(auth)
    post(app, "/v1/shadow/events:batch", seed, "shadow.events:write", "seed")
    revoke = revocation(auth)
    _, revoked = post(app, "/v1/shadow/revocations", revoke, "shadow.revocations:write", "revoke")
    assert revoked["status"] == "complete"
    assert revoked["pending"] is False

    resurrection = event_batch(auth, idempotency="after-revocation")
    _, rejected = post(
        app, "/v1/shadow/events:batch", resurrection, "shadow.events:write", "resurrect"
    )
    assert rejected["status"] == "partial"
    assert rejected["results"][0] == {
        "eventRef": resurrection["events"][0]["eventRef"],
        "idempotencyRef": resurrection["events"][0]["idempotencyRef"],
        "disposition": "permanent",
        "errorCode": "permanent_rejection",
    }
    _, repeated_rejection = post(
        app, "/v1/shadow/events:batch", resurrection, "shadow.events:write", "resurrect-repeat"
    )
    assert repeated_rejection["results"] == rejected["results"]

    status, record = call_app(
        app,
        "GET",
        f"/v1/shadow/revocations/{revoke['revocation']['revocationRef']}",
        bearer=token(auth, "shadow.revocations:read", nonce="status"),
    )
    assert status == 200
    assert record["status"] == "complete"


def test_backend_failure_is_explicit_unavailable_not_empty():
    auth = authorization()
    store = InMemoryTenantPartitionedShadowStore(available=False)
    app = synthetic_app(store)
    status, response = post(
        app,
        "/v1/shadow/retrievals",
        retrieval(auth),
        "shadow.retrievals:read",
        "unavailable",
    )
    assert status == 200
    assert response["status"] == "unavailable"
    assert response["candidates"] == []
    assert response["omissionCodes"] == ["source_failure"]


def test_candidate_budget_is_explicit_partial():
    auth = authorization()
    app = synthetic_app()
    post(
        app,
        "/v1/shadow/events:batch",
        event_batch(auth, memory="memory-a", idempotency="seed-a"),
        "shadow.events:write",
        "partial-seed-a",
    )
    post(
        app,
        "/v1/shadow/events:batch",
        event_batch(auth, memory="memory-b", idempotency="seed-b"),
        "shadow.events:write",
        "partial-seed-b",
    )
    request = retrieval(auth, memory="memory-a")
    second = copy.deepcopy(request["candidateMappings"][0])
    second.update(
        {
            "candidateRef": ref("memory-b"),
            "nativeMemoryRef": ref("native-memory-b"),
            "mappingRef": ref("mapping-memory-b"),
        }
    )
    request["candidateMappings"].append(second)
    status, response = post(
        app,
        "/v1/shadow/retrievals",
        request,
        "shadow.retrievals:read",
        "partial-retrieval",
    )
    assert status == 200
    assert response["status"] == "partial"
    assert len(response["candidates"]) == 1
    assert response["omissionCodes"] == ["result_budget"]


def test_decision_and_provenance_routes_are_structural_and_scoped():
    auth = authorization()
    app = synthetic_app()
    seed = event_batch(auth)
    post(app, "/v1/shadow/events:batch", seed, "shadow.events:write", "prov-seed")

    status, recorded = post(
        app,
        "/v1/shadow/decisions",
        decision(auth),
        "shadow.decisions:write",
        "decision",
    )
    assert status == 200
    assert recorded["status"] == "complete"
    assert recorded["disposition"] == "applied"

    status, provenance = call_app(
        app,
        "GET",
        f"/v1/shadow/provenance/{ref('memory')}",
        bearer=token(auth, "shadow.provenance:read", nonce="provenance"),
    )
    assert status == 200
    assert provenance["status"] == "complete"
    assert {entry["kind"] for entry in provenance["entries"]} == {
        "event",
        "integrity",
        "lineage",
    }
    assert all(set(entry) == {"kind", "referenceRef", "occurredAt", "lifecycle"} for entry in provenance["entries"])


def test_expired_mutation_fence_cannot_commit_late():
    auth = authorization()
    store = InMemoryTenantPartitionedShadowStore(mutation_delay_seconds=0.05)
    app = synthetic_app(
        store,
        settings=FacadeSettings(enabled=True, mutation_deadline_seconds=0.01),
    )
    status, response = post(
        app,
        "/v1/shadow/events:batch",
        event_batch(auth),
        "shadow.events:write",
        "deadline-mutation",
    )
    assert status == 200
    assert response["status"] == "unavailable"

    time.sleep(0.06)
    _, retrieved = post(
        app,
        "/v1/shadow/retrievals",
        retrieval(auth),
        "shadow.retrievals:read",
        "deadline-read",
    )
    assert retrieved["status"] == "complete_empty"
    assert retrieved["candidates"] == []
