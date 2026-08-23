from __future__ import annotations

import json
from pathlib import Path

from semantica.mae_shadow_facade.app import create_app

from .helpers import authorization, call_app, synthetic_app, token


class CaptureSink:
    def __init__(self):
        self.events = []

    def emit(self, event, route, status):
        self.events.append({"event": event, "route": route, "status": status})


def test_swift_event_fixture_decodes_and_diagnostics_are_metadata_only():
    path = Path(__file__).parent / "fixtures" / "swift_event_batch_v1.json"
    request = json.loads(path.read_text())
    auth = authorization()
    request["authorization"] = auth
    request["events"][0]["scope"] = auth["scope"]
    request["events"][0]["links"][0]["targetScope"] = auth["scope"]
    request["events"][0]["occurredAt"] = auth["issuedAt"]
    sink = CaptureSink()
    app = synthetic_app(sink=sink)
    raw_token = token(auth, "shadow.events:write", nonce="fixture")
    status, response = call_app(
        app, "POST", "/v1/shadow/events:batch", body=request, bearer=raw_token
    )
    assert status == 200
    assert response["authorization"] == auth
    serialized = json.dumps(sink.events)
    assert request["events"][0]["memoryRef"] not in serialized
    assert auth["scope"]["familyRef"] not in serialized
    assert raw_token not in serialized
    assert sink.events == [{"event": "request_complete", "route": "events_batch", "status": 200}]


def test_health_and_unknown_routes_disclose_no_dependencies_or_tenants():
    app = create_app()
    assert call_app(app, "GET", "/health/live") == (200, {"status": "live"})
    assert call_app(app, "GET", "/health/ready") == (503, {"status": "unavailable"})
    assert call_app(app, "GET", "/v1/shadow/query") == (404, {"error": "not_found"})


def test_swift_revocation_fixture_and_unknown_status_are_decodable():
    path = Path(__file__).parent / "fixtures" / "swift_revocation_v1.json"
    fixture = json.loads(path.read_text())
    auth = authorization()
    request = fixture["request"]
    request["authorization"] = auth
    request["revocation"]["scope"] = auth["scope"]
    request["revocation"]["occurredAt"] = auth["issuedAt"]
    expected_unknown = fixture["unknownResponse"]
    expected_unknown["authorization"] = auth
    app = synthetic_app()

    revocation_ref = request["revocation"]["revocationRef"]
    status, unknown = call_app(
        app,
        "GET",
        f"/v1/shadow/revocations/{revocation_ref}",
        bearer=token(auth, "shadow.revocations:read", nonce="unknown-revocation"),
    )
    assert status == 200
    assert unknown == expected_unknown

    status, completed = call_app(
        app,
        "POST",
        "/v1/shadow/revocations",
        body=request,
        bearer=token(auth, "shadow.revocations:write", nonce="fixture-revocation"),
    )
    assert status == 200
    assert set(completed) == {
        "schemaVersion",
        "authorization",
        "revocationRef",
        "status",
        "pending",
    }
    assert completed["authorization"] == auth
    assert completed["revocationRef"] == revocation_ref
    assert completed["status"] == "complete"
    assert completed["pending"] is False
