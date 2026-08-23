from __future__ import annotations

import json
from pathlib import Path

from semantica.mae_shadow_facade.app import FacadeSettings, create_app
from semantica.mae_shadow_facade.auth import SyntheticHMACWorkloadTokenVerifier
from semantica.mae_shadow_facade.storage import InMemoryTenantPartitionedShadowStore

from .helpers import SYNTHETIC_KEY, authorization, call_app, token


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
    verifier = SyntheticHMACWorkloadTokenVerifier(
        issuer="mae-gateway",
        audience="mae-semantica-shadow",
        keys={"synthetic-v1": SYNTHETIC_KEY},
    )
    app = create_app(
        settings=FacadeSettings(enabled=True, allow_synthetic=True),
        verifier=verifier,
        store=InMemoryTenantPartitionedShadowStore(),
        event_sink=sink,
    )
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
