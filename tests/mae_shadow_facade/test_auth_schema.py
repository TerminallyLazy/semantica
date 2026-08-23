from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from semantica.mae_shadow_facade.app import FacadeSettings, create_app
from semantica.mae_shadow_facade.auth import AuthenticationFailure
from semantica.mae_shadow_facade.logging import NullEventSink
from semantica.mae_shadow_facade.storage import InMemoryTenantPartitionedShadowStore

from .helpers import (
    TestAccountLimiter,
    TestHMACVerifier,
    authorization,
    call_app,
    event_batch,
    synthetic_app,
    token,
)


class ProductionVerifierStub:
    production_ready = True

    def verify(self, token, *, required_permission, now=None):
        raise AuthenticationFailure("stub")


class ProductionStoreStub(InMemoryTenantPartitionedShadowStore):
    production_ready = True


def test_facade_defaults_disabled():
    status, payload = call_app(create_app(event_sink=NullEventSink()), "GET", "/health/ready")
    assert (status, payload) == (503, {"status": "unavailable"})


def test_production_factory_cannot_enable_tests_only_hs256():
    with pytest.raises(ValueError, match="production verifier"):
        create_app(settings=FacadeSettings(enabled=True), verifier=TestHMACVerifier())

    runtime_python = "\n".join(
        path.read_text()
        for path in Path("semantica/mae_shadow_facade").glob("*.py")
    )
    assert "HS256" not in runtime_python


def test_production_factory_requires_distributed_limiter():
    with pytest.raises(ValueError, match="production limiter"):
        create_app(
            settings=FacadeSettings(enabled=True),
            verifier=ProductionVerifierStub(),
            store=ProductionStoreStub(),
            attempt_limiter=TestAccountLimiter(),
        )


def test_valid_short_lived_audience_bound_token_and_exact_scope():
    auth = authorization()
    request = event_batch(auth)
    bearer = token(auth, "shadow.events:write", nonce="valid")
    status, response = call_app(
        synthetic_app(), "POST", "/v1/shadow/events:batch", body=request, bearer=bearer
    )
    assert status == 200
    assert response["authorization"] == auth
    assert response["status"] == "complete"
    assert response["results"][0]["disposition"] == "applied"


def test_wrong_audience_and_static_api_key_are_rejected_without_fallback():
    auth = authorization()
    request = event_batch(auth)
    wrong = token(auth, "shadow.events:write", nonce="aud", audience="other")
    assert call_app(
        synthetic_app(), "POST", "/v1/shadow/events:batch", body=request, bearer=wrong
    )[0] == 401

    valid = token(auth, "shadow.events:write", nonce="api-key")
    status, _ = call_app(
        synthetic_app(),
        "POST",
        "/v1/shadow/events:batch",
        body=request,
        bearer=valid,
        extra_headers=[(b"x-api-key", b"prohibited")],
    )
    assert status == 401


def test_token_body_scope_mismatch_is_rejected():
    token_auth = authorization(family="family-a")
    body_auth = authorization(family="family-b")
    status, payload = call_app(
        synthetic_app(),
        "POST",
        "/v1/shadow/events:batch",
        body=event_batch(body_auth),
        bearer=token(token_auth, "shadow.events:write", nonce="scope"),
    )
    assert (status, payload) == (401, {"error": "unauthorized"})


def test_expired_and_replayed_tokens_fail_closed():
    auth = authorization()
    request = event_batch(auth)
    app = synthetic_app()
    bearer = token(auth, "shadow.events:write", nonce="single-use")
    assert call_app(
        app, "POST", "/v1/shadow/events:batch", body=request, bearer=bearer
    )[0] == 200
    assert call_app(
        app, "POST", "/v1/shadow/events:batch", body=request, bearer=bearer
    ) == (401, {"error": "unauthorized"})

    expired_auth = authorization()
    expired = datetime.now(timezone.utc) - timedelta(minutes=2)
    expired_auth["issuedAt"] = expired.isoformat(timespec="seconds").replace("+00:00", "Z")
    expired_auth["expiresAt"] = (expired + timedelta(seconds=60)).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")
    expired_request = event_batch(expired_auth)
    assert call_app(
        synthetic_app(),
        "POST",
        "/v1/shadow/events:batch",
        body=expired_request,
        bearer=token(expired_auth, "shadow.events:write", nonce="expired"),
    ) == (401, {"error": "unauthorized"})


def test_unknown_and_prohibited_fields_fail_closed():
    auth = authorization()
    unknown = event_batch(auth)
    unknown["unexpected"] = True
    prohibited = copy.deepcopy(event_batch(auth))
    prohibited["events"][0]["clinicalPayload"] = {"diagnosis": "synthetic"}

    for nonce, request in (("unknown", unknown), ("phi-field", prohibited)):
        status, response = call_app(
            synthetic_app(),
            "POST",
            "/v1/shadow/events:batch",
            body=request,
            bearer=token(auth, "shadow.events:write", nonce=nonce),
        )
        assert (status, response) == (422, {"error": "invalid_contract"})


def test_event_count_limit_is_rejected():
    auth = authorization()
    request = event_batch(auth)
    request["events"] = [copy.deepcopy(request["events"][0]) for _ in range(51)]
    status, response = call_app(
        synthetic_app(),
        "POST",
        "/v1/shadow/events:batch",
        body=request,
        bearer=token(auth, "shadow.events:write", nonce="event-limit"),
    )
    assert (status, response) == (422, {"error": "invalid_contract"})


def test_slow_and_malformed_bodies_charge_account_attempt_quota():
    limiter = TestAccountLimiter()
    settings = FacadeSettings(
        enabled=True,
        mutation_deadline_seconds=0.01,
        event_requests_per_minute=2,
    )
    app = synthetic_app(limiter=limiter, settings=settings)
    auth_a = authorization(family="family-a", member="member-a")
    slow_status, _ = call_app(
        app,
        "POST",
        "/v1/shadow/events:batch",
        body=event_batch(auth_a),
        bearer=token(auth_a, "shadow.events:write", nonce="slow-body"),
        receive_delay_seconds=0.03,
    )
    assert slow_status == 408

    malformed_status, _ = call_app(
        app,
        "POST",
        "/v1/shadow/events:batch",
        raw_body=b"{",
        bearer=token(auth_a, "shadow.events:write", nonce="malformed-body"),
    )
    assert malformed_status == 422

    auth_b = authorization(family="family-b", member="member-b")
    denied_status, _ = call_app(
        app,
        "POST",
        "/v1/shadow/events:batch",
        body=event_batch(auth_b),
        bearer=token(auth_b, "shadow.events:write", nonce="account-quota"),
    )
    assert denied_status == 429
    assert {call[0] for call in limiter.calls} == {auth_a["scope"]["accountRef"]}
    assert {call[1:] for call in limiter.calls} == {("events_batch", 2)}
