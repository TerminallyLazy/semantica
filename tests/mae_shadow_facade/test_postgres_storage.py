from __future__ import annotations

import asyncio
import base64
import json
import os
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from psycopg_pool import ConnectionPool

from semantica.mae_shadow_facade.auth import AuthenticationFailure
from semantica.mae_shadow_facade.contracts import (
    parse_event_batch,
    parse_retrieval,
    parse_revocation,
)
from semantica.mae_shadow_facade.postgres_storage import (
    PostgresAccountAttemptLimiter,
    PostgresTenantPartitionedShadowStore,
)
from semantica.mae_shadow_facade.production_auth import (
    KMSRS256VerifierSettings,
    KMSRS256WorkloadTokenVerifier,
)
from semantica.mae_shadow_facade.storage import OperationFence

from .helpers import authorization, event_batch, ref, retrieval, revocation

DATABASE_URL = os.environ.get("MAE_SHADOW_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason="MAE_SHADOW_TEST_DATABASE_URL is required for PostgreSQL integration tests",
)


def _fence(label: str) -> OperationFence:
    return OperationFence(ref(label), time.monotonic() + 5)


def _segment(value: object) -> str:
    return (
        base64.urlsafe_b64encode(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        )
        .decode()
        .rstrip("=")
    )


@pytest.fixture()
def pool():
    instance = ConnectionPool(DATABASE_URL, min_size=1, max_size=4, open=True)
    with instance.connection() as connection, connection.transaction():
        connection.execute(
            """TRUNCATE mae_shadow.projections, mae_shadow.event_idempotency,
               mae_shadow.decisions, mae_shadow.revocations, mae_shadow.policies,
               mae_shadow.rate_limits, mae_shadow.workload_jti"""
        )
    yield instance
    instance.close()


def test_postgres_store_isolates_tenants_and_rejects_resurrection(pool):
    store = PostgresTenantPartitionedShadowStore(pool)
    auth_a = authorization(family="postgres-family-a")
    auth_b = authorization(family="postgres-family-b")
    seed = parse_event_batch(event_batch(auth_a))

    first = asyncio.run(
        store.apply_events(seed.authorization.scope, seed.events, _fence("seed"))
    )
    duplicate = asyncio.run(
        store.apply_events(seed.authorization.scope, seed.events, _fence("duplicate"))
    )
    assert first[0]["disposition"] == "applied"
    assert duplicate[0]["disposition"] == "duplicate"

    found = asyncio.run(
        store.retrieve(parse_retrieval(retrieval(auth_a)), _fence("read-a"))
    )
    isolated = asyncio.run(
        store.retrieve(parse_retrieval(retrieval(auth_b)), _fence("read-b"))
    )
    assert found["status"] == "complete"
    assert found["candidates"][0]["memoryRef"] == ref("memory")
    assert isolated == {
        "status": "complete_empty",
        "candidates": [],
        "omissionCodes": ["unhydrated"],
    }

    revoked = parse_revocation(revocation(auth_a))
    assert asyncio.run(store.revoke(revoked.revocation, _fence("revoke"))) == "applied"
    after_revoke = parse_event_batch(
        event_batch(auth_a, idempotency="postgres-resurrection")
    )
    rejected = asyncio.run(
        store.apply_events(
            after_revoke.authorization.scope, after_revoke.events, _fence("resurrect")
        )
    )
    assert rejected[0]["disposition"] == "permanent"
    assert rejected[0]["errorCode"] == "permanent_rejection"

    scope = seed.authorization.scope
    with pool.connection() as connection, connection.transaction():
        connection.execute(
            "SELECT mae_shadow.delete_exact_tenant(%s, %s, %s)",
            (scope.account_ref, scope.family_ref, scope.member_ref),
        )
        remaining = connection.execute(
            """SELECT
                 (SELECT count(*) FROM mae_shadow.projections WHERE account_ref=%s AND family_ref=%s AND member_ref=%s) +
                 (SELECT count(*) FROM mae_shadow.event_idempotency WHERE account_ref=%s AND family_ref=%s AND member_ref=%s) +
                 (SELECT count(*) FROM mae_shadow.decisions WHERE account_ref=%s AND family_ref=%s AND member_ref=%s) +
                 (SELECT count(*) FROM mae_shadow.revocations WHERE account_ref=%s AND family_ref=%s AND member_ref=%s) +
                 (SELECT count(*) FROM mae_shadow.policies WHERE account_ref=%s AND family_ref=%s AND member_ref=%s)""",
            (scope.account_ref, scope.family_ref, scope.member_ref) * 5,
        ).fetchone()
    assert remaining == (0,)


def test_postgres_limiter_is_atomic_across_instances(pool):
    first = PostgresAccountAttemptLimiter(pool)
    second = PostgresAccountAttemptLimiter(pool)
    account = ref("postgres-rate-account")
    assert asyncio.run(first.consume(account, "retrievals", 2, _fence("limit-1")))
    assert asyncio.run(second.consume(account, "retrievals", 2, _fence("limit-2")))
    assert not asyncio.run(first.consume(account, "retrievals", 2, _fence("limit-3")))


def test_postgres_replay_rejection_survives_verifier_instances(pool):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    settings = KMSRS256VerifierSettings(
        issuer="gateway@example.iam.gserviceaccount.com",
        audience="mae-semantica-shadow",
        public_keys={"kms-v1": public_pem},
    )
    auth = authorization()
    issued = int(time.time())
    header = _segment({"alg": "RS256", "kid": "kms-v1", "typ": "JWT"})
    payload = _segment(
        {
            "iss": settings.issuer,
            "aud": settings.audience,
            "iat": issued,
            "nbf": issued - 2,
            "exp": issued + 60,
            "jti": "postgres-single-use-token",
            "permission": "shadow.retrievals:read",
            "authorization": auth,
        }
    )
    signing_input = f"{header}.{payload}".encode()
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    token = (
        f"{header}.{payload}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"
    )

    first = KMSRS256WorkloadTokenVerifier(settings, pool)
    second = KMSRS256WorkloadTokenVerifier(settings, pool)
    assert (
        first.verify(token, required_permission="shadow.retrievals:read").jti
        == "postgres-single-use-token"
    )
    with pytest.raises(AuthenticationFailure):
        second.verify(token, required_permission="shadow.retrievals:read")
