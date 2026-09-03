"""Fail-closed production ASGI composition for Mae's private Cloud Run service."""

from __future__ import annotations

import json
import os

from psycopg_pool import ConnectionPool

from .app import FacadeSettings, create_app
from .logging import MetadataOnlyEventSink
from .postgres_storage import (
    PostgresAccountAttemptLimiter,
    PostgresTenantPartitionedShadowStore,
)
from .production_auth import (
    KMSRS256VerifierSettings,
    KMSRS256WorkloadTokenVerifier,
)


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"missing required production setting: {name}")
    return value


def build_production_app():
    if _required("SEMANTICA_ENABLED").lower() != "true":
        raise RuntimeError("production Semantica facade is not enabled")
    pool = ConnectionPool(
        conninfo=_required("DATABASE_URL"),
        min_size=1,
        max_size=int(os.environ.get("SEMANTICA_DATABASE_POOL_SIZE", "8")),
        kwargs={"autocommit": False},
        open=True,
    )
    try:
        public_keys = json.loads(_required("SEMANTICA_JWT_PUBLIC_KEYS_JSON"))
    except json.JSONDecodeError as error:
        raise RuntimeError("invalid SEMANTICA_JWT_PUBLIC_KEYS_JSON") from error
    if not isinstance(public_keys, dict):
        raise RuntimeError("SEMANTICA_JWT_PUBLIC_KEYS_JSON must be an object")
    verifier = KMSRS256WorkloadTokenVerifier(
        KMSRS256VerifierSettings(
            issuer=_required("SEMANTICA_JWT_ISSUER"),
            audience=_required("SEMANTICA_JWT_AUDIENCE"),
            public_keys=public_keys,
        ),
        pool,
    )
    store = PostgresTenantPartitionedShadowStore(pool)
    limiter = PostgresAccountAttemptLimiter(pool)
    if not store.ready() or not limiter.ready():
        raise RuntimeError("Semantica production database migration is not ready")
    return create_app(
        settings=FacadeSettings(enabled=True),
        verifier=verifier,
        store=store,
        event_sink=MetadataOnlyEventSink(),
        attempt_limiter=limiter,
    )


app = build_production_app()
