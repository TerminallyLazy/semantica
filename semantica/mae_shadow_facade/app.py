"""Minimal private ASGI boundary for Mae's Semantica shadow facade.

The module-level application is intentionally disabled. Production enablement
must inject both a production-ready workload identity verifier and a production
tenant-partitioned store. Symmetric test authentication is absent from this
package and cannot be enabled through the production factory.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping, Protocol

from .auth import (
    AuthenticationFailure,
    RejectingWorkloadTokenVerifier,
    WorkloadIdentity,
    WorkloadTokenVerifier,
)
from .contracts import (
    MAX_DEFAULT_BODY_BYTES,
    MAX_EVENT_BATCH_BYTES,
    ContractViolation,
    parse_decision,
    parse_event_batch,
    parse_retrieval,
    parse_revocation,
    validate_opaque_ref,
)
from .logging import MetadataOnlyEventSink, SafeEventSink
from .service import MaeShadowService, authorization_wire
from .storage import (
    IdempotencyConflict,
    InMemoryTenantPartitionedShadowStore,
    OperationDeadlineExceeded,
    OperationFence,
    StoreUnavailable,
    TenantPartitionedShadowStore,
)


@dataclass(frozen=True)
class FacadeSettings:
    enabled: bool = False
    mutation_deadline_seconds: float = 2.0
    query_deadline_seconds: float = 0.2
    event_requests_per_minute: int = 60
    retrieval_requests_per_minute: int = 30
    other_requests_per_minute: int = 60


@dataclass(frozen=True)
class _Route:
    name: str
    method: str
    permission: str
    parser: Callable[[Any], Any] | None
    mutation: bool
    maximum_body_bytes: int


_ROUTES = {
    ("POST", "/v1/shadow/events:batch"): _Route(
        "events_batch", "POST", "shadow.events:write", parse_event_batch, True,
        MAX_EVENT_BATCH_BYTES,
    ),
    ("POST", "/v1/shadow/retrievals"): _Route(
        "retrievals", "POST", "shadow.retrievals:read", parse_retrieval, False,
        MAX_DEFAULT_BODY_BYTES,
    ),
    ("POST", "/v1/shadow/decisions"): _Route(
        "decisions", "POST", "shadow.decisions:write", parse_decision, True,
        MAX_DEFAULT_BODY_BYTES,
    ),
    ("POST", "/v1/shadow/revocations"): _Route(
        "revocations", "POST", "shadow.revocations:write", parse_revocation, True,
        MAX_DEFAULT_BODY_BYTES,
    ),
}


class AccountAttemptLimiter(Protocol):
    """Distributed-ready account attempt quota seam."""

    production_ready: bool

    def ready(self) -> bool: ...

    async def consume(
        self,
        account_ref: str,
        bucket: str,
        limit: int,
        fence: OperationFence,
    ) -> bool: ...


class RejectingAccountAttemptLimiter:
    """Fail-closed default; never usable by an enabled deployment."""

    production_ready = False

    def ready(self) -> bool:
        return False

    async def consume(
        self,
        account_ref: str,
        bucket: str,
        limit: int,
        fence: OperationFence,
    ) -> bool:
        return False


class MaeShadowASGI:
    def __init__(
        self,
        *,
        settings: FacadeSettings,
        verifier: WorkloadTokenVerifier,
        store: TenantPartitionedShadowStore,
        event_sink: SafeEventSink,
        attempt_limiter: AccountAttemptLimiter,
    ) -> None:
        if settings.enabled and not verifier.production_ready:
            raise ValueError(
                "enabled facade requires an asymmetric/KMS or mTLS production verifier"
            )
        if settings.enabled and not store.production_ready:
            raise ValueError("enabled facade requires a production tenant store")
        if settings.enabled and not attempt_limiter.production_ready:
            raise ValueError("enabled facade requires a distributed production limiter")
        self._settings = settings
        self._verifier = verifier
        self._service = MaeShadowService(store)
        self._event_sink = event_sink
        self._attempt_limiter = attempt_limiter

    async def __call__(self, scope: Mapping[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope.get("type") != "http":
            return

        method = str(scope.get("method", "GET")).upper()
        path = str(scope.get("path", ""))
        if scope.get("query_string"):
            await self._send_json(send, 400, {"error": "invalid_request"})
            return
        if method == "GET" and path == "/health/live":
            await self._send_json(send, 200, {"status": "live"})
            return
        if method == "GET" and path == "/health/ready":
            try:
                ready = (
                    self._settings.enabled
                    and self._service.ready()
                    and self._attempt_limiter.ready()
                )
            except Exception:
                ready = False
            await self._send_json(send, 200 if ready else 503, {"status": "ready" if ready else "unavailable"})
            return

        route, path_ref = self._match_route(method, path)
        if route is None:
            await self._send_json(send, 404, {"error": "not_found"})
            return
        if not self._settings.enabled:
            self._event_sink.emit("disabled", route.name, 503)
            await self._send_json(send, 503, {"error": "facade_disabled"})
            return

        status = 500
        parsed: Any = None
        identity: WorkloadIdentity | None = None
        invoking = False
        ingress_started = time.monotonic()
        deadline_seconds = (
            self._settings.mutation_deadline_seconds
            if route.mutation
            else self._settings.query_deadline_seconds
        )
        deadline_at = ingress_started + deadline_seconds
        try:
            headers = self._headers(scope)
            if "x-api-key" in headers or "api-key" in headers:
                raise AuthenticationFailure("static API keys are prohibited")
            authorization_headers = headers.get("authorization", [])
            if len(authorization_headers) != 1:
                raise AuthenticationFailure("exactly one workload token required")
            prefix, separator, token = authorization_headers[0].partition(" ")
            if prefix != "Bearer" or not separator or not token or " " in token:
                raise AuthenticationFailure("bearer workload token required")
            identity = self._verifier.verify(token, required_permission=route.permission)
            fence = OperationFence(
                request_ref=identity.jti,
                deadline_monotonic=deadline_at,
            )
            fence.ensure_active()

            limit = self._limit_for(route)
            allowed = await asyncio.wait_for(
                self._attempt_limiter.consume(
                    identity.authorization.scope.account_ref,
                    route.name,
                    limit,
                    fence,
                ),
                timeout=fence.remaining(),
            )
            if not allowed:
                status = 429
                await self._send_json(send, status, {"error": "rate_limited"})
                return

            if path_ref is not None:
                path_ref = validate_opaque_ref(path_ref)
            if route.parser is not None:
                body = await self._read_json(
                    receive, route.maximum_body_bytes, headers, fence
                )
                parsed = route.parser(body)
                if parsed.authorization != identity.authorization:
                    raise AuthenticationFailure("token and body authorization mismatch")
            fence.ensure_active()
            invoking = True
            try:
                response = await asyncio.wait_for(
                    self._invoke(
                        route.name, parsed, identity, path_ref, fence
                    ),
                    timeout=fence.remaining(),
                )
            except (
                asyncio.TimeoutError,
                OperationDeadlineExceeded,
                StoreUnavailable,
            ):
                response = self._unavailable(route.name, parsed, identity, path_ref)
            status = 200
            await self._send_json(send, status, response)
        except AuthenticationFailure:
            status = 401
            await self._send_json(send, status, {"error": "unauthorized"})
        except BodyTooLarge:
            status = 413
            await self._send_json(send, status, {"error": "payload_too_large"})
        except (ContractViolation, DuplicateJSONKey, json.JSONDecodeError, UnicodeDecodeError):
            status = 422
            await self._send_json(send, status, {"error": "invalid_contract"})
        except IdempotencyConflict:
            status = 409
            await self._send_json(send, status, {"error": "idempotency_conflict"})
        except (asyncio.TimeoutError, OperationDeadlineExceeded):
            if invoking and identity is not None:
                status = 200
                await self._send_json(
                    send,
                    status,
                    self._unavailable(route.name, parsed, identity, path_ref),
                )
            else:
                status = 408
                await self._send_json(send, status, {"error": "request_timeout"})
        except Exception:
            status = 500
            await self._send_json(send, status, {"error": "internal_error"})
        finally:
            self._event_sink.emit("request_complete", route.name, status)

    async def _invoke(
        self,
        route: str,
        parsed: Any,
        identity: WorkloadIdentity,
        path_ref: str | None,
        fence: OperationFence,
    ) -> dict[str, Any]:
        if route == "events_batch":
            return await self._service.apply_events(parsed, fence)
        if route == "retrievals":
            return await self._service.retrieve(parsed, fence)
        if route == "decisions":
            return await self._service.record_decision(parsed, fence)
        if route == "revocations":
            return await self._service.revoke(parsed, fence)
        if route == "provenance":
            return await self._service.provenance(
                identity.authorization, path_ref or "", fence
            )
        if route == "revocation_status":
            return await self._service.revocation_status(
                identity.authorization, path_ref or "", fence
            )
        raise ContractViolation("unknown operation")

    def _unavailable(
        self,
        route: str,
        parsed: Any,
        identity: WorkloadIdentity,
        path_ref: str | None,
    ) -> dict[str, Any]:
        authorization = authorization_wire(identity.authorization)
        if route == "events_batch":
            return {"schemaVersion": 1, "authorization": authorization, "status": "unavailable", "results": []}
        if route == "retrievals":
            return {
                "schemaVersion": 1,
                "requestRef": parsed.request_ref,
                "authorization": authorization,
                "status": "unavailable",
                "candidates": [],
                "omissionCodes": ["source_failure"],
            }
        if route == "revocations":
            return {
                "schemaVersion": 1,
                "authorization": authorization,
                "revocationRef": parsed.revocation.revocation_ref,
                "status": "unavailable",
                "pending": True,
            }
        result = {
            "schemaVersion": 1,
            "authorization": authorization,
            "status": "unavailable",
        }
        if route == "decisions":
            result["decisionRef"] = parsed.decision_ref
        elif route == "provenance":
            result.update({"memoryRef": path_ref, "entries": [], "omissionCodes": ["source_failure"]})
        elif route == "revocation_status":
            result.update({"revocationRef": path_ref, "pending": True})
        return result

    @staticmethod
    def _match_route(method: str, path: str) -> tuple[_Route | None, str | None]:
        direct = _ROUTES.get((method, path))
        if direct is not None:
            return direct, None
        provenance_prefix = "/v1/shadow/provenance/"
        if method == "GET" and path.startswith(provenance_prefix):
            reference = path[len(provenance_prefix) :]
            if reference and "/" not in reference:
                return _Route("provenance", "GET", "shadow.provenance:read", None, False, 0), reference
        revocation_prefix = "/v1/shadow/revocations/"
        if method == "GET" and path.startswith(revocation_prefix):
            reference = path[len(revocation_prefix) :]
            if reference and "/" not in reference:
                return _Route("revocation_status", "GET", "shadow.revocations:read", None, False, 0), reference
        return None, None

    @staticmethod
    def _headers(scope: Mapping[str, Any]) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for raw_name, raw_value in scope.get("headers", []):
            name = raw_name.decode("latin-1").lower()
            value = raw_value.decode("latin-1")
            result.setdefault(name, []).append(value)
        return result

    async def _read_json(
        self,
        receive: Any,
        maximum: int,
        headers: Mapping[str, list[str]],
        fence: OperationFence,
    ) -> Any:
        content_types = headers.get("content-type", [])
        if len(content_types) != 1 or content_types[0].split(";", 1)[0].strip().lower() != "application/json":
            raise ContractViolation("JSON content type required")
        lengths = headers.get("content-length", [])
        if len(lengths) > 1:
            raise ContractViolation("duplicate content length")
        if lengths:
            try:
                declared_length = int(lengths[0])
                if declared_length < 0:
                    raise ContractViolation("invalid content length")
                if declared_length > maximum:
                    raise BodyTooLarge
            except ValueError as error:
                raise ContractViolation("invalid content length") from error
        chunks = bytearray()
        while True:
            message = await asyncio.wait_for(receive(), timeout=fence.remaining())
            fence.ensure_active()
            if message.get("type") == "http.disconnect":
                raise ContractViolation("request disconnected")
            if message.get("type") != "http.request":
                raise ContractViolation("invalid request body")
            chunks.extend(message.get("body", b""))
            if len(chunks) > maximum:
                raise BodyTooLarge
            if not message.get("more_body", False):
                break
        result = json.loads(bytes(chunks), object_pairs_hook=_reject_duplicate_pairs)
        fence.ensure_active()
        return result

    def _limit_for(self, route: _Route) -> int:
        if route.name == "retrievals":
            return self._settings.retrieval_requests_per_minute
        if route.name == "events_batch":
            return self._settings.event_requests_per_minute
        return self._settings.other_requests_per_minute

    @staticmethod
    async def _send_json(send: Any, status: int, value: Mapping[str, Any]) -> None:
        body = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=_json_default,
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    @staticmethod
    async def _lifespan(receive: Any, send: Any) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return


class BodyTooLarge(ValueError):
    pass


class DuplicateJSONKey(ValueError):
    pass


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKey
        result[key] = value
    return result


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    raise TypeError("unsupported response value")


def create_app(
    *,
    settings: FacadeSettings | None = None,
    verifier: WorkloadTokenVerifier | None = None,
    store: TenantPartitionedShadowStore | None = None,
    event_sink: SafeEventSink | None = None,
    attempt_limiter: AccountAttemptLimiter | None = None,
) -> MaeShadowASGI:
    return MaeShadowASGI(
        settings=settings or FacadeSettings(),
        verifier=verifier or RejectingWorkloadTokenVerifier(),
        store=store or InMemoryTenantPartitionedShadowStore(),
        event_sink=event_sink or MetadataOnlyEventSink(),
        attempt_limiter=attempt_limiter or RejectingAccountAttemptLimiter(),
    )


app = create_app()
