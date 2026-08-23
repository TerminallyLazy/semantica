from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import time
from typing import Any


SYNTHETIC_KEY = b"synthetic-mae-shadow-key-32-bytes-minimum"


def ref(label: str) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(label.encode()).digest())
    return f"hmac-sha256.test-v1.{digest.decode().rstrip('=')}"


def authorization(*, family: str = "family", member: str | None = "member") -> dict[str, Any]:
    issued = int(time.time())
    scope = {"accountRef": ref("account"), "familyRef": ref(family)}
    if member is not None:
        scope["memberRef"] = ref(member)
    return {
        "scope": scope,
        "authorizationGeneration": 7,
        "sessionBindingRef": ref("session"),
        "issuedAt": _timestamp(issued),
        "expiresAt": _timestamp(issued + 60),
    }


def event_batch(
    auth: dict[str, Any],
    *,
    memory: str = "memory",
    idempotency: str = "idempotency",
    target: str | None = None,
) -> dict[str, Any]:
    event = {
        "schemaVersion": 1,
        "eventRef": ref(f"event-{memory}"),
        "idempotencyRef": ref(idempotency),
        "memoryRef": ref(memory),
        "scope": auth["scope"],
        "facet": "longitudinal",
        "authority": "connected_clinical_record",
        "sensitivity": "restricted_clinical",
        "retention": "source_bound",
        "lifecycle": "active",
        "freshness": "current",
        "occurredAt": auth["issuedAt"],
        "integrityRef": ref(f"integrity-{memory}"),
        "lineageRefs": [ref(f"lineage-{memory}")],
        "links": [],
    }
    if target is not None:
        event["links"] = [
            {
                "kind": "evidence",
                "targetRef": ref(target),
                "targetScope": auth["scope"],
            }
        ]
    return {"schemaVersion": 1, "authorization": auth, "events": [event]}


def retrieval(
    auth: dict[str, Any],
    *,
    memory: str = "memory",
    anchor: str | None = None,
) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "requestRef": ref(f"request-{memory}"),
        "authorization": auth,
        "anchorRefs": [] if anchor is None else [ref(anchor)],
        "candidateMappings": [
            {
                "candidateRef": ref(memory),
                "nativeMemoryRef": ref(f"native-{memory}"),
                "mappingRef": ref(f"mapping-{memory}"),
                "projectionVersionRef": ref("projection-v1"),
                "scope": auth["scope"],
            }
        ],
        "candidateLimit": 1,
        "maxHops": 3,
    }


def revocation(auth: dict[str, Any], *, memory: str = "memory") -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "authorization": auth,
        "revocation": {
            "schemaVersion": 1,
            "revocationRef": ref(f"revocation-{memory}"),
            "idempotencyRef": ref(f"revocation-idempotency-{memory}"),
            "memoryRef": ref(memory),
            "scope": auth["scope"],
            "lifecycle": "revoked",
            "occurredAt": auth["issuedAt"],
        },
    }


def decision(auth: dict[str, Any], *, memory: str = "memory") -> dict[str, Any]:
    candidate = ref(memory)
    return {
        "schemaVersion": 1,
        "decisionRef": ref(f"decision-{memory}"),
        "idempotencyRef": ref(f"decision-idempotency-{memory}"),
        "requestRef": ref(f"request-{memory}"),
        "nativeReceiptRef": ref(f"native-receipt-{memory}"),
        "integrityRef": ref(f"decision-integrity-{memory}"),
        "authorization": auth,
        "status": "complete",
        "candidateRefs": [candidate],
        "selectedCandidateRefs": [candidate],
        "reasonCodes": ["structural_proximity"],
        "observedAt": auth["issuedAt"],
    }


def token(
    auth: dict[str, Any],
    permission: str,
    *,
    nonce: str,
    audience: str = "mae-semantica-shadow",
) -> str:
    header = {"alg": "HS256", "typ": "JWT", "kid": "synthetic-v1"}
    # Authorization timestamps are deliberately the source of JWT times.
    from datetime import datetime

    issued = int(datetime.fromisoformat(auth["issuedAt"].replace("Z", "+00:00")).timestamp())
    expires = int(datetime.fromisoformat(auth["expiresAt"].replace("Z", "+00:00")).timestamp())
    claims = {
        "iss": "mae-gateway",
        "aud": audience,
        "sub": "mae-gateway",
        "iat": issued,
        "exp": expires,
        "jti": ref(f"jti-{nonce}"),
        "permission": permission,
        "authorization": auth,
    }
    encoded_header = _encode(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    encoded_claims = _encode(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_claims}".encode()
    signature = _encode(hmac.new(SYNTHETIC_KEY, signing_input, hashlib.sha256).digest())
    return f"{encoded_header}.{encoded_claims}.{signature}"


def call_app(
    app: Any,
    method: str,
    path: str,
    *,
    body: Any = None,
    bearer: str | None = None,
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> tuple[int, dict[str, Any]]:
    encoded = b"" if body is None else json.dumps(body, separators=(",", ":")).encode()
    headers = list(extra_headers or [])
    if body is not None:
        headers.extend(
            [(b"content-type", b"application/json"), (b"content-length", str(len(encoded)).encode())]
        )
    if bearer is not None:
        headers.append((b"authorization", f"Bearer {bearer}".encode()))
    sent: list[dict[str, Any]] = []
    received = False

    async def receive() -> dict[str, Any]:
        nonlocal received
        if received:
            return {"type": "http.disconnect"}
        received = True
        return {"type": "http.request", "body": encoded, "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "headers": headers,
    }
    asyncio.run(app(scope, receive, send))
    start = next(item for item in sent if item["type"] == "http.response.start")
    response_body = next(item for item in sent if item["type"] == "http.response.body")
    return start["status"], json.loads(response_body["body"])


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _timestamp(seconds: int) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat().replace("+00:00", "Z")
