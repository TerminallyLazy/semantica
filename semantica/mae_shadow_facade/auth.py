"""Injected workload-token boundary for the private Mae shadow facade."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import threading
import time
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .contracts import (
    ContractViolation,
    WireAuthorization,
    parse_authorization,
    validate_opaque_ref,
)


class AuthenticationFailure(ValueError):
    """Raised without copying token or tenant details into the error."""


@dataclass(frozen=True)
class WorkloadIdentity:
    authorization: WireAuthorization
    permission: str
    jti: str


class WorkloadTokenVerifier(Protocol):
    """Production seam for asymmetric KMS-backed JWT or mTLS verification."""

    production_ready: bool

    def verify(
        self,
        token: str,
        *,
        required_permission: str,
        now: float | None = None,
    ) -> WorkloadIdentity: ...


class RejectingWorkloadTokenVerifier:
    """Fail-closed default used until production identity infrastructure exists."""

    production_ready = False

    def verify(
        self,
        token: str,
        *,
        required_permission: str,
        now: float | None = None,
    ) -> WorkloadIdentity:
        raise AuthenticationFailure("workload verifier unavailable")


class InMemoryReplayGuard:
    """Synthetic replay guard; a durable distributed implementation is required later."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._expirations: dict[str, int] = {}

    def consume(self, jti: str, expires_at: int, now: int) -> None:
        with self._lock:
            self._expirations = {
                key: expiry for key, expiry in self._expirations.items() if expiry > now
            }
            if jti in self._expirations:
                raise AuthenticationFailure("workload token replayed")
            self._expirations[jti] = expires_at


class SyntheticHMACWorkloadTokenVerifier:
    """HS256 verifier only for synthetic local tests.

    This verifier is intentionally marked non-production. Enabling a real facade
    requires an injected audience-bound asymmetric/KMS verifier or mTLS identity
    verifier whose ``production_ready`` property is true.
    """

    production_ready = False

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        keys: Mapping[str, bytes],
        replay_guard: InMemoryReplayGuard | None = None,
        clock_skew_seconds: int = 5,
    ) -> None:
        if not issuer or not audience or not keys:
            raise ValueError("synthetic verifier configuration")
        if any(len(secret) < 32 for secret in keys.values()):
            raise ValueError("synthetic HMAC keys must be at least 32 bytes")
        self._issuer = issuer
        self._audience = audience
        self._keys = dict(keys)
        self._replay_guard = replay_guard or InMemoryReplayGuard()
        self._clock_skew_seconds = clock_skew_seconds

    def verify(
        self,
        token: str,
        *,
        required_permission: str,
        now: float | None = None,
    ) -> WorkloadIdentity:
        try:
            encoded_header, encoded_payload, encoded_signature = token.split(".")
        except ValueError as error:
            raise AuthenticationFailure("malformed workload token") from error

        header = _decode_json_segment(encoded_header)
        claims = _decode_json_segment(encoded_payload)
        if set(header) != {"alg", "typ", "kid"}:
            raise AuthenticationFailure("invalid workload token header")
        if (
            header["alg"] != "HS256"
            or header["typ"] != "JWT"
            or not isinstance(header["kid"], str)
        ):
            raise AuthenticationFailure("unsupported synthetic token algorithm")
        secret = self._keys.get(header["kid"])
        if secret is None:
            raise AuthenticationFailure("unknown synthetic token key")

        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
        supplied = _decode_segment(encoded_signature)
        if not hmac.compare_digest(expected, supplied):
            raise AuthenticationFailure("invalid workload token signature")

        required_claims = {
            "iss",
            "aud",
            "sub",
            "iat",
            "exp",
            "jti",
            "permission",
            "authorization",
        }
        if set(claims) != required_claims:
            raise AuthenticationFailure("invalid workload token claims")
        if (
            claims["iss"] != self._issuer
            or claims["aud"] != self._audience
            or claims["sub"] != "mae-gateway"
            or claims["permission"] != required_permission
        ):
            raise AuthenticationFailure("workload token binding failed")

        issued_at = _integer_date(claims["iat"])
        expires_at = _integer_date(claims["exp"])
        current = int(time.time() if now is None else now)
        if (
            expires_at <= issued_at
            or expires_at - issued_at > 60
            or issued_at > current + self._clock_skew_seconds
            or expires_at <= current - self._clock_skew_seconds
        ):
            raise AuthenticationFailure("workload token expired")

        try:
            jti = validate_opaque_ref(claims["jti"])
            authorization = parse_authorization(claims["authorization"])
        except ContractViolation as error:
            raise AuthenticationFailure("invalid workload authorization") from error
        if (
            abs(authorization.issued_at.timestamp() - issued_at) > 0.001
            or abs(authorization.expires_at.timestamp() - expires_at) > 0.001
        ):
            raise AuthenticationFailure("workload authorization time mismatch")

        self._replay_guard.consume(jti, expires_at, current)
        return WorkloadIdentity(
            authorization=authorization,
            permission=required_permission,
            jti=jti,
        )


def _integer_date(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AuthenticationFailure("invalid workload token time")
    return value


def _decode_segment(value: str) -> bytes:
    if not value or any(character not in _BASE64URL for character in value):
        raise AuthenticationFailure("malformed workload token segment")
    try:
        return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (ValueError, binascii.Error) as error:
        raise AuthenticationFailure("malformed workload token segment") from error


def _decode_json_segment(value: str) -> dict[str, Any]:
    try:
        decoded = json.loads(
            _decode_segment(value),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthenticationFailure("malformed workload token JSON") from error
    if not isinstance(decoded, dict):
        raise AuthenticationFailure("workload token segment must be an object")
    return decoded


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuthenticationFailure("duplicate workload token claim")
        result[key] = value
    return result


_BASE64URL = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
