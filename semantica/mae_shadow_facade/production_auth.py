"""KMS-backed RS256 workload verification with durable replay rejection."""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from psycopg.errors import UniqueViolation
from psycopg_pool import ConnectionPool

from .auth import AuthenticationFailure, WorkloadIdentity
from .contracts import ContractViolation, parse_authorization


def _decode_segment(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as error:
        raise AuthenticationFailure("invalid workload token") from error


def _object(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise AuthenticationFailure("invalid workload token")
    return value


@dataclass(frozen=True)
class KMSRS256VerifierSettings:
    issuer: str
    audience: str
    public_keys: Mapping[str, str]
    maximum_lifetime_seconds: int = 60
    clock_skew_seconds: int = 5


class KMSRS256WorkloadTokenVerifier:
    """Verifies JWTs signed by non-exportable Cloud KMS RSA keys.

    Public keys are non-secret and multiple ``kid`` values may be supplied for
    zero-downtime rotation. Every accepted ``jti`` is inserted into PostgreSQL
    before returning, so a valid token can be used exactly once.
    """

    production_ready = True

    def __init__(
        self,
        settings: KMSRS256VerifierSettings,
        pool: ConnectionPool,
    ) -> None:
        if not settings.issuer or not settings.audience or not settings.public_keys:
            raise ValueError("workload verifier configuration incomplete")
        keys: dict[str, rsa.RSAPublicKey] = {}
        for kid, pem in settings.public_keys.items():
            if not kid or len(kid) > 128 or not isinstance(pem, str):
                raise ValueError("invalid workload public key")
            key = serialization.load_pem_public_key(pem.encode("ascii"))
            if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
                raise ValueError("RS256 workload keys must be RSA-2048 or stronger")
            keys[kid] = key
        self._settings = settings
        self._keys = keys
        self._pool = pool

    def verify(
        self,
        token: str,
        *,
        required_permission: str,
        now: float | None = None,
    ) -> WorkloadIdentity:
        try:
            header_segment, payload_segment, signature_segment = token.split(".")
            header = _object(json.loads(_decode_segment(header_segment)))
            claims = _object(json.loads(_decode_segment(payload_segment)))
            if set(header) != {"alg", "typ", "kid"}:
                raise AuthenticationFailure("invalid workload header")
            if header["alg"] != "RS256" or header["typ"] != "JWT":
                raise AuthenticationFailure("invalid workload algorithm")
            kid = header["kid"]
            if not isinstance(kid, str) or kid not in self._keys:
                raise AuthenticationFailure("unknown workload key")
            self._keys[kid].verify(
                _decode_segment(signature_segment),
                f"{header_segment}.{payload_segment}".encode("ascii"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            required = {
                "iss",
                "aud",
                "iat",
                "nbf",
                "exp",
                "jti",
                "permission",
                "authorization",
            }
            if set(claims) != required:
                raise AuthenticationFailure("invalid workload claims")
            current = time.time() if now is None else now
            issued = claims["iat"]
            not_before = claims["nbf"]
            expires = claims["exp"]
            if any(
                isinstance(value, bool) or not isinstance(value, int)
                for value in (issued, not_before, expires)
            ):
                raise AuthenticationFailure("invalid workload time")
            skew = self._settings.clock_skew_seconds
            if (
                claims["iss"] != self._settings.issuer
                or claims["aud"] != self._settings.audience
                or claims["permission"] != required_permission
                or issued > current + skew
                or not_before > current + skew
                or expires <= current - skew
                or expires - issued <= 0
                or expires - issued > self._settings.maximum_lifetime_seconds
            ):
                raise AuthenticationFailure("workload claim mismatch")
            jti = claims["jti"]
            if not isinstance(jti, str) or not 1 <= len(jti) <= 128:
                raise AuthenticationFailure("invalid workload nonce")
            authorization = parse_authorization(claims["authorization"])
            if (
                authorization.issued_at.timestamp() < issued - skew
                or authorization.expires_at.timestamp() > expires + skew
            ):
                raise AuthenticationFailure("authorization lifetime exceeds token")
            self._consume_once(jti, expires)
            return WorkloadIdentity(
                authorization=authorization,
                permission=required_permission,
                jti=jti,
            )
        except AuthenticationFailure:
            raise
        except (
            InvalidSignature,
            ContractViolation,
            ValueError,
            TypeError,
            KeyError,
            UnicodeError,
        ) as error:
            raise AuthenticationFailure("invalid workload token") from error

    def _consume_once(self, jti: str, expires: int) -> None:
        try:
            with self._pool.connection() as connection:
                with connection.transaction():
                    connection.execute(
                        "DELETE FROM mae_shadow.workload_jti WHERE expires_at < now()"
                    )
                    connection.execute(
                        "INSERT INTO mae_shadow.workload_jti (jti, expires_at) VALUES (%s, to_timestamp(%s))",
                        (jti, expires),
                    )
        except UniqueViolation as error:
            raise AuthenticationFailure("workload token replay") from error
        except AuthenticationFailure:
            raise
        except Exception as error:
            raise AuthenticationFailure("replay protection unavailable") from error
