from __future__ import annotations

import base64
import json
import time
from contextlib import nullcontext

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from psycopg.errors import UniqueViolation

from semantica.mae_shadow_facade.auth import AuthenticationFailure
from semantica.mae_shadow_facade.production_auth import (
    KMSRS256VerifierSettings,
    KMSRS256WorkloadTokenVerifier,
)

from .helpers import authorization


def _segment(value: object) -> str:
    return (
        base64.urlsafe_b64encode(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        )
        .decode()
        .rstrip("=")
    )


class _Cursor:
    def fetchone(self):
        return None


class _Connection:
    def __init__(self, used: set[str]):
        self.used = used

    def transaction(self):
        return nullcontext()

    def execute(self, sql: str, params=()):
        if "INSERT INTO mae_shadow.workload_jti" in sql:
            jti = params[0]
            if jti in self.used:
                raise UniqueViolation("duplicate")
            self.used.add(jti)
        return _Cursor()


class _Pool:
    def __init__(self):
        self.used: set[str] = set()

    def connection(self):
        return nullcontext(_Connection(self.used))


def _token(private_key, auth, permission="shadow.retrievals:read", jti="once"):
    now = int(time.time())
    header = _segment({"alg": "RS256", "kid": "kms-v1", "typ": "JWT"})
    payload = _segment(
        {
            "iss": "gateway@example.iam.gserviceaccount.com",
            "aud": "mae-semantica-shadow",
            "iat": now,
            "nbf": now - 2,
            "exp": now + 60,
            "jti": jti,
            "permission": permission,
            "authorization": auth,
        }
    )
    signing_input = f"{header}.{payload}".encode()
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return (
        f"{header}.{payload}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"
    )


def _fixture():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    pool = _Pool()
    verifier = KMSRS256WorkloadTokenVerifier(
        KMSRS256VerifierSettings(
            issuer="gateway@example.iam.gserviceaccount.com",
            audience="mae-semantica-shadow",
            public_keys={"kms-v1": public_pem},
        ),
        pool,
    )
    return private_key, verifier


def test_kms_rs256_token_is_exactly_permissioned_and_single_use():
    private_key, verifier = _fixture()
    auth = authorization()
    token = _token(private_key, auth)
    identity = verifier.verify(token, required_permission="shadow.retrievals:read")
    assert identity.authorization.authorization_generation == 7
    assert identity.jti == "once"
    with pytest.raises(AuthenticationFailure):
        verifier.verify(token, required_permission="shadow.retrievals:read")


def test_kms_rs256_token_rejects_permission_substitution():
    private_key, verifier = _fixture()
    with pytest.raises(AuthenticationFailure):
        verifier.verify(
            _token(private_key, authorization(), permission="shadow.events:write"),
            required_permission="shadow.retrievals:read",
        )
