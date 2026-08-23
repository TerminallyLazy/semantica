"""Production workload-identity seam for the private Mae shadow facade."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .contracts import WireAuthorization


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
