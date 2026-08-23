"""Strict structural-only wire contracts for Mae's private shadow facade."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence


MAX_EVENT_BATCH_BYTES = 256 * 1024
MAX_DEFAULT_BODY_BYTES = 64 * 1024
MAX_EVENTS = 50
MAX_LINKS = 32
MAX_LINEAGE_REFS = 32
MAX_ANCHORS = 10
MAX_CANDIDATES = 20
MAX_HOPS = 3
MAX_PROVENANCE_ENTRIES = 50

FACETS = frozenset(
    {
        "working",
        "episodic",
        "semantic",
        "longitudinal",
        "procedural",
        "prospective",
        "decision",
        "clinical_evidence",
    }
)
AUTHORITIES = frozenset(
    {
        "identity",
        "shared_care",
        "connected_clinical_record",
        "healthkit_clinical_record",
        "local_conversation",
        "public_medical_source",
        "user_statement",
        "derived_memory",
        "model_inference",
    }
)
SENSITIVITIES = frozenset(
    {"non_sensitive", "personal", "clinical", "restricted_clinical"}
)
RETENTION_CODES = frozenset({"session", "source_bound", "until_date", "durable"})
LIFECYCLE_CODES = frozenset({"active", "superseded", "revoked", "deleted", "reindex"})
EVENT_LIFECYCLE_CODES = frozenset({"active", "superseded", "reindex"})
FRESHNESS_CODES = frozenset({"current", "stale_projection", "partial", "unknown"})
LINK_KINDS = frozenset({"derived_from", "supersedes", "evidence"})
RESULT_STATUSES = frozenset(
    {"complete", "complete_empty", "partial", "unavailable", "skipped"}
)
SELECTION_REASONS = frozenset(
    {"structural_proximity", "provenance_match", "lifecycle_match", "freshness_match"}
)
OMISSION_CODES = frozenset(
    {
        "scope",
        "generation",
        "revoked",
        "expired",
        "duplicate",
        "unhydrated",
        "deadline",
        "result_budget",
        "content_budget",
        "conflict_budget",
        "source_failure",
    }
)

_OPAQUE_REF = re.compile(
    r"^hmac-sha256\.([A-Za-z0-9_-]{1,32})\.([A-Za-z0-9_-]{43})$"
)
_PROHIBITED_KEYS = frozenset(
    {
        "content",
        "text",
        "utterance",
        "prompt",
        "response",
        "summary",
        "rationale",
        "reasoning",
        "chainofthought",
        "rawidentifier",
        "rawpayload",
        "clinicalpayload",
        "fhir",
        "healthkit",
        "document",
        "attachment",
        "demographic",
        "diagnosis",
        "medication",
        "observation",
        "clinicalvalue",
        "sourceurl",
        "credential",
        "apikey",
        "embedding",
        "vector",
        "sparql",
        "cypher",
        "query",
        "import",
        "export",
        "mcp",
        "llm",
    }
)


class ContractViolation(ValueError):
    """Raised when a request is outside the strict Mae shadow contract."""


def validate_no_prohibited_fields(value: Any) -> None:
    """Reject prohibited field names at any nesting level before parsing."""

    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if normalized in _PROHIBITED_KEYS:
                raise ContractViolation("prohibited field")
            validate_no_prohibited_fields(nested)
    elif isinstance(value, list):
        for nested in value:
            validate_no_prohibited_fields(nested)


def validate_opaque_ref(value: Any) -> str:
    if not isinstance(value, str):
        raise ContractViolation("invalid opaque reference")
    match = _OPAQUE_REF.fullmatch(value)
    if match is None:
        raise ContractViolation("invalid opaque reference")
    digest_text = match.group(2)
    try:
        digest = base64.urlsafe_b64decode(digest_text + "=")
    except (ValueError, binascii.Error) as error:
        raise ContractViolation("invalid opaque reference") from error
    canonical = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    if len(digest) != 32 or canonical != digest_text:
        raise ContractViolation("non-canonical opaque reference")
    return value


def parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ContractViolation("invalid timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ContractViolation("invalid timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ContractViolation("timestamp must be UTC")
    return parsed


def _object(
    value: Any,
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractViolation("expected object")
    optional = optional or set()
    keys = set(value)
    if keys - required - optional:
        raise ContractViolation("unknown field")
    if required - keys:
        raise ContractViolation("missing field")
    return value


def _array(value: Any, *, maximum: int, allow_empty: bool = True) -> Sequence[Any]:
    if not isinstance(value, list) or len(value) > maximum or (not allow_empty and not value):
        raise ContractViolation("invalid array bounds")
    return value


def _enum(value: Any, allowed: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ContractViolation("invalid code")
    return value


def _positive_uint(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value >= 2**64:
        raise ContractViolation("invalid unsigned integer")
    return value


@dataclass(frozen=True)
class ScopeReferences:
    account_ref: str
    family_ref: str
    member_ref: str | None

    @property
    def partition(self) -> tuple[str, str, str | None]:
        return self.account_ref, self.family_ref, self.member_ref


@dataclass(frozen=True)
class WireAuthorization:
    scope: ScopeReferences
    authorization_generation: int
    session_binding_ref: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class StructuralLink:
    kind: str
    target_ref: str
    target_scope: ScopeReferences


@dataclass(frozen=True)
class EventProjection:
    event_ref: str
    idempotency_ref: str
    memory_ref: str
    scope: ScopeReferences
    facet: str
    authority: str
    sensitivity: str
    retention: str
    lifecycle: str
    freshness: str
    occurred_at: datetime
    integrity_ref: str
    lineage_refs: tuple[str, ...]
    links: tuple[StructuralLink, ...]
    canonical_payload: Mapping[str, Any]


@dataclass(frozen=True)
class EventBatchRequest:
    authorization: WireAuthorization
    events: tuple[EventProjection, ...]


@dataclass(frozen=True)
class CandidateMapping:
    candidate_ref: str
    native_memory_ref: str
    mapping_ref: str
    projection_version_ref: str
    scope: ScopeReferences


@dataclass(frozen=True)
class RetrievalRequest:
    request_ref: str
    authorization: WireAuthorization
    anchor_refs: tuple[str, ...]
    candidate_mappings: tuple[CandidateMapping, ...]
    candidate_limit: int
    max_hops: int


@dataclass(frozen=True)
class DecisionRecord:
    decision_ref: str
    idempotency_ref: str
    request_ref: str
    native_receipt_ref: str
    integrity_ref: str
    authorization: WireAuthorization
    status: str
    candidate_refs: tuple[str, ...]
    selected_candidate_refs: tuple[str, ...]
    reason_codes: tuple[str, ...]
    observed_at: datetime
    canonical_payload: Mapping[str, Any]


@dataclass(frozen=True)
class RevocationRecord:
    revocation_ref: str
    idempotency_ref: str
    memory_ref: str
    scope: ScopeReferences
    lifecycle: str
    occurred_at: datetime
    canonical_payload: Mapping[str, Any]


@dataclass(frozen=True)
class RevocationRequest:
    authorization: WireAuthorization
    revocation: RevocationRecord


def parse_scope(value: Any) -> ScopeReferences:
    obj = _object(
        value,
        required={"accountRef", "familyRef"},
        optional={"memberRef"},
    )
    member_ref = None
    if "memberRef" in obj:
        member_ref = validate_opaque_ref(obj["memberRef"])
    return ScopeReferences(
        account_ref=validate_opaque_ref(obj["accountRef"]),
        family_ref=validate_opaque_ref(obj["familyRef"]),
        member_ref=member_ref,
    )


def parse_authorization(value: Any) -> WireAuthorization:
    obj = _object(
        value,
        required={
            "scope",
            "authorizationGeneration",
            "sessionBindingRef",
            "issuedAt",
            "expiresAt",
        },
    )
    issued_at = parse_timestamp(obj["issuedAt"])
    expires_at = parse_timestamp(obj["expiresAt"])
    lifetime = (expires_at - issued_at).total_seconds()
    if lifetime <= 0 or lifetime > 60:
        raise ContractViolation("authorization lifetime")
    return WireAuthorization(
        scope=parse_scope(obj["scope"]),
        authorization_generation=_positive_uint(obj["authorizationGeneration"]),
        session_binding_ref=validate_opaque_ref(obj["sessionBindingRef"]),
        issued_at=issued_at,
        expires_at=expires_at,
    )


def _parse_link(value: Any, expected_scope: ScopeReferences) -> StructuralLink:
    obj = _object(value, required={"kind", "targetRef", "targetScope"})
    target_scope = parse_scope(obj["targetScope"])
    if target_scope != expected_scope:
        raise ContractViolation("link scope mismatch")
    return StructuralLink(
        kind=_enum(obj["kind"], LINK_KINDS),
        target_ref=validate_opaque_ref(obj["targetRef"]),
        target_scope=target_scope,
    )


def _parse_event(value: Any, authorization: WireAuthorization) -> EventProjection:
    obj = _object(
        value,
        required={
            "schemaVersion",
            "eventRef",
            "idempotencyRef",
            "memoryRef",
            "scope",
            "facet",
            "authority",
            "sensitivity",
            "retention",
            "lifecycle",
            "freshness",
            "occurredAt",
            "integrityRef",
            "lineageRefs",
            "links",
        },
    )
    if obj["schemaVersion"] != 1:
        raise ContractViolation("unsupported schema version")
    scope = parse_scope(obj["scope"])
    if scope != authorization.scope:
        raise ContractViolation("event scope mismatch")
    lineage = tuple(
        validate_opaque_ref(item)
        for item in _array(obj["lineageRefs"], maximum=MAX_LINEAGE_REFS)
    )
    links = tuple(
        _parse_link(item, scope) for item in _array(obj["links"], maximum=MAX_LINKS)
    )
    return EventProjection(
        event_ref=validate_opaque_ref(obj["eventRef"]),
        idempotency_ref=validate_opaque_ref(obj["idempotencyRef"]),
        memory_ref=validate_opaque_ref(obj["memoryRef"]),
        scope=scope,
        facet=_enum(obj["facet"], FACETS),
        authority=_enum(obj["authority"], AUTHORITIES),
        sensitivity=_enum(obj["sensitivity"], SENSITIVITIES),
        retention=_enum(obj["retention"], RETENTION_CODES),
        lifecycle=_enum(obj["lifecycle"], EVENT_LIFECYCLE_CODES),
        freshness=_enum(obj["freshness"], FRESHNESS_CODES),
        occurred_at=parse_timestamp(obj["occurredAt"]),
        integrity_ref=validate_opaque_ref(obj["integrityRef"]),
        lineage_refs=lineage,
        links=links,
        canonical_payload=dict(obj),
    )


def parse_event_batch(value: Any) -> EventBatchRequest:
    validate_no_prohibited_fields(value)
    obj = _object(value, required={"schemaVersion", "authorization", "events"})
    if obj["schemaVersion"] != 1:
        raise ContractViolation("unsupported schema version")
    authorization = parse_authorization(obj["authorization"])
    events = tuple(
        _parse_event(item, authorization)
        for item in _array(obj["events"], maximum=MAX_EVENTS, allow_empty=False)
    )
    return EventBatchRequest(authorization=authorization, events=events)


def _parse_candidate_mapping(value: Any, scope: ScopeReferences) -> CandidateMapping:
    obj = _object(
        value,
        required={
            "candidateRef",
            "nativeMemoryRef",
            "mappingRef",
            "projectionVersionRef",
            "scope",
        },
    )
    candidate_scope = parse_scope(obj["scope"])
    if candidate_scope != scope:
        raise ContractViolation("candidate scope mismatch")
    return CandidateMapping(
        candidate_ref=validate_opaque_ref(obj["candidateRef"]),
        native_memory_ref=validate_opaque_ref(obj["nativeMemoryRef"]),
        mapping_ref=validate_opaque_ref(obj["mappingRef"]),
        projection_version_ref=validate_opaque_ref(obj["projectionVersionRef"]),
        scope=candidate_scope,
    )


def parse_retrieval(value: Any) -> RetrievalRequest:
    validate_no_prohibited_fields(value)
    obj = _object(
        value,
        required={
            "schemaVersion",
            "requestRef",
            "authorization",
            "anchorRefs",
            "candidateMappings",
            "candidateLimit",
            "maxHops",
        },
    )
    if obj["schemaVersion"] != 1:
        raise ContractViolation("unsupported schema version")
    authorization = parse_authorization(obj["authorization"])
    anchors = tuple(
        validate_opaque_ref(item)
        for item in _array(obj["anchorRefs"], maximum=MAX_ANCHORS)
    )
    mappings = tuple(
        _parse_candidate_mapping(item, authorization.scope)
        for item in _array(obj["candidateMappings"], maximum=MAX_CANDIDATES)
    )
    candidate_limit = obj["candidateLimit"]
    max_hops = obj["maxHops"]
    if (
        isinstance(candidate_limit, bool)
        or not isinstance(candidate_limit, int)
        or not 0 <= candidate_limit <= min(MAX_CANDIDATES, len(mappings))
        or isinstance(max_hops, bool)
        or not isinstance(max_hops, int)
        or not 0 <= max_hops <= MAX_HOPS
    ):
        raise ContractViolation("retrieval bounds")
    return RetrievalRequest(
        request_ref=validate_opaque_ref(obj["requestRef"]),
        authorization=authorization,
        anchor_refs=anchors,
        candidate_mappings=mappings,
        candidate_limit=candidate_limit,
        max_hops=max_hops,
    )


def parse_decision(value: Any) -> DecisionRecord:
    validate_no_prohibited_fields(value)
    obj = _object(
        value,
        required={
            "schemaVersion",
            "decisionRef",
            "idempotencyRef",
            "requestRef",
            "nativeReceiptRef",
            "integrityRef",
            "authorization",
            "status",
            "candidateRefs",
            "selectedCandidateRefs",
            "reasonCodes",
            "observedAt",
        },
    )
    if obj["schemaVersion"] != 1:
        raise ContractViolation("unsupported schema version")
    candidates = tuple(
        validate_opaque_ref(item)
        for item in _array(obj["candidateRefs"], maximum=MAX_CANDIDATES)
    )
    selected = tuple(
        validate_opaque_ref(item)
        for item in _array(obj["selectedCandidateRefs"], maximum=MAX_CANDIDATES)
    )
    if not set(selected).issubset(candidates):
        raise ContractViolation("decision selection mismatch")
    reasons = tuple(
        _enum(item, SELECTION_REASONS)
        for item in _array(obj["reasonCodes"], maximum=4)
    )
    status = _enum(obj["status"], RESULT_STATUSES)
    if status in {"complete_empty", "unavailable", "skipped"} and selected:
        raise ContractViolation("decision status mismatch")
    return DecisionRecord(
        decision_ref=validate_opaque_ref(obj["decisionRef"]),
        idempotency_ref=validate_opaque_ref(obj["idempotencyRef"]),
        request_ref=validate_opaque_ref(obj["requestRef"]),
        native_receipt_ref=validate_opaque_ref(obj["nativeReceiptRef"]),
        integrity_ref=validate_opaque_ref(obj["integrityRef"]),
        authorization=parse_authorization(obj["authorization"]),
        status=status,
        candidate_refs=candidates,
        selected_candidate_refs=selected,
        reason_codes=reasons,
        observed_at=parse_timestamp(obj["observedAt"]),
        canonical_payload=dict(obj),
    )


def parse_revocation(value: Any) -> RevocationRequest:
    validate_no_prohibited_fields(value)
    obj = _object(value, required={"schemaVersion", "authorization", "revocation"})
    if obj["schemaVersion"] != 1:
        raise ContractViolation("unsupported schema version")
    authorization = parse_authorization(obj["authorization"])
    revocation_obj = _object(
        obj["revocation"],
        required={
            "schemaVersion",
            "revocationRef",
            "idempotencyRef",
            "memoryRef",
            "scope",
            "lifecycle",
            "occurredAt",
        },
    )
    if revocation_obj["schemaVersion"] != 1:
        raise ContractViolation("unsupported schema version")
    scope = parse_scope(revocation_obj["scope"])
    if scope != authorization.scope:
        raise ContractViolation("revocation scope mismatch")
    lifecycle = _enum(revocation_obj["lifecycle"], LIFECYCLE_CODES)
    if lifecycle not in {"revoked", "deleted"}:
        raise ContractViolation("invalid revocation lifecycle")
    revocation = RevocationRecord(
        revocation_ref=validate_opaque_ref(revocation_obj["revocationRef"]),
        idempotency_ref=validate_opaque_ref(revocation_obj["idempotencyRef"]),
        memory_ref=validate_opaque_ref(revocation_obj["memoryRef"]),
        scope=scope,
        lifecycle=lifecycle,
        occurred_at=parse_timestamp(revocation_obj["occurredAt"]),
        canonical_payload=dict(revocation_obj),
    )
    return RevocationRequest(authorization=authorization, revocation=revocation)
