# Mae Semantica shadow facade

This package is a dedicated, private, structural-only façade for Mae's optional
Semantica shadow plane. It is not Semantica Explorer and deliberately imports
none of Explorer, LLM, embedding, MCP, generic graph-query, import, export, or
document-processing code.

Mae's native stores remain authoritative for identity, consent, health records,
conversation content, and clinical facts. The façade may store only canonical
versioned HMAC-SHA256 references plus allowlisted structural lifecycle,
freshness, provenance, graph-link, and comparison-result codes. It can rank only
the candidate references supplied by Mae; it cannot retrieve or create clinical
content.

## Disabled-by-default operation

The module-level ASGI `app` is disabled and returns `503` for every data route.
Enabling it in production requires explicit injection of:

- an audience-bound, short-lived asymmetric/KMS JWT or mTLS workload verifier
  whose `production_ready` property is `True`; and
- a production tenant-partitioned store with transactional deadline fences; and
- a distributed account-attempt limiter whose `production_ready` property is
  `True`.

There is no static API-key fallback and no symmetric workload verifier in the
runtime package. Synthetic signing and verification exist only under `tests/`.
`InMemoryTenantPartitionedShadowStore` is a non-production reference component,
and the constructor refuses it in enabled mode. There is no production bypass.

The production verifier must validate issuer, audience, subject, permission,
expiry of at most 60 seconds, unique token identity/replay, and the complete
`authorization` capability. The façade then requires exact equality between the
signed capability and the request body's capability.

## Private route allowlist

| Method | Route | Workload permission |
| --- | --- | --- |
| `POST` | `/v1/shadow/events:batch` | `shadow.events:write` |
| `POST` | `/v1/shadow/retrievals` | `shadow.retrievals:read` |
| `POST` | `/v1/shadow/decisions` | `shadow.decisions:write` |
| `GET` | `/v1/shadow/provenance/{memoryRef}` | `shadow.provenance:read` |
| `POST` | `/v1/shadow/revocations` | `shadow.revocations:write` |
| `GET` | `/v1/shadow/revocations/{revocationRef}` | `shadow.revocations:read` |
| `GET` | `/health/live` | none; redacted liveness only |
| `GET` | `/health/ready` | none; redacted aggregate readiness only |

Unknown JSON properties, duplicate keys, prohibited fields, noncanonical
references, cross-scope links/mappings, query strings, unbounded batches, and
static API-key headers fail closed. Retrieval is deterministic and bounded to
10 anchors, 20 candidate mappings, three hops, and a 200-node synthetic graph
visit budget. Events are limited to 50 and 256 KiB. Backend failures remain
distinguishable from empty results through explicit `unavailable` responses.
The ingress deadline begins before authentication, account quota charging, and
body receipt; authenticated malformed requests consume account-level quota.
Store operations are asynchronous and carry an immutable deadline fence that a
production transaction must validate immediately before committing. No worker
thread may continue a mutation after an `unavailable` response.

## Operational blockers before real data

No deployment configuration is included and this reference must not receive
real PHI. Production remains blocked until, at minimum, the operator has:

- an executed BAA and approved data-flow/threat-model review;
- a private network ingress/egress policy and authenticated Mae gateway;
- asymmetric KMS-backed signing/key rotation or workload mTLS, a distributed
  replay cache, and auditable secret lifecycle;
- a durable encrypted tenant-partitioned backend with independently verified
  isolation, backup/restore, deletion, and revocation behavior;
- PHI-safe observability, on-call ownership, incident response, audit retention,
  rate limiting, and deployment rollback controls; and
- physical-device account-switch, longitudinal, revocation, and failure-mode
  acceptance using synthetic data before a separately approved real-data gate.

## Focused synthetic verification

Run only the façade tests:

```bash
python3 -m pytest -q tests/mae_shadow_facade
```

The runtime implementation uses only Python's standard library. The adjacent
lock, CycloneDX SBOM, provenance record, and generated source manifest cover
this isolated façade, not Semantica's much larger base distribution.
