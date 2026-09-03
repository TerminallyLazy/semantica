# Mae production shadow deployment

This deployment is a private, observe-only Semantica façade. It accepts only
opaque tenant references and bounded structural metadata. The contracts reject
clinical content, prompts, transcripts, credentials, embeddings, and unknown
fields before storage.

## Required infrastructure

- A dedicated Google Cloud project and approved region under the applicable
  organization controls and data-flow review.
- Private Cloud Run ingress with unauthenticated invocation disabled.
- PostgreSQL with encrypted connections, CMEK where required, automated
  backups, point-in-time recovery, and a dedicated least-privilege database
  role limited to the `mae_shadow` schema.
- Cloud KMS HMAC-SHA256 key for opaque reference derivation and an RSA signing
  key using `RSA_SIGN_PKCS1_2048_SHA256` or stronger. Private key material must
  never be exported.
- Secret Manager delivery for `DATABASE_URL` and the public-key JSON. The JWT
  public keys are not secret, but treating configuration uniformly avoids
  accidental image baking.
- Vercel Workload Identity Federation restricted to the exact Mae production
  project/environment subject.

Apply `001_schema.sql` and then `002_operations.sql` before starting the
service. Readiness remains unavailable unless schema version 2 is present.

## Runtime settings

Required:

- `SEMANTICA_ENABLED=true`
- `DATABASE_URL`
- `SEMANTICA_JWT_ISSUER`: exact gateway service-account email
- `SEMANTICA_JWT_AUDIENCE`: must match the gateway value
- `SEMANTICA_JWT_PUBLIC_KEYS_JSON`: object mapping each accepted `kid` to its
  KMS public PEM; include old and new keys during rotation

Optional `SEMANTICA_DATABASE_POOL_SIZE` defaults to 8 per worker. The supplied
image starts two workers, so size the database for twice that maximum plus
administrative connections.

Build with `Dockerfile.mae-shadow`. It pins the base image by digest, installs
the hashed lock file, runs as UID 10001, and disables access logs. Application
events are metadata-only and must never include body, reference, token, or PHI
values.

## Promotion gates

1. Apply both migrations and verify `/health/ready` through an authenticated
   Cloud Run invocation.
2. Run `tests/mae_shadow_facade` against that PostgreSQL instance using only
   synthetic opaque references.
3. Verify replay rejection, tenant isolation, revocation/no-resurrection,
   deadline rollback, backup restore, and `delete_exact_tenant` in the target
   environment.
4. Confirm the Cloud Run revision, image digest, ingress, IAM bindings, database
   encryption/backup state, KMS key versions, and log exclusions by readback.
5. Record the applicable BAA/data-flow approval and region decision.
6. Only then enable all four independent iOS release gates. Semantica remains
   an observer; it is never authoritative for prompt composition or app state.

`delete_exact_tenant(account_ref, family_ref, member_ref)` is the exact-member
data-subject deletion primitive. `cleanup_ephemeral_state()` removes expired
JWT replay records and stale rate windows. Decision/audit retention is not
silently guessed by code; operations must apply the approved written retention
schedule.
