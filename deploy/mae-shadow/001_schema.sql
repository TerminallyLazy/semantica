BEGIN;
CREATE SCHEMA IF NOT EXISTS mae_shadow;

CREATE TABLE IF NOT EXISTS mae_shadow.schema_version (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  version integer NOT NULL CHECK (version >= 1),
  applied_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO mae_shadow.schema_version (singleton, version)
VALUES (true, 1) ON CONFLICT (singleton) DO UPDATE SET version = EXCLUDED.version;

CREATE TABLE IF NOT EXISTS mae_shadow.projections (
  account_ref text NOT NULL,
  family_ref text NOT NULL,
  member_ref text NOT NULL,
  memory_ref text NOT NULL,
  event_ref text NOT NULL,
  facet text NOT NULL,
  authority text NOT NULL,
  sensitivity text NOT NULL,
  retention text NOT NULL,
  lifecycle text NOT NULL,
  freshness text NOT NULL,
  occurred_at timestamptz NOT NULL,
  integrity_ref text NOT NULL,
  lineage_refs text[] NOT NULL DEFAULT '{}',
  links jsonb NOT NULL DEFAULT '[]',
  payload_digest text NOT NULL,
  canonical_payload jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_ref, family_ref, member_ref, memory_ref)
);

CREATE TABLE IF NOT EXISTS mae_shadow.event_idempotency (
  account_ref text NOT NULL,
  family_ref text NOT NULL,
  member_ref text NOT NULL,
  idempotency_ref text NOT NULL,
  event_ref text NOT NULL,
  payload_digest text NOT NULL,
  disposition text NOT NULL,
  error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_ref, family_ref, member_ref, idempotency_ref)
);

CREATE TABLE IF NOT EXISTS mae_shadow.decisions (
  account_ref text NOT NULL,
  family_ref text NOT NULL,
  member_ref text NOT NULL,
  idempotency_ref text NOT NULL,
  decision_ref text NOT NULL,
  request_ref text NOT NULL,
  native_receipt_ref text NOT NULL,
  integrity_ref text NOT NULL,
  status text NOT NULL,
  candidate_refs text[] NOT NULL,
  selected_candidate_refs text[] NOT NULL,
  reason_codes text[] NOT NULL,
  observed_at timestamptz NOT NULL,
  payload_digest text NOT NULL,
  canonical_payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_ref, family_ref, member_ref, idempotency_ref),
  UNIQUE (account_ref, family_ref, member_ref, decision_ref)
);

CREATE TABLE IF NOT EXISTS mae_shadow.revocations (
  account_ref text NOT NULL,
  family_ref text NOT NULL,
  member_ref text NOT NULL,
  idempotency_ref text NOT NULL,
  revocation_ref text NOT NULL,
  memory_ref text NOT NULL,
  lifecycle text NOT NULL,
  occurred_at timestamptz NOT NULL,
  payload_digest text NOT NULL,
  canonical_payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_ref, family_ref, member_ref, idempotency_ref),
  UNIQUE (account_ref, family_ref, member_ref, revocation_ref),
  UNIQUE (account_ref, family_ref, member_ref, memory_ref)
);

CREATE TABLE IF NOT EXISTS mae_shadow.policies (
  account_ref text NOT NULL,
  family_ref text NOT NULL,
  member_ref text NOT NULL,
  policy_ref text NOT NULL,
  policy_version text NOT NULL,
  active boolean NOT NULL DEFAULT false,
  canonical_payload jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_ref, family_ref, member_ref, policy_ref)
);

CREATE TABLE IF NOT EXISTS mae_shadow.rate_limits (
  account_ref text NOT NULL,
  bucket text NOT NULL,
  window_start timestamptz NOT NULL,
  attempts integer NOT NULL CHECK (attempts > 0),
  PRIMARY KEY (account_ref, bucket, window_start)
);

CREATE TABLE IF NOT EXISTS mae_shadow.workload_jti (
  jti text PRIMARY KEY,
  expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS mae_shadow_projection_event_idx
  ON mae_shadow.projections (account_ref, family_ref, member_ref, event_ref);
CREATE INDEX IF NOT EXISTS mae_shadow_revocation_memory_idx
  ON mae_shadow.revocations (account_ref, family_ref, member_ref, memory_ref);
CREATE INDEX IF NOT EXISTS mae_shadow_decision_request_idx
  ON mae_shadow.decisions (account_ref, family_ref, member_ref, request_ref);
CREATE INDEX IF NOT EXISTS mae_shadow_rate_expiry_idx
  ON mae_shadow.rate_limits (window_start);
CREATE INDEX IF NOT EXISTS mae_shadow_jti_expiry_idx
  ON mae_shadow.workload_jti (expires_at);
COMMIT;
