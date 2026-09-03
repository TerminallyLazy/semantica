BEGIN;

CREATE OR REPLACE FUNCTION mae_shadow.delete_exact_tenant(
  target_account_ref text,
  target_family_ref text,
  target_member_ref text
) RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, mae_shadow
AS $$
BEGIN
  IF target_account_ref IS NULL OR target_account_ref = ''
     OR target_family_ref IS NULL OR target_family_ref = ''
     OR target_member_ref IS NULL OR target_member_ref = '' THEN
    RAISE EXCEPTION 'exact tenant references are required';
  END IF;

  DELETE FROM mae_shadow.decisions
    WHERE account_ref = target_account_ref AND family_ref = target_family_ref
      AND member_ref = target_member_ref;
  DELETE FROM mae_shadow.event_idempotency
    WHERE account_ref = target_account_ref AND family_ref = target_family_ref
      AND member_ref = target_member_ref;
  DELETE FROM mae_shadow.policies
    WHERE account_ref = target_account_ref AND family_ref = target_family_ref
      AND member_ref = target_member_ref;
  DELETE FROM mae_shadow.projections
    WHERE account_ref = target_account_ref AND family_ref = target_family_ref
      AND member_ref = target_member_ref;
  DELETE FROM mae_shadow.revocations
    WHERE account_ref = target_account_ref AND family_ref = target_family_ref
      AND member_ref = target_member_ref;
END;
$$;

CREATE OR REPLACE FUNCTION mae_shadow.cleanup_ephemeral_state()
RETURNS TABLE(expired_workload_tokens bigint, expired_rate_windows bigint)
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, mae_shadow
AS $$
DECLARE
  workload_count bigint;
  rate_count bigint;
BEGIN
  DELETE FROM mae_shadow.workload_jti WHERE expires_at < now();
  GET DIAGNOSTICS workload_count = ROW_COUNT;
  DELETE FROM mae_shadow.rate_limits WHERE window_start < date_trunc('minute', now()) - interval '2 minutes';
  GET DIAGNOSTICS rate_count = ROW_COUNT;
  RETURN QUERY SELECT workload_count, rate_count;
END;
$$;

UPDATE mae_shadow.schema_version SET version = 2 WHERE singleton = true;
COMMIT;
