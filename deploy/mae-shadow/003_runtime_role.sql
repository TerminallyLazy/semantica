BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mae_shadow_runtime') THEN
    CREATE ROLE mae_shadow_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END;
$$;

REVOKE ALL ON SCHEMA mae_shadow FROM PUBLIC;
GRANT USAGE ON SCHEMA mae_shadow TO mae_shadow_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA mae_shadow
  TO mae_shadow_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA mae_shadow
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO mae_shadow_runtime;
REVOKE EXECUTE ON FUNCTION mae_shadow.delete_exact_tenant(text, text, text)
  FROM PUBLIC, mae_shadow_runtime;
REVOKE EXECUTE ON FUNCTION mae_shadow.cleanup_ephemeral_state()
  FROM PUBLIC, mae_shadow_runtime;

UPDATE mae_shadow.schema_version SET version = 3 WHERE singleton = true;
COMMIT;
