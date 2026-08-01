CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS cookie_core_services (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  category text NOT NULL DEFAULT 'Geral',
  upstream_url text NOT NULL CHECK (upstream_url LIKE 'https://%'),
  allowed_domains text[] NOT NULL,
  allowed_paths text[] NOT NULL DEFAULT ARRAY['/'],
  allowed_cookie_names text[] NOT NULL DEFAULT ARRAY[]::text[],
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Upgrade from the former multi-profile model. For each user/service, retain
-- only the default (or most recently updated) profile's cookies.
DO $$
BEGIN
  IF to_regclass('cookie_core_profiles') IS NOT NULL THEN
    IF to_regclass('cookie_core_proxy_grants') IS NOT NULL THEN
      EXECUTE 'DELETE FROM cookie_core_proxy_grants';
      EXECUTE 'ALTER TABLE cookie_core_proxy_grants DROP CONSTRAINT IF EXISTS cookie_core_proxy_grants_profile_id_user_id_service_id_fkey';
      EXECUTE 'ALTER TABLE cookie_core_proxy_grants DROP COLUMN IF EXISTS profile_id';
    END IF;

    IF to_regclass('cookie_core_launch_tokens') IS NOT NULL THEN
      EXECUTE 'DELETE FROM cookie_core_launch_tokens';
      EXECUTE 'ALTER TABLE cookie_core_launch_tokens DROP CONSTRAINT IF EXISTS cookie_core_launch_tokens_profile_id_user_id_service_id_fkey';
      EXECUTE 'ALTER TABLE cookie_core_launch_tokens DROP COLUMN IF EXISTS profile_id';
    END IF;

    IF to_regclass('cookie_core_stored_cookies') IS NOT NULL THEN
      EXECUTE 'ALTER TABLE cookie_core_stored_cookies DROP CONSTRAINT IF EXISTS cookie_core_stored_cookies_profile_id_user_id_service_id_fkey';
      EXECUTE 'ALTER TABLE cookie_core_stored_cookies DROP CONSTRAINT IF EXISTS cookie_core_stored_cookies_user_id_service_id_profile_id_name_domain_path_key';
      EXECUTE $migration$
        DELETE FROM cookie_core_stored_cookies c
        USING (
          SELECT DISTINCT ON (user_id, service_id)
            id, user_id, service_id
          FROM cookie_core_profiles
          ORDER BY user_id, service_id, is_default DESC, updated_at DESC, created_at DESC
        ) selected
        WHERE c.user_id=selected.user_id
          AND c.service_id=selected.service_id
          AND c.profile_id<>selected.id
      $migration$;
      EXECUTE 'ALTER TABLE cookie_core_stored_cookies DROP COLUMN IF EXISTS profile_id';
    END IF;

    IF to_regclass('cookie_core_audit_logs') IS NOT NULL THEN
      EXECUTE 'ALTER TABLE cookie_core_audit_logs DROP COLUMN IF EXISTS profile_id';
    END IF;

    DROP TABLE cookie_core_profiles;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS cookie_core_stored_cookies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id text NOT NULL,
  service_id uuid NOT NULL REFERENCES cookie_core_services(id) ON DELETE CASCADE,
  name text NOT NULL,
  domain text NOT NULL,
  path text NOT NULL DEFAULT '/',
  encrypted_value bytea NOT NULL,
  nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
  expires_at timestamptz,
  secure boolean NOT NULL DEFAULT true,
  http_only boolean NOT NULL DEFAULT true,
  same_site text CHECK (same_site IN ('Strict','Lax','None') OR same_site IS NULL),
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS cookie_core_stored_cookies_scope_key
  ON cookie_core_stored_cookies(user_id,service_id,name,domain,path);
CREATE INDEX IF NOT EXISTS cookie_core_stored_cookies_owner_idx
  ON cookie_core_stored_cookies(user_id,service_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS cookie_core_launch_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash text NOT NULL UNIQUE,
  user_id text NOT NULL,
  service_id uuid NOT NULL REFERENCES cookie_core_services(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS cookie_core_launch_tokens_expiry_idx
  ON cookie_core_launch_tokens(expires_at);

CREATE TABLE IF NOT EXISTS cookie_core_proxy_grants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash text NOT NULL UNIQUE,
  user_id text NOT NULL,
  service_id uuid NOT NULL REFERENCES cookie_core_services(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS cookie_core_proxy_grants_expiry_idx
  ON cookie_core_proxy_grants(expires_at) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS cookie_core_audit_logs (
  id bigserial PRIMARY KEY,
  actor_user_id text NOT NULL,
  subject_user_id text NOT NULL,
  service_id uuid,
  action text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);


ALTER TABLE cookie_core_services ENABLE ROW LEVEL SECURITY;
ALTER TABLE cookie_core_stored_cookies ENABLE ROW LEVEL SECURITY;
ALTER TABLE cookie_core_launch_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE cookie_core_proxy_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE cookie_core_audit_logs ENABLE ROW LEVEL SECURITY;

-- The Lovable client uses the API/Edge Function, never these tables directly.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    REVOKE ALL ON cookie_core_services, cookie_core_stored_cookies,
      cookie_core_launch_tokens, cookie_core_proxy_grants,
      cookie_core_audit_logs FROM anon;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    REVOKE ALL ON cookie_core_services, cookie_core_stored_cookies,
      cookie_core_launch_tokens, cookie_core_proxy_grants,
      cookie_core_audit_logs FROM authenticated;
  END IF;
END $$;
