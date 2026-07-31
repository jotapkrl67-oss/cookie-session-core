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

CREATE TABLE IF NOT EXISTS cookie_core_profiles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id text NOT NULL,
  service_id uuid NOT NULL REFERENCES cookie_core_services(id) ON DELETE CASCADE,
  label text NOT NULL CHECK (length(label) BETWEEN 1 AND 80),
  is_default boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(user_id, service_id, label),
  UNIQUE(id, user_id, service_id)
);

CREATE TABLE IF NOT EXISTS cookie_core_stored_cookies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id text NOT NULL,
  service_id uuid NOT NULL REFERENCES cookie_core_services(id) ON DELETE CASCADE,
  profile_id uuid NOT NULL,
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
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY(profile_id,user_id,service_id)
    REFERENCES cookie_core_profiles(id,user_id,service_id) ON DELETE CASCADE,
  UNIQUE(user_id,service_id,profile_id,name,domain,path)
);
CREATE INDEX IF NOT EXISTS cookie_core_stored_cookies_owner_idx
  ON cookie_core_stored_cookies(user_id,service_id,profile_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS cookie_core_launch_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash text NOT NULL UNIQUE,
  user_id text NOT NULL,
  service_id uuid NOT NULL,
  profile_id uuid NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY(profile_id,user_id,service_id)
    REFERENCES cookie_core_profiles(id,user_id,service_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS cookie_core_launch_tokens_expiry_idx
  ON cookie_core_launch_tokens(expires_at);

CREATE TABLE IF NOT EXISTS cookie_core_audit_logs (
  id bigserial PRIMARY KEY,
  actor_user_id text NOT NULL,
  subject_user_id text NOT NULL,
  service_id uuid,
  profile_id uuid,
  action text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
