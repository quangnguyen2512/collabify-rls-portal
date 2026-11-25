-- =============================================================================
-- Collabify Production Multi-Tenant Shared-Schema PostgreSQL RLS Migration
-- Migration: 001_multi_tenant_rls.sql
--
-- Security Invariants:
-- 1. Separation of Duties:
--    - `collabify_migrator`: owns schema & runs DDL migrations.
--    - `collabify_app`: runtime role with NOSUPERUSER + NOBYPASSRLS.
-- 2. Fail-Closed RLS:
--    - Every tenant-scoped table has BOTH `ENABLE ROW LEVEL SECURITY` AND
--      `FORCE ROW LEVEL SECURITY` (protects even against table-owner queries).
--    - Policies evaluate `tenant_id = app_current_tenant_id()`. When
--      `app.current_tenant_id` is unset/empty, `app_current_tenant_id()` returns
--      NULL -> `tenant_id = NULL` is UNKNOWN -> ZERO rows returned & writes fail.
-- 3. Composite Foreign Keys:
--    - `(tenant_id, portal_id)` and `(tenant_id, video_id)` prevent cross-tenant
--      foreign-key linking even if an application query or migration has a bug.
-- 4. PgBouncer Transaction-Pooling Safety:
--    - Application code MUST use `SET LOCAL` / `set_config('app.current_tenant_id', $1, true)`
--      inside an explicit transaction block.
-- =============================================================================

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 1. Least-Privilege Roles (idempotent)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'collabify_migrator') THEN
    CREATE ROLE collabify_migrator LOGIN PASSWORD 'local_dev_migrator_only' NOSUPERUSER CREATEDB NOCREATEROLE NOINHERIT;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'collabify_app') THEN
    CREATE ROLE collabify_app LOGIN PASSWORD 'local_dev_app_only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  ELSE
    ALTER ROLE collabify_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;

  -- Dedicated zero-login, NOBYPASSRLS definer role for pre-context subdomain lookup.
  -- Prevents a subtle production bug: under FORCE ROW LEVEL SECURITY, if `collabify_migrator`
  -- runs migrations (instead of superuser `postgres`) and owns `resolve_tenant_by_host`,
  -- a `tenants` policy scoped only to `collabify_app` would return 0 rows even inside
  -- SECURITY DEFINER. Binding the function to `collabify_host_resolver` with an explicit
  -- active-only SELECT policy works identically under non-superuser migrators without BYPASSRLS.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'collabify_host_resolver') THEN
    CREATE ROLE collabify_host_resolver NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  ELSE
    ALTER ROLE collabify_host_resolver NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
END
$$;

-- 2. Fail-Closed Tenant Context Helper
-- Returns NULL when GUC is unset or empty string (never throws on missing GUC,
-- never falls back to a default tenant).
CREATE OR REPLACE FUNCTION app_current_tenant_id()
RETURNS uuid
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('app.current_tenant_id', true), '')::uuid;
$$;

-- =============================================================================
-- 3. Schema Definitions
-- =============================================================================

-- Tenants (control-plane root; direct SELECT restricted to active tenant via RLS)
CREATE TABLE IF NOT EXISTS tenants (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug           text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'),
  custom_domain  text UNIQUE CHECK (custom_domain IS NULL OR custom_domain ~ '^[a-z0-9.-]+\.[a-z]{2,}$'),
  name           text NOT NULL,
  status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'archived')),
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);

-- Users (global credentials; RLS restricts visibility to users in the active tenant)
CREATE TABLE IF NOT EXISTS users (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email          text NOT NULL UNIQUE,
  full_name      text NOT NULL,
  password_hash  text NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now()
);

-- Tenant Memberships (binds users to a tenant with role)
CREATE TABLE IF NOT EXISTS tenant_memberships (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role           text NOT NULL CHECK (role IN ('owner', 'member')),
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_tenant_memberships_tenant_user
  ON tenant_memberships (tenant_id, user_id);

-- Client Portals (subdomain workspace deliverables per client)
CREATE TABLE IF NOT EXISTS client_portals (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name           text NOT NULL,
  client_name    text NOT NULL,
  status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  -- Composite unique key enables tenant-locked foreign keys from child tables
  UNIQUE (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS idx_client_portals_tenant_created
  ON client_portals (tenant_id, created_at DESC);

-- Portal Magic Links (hashed, short-lived, single-use external client invites)
CREATE TABLE IF NOT EXISTS portal_magic_links (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL,
  portal_id      uuid NOT NULL,
  client_email   text NOT NULL,
  token_hash     text NOT NULL UNIQUE,
  expires_at     timestamptz NOT NULL,
  consumed_at    timestamptz,
  created_by     uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  -- Composite FK guarantees magic link portal belongs to the exact same tenant
  CONSTRAINT fk_magic_links_tenant_portal
    FOREIGN KEY (tenant_id, portal_id)
    REFERENCES client_portals (tenant_id, id)
    ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_portal_magic_links_tenant_hash
  ON portal_magic_links (tenant_id, token_hash);

-- Video Assets (large multipart uploads scoped strictly to tenant + portal)
CREATE TABLE IF NOT EXISTS video_assets (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           uuid NOT NULL,
  portal_id           uuid NOT NULL,
  upload_id           text NOT NULL UNIQUE,
  filename            text NOT NULL,
  object_key          text NOT NULL UNIQUE,
  content_type        text NOT NULL,
  size_bytes          bigint NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 10737418240),
  expected_part_count integer NOT NULL CHECK (expected_part_count BETWEEN 1 AND 10000),
  status              text NOT NULL DEFAULT 'UPLOADING' CHECK (status IN ('UPLOADING', 'READY', 'FAILED')),
  manifest_sha256     text,
  approved_at         timestamptz,
  approved_by_email   text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  -- Composite FK prevents attaching Tenant A video to Tenant B portal
  CONSTRAINT fk_video_assets_tenant_portal
    FOREIGN KEY (tenant_id, portal_id)
    REFERENCES client_portals (tenant_id, id)
    ON DELETE CASCADE,
  -- Defense-in-depth prefix check on object storage key
  CONSTRAINT chk_video_assets_object_key_tenant_prefix
    CHECK (object_key LIKE ('tenants/' || tenant_id::text || '/portals/' || portal_id::text || '/videos/%'))
);
CREATE INDEX IF NOT EXISTS idx_video_assets_tenant_portal
  ON video_assets (tenant_id, portal_id, created_at DESC);

-- Video Upload Parts (chunk checksums & ETags for resumable multipart verification)
CREATE TABLE IF NOT EXISTS video_upload_parts (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL,
  video_id       uuid NOT NULL,
  part_number    integer NOT NULL CHECK (part_number BETWEEN 1 AND 10000),
  size_bytes     bigint NOT NULL CHECK (size_bytes > 0),
  sha256         text NOT NULL,
  etag           text NOT NULL,
  uploaded_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, video_id, part_number),
  -- Composite FK prevents attaching chunk to another tenant's video
  CONSTRAINT fk_video_upload_parts_tenant_video
    FOREIGN KEY (tenant_id, video_id)
    REFERENCES video_assets (tenant_id, id)
    ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_video_upload_parts_tenant_video
  ON video_upload_parts (tenant_id, video_id, part_number);

-- Audit Events (append-only security & activity log per tenant)
CREATE TABLE IF NOT EXISTS audit_events (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  actor_kind     text NOT NULL CHECK (actor_kind IN ('agency_admin', 'portal_guest', 'system')),
  actor_id       text NOT NULL,
  action         text NOT NULL,
  resource_type  text NOT NULL,
  resource_id    text NOT NULL,
  metadata       jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_created
  ON audit_events (tenant_id, created_at DESC);

-- =============================================================================
-- 4. Enable & FORCE Row-Level Security on ALL Tenant Tables (Fail-Closed)
-- =============================================================================

-- tenants
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenants_isolation_policy ON tenants;
CREATE POLICY tenants_isolation_policy ON tenants
  FOR ALL
  TO collabify_app
  USING (id = app_current_tenant_id())
  WITH CHECK (id = app_current_tenant_id());

DROP POLICY IF EXISTS tenants_host_resolver_policy ON tenants;
CREATE POLICY tenants_host_resolver_policy ON tenants
  FOR SELECT
  TO collabify_host_resolver
  USING (status = 'active');

-- users (visible only if member of the active tenant)
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS users_tenant_membership_policy ON users;
CREATE POLICY users_tenant_membership_policy ON users
  FOR SELECT
  TO collabify_app
  USING (
    EXISTS (
      SELECT 1
      FROM tenant_memberships tm
      WHERE tm.user_id = users.id
        AND tm.tenant_id = app_current_tenant_id()
    )
  );

-- tenant_memberships
ALTER TABLE tenant_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_memberships FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_memberships_isolation_policy ON tenant_memberships;
CREATE POLICY tenant_memberships_isolation_policy ON tenant_memberships
  FOR ALL
  TO collabify_app
  USING (tenant_id = app_current_tenant_id())
  WITH CHECK (tenant_id = app_current_tenant_id());

-- client_portals
ALTER TABLE client_portals ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_portals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS client_portals_isolation_policy ON client_portals;
CREATE POLICY client_portals_isolation_policy ON client_portals
  FOR ALL
  TO collabify_app
  USING (tenant_id = app_current_tenant_id())
  WITH CHECK (tenant_id = app_current_tenant_id());

-- portal_magic_links
ALTER TABLE portal_magic_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_magic_links FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS portal_magic_links_isolation_policy ON portal_magic_links;
CREATE POLICY portal_magic_links_isolation_policy ON portal_magic_links
  FOR ALL
  TO collabify_app
  USING (tenant_id = app_current_tenant_id())
  WITH CHECK (tenant_id = app_current_tenant_id());

-- video_assets
ALTER TABLE video_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE video_assets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS video_assets_isolation_policy ON video_assets;
CREATE POLICY video_assets_isolation_policy ON video_assets
  FOR ALL
  TO collabify_app
  USING (tenant_id = app_current_tenant_id())
  WITH CHECK (tenant_id = app_current_tenant_id());

-- video_upload_parts
ALTER TABLE video_upload_parts ENABLE ROW LEVEL SECURITY;
ALTER TABLE video_upload_parts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS video_upload_parts_isolation_policy ON video_upload_parts;
CREATE POLICY video_upload_parts_isolation_policy ON video_upload_parts
  FOR ALL
  TO collabify_app
  USING (tenant_id = app_current_tenant_id())
  WITH CHECK (tenant_id = app_current_tenant_id());

-- audit_events
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_events_isolation_policy ON audit_events;
CREATE POLICY audit_events_isolation_policy ON audit_events
  FOR ALL
  TO collabify_app
  USING (tenant_id = app_current_tenant_id())
  WITH CHECK (tenant_id = app_current_tenant_id());

-- =============================================================================
-- 5. Narrow SECURITY DEFINER Bootstrapper for Pre-Context Subdomain Lookup
-- =============================================================================
-- Before `app.current_tenant_id` is known, the subdomain middleware must map
-- Host -> active tenant without exposing `SELECT * FROM tenants`.
-- Owned by `collabify_host_resolver` (NOLOGIN, NOBYPASSRLS) with column-scoped
-- SELECT + active-only RLS policy so it never requires BYPASSRLS or superuser.
CREATE OR REPLACE FUNCTION resolve_tenant_by_host(
  p_slug text,
  p_custom_domain text
)
RETURNS TABLE (
  id uuid,
  slug text,
  custom_domain text,
  name text,
  status text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT t.id, t.slug, t.custom_domain, t.name, t.status
  FROM tenants t
  WHERE t.status = 'active'
    AND (
      (p_slug IS NOT NULL AND t.slug = lower(p_slug))
      OR (p_custom_domain IS NOT NULL AND t.custom_domain = lower(p_custom_domain))
    )
  LIMIT 1;
$$;
ALTER FUNCTION resolve_tenant_by_host(text, text) OWNER TO collabify_host_resolver;

-- =============================================================================
-- 6. Least-Privilege Grants for collabify_app & collabify_host_resolver
-- =============================================================================
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

GRANT USAGE ON SCHEMA public TO collabify_host_resolver;
GRANT SELECT (id, slug, custom_domain, name, status) ON tenants TO collabify_host_resolver;

GRANT USAGE ON SCHEMA public TO collabify_app;

GRANT SELECT ON tenants TO collabify_app;
GRANT SELECT ON users TO collabify_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_memberships TO collabify_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON client_portals TO collabify_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON portal_magic_links TO collabify_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON video_assets TO collabify_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON video_upload_parts TO collabify_app;

-- Audit events are strictly append-only for the runtime application role
GRANT SELECT, INSERT ON audit_events TO collabify_app;

GRANT EXECUTE ON FUNCTION app_current_tenant_id() TO collabify_app;
GRANT EXECUTE ON FUNCTION resolve_tenant_by_host(text, text) TO collabify_app;

COMMIT;
