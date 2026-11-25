import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');

const MIGRATION_PATH = path.join(ROOT, 'db', 'migrations', '001_multi_tenant_rls.sql');
const TENANT_CONTEXT_PATH = path.join(ROOT, 'src', 'server', 'db', 'tenantContext.ts');

const ALL_RLS_TABLES = [
  'tenants',
  'users',
  'tenant_memberships',
  'client_portals',
  'portal_magic_links',
  'video_assets',
  'video_upload_parts',
  'audit_events',
] as const;

const DIRECT_TENANT_ID_TABLES = [
  'tenant_memberships',
  'client_portals',
  'portal_magic_links',
  'video_assets',
  'video_upload_parts',
  'audit_events',
] as const;

describe('Static PostgreSQL Multi-Tenant RLS Migration Verification', () => {
  const sql = fs.readFileSync(MIGRATION_PATH, 'utf8');
  const tenantContextSource = fs.readFileSync(TENANT_CONTEXT_PATH, 'utf8');

  it('provisions a non-superuser runtime role collabify_app with NOBYPASSRLS separate from migrator', () => {
    expect(sql).toMatch(/CREATE ROLE collabify_migrator/i);
    expect(sql).toMatch(/CREATE ROLE collabify_app[\s\S]*?NOSUPERUSER[\s\S]*?NOBYPASSRLS/i);
    expect(sql).toMatch(/ALTER ROLE collabify_app[\s\S]*?NOBYPASSRLS/i);
  });

  it('defines fail-closed app_current_tenant_id() using current_setting(..., true)', () => {
    expect(sql).toMatch(
      /CREATE OR REPLACE FUNCTION app_current_tenant_id\(\)[\s\S]*?current_setting\('app\.current_tenant_id',\s*true\)/i,
    );
  });

  it.each(ALL_RLS_TABLES)(
    'enables AND forces Row-Level Security on table "%s"',
    (tableName) => {
      const enablePattern = new RegExp(
        `ALTER TABLE\\s+${tableName}\\s+ENABLE ROW LEVEL SECURITY;`,
        'i',
      );
      const forcePattern = new RegExp(
        `ALTER TABLE\\s+${tableName}\\s+FORCE ROW LEVEL SECURITY;`,
        'i',
      );
      expect(sql).toMatch(enablePattern);
      expect(sql).toMatch(forcePattern);
    },
  );

  it.each(DIRECT_TENANT_ID_TABLES)(
    'defines fail-closed USING + WITH CHECK policy bound to app_current_tenant_id() on "%s"',
    (tableName) => {
      const policyPattern = new RegExp(
        `CREATE POLICY\\s+${tableName}_isolation_policy\\s+ON\\s+${tableName}[\\s\\S]*?TO\\s+collabify_app[\\s\\S]*?USING\\s*\\(tenant_id\\s*=\\s*app_current_tenant_id\\(\\)\\)[\\s\\S]*?WITH CHECK\\s*\\(tenant_id\\s*=\\s*app_current_tenant_id\\(\\)\\);`,
        'i',
      );
      expect(sql).toMatch(policyPattern);
    },
  );

  it('enforces composite foreign keys (tenant_id, id) across portals -> magic links / videos -> upload parts', () => {
    expect(sql).toMatch(/UNIQUE\s*\(tenant_id,\s*id\)/i);
    expect(sql).toMatch(
      /FOREIGN KEY\s*\(tenant_id,\s*portal_id\)\s*REFERENCES\s+client_portals\s*\(tenant_id,\s*id\)/i,
    );
    expect(sql).toMatch(
      /FOREIGN KEY\s*\(tenant_id,\s*video_id\)\s*REFERENCES\s+video_assets\s*\(tenant_id,\s*id\)/i,
    );
  });

  it('keeps audit_events strictly append-only for collabify_app', () => {
    expect(sql).toMatch(/GRANT SELECT,\s*INSERT ON audit_events TO collabify_app;/i);
    expect(sql).not.toMatch(/GRANT[^;]*?(UPDATE|DELETE)[^;]*?ON audit_events TO collabify_app;/i);
  });

  it('binds resolve_tenant_by_host to NOLOGIN NOBYPASSRLS collabify_host_resolver with active-only SELECT policy', () => {
    expect(sql).toMatch(
      /CREATE ROLE collabify_host_resolver\s+NOLOGIN[\s\S]*?NOSUPERUSER[\s\S]*?NOBYPASSRLS/i,
    );
    expect(sql).toMatch(
      /CREATE POLICY\s+tenants_host_resolver_policy\s+ON\s+tenants[\s\S]*?FOR SELECT[\s\S]*?TO\s+collabify_host_resolver[\s\S]*?USING\s*\(status\s*=\s*'active'\);/i,
    );
    expect(sql).toMatch(
      /ALTER FUNCTION resolve_tenant_by_host\(text,\s*text\)\s+OWNER TO collabify_host_resolver;/i,
    );
    expect(sql).toMatch(
      /GRANT SELECT \(id,\s*slug,\s*custom_domain,\s*name,\s*status\) ON tenants TO collabify_host_resolver;/i,
    );
  });

  it('uses transaction-local set_config(..., true) in tenantContext.ts for PgBouncer transaction pooling', () => {
    const executableCodeOnly = tenantContextSource
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\/\/.*$/gm, '');
    expect(executableCodeOnly).toContain("set_config('app.current_tenant_id', $1, true)");
    // Must never execute session-level SET app.current_tenant_id without LOCAL
    expect(executableCodeOnly).not.toMatch(/SET\s+app\.current_tenant_id\s*=/i);
  });
});
