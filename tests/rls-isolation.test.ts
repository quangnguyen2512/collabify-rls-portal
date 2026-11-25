import type { Pool, PoolClient } from 'pg';
import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';
import { createApp } from '../src/server/app.js';
import { loadConfig } from '../src/server/config.js';
import { DEMO_ADMIN_PASSWORD, MemoryRlsStore, SEED_IDS } from '../src/server/db/memoryStore.js';
import {
  CompositeForeignKeyViolationError,
  RlsPolicyViolationError,
  SET_LOCAL_TENANT_SQL,
  withPgTenantContext,
} from '../src/server/db/tenantContext.js';

describe('PostgreSQL Shared-Schema RLS Isolation & PgBouncer Transaction Context', () => {
  it('fails closed (0 rows / null) when tenant context is missing and blocks uncontextualized writes', async () => {
    const store = new MemoryRlsStore(true);

    expect(store.getCurrentTenantContext()).toBeNull();
    expect(await store.listPortals()).toEqual([]);
    expect(await store.getPortalById(SEED_IDS.portals.acmeLaunch)).toBeNull();
    expect(await store.listVideosByPortal(SEED_IDS.portals.acmeLaunch)).toEqual([]);
    expect(await store.listAuditEvents()).toEqual([]);

    await expect(
      store.createPortal({
        tenantId: SEED_IDS.tenants.acme,
        name: 'Orphan Portal',
        clientName: 'No Context',
      }),
    ).rejects.toThrow(RlsPolicyViolationError);
  });

  it('strictly isolates reads and blocks cross-tenant writes & composite FK tampering', async () => {
    const store = new MemoryRlsStore(true);

    // Acme context cannot read Velvet's portals or videos
    await store.withTenantContext(SEED_IDS.tenants.acme, async () => {
      const portals = await store.listPortals();
      expect(portals.length).toBe(2);
      expect(portals.every((p) => p.tenantId === SEED_IDS.tenants.acme)).toBe(true);

      const velvetPortal = await store.getPortalById(SEED_IDS.portals.velvetTeaser);
      expect(velvetPortal).toBeNull();

      const velvetVideo = await store.getVideoById(SEED_IDS.videos.velvetSeedVideo);
      expect(velvetVideo).toBeNull();

      // Cross-tenant INSERT violates RLS WITH CHECK (SQLSTATE 42501)
      await expect(
        store.createPortal({
          tenantId: SEED_IDS.tenants.velvet,
          name: 'Spoofed Velvet Portal',
          clientName: 'Attacker',
        }),
      ).rejects.toMatchObject({ name: 'RlsPolicyViolationError', code: '42501' });

      // Composite FK prevents linking an Acme video to Velvet's portal UUID (SQLSTATE 23503)
      await expect(
        store.createVideoAsset({
          id: '77777777-7777-4777-8777-777777777777',
          tenantId: SEED_IDS.tenants.acme,
          portalId: SEED_IDS.portals.velvetTeaser,
          uploadId: 'upl_fk_violation_test',
          filename: 'cross_link.mp4',
          objectKey: `tenants/${SEED_IDS.tenants.acme}/portals/${SEED_IDS.portals.velvetTeaser}/videos/77777777-7777-4777-8777-777777777777/cross_link.mp4`,
          contentType: 'video/mp4',
          sizeBytes: 1024,
          expectedPartCount: 1,
        }),
      ).rejects.toThrow(CompositeForeignKeyViolationError);
    });

    // Context automatically clears once transaction callback finishes
    expect(store.getCurrentTenantContext()).toBeNull();
    expect(await store.listPortals()).toEqual([]);
  });

  it('executes BEGIN -> set_config(is_local=true) -> work -> COMMIT and ROLLBACK on error for PgBouncer safety', async () => {
    const executed: Array<{ sql: string; params?: unknown[] }> = [];
    const release = vi.fn();
    const mockClient = {
      query: vi.fn(async (sql: string, params?: unknown[]) => {
        executed.push({ sql, params });
        return { rows: [{ ok: true }] };
      }),
      release,
    } as unknown as PoolClient;

    const mockPool = {
      connect: vi.fn(async () => mockClient),
    } as unknown as Pick<Pool, 'connect'>;

    const result = await withPgTenantContext(mockPool, SEED_IDS.tenants.acme, async (client) => {
      await client.query('SELECT * FROM client_portals');
      return 'done';
    });

    expect(result).toBe('done');
    expect(executed).toEqual([
      { sql: 'BEGIN', params: undefined },
      { sql: SET_LOCAL_TENANT_SQL, params: [SEED_IDS.tenants.acme] },
      { sql: 'SELECT * FROM client_portals', params: undefined },
      { sql: 'COMMIT', params: undefined },
    ]);
    expect(release).toHaveBeenCalledTimes(1);

    // Error path rolls back and still releases client
    executed.length = 0;
    release.mockClear();

    await expect(
      withPgTenantContext(mockPool, SEED_IDS.tenants.velvet, async () => {
        throw new Error('simulated query failure');
      }),
    ).rejects.toThrow('simulated query failure');

    expect(executed.map((e) => e.sql)).toEqual(['BEGIN', SET_LOCAL_TENANT_SQL, 'ROLLBACK']);
    expect(release).toHaveBeenCalledTimes(1);

    // Invalid tenant UUID is rejected before touching DB pool
    await expect(
      withPgTenantContext(mockPool, "'; DROP TABLE tenants; --", async () => 'nope'),
    ).rejects.toThrow(/Invalid tenant UUID/);
  });

  it('exposes /api/demo/rls-probe confirming all fail-closed invariants over HTTP', async () => {
    const config = loadConfig({ NODE_ENV: 'test', BASE_DOMAIN: 'collabify.local' });
    const { app } = createApp({ store: new MemoryRlsStore(true), config });

    const loginRes = await request(app)
      .post('/api/auth/agency/login')
      .set('Host', 'acme.collabify.local')
      .send({ email: 'alice@acme.studio', password: DEMO_ADMIN_PASSWORD });
    expect(loginRes.status).toBe(200);

    const probeRes = await request(app)
      .post('/api/demo/rls-probe')
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${loginRes.body.token}`);

    expect(probeRes.status).toBe(200);
    expect(probeRes.body.checks.missingContextFailClosed).toBe(true);
    expect(probeRes.body.checks.missingContextRowCount).toBe(0);
    expect(probeRes.body.checks.crossTenantReadReturnedNull).toBe(true);
    expect(probeRes.body.checks.crossTenantWriteBlocked).toBe(true);
    expect(probeRes.body.checks.crossTenantWriteError.code).toBe('42501');
  });

  it('disables /api/demo/rls-probe in production mode (404 DEMO_ENDPOINT_DISABLED)', async () => {
    const prodSecret = 'a'.repeat(64);
    const config = loadConfig({
      NODE_ENV: 'production',
      BASE_DOMAIN: 'collabify.local',
      AUTH_SIGNING_SECRET: prodSecret,
      UPLOAD_SIGNING_SECRET: prodSecret,
    });
    const store = new MemoryRlsStore(true);
    const { app } = createApp({ store, config });

    const { signAgencyToken } = await import('../src/server/auth/tokens.js');
    const prodToken = signAgencyToken(
      {
        sub: SEED_IDS.users.alice,
        email: 'alice@acme.studio',
        tenantId: SEED_IDS.tenants.acme,
        role: 'owner',
      },
      prodSecret,
    );

    const probeRes = await request(app)
      .post('/api/demo/rls-probe')
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${prodToken}`);

    expect(probeRes.status).toBe(404);
    expect(probeRes.body.error).toBe('DEMO_ENDPOINT_DISABLED');
  });
});
