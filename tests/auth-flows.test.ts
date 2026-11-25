import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/server/app.js';
import { loadConfig } from '../src/server/config.js';
import { DEMO_ADMIN_PASSWORD, MemoryRlsStore, SEED_IDS } from '../src/server/db/memoryStore.js';

describe('Dual Auth Flows (Agency Admin vs Scoped Client Portal Magic Link)', () => {
  function setup() {
    const config = loadConfig({ NODE_ENV: 'test', BASE_DOMAIN: 'collabify.local' });
    return createApp({ store: new MemoryRlsStore(true), config });
  }

  it('authenticates Flow A Agency Admin and strictly blocks cross-tenant token replay (403 TENANT_MISMATCH)', async () => {
    const { app } = setup();

    // Alice cannot log into Velvet's subdomain
    const wrongSubdomainLogin = await request(app)
      .post('/api/auth/agency/login')
      .set('Host', 'velvet.collabify.local')
      .send({ email: 'alice@acme.studio', password: DEMO_ADMIN_PASSWORD });
    expect(wrongSubdomainLogin.status).toBe(401);

    // Alice logs into Acme's subdomain
    const acmeLogin = await request(app)
      .post('/api/auth/agency/login')
      .set('Host', 'acme.collabify.local')
      .send({ email: 'alice@acme.studio', password: DEMO_ADMIN_PASSWORD });
    expect(acmeLogin.status).toBe(200);
    const acmeToken: string = acmeLogin.body.token;

    // Works on Acme
    const acmePortals = await request(app)
      .get('/api/portals')
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${acmeToken}`);
    expect(acmePortals.status).toBe(200);
    expect(acmePortals.body.portals).toHaveLength(2);

    // Replaying Acme Admin token against Velvet subdomain is blocked with 403 TENANT_MISMATCH
    const replayOnVelvet = await request(app)
      .get('/api/portals')
      .set('Host', 'velvet.collabify.local')
      .set('Authorization', `Bearer ${acmeToken}`);
    expect(replayOnVelvet.status).toBe(403);
    expect(replayOnVelvet.body.error).toBe('TENANT_MISMATCH');
  });

  it('enforces Flow B single-use magic-link exchange and strict (tenantId, portalId) guest scope boundaries', async () => {
    const { app } = setup();

    // 1. Acme Admin signs in
    const acmeLogin = await request(app)
      .post('/api/auth/agency/login')
      .set('Host', 'acme.collabify.local')
      .send({ email: 'alice@acme.studio', password: DEMO_ADMIN_PASSWORD });
    const adminToken: string = acmeLogin.body.token;

    // 2. Acme Admin mints single-use magic link for Portal 1 (`acmeLaunch`)
    const mintRes = await request(app)
      .post(`/api/portals/${SEED_IDS.portals.acmeLaunch}/magic-links`)
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ clientEmail: 'client@northstar.ai' });
    expect(mintRes.status).toBe(201);
    const rawMagicToken: string = mintRes.body.rawToken;

    // 3. Cannot exchange Acme's magic link on Velvet's subdomain
    const crossTenantExchange = await request(app)
      .post('/api/auth/portal/exchange')
      .set('Host', 'velvet.collabify.local')
      .send({ token: rawMagicToken });
    expect(crossTenantExchange.status).toBe(401);
    expect(crossTenantExchange.body.error).toBe('MAGIC_LINK_INVALID_OR_USED');

    // 4. First valid exchange on Acme succeeds -> returns scoped portal_guest JWT
    const exchangeRes = await request(app)
      .post('/api/auth/portal/exchange')
      .set('Host', 'acme.collabify.local')
      .send({ token: rawMagicToken });
    expect(exchangeRes.status).toBe(200);
    expect(exchangeRes.body.principal.kind).toBe('portal_guest');
    expect(exchangeRes.body.principal.portalId).toBe(SEED_IDS.portals.acmeLaunch);
    const guestToken: string = exchangeRes.body.token;

    // 5. Replaying the same magic link a second time fails (single-use enforcement)
    const replayMagicRes = await request(app)
      .post('/api/auth/portal/exchange')
      .set('Host', 'acme.collabify.local')
      .send({ token: rawMagicToken });
    expect(replayMagicRes.status).toBe(401);
    expect(replayMagicRes.body.error).toBe('MAGIC_LINK_INVALID_OR_USED');

    // 6. Guest CAN list ONLY their single scoped portal, view its videos, get playback URL, and approve
    const guestPortals = await request(app)
      .get('/api/portals')
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${guestToken}`);
    expect(guestPortals.status).toBe(200);
    expect(guestPortals.body.portals).toHaveLength(1);
    expect(guestPortals.body.portals[0].id).toBe(SEED_IDS.portals.acmeLaunch);

    const portal1Videos = await request(app)
      .get(`/api/portals/${SEED_IDS.portals.acmeLaunch}/videos`)
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${guestToken}`);
    expect(portal1Videos.status).toBe(200);
    expect(portal1Videos.body.videos).toHaveLength(1);

    const approveRes = await request(app)
      .post(
        `/api/portals/${SEED_IDS.portals.acmeLaunch}/videos/${SEED_IDS.videos.acmeSeedVideo}/approve`,
      )
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${guestToken}`);
    expect(approveRes.status).toBe(200);
    expect(approveRes.body.video.approvedByEmail).toBe('client@northstar.ai');

    // 7. Guest CANNOT access Portal 2 (`acmeBrand`) in the SAME tenant -> 403 PORTAL_SCOPE_MISMATCH
    const portal2Escape = await request(app)
      .get(`/api/portals/${SEED_IDS.portals.acmeBrand}/videos`)
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${guestToken}`);
    expect(portal2Escape.status).toBe(403);
    expect(portal2Escape.body.error).toBe('PORTAL_SCOPE_MISMATCH');

    // 8. Guest CANNOT perform Agency Admin actions (create portal / mint links / init uploads / read audit logs)
    const createPortalAttempt = await request(app)
      .post('/api/portals')
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${guestToken}`)
      .send({ name: 'Unauthorized', clientName: 'Guest' });
    expect(createPortalAttempt.status).toBe(403);
    expect(createPortalAttempt.body.error).toBe('INSUFFICIENT_ROLE');

    const initUploadAttempt = await request(app)
      .post(`/api/portals/${SEED_IDS.portals.acmeLaunch}/videos/init`)
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${guestToken}`)
      .send({
        filename: 'unauthorized.mp4',
        contentType: 'video/mp4',
        sizeBytes: 1024,
        partCount: 1,
      });
    expect(initUploadAttempt.status).toBe(403);
    expect(initUploadAttempt.body.error).toBe('INSUFFICIENT_ROLE');
  });

  it('issues strictly host-only HttpOnly cookies (no wildcard Domain=) and supports logout clearing', async () => {
    const { app } = setup();

    const loginRes = await request(app)
      .post('/api/auth/agency/login')
      .set('Host', 'acme.collabify.local')
      .send({ email: 'alice@acme.studio', password: DEMO_ADMIN_PASSWORD });

    expect(loginRes.status).toBe(200);
    const setCookieHeader = loginRes.headers['set-cookie'];
    const rawCookie = Array.isArray(setCookieHeader) ? setCookieHeader[0]! : String(setCookieHeader);
    expect(rawCookie).toContain('collabify_session=');
    expect(rawCookie).toContain('HttpOnly');
    expect(rawCookie).toContain('SameSite=Lax');
    expect(rawCookie).toContain('Max-Age=3600');
    expect(rawCookie.toLowerCase()).not.toContain('domain=');

    const logoutRes = await request(app)
      .post('/api/auth/logout')
      .set('Host', 'acme.collabify.local');
    expect(logoutRes.status).toBe(200);
    const clearedCookie = Array.isArray(logoutRes.headers['set-cookie'])
      ? logoutRes.headers['set-cookie'][0]!
      : String(logoutRes.headers['set-cookie']);
    expect(clearedCookie).toContain('Max-Age=0');
    expect(clearedCookie.toLowerCase()).not.toContain('domain=');
  });
});
