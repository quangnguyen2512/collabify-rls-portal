import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/server/app.js';
import { loadConfig } from '../src/server/config.js';
import { MemoryRlsStore, SEED_IDS } from '../src/server/db/memoryStore.js';
import { parseHostCandidate } from '../src/server/middleware/subdomain.js';

describe('Subdomain & Custom Domain Tenant Resolution', () => {
  it('parses valid subdomains, custom domains, and rejects raw IPs / multi-level / reserved labels', () => {
    expect(parseHostCandidate('acme.collabify.local:3090', 'collabify.local')).toEqual({
      ok: true,
      kind: 'subdomain',
      slug: 'acme',
      normalizedHost: 'acme.collabify.local',
    });

    expect(parseHostCandidate('portal.acmecreative.io', 'collabify.local')).toEqual({
      ok: true,
      kind: 'custom_domain',
      customDomain: 'portal.acmecreative.io',
      normalizedHost: 'portal.acmecreative.io',
    });

    expect(parseHostCandidate('127.0.0.1:3090', 'collabify.local').ok).toBe(false);
    expect(parseHostCandidate('[::1]:3090', 'collabify.local').ok).toBe(false);
    expect(parseHostCandidate('localhost:3090', 'collabify.local').ok).toBe(false);
    expect(parseHostCandidate('collabify.local', 'collabify.local').ok).toBe(false);
    expect(parseHostCandidate('evil.acme.collabify.local', 'collabify.local').ok).toBe(false);
    expect(parseHostCandidate('admin.collabify.local', 'collabify.local').ok).toBe(false);
    expect(parseHostCandidate('acme.collabify.local, velvet.collabify.local', 'collabify.local').ok).toBe(false);
  });

  it('resolves active subdomain and custom domain via Host header', async () => {
    const config = loadConfig({ NODE_ENV: 'test', BASE_DOMAIN: 'collabify.local' });
    const { app } = createApp({ store: new MemoryRlsStore(true), config });

    const subRes = await request(app)
      .get('/api/tenant/context')
      .set('Host', 'acme.collabify.local:3090');
    expect(subRes.status).toBe(200);
    expect(subRes.body.tenant.id).toBe(SEED_IDS.tenants.acme);
    expect(subRes.body.tenant.slug).toBe('acme');

    const customRes = await request(app)
      .get('/api/tenant/context')
      .set('Host', 'review.velvetmotion.tv');
    expect(customRes.status).toBe(200);
    expect(customRes.body.tenant.id).toBe(SEED_IDS.tenants.velvet);
  });

  it('returns identical 404 PORTAL_NOT_FOUND for unknown AND suspended subdomains (anti-enumeration)', async () => {
    const config = loadConfig({ NODE_ENV: 'test', BASE_DOMAIN: 'collabify.local' });
    const { app } = createApp({ store: new MemoryRlsStore(true), config });

    const unknownRes = await request(app)
      .get('/api/tenant/context')
      .set('Host', 'does-not-exist.collabify.local');
    const suspendedRes = await request(app)
      .get('/api/tenant/context')
      .set('Host', 'suspended-co.collabify.local');

    expect(unknownRes.status).toBe(404);
    expect(suspendedRes.status).toBe(404);
    expect(unknownRes.body).toEqual({
      error: 'PORTAL_NOT_FOUND',
      message: 'Workspace not found',
    });
    expect(suspendedRes.body).toEqual(unknownRes.body);
  });

  it('rejects raw IP Host headers and spoofed X-Forwarded-Host from untrusted sources', async () => {
    const config = loadConfig({
      NODE_ENV: 'test',
      BASE_DOMAIN: 'collabify.local',
      TRUSTED_PROXY_IPS: '',
    });
    const { app } = createApp({ store: new MemoryRlsStore(true), config });

    const ipRes = await request(app)
      .get('/api/tenant/context')
      .set('Host', '127.0.0.1:3090');
    expect(ipRes.status).toBe(400);
    expect(ipRes.body.error).toBe('IP_HOST_REJECTED');

    const spoofRes = await request(app)
      .get('/api/tenant/context')
      .set('Host', 'acme.collabify.local')
      .set('X-Forwarded-Host', 'velvet.collabify.local');
    expect(spoofRes.status).toBe(400);
    expect(spoofRes.body.error).toBe('UNTRUSTED_FORWARDED_HOST');
  });

  it('honors single valid X-Forwarded-Host from a configured trusted proxy and rejects comma-injected chains', async () => {
    const config = loadConfig({
      NODE_ENV: 'test',
      BASE_DOMAIN: 'collabify.local',
      TRUSTED_PROXY_IPS: '127.0.0.1,::1',
    });
    const { app } = createApp({ store: new MemoryRlsStore(true), config });

    const trustedRes = await request(app)
      .get('/api/tenant/context')
      .set('Host', 'internal-alb.local')
      .set('X-Forwarded-Host', 'velvet.collabify.local');
    expect(trustedRes.status).toBe(200);
    expect(trustedRes.body.tenant.id).toBe(SEED_IDS.tenants.velvet);

    const chainedRes = await request(app)
      .get('/api/tenant/context')
      .set('Host', 'internal-alb.local')
      .set('X-Forwarded-Host', 'velvet.collabify.local, acme.collabify.local');
    expect(chainedRes.status).toBe(400);
    expect(chainedRes.body.error).toBe('INVALID_FORWARDED_HOST');
  });

  it('serves healthz and single-screen Demo UI workbench on root host without requiring tenant subdomain', async () => {
    const config = loadConfig({ NODE_ENV: 'test', BASE_DOMAIN: 'collabify.local' });
    const { app } = createApp({ store: new MemoryRlsStore(true), config });

    const healthRes = await request(app).get('/healthz');
    expect(healthRes.status).toBe(200);
    expect(healthRes.body.status).toBe('ok');

    const uiRes = await request(app).get('/');
    expect(uiRes.status).toBe(200);
    expect(uiRes.text).toContain('Collabify Multi-Tenant Reference');
  });
});
