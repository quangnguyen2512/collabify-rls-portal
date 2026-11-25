import { Router } from 'express';
import { z } from 'zod';
import type { AppConfig } from '../config.js';
import type { AppStore } from '../db/store.js';
import { createAuthMiddleware, requireAgencyAdmin } from './middleware.js';
import {
  generateOpaqueToken,
  hashOpaqueToken,
  signAgencyToken,
  signPortalGuestToken,
  verifyPassword,
} from './tokens.js';

const agencyLoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

const mintMagicLinkSchema = z.object({
  clientEmail: z.string().email(),
  ttlSeconds: z.number().int().min(60).max(3600).optional(),
});

const exchangeMagicLinkSchema = z.object({
  token: z.string().min(16),
});

export function createAuthRouter(store: AppStore, config: AppConfig): Router {
  const router = Router();
  const authenticate = createAuthMiddleware(config);

  /**
   * Flow A: Agency Admin Login (bound strictly to the resolved subdomain tenant).
   */
  router.post('/auth/agency/login', async (req, res, next) => {
    try {
      const tenant = req.tenant!;
      const parsed = agencyLoginSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: 'VALIDATION_ERROR', details: parsed.error.flatten() });
        return;
      }

      const member = await store.withTenantContext(tenant.id, async () =>
        store.findAgencyMemberByEmail(parsed.data.email),
      );

      if (
        !member ||
        !verifyPassword(parsed.data.password, member.passwordHash, config.nodeEnv !== 'production')
      ) {
        res.status(401).json({
          error: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password for this workspace',
        });
        return;
      }

      const token = signAgencyToken(
        {
          sub: member.userId,
          email: member.email,
          tenantId: tenant.id,
          role: member.role,
        },
        config.authSigningSecret,
      );

      await store.withTenantContext(tenant.id, async () =>
        store.appendAuditEvent({
          tenantId: tenant.id,
          actorKind: 'agency_admin',
          actorId: member.userId,
          action: 'auth.agency_login',
          resourceType: 'tenant',
          resourceId: tenant.id,
          metadata: { email: member.email, role: member.role },
        }),
      );

      const secureFlag = config.nodeEnv === 'production' ? '; Secure' : '';
      // Host-only cookie (explicitly NO Domain= attribute so sessions never bleed across subdomains)
      res.setHeader(
        'Set-Cookie',
        `collabify_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600${secureFlag}`,
      );

      res.status(200).json({
        token,
        principal: {
          kind: 'agency_admin',
          sub: member.userId,
          email: member.email,
          fullName: member.fullName,
          tenantId: tenant.id,
          role: member.role,
        },
        tenant: {
          id: tenant.id,
          slug: tenant.slug,
          name: tenant.name,
        },
      });
    } catch (err) {
      next(err);
    }
  });

  /**
   * Flow B (Step 1): Agency Admin mints a single-use, short-TTL magic link
   * scoped to ONE `(tenantId, portalId)`. Only SHA-256(token) is persisted.
   */
  router.post(
    '/portals/:portalId/magic-links',
    authenticate,
    requireAgencyAdmin(),
    async (req, res, next) => {
      try {
        const tenant = req.tenant!;
        const principal = req.principal!;
        const portalId = String(req.params.portalId);

        const parsed = mintMagicLinkSchema.safeParse(req.body);
        if (!parsed.success) {
          res.status(400).json({ error: 'VALIDATION_ERROR', details: parsed.error.flatten() });
          return;
        }

        const ttlSeconds = parsed.data.ttlSeconds ?? config.magicLinkTtlSeconds;
        const rawToken = generateOpaqueToken();
        const tokenHash = hashOpaqueToken(rawToken);
        const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();

        const created = await store.withTenantContext(tenant.id, async () => {
          const portal = await store.getPortalById(portalId);
          if (!portal) return null;

          const link = await store.createMagicLink({
            tenantId: tenant.id,
            portalId: portal.id,
            clientEmail: parsed.data.clientEmail,
            tokenHash,
            expiresAt,
            createdBy: principal.sub,
          });

          await store.appendAuditEvent({
            tenantId: tenant.id,
            actorKind: 'agency_admin',
            actorId: principal.sub,
            action: 'auth.magic_link_minted',
            resourceType: 'client_portal',
            resourceId: portal.id,
            metadata: { clientEmail: link.clientEmail, expiresAt },
          });

          return { portal, link };
        });

        if (!created) {
          res.status(404).json({ error: 'PORTAL_NOT_FOUND', message: 'Client portal not found' });
          return;
        }

        res.status(201).json({
          magicLinkId: created.link.id,
          portalId: created.portal.id,
          clientEmail: created.link.clientEmail,
          expiresAt: created.link.expiresAt,
          // Raw token is returned ONCE to the caller (or sent via email provider); DB stores hash only.
          rawToken,
          exchangeUrl: `https://${tenant.slug}.${config.baseDomain}/portal/enter?token=${rawToken}`,
        });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * Flow B (Step 2): External client exchanges single-use magic link token
   * for a scoped `portal_guest` session locked to `(tenantId, portalId)`.
   */
  router.post('/auth/portal/exchange', async (req, res, next) => {
    try {
      const tenant = req.tenant!;
      const parsed = exchangeMagicLinkSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: 'VALIDATION_ERROR', details: parsed.error.flatten() });
        return;
      }

      const tokenHash = hashOpaqueToken(parsed.data.token);
      const nowIso = new Date().toISOString();

      const consumed = await store.withTenantContext(tenant.id, async () => {
        const link = await store.consumeMagicLinkByHash(tokenHash, nowIso);
        if (!link) return null;

        await store.appendAuditEvent({
          tenantId: tenant.id,
          actorKind: 'portal_guest',
          actorId: link.clientEmail,
          action: 'auth.magic_link_exchanged',
          resourceType: 'client_portal',
          resourceId: link.portalId,
          metadata: { magicLinkId: link.id },
        });
        return link;
      });

      if (!consumed) {
        res.status(401).json({
          error: 'MAGIC_LINK_INVALID_OR_USED',
          message: 'Magic link is invalid, expired, or already used',
        });
        return;
      }

      const scope = ['video:read', 'portal:comment', 'video:approve'] as const;
      const guestToken = signPortalGuestToken(
        {
          sub: `guest:${consumed.id}`,
          email: consumed.clientEmail,
          tenantId: tenant.id,
          portalId: consumed.portalId,
          scope: [...scope],
        },
        config.authSigningSecret,
      );

      const secureFlag = config.nodeEnv === 'production' ? '; Secure' : '';
      // Host-only cookie (explicitly NO Domain= attribute so guest sessions stay locked to tenant host)
      res.setHeader(
        'Set-Cookie',
        `collabify_session=${encodeURIComponent(guestToken)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=7200${secureFlag}`,
      );

      res.status(200).json({
        token: guestToken,
        principal: {
          kind: 'portal_guest',
          sub: `guest:${consumed.id}`,
          email: consumed.clientEmail,
          tenantId: tenant.id,
          portalId: consumed.portalId,
          scope,
        },
      });
    } catch (err) {
      next(err);
    }
  });

  router.post('/auth/logout', (req, res) => {
    const secureFlag = config.nodeEnv === 'production' ? '; Secure' : '';
    res.setHeader(
      'Set-Cookie',
      `collabify_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secureFlag}`,
    );
    res.status(200).json({ ok: true, clearedHost: req.resolvedHost });
  });

  router.get('/auth/me', authenticate, (req, res) => {
    res.status(200).json({
      principal: req.principal,
      tenant: req.tenant,
      resolvedHost: req.resolvedHost,
    });
  });

  return router;
}
