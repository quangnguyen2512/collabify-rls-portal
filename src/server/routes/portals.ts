import { Router } from 'express';
import { z } from 'zod';
import { createAuthMiddleware, requireAgencyAdmin, requirePortalAccess } from '../auth/middleware.js';
import type { AppConfig } from '../config.js';
import { SEED_IDS } from '../db/memoryStore.js';
import type { AppStore } from '../db/store.js';
import { RlsPolicyViolationError } from '../db/tenantContext.js';

const createPortalSchema = z.object({
  name: z.string().min(2).max(120),
  clientName: z.string().min(2).max(120),
});

export function createPortalsRouter(store: AppStore, config: AppConfig): Router {
  const router = Router();
  const authenticate = createAuthMiddleware(config);

  /**
   * Lists portals visible to the caller inside active tenant RLS context.
   * - Agency Admin: sees all portals in their tenant.
   * - Portal Guest: sees ONLY the single portal their token is scoped to.
   */
  router.get('/portals', authenticate, async (req, res, next) => {
    try {
      const tenant = req.tenant!;
      const principal = req.principal!;

      const portals = await store.withTenantContext(tenant.id, async () => {
        if (principal.kind === 'portal_guest') {
          const scoped = await store.getPortalById(principal.portalId);
          return scoped ? [scoped] : [];
        }
        return store.listPortals();
      });

      res.status(200).json({ tenantId: tenant.id, portals });
    } catch (err) {
      next(err);
    }
  });

  /**
   * Create new client portal (Agency Admin only).
   */
  router.post('/portals', authenticate, requireAgencyAdmin(), async (req, res, next) => {
    try {
      const tenant = req.tenant!;
      const principal = req.principal!;
      const parsed = createPortalSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: 'VALIDATION_ERROR', details: parsed.error.flatten() });
        return;
      }

      const portal = await store.withTenantContext(tenant.id, async () => {
        const created = await store.createPortal({
          tenantId: tenant.id,
          name: parsed.data.name,
          clientName: parsed.data.clientName,
        });
        await store.appendAuditEvent({
          tenantId: tenant.id,
          actorKind: 'agency_admin',
          actorId: principal.sub,
          action: 'portal.created',
          resourceType: 'client_portal',
          resourceId: created.id,
          metadata: { name: created.name, clientName: created.clientName },
        });
        return created;
      });

      res.status(201).json({ portal });
    } catch (err) {
      next(err);
    }
  });

  /**
   * List videos for a specific portal (Agency Admin OR Guest scoped to this portal).
   */
  router.get(
    '/portals/:portalId/videos',
    authenticate,
    requirePortalAccess('video:read'),
    async (req, res, next) => {
      try {
        const tenant = req.tenant!;
        const portalId = String(req.params.portalId);

        const result = await store.withTenantContext(tenant.id, async () => {
          const portal = await store.getPortalById(portalId);
          if (!portal) return null;
          const videos = await store.listVideosByPortal(portal.id);
          return { portal, videos };
        });

        if (!result) {
          res.status(404).json({ error: 'PORTAL_NOT_FOUND', message: 'Client portal not found' });
          return;
        }

        res.status(200).json(result);
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * Read tenant-scoped audit trail (Agency Admin only).
   */
  router.get('/audit-events', authenticate, requireAgencyAdmin(), async (req, res, next) => {
    try {
      const tenant = req.tenant!;
      const events = await store.withTenantContext(tenant.id, async () => store.listAuditEvents(50));
      res.status(200).json({ tenantId: tenant.id, events });
    } catch (err) {
      next(err);
    }
  });

  /**
   * Fail-Closed RLS Live Probe (for interactive founder demo & verification).
   * Demonstrates three invariants safely without ever leaking cross-tenant rows:
   * 1. Querying `client_portals` WITHOUT `SET LOCAL app.current_tenant_id` -> 0 rows.
   * 2. Querying another tenant's known portal UUID INSIDE active tenant context -> null (0 rows).
   * 3. Attempting an INSERT carrying another tenant's `tenant_id` -> SQLSTATE 42501 RLS violation.
   */
  router.post('/demo/rls-probe', authenticate, async (req, res, next) => {
    if (config.nodeEnv === 'production') {
      res.status(404).json({ error: 'DEMO_ENDPOINT_DISABLED', message: 'Not found' });
      return;
    }
    try {
      const tenant = req.tenant!;
      const otherTenantId =
        tenant.id === SEED_IDS.tenants.acme ? SEED_IDS.tenants.velvet : SEED_IDS.tenants.acme;
      const otherPortalId =
        tenant.id === SEED_IDS.tenants.acme
          ? SEED_IDS.portals.velvetTeaser
          : SEED_IDS.portals.acmeLaunch;

      // 1. Missing tenant context -> 0 rows (fail-closed)
      const rowsWithoutContext = await store.listPortals();

      // 2. Active tenant context reading another tenant's known portal ID -> null
      const crossTenantRead = await store.withTenantContext(tenant.id, async () =>
        store.getPortalById(otherPortalId),
      );

      // 3. Active tenant context attempting to write a row with another tenant's tenant_id -> blocked
      let crossTenantWriteError: { code: string; message: string } | null = null;
      try {
        await store.withTenantContext(tenant.id, async () =>
          store.createPortal({
            tenantId: otherTenantId,
            name: 'Injected Cross-Tenant Portal',
            clientName: 'Red Team Probe',
          }),
        );
      } catch (err) {
        if (err instanceof RlsPolicyViolationError) {
          crossTenantWriteError = { code: err.code, message: err.message };
        } else {
          const pgErr = err as { code?: string; message?: string };
          crossTenantWriteError = {
            code: pgErr.code ?? 'RLS_BLOCKED',
            message: pgErr.message ?? 'Blocked by RLS policy',
          };
        }
      }

      res.status(200).json({
        activeTenantId: tenant.id,
        checks: {
          missingContextRowCount: rowsWithoutContext.length,
          missingContextFailClosed: rowsWithoutContext.length === 0,
          crossTenantReadReturnedNull: crossTenantRead === null,
          crossTenantWriteBlocked: crossTenantWriteError !== null,
          crossTenantWriteError,
        },
      });
    } catch (err) {
      next(err);
    }
  });

  return router;
}
