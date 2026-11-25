import type { NextFunction, Request, Response } from 'express';
import type { AppConfig } from '../config.js';
import type { AgencyRole, PortalGuestScope } from '../types.js';
import { verifyAuthToken } from './tokens.js';

function parseCookieHeader(cookieHeader: string | undefined): Record<string, string> {
  const result: Record<string, string> = {};
  if (!cookieHeader) return result;
  for (const part of cookieHeader.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    const val = part.slice(eq + 1).trim();
    if (key) result[key] = decodeURIComponent(val);
  }
  return result;
}

function extractToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7).trim();
    if (token) return token;
  }

  const cookies = parseCookieHeader(req.headers.cookie);
  return cookies.collabify_session ?? null;
}

/**
 * Authenticates either Flow A (`agency_admin`) or Flow B (`portal_guest`)
 * AND strictly enforces that the token's `tenantId` matches the resolved subdomain tenant.
 *
 * Cross-tenant token replay (e.g., Tenant A JWT replayed against Tenant B subdomain)
 * is immediately rejected with `403 TENANT_MISMATCH` before any business logic runs.
 */
export function createAuthMiddleware(config: AppConfig) {
  return function authenticatePrincipal(req: Request, res: Response, next: NextFunction): void {
    const tenant = req.tenant;
    if (!tenant) {
      res.status(500).json({
        error: 'MISSING_TENANT_CONTEXT',
        message: 'Subdomain tenant resolution must run before authentication',
      });
      return;
    }

    const rawToken = extractToken(req);
    if (!rawToken) {
      res.status(401).json({
        error: 'AUTH_REQUIRED',
        message: 'Authentication token required',
      });
      return;
    }

    const principal = verifyAuthToken(rawToken, config.authSigningSecret);
    if (!principal) {
      res.status(401).json({
        error: 'INVALID_TOKEN',
        message: 'Token is invalid or expired',
      });
      return;
    }

    if (principal.tenantId !== tenant.id) {
      res.status(403).json({
        error: 'TENANT_MISMATCH',
        message: 'Token tenant does not match target workspace subdomain',
      });
      return;
    }

    req.principal = principal;
    next();
  };
}

export function requireAgencyAdmin(allowedRoles?: AgencyRole[]) {
  return function agencyAdminGuard(req: Request, res: Response, next: NextFunction): void {
    const principal = req.principal;
    if (!principal || principal.kind !== 'agency_admin') {
      res.status(403).json({
        error: 'INSUFFICIENT_ROLE',
        message: 'Agency admin credentials required for this operation',
      });
      return;
    }
    if (allowedRoles && !allowedRoles.includes(principal.role)) {
      res.status(403).json({
        error: 'INSUFFICIENT_ROLE',
        message: `Requires one of roles: ${allowedRoles.join(', ')}`,
      });
      return;
    }
    next();
  };
}

/**
 * Allows either:
 * - An authenticated `agency_admin` of the active tenant, OR
 * - A `portal_guest` whose token is explicitly scoped to `:portalId` AND holds `requiredScope`.
 */
export function requirePortalAccess(requiredScope?: PortalGuestScope) {
  return function portalScopeGuard(req: Request, res: Response, next: NextFunction): void {
    const principal = req.principal;
    if (!principal) {
      res.status(401).json({ error: 'AUTH_REQUIRED', message: 'Authentication required' });
      return;
    }

    if (principal.kind === 'agency_admin') {
      next();
      return;
    }

    const targetPortalId = String(req.params.portalId ?? '');
    if (!targetPortalId || principal.portalId !== targetPortalId) {
      res.status(403).json({
        error: 'PORTAL_SCOPE_MISMATCH',
        message: 'Client portal token is strictly scoped to a different portal',
      });
      return;
    }

    if (requiredScope && !principal.scope.includes(requiredScope)) {
      res.status(403).json({
        error: 'INSUFFICIENT_SCOPE',
        message: `Missing required portal scope: ${requiredScope}`,
      });
      return;
    }

    next();
  };
}
