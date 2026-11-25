import type { NextFunction, Request, Response } from 'express';
import type { AppConfig } from '../config.js';
import type { AppStore } from '../db/store.js';

const IPV4_REGEX = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const SUBDOMAIN_LABEL_REGEX = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const FQDN_REGEX =
  /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const RESERVED_SLUGS = new Set(['www', 'api', 'app', 'admin', 'auth', 'static', 'cdn', 'status']);

export type ParsedHostResult =
  | { ok: true; kind: 'subdomain'; slug: string; normalizedHost: string }
  | { ok: true; kind: 'custom_domain'; customDomain: string; normalizedHost: string }
  | { ok: false; code: 'INVALID_HOST' | 'IP_HOST_REJECTED' | 'ROOT_DOMAIN_NO_TENANT'; reason: string };

export function normalizeRemoteIp(remoteAddress: string | undefined): string {
  if (!remoteAddress) return '';
  return remoteAddress.startsWith('::ffff:') ? remoteAddress.slice(7) : remoteAddress;
}

export function parseHostCandidate(rawHost: string, baseDomain: string): ParsedHostResult {
  const trimmed = rawHost.trim().toLowerCase();
  if (!trimmed) {
    return { ok: false, code: 'INVALID_HOST', reason: 'Missing Host header' };
  }

  // Reject header injection characters, whitespace, commas (multi-host spoofing), paths, credentials
  if (/[\s,/\\?#@]/.test(trimmed)) {
    return { ok: false, code: 'INVALID_HOST', reason: 'Malformed Host header characters' };
  }

  // Reject IPv6 bracketed literals
  if (trimmed.startsWith('[') || trimmed.includes(']')) {
    return { ok: false, code: 'IP_HOST_REJECTED', reason: 'IP literal Host headers are not permitted' };
  }

  // Strip optional single :port suffix
  const colonIdx = trimmed.indexOf(':');
  let hostname = trimmed;
  if (colonIdx !== -1) {
    const portPart = trimmed.slice(colonIdx + 1);
    if (!/^\d{1,5}$/.test(portPart) || trimmed.indexOf(':', colonIdx + 1) !== -1) {
      return { ok: false, code: 'INVALID_HOST', reason: 'Invalid port in Host header' };
    }
    hostname = trimmed.slice(0, colonIdx);
  }

  if (!hostname || hostname === 'localhost' || IPV4_REGEX.test(hostname)) {
    return { ok: false, code: 'IP_HOST_REJECTED', reason: 'Raw IP or localhost Host is not a tenant portal' };
  }

  const normalizedBase = baseDomain.trim().toLowerCase();
  if (hostname === normalizedBase) {
    return { ok: false, code: 'ROOT_DOMAIN_NO_TENANT', reason: 'Root domain has no tenant subdomain' };
  }

  const baseSuffix = `.${normalizedBase}`;
  if (hostname.endsWith(baseSuffix)) {
    const slug = hostname.slice(0, -baseSuffix.length);
    // Must be exactly ONE DNS label under baseDomain (rejects evil.acme.collabify.app)
    if (!SUBDOMAIN_LABEL_REGEX.test(slug) || RESERVED_SLUGS.has(slug)) {
      return {
        ok: false,
        code: 'INVALID_HOST',
        reason: 'Invalid or reserved tenant subdomain label',
      };
    }
    return { ok: true, kind: 'subdomain', slug, normalizedHost: hostname };
  }

  if (!FQDN_REGEX.test(hostname)) {
    return { ok: false, code: 'INVALID_HOST', reason: 'Invalid custom domain hostname' };
  }

  return { ok: true, kind: 'custom_domain', customDomain: hostname, normalizedHost: hostname };
}

export function createSubdomainTenantMiddleware(store: AppStore, config: AppConfig) {
  const trustedIps = new Set(config.trustedProxyIps);

  return async function subdomainTenantResolver(
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> {
    try {
      const forwardedHostHeader = req.headers['x-forwarded-host'];
      const remoteIp = normalizeRemoteIp(req.socket?.remoteAddress);
      let rawHost = typeof req.headers.host === 'string' ? req.headers.host : '';

      if (forwardedHostHeader !== undefined) {
        // Reject X-Forwarded-Host unless the immediate peer IP is an explicitly trusted proxy
        if (!trustedIps.has(remoteIp)) {
          res.status(400).json({
            error: 'UNTRUSTED_FORWARDED_HOST',
            message: 'X-Forwarded-Host rejected from untrusted source',
          });
          return;
        }
        if (Array.isArray(forwardedHostHeader) || forwardedHostHeader.includes(',')) {
          res.status(400).json({
            error: 'INVALID_FORWARDED_HOST',
            message: 'Multiple X-Forwarded-Host values are rejected',
          });
          return;
        }
        rawHost = forwardedHostHeader;
      } else if (config.allowDemoHostHeader && typeof req.headers['x-demo-tenant-host'] === 'string') {
        // Dev-only convenience for local single-host demo workbench (strictly disabled in production)
        rawHost = req.headers['x-demo-tenant-host'];
      }

      const parsed = parseHostCandidate(rawHost, config.baseDomain);
      if (!parsed.ok) {
        res.status(400).json({
          error: parsed.code,
          message: parsed.reason,
        });
        return;
      }

      const tenant =
        parsed.kind === 'subdomain'
          ? await store.resolveTenantByHost({ slug: parsed.slug })
          : await store.resolveTenantByHost({ customDomain: parsed.customDomain });

      // Uniform 404 for both nonexistent and suspended tenants (prevents tenant enumeration)
      if (!tenant || tenant.status !== 'active') {
        res.status(404).json({
          error: 'PORTAL_NOT_FOUND',
          message: 'Workspace not found',
        });
        return;
      }

      req.tenant = tenant;
      req.resolvedHost = parsed.normalizedHost;
      next();
    } catch (err) {
      next(err);
    }
  };
}
