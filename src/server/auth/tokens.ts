import crypto from 'node:crypto';
import type {
  AgencyAdminPrincipal,
  AgencyRole,
  AuthPrincipal,
  PortalGuestPrincipal,
  PortalGuestScope,
} from '../types.js';

const JWT_ISSUER = 'collabify';

interface JwtHeader {
  alg: 'HS256';
  typ: 'JWT';
}

interface BaseJwtPayload {
  iss: string;
  aud: 'agency_admin' | 'portal_guest';
  sub: string;
  email: string;
  tenantId: string;
  iat: number;
  exp: number;
}

interface AgencyJwtPayload extends BaseJwtPayload {
  aud: 'agency_admin';
  role: AgencyRole;
}

interface PortalGuestJwtPayload extends BaseJwtPayload {
  aud: 'portal_guest';
  portalId: string;
  scope: PortalGuestScope[];
}

type CollabifyJwtPayload = AgencyJwtPayload | PortalGuestJwtPayload;

function base64UrlEncode(input: string | Buffer): string {
  return Buffer.from(input).toString('base64url');
}

function base64UrlDecode(input: string): string {
  return Buffer.from(input, 'base64url').toString('utf8');
}

function signHmacSha256(signingInput: string, secret: string): Buffer {
  return crypto.createHmac('sha256', secret).update(signingInput).digest();
}

function issueJwt(payload: CollabifyJwtPayload, secret: string): string {
  const header: JwtHeader = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const sig = signHmacSha256(signingInput, secret).toString('base64url');
  return `${signingInput}.${sig}`;
}

export function signAgencyToken(
  params: { sub: string; email: string; tenantId: string; role: AgencyRole },
  secret: string,
  ttlSeconds = 3600,
): string {
  const now = Math.floor(Date.now() / 1000);
  const payload: AgencyJwtPayload = {
    iss: JWT_ISSUER,
    aud: 'agency_admin',
    sub: params.sub,
    email: params.email,
    tenantId: params.tenantId,
    role: params.role,
    iat: now,
    exp: now + ttlSeconds,
  };
  return issueJwt(payload, secret);
}

export function signPortalGuestToken(
  params: {
    sub: string;
    email: string;
    tenantId: string;
    portalId: string;
    scope?: PortalGuestScope[];
  },
  secret: string,
  ttlSeconds = 7200,
): string {
  const now = Math.floor(Date.now() / 1000);
  const payload: PortalGuestJwtPayload = {
    iss: JWT_ISSUER,
    aud: 'portal_guest',
    sub: params.sub,
    email: params.email,
    tenantId: params.tenantId,
    portalId: params.portalId,
    scope: params.scope ?? ['video:read', 'portal:comment', 'video:approve'],
    iat: now,
    exp: now + ttlSeconds,
  };
  return issueJwt(payload, secret);
}

export function verifyAuthToken(token: string, secret: string): AuthPrincipal | null {
  const segments = token.split('.');
  if (segments.length !== 3) return null;

  const [encodedHeader, encodedPayload, encodedSig] = segments;
  if (!encodedHeader || !encodedPayload || !encodedSig) return null;

  try {
    const header = JSON.parse(base64UrlDecode(encodedHeader)) as Partial<JwtHeader>;
    // Strictly reject algorithm confusion (e.g., alg: none or RS256)
    if (header.alg !== 'HS256' || header.typ !== 'JWT') return null;

    const expectedSig = signHmacSha256(`${encodedHeader}.${encodedPayload}`, secret);
    const providedSig = Buffer.from(encodedSig, 'base64url');
    if (expectedSig.length !== providedSig.length) return null;
    if (!crypto.timingSafeEqual(expectedSig, providedSig)) return null;

    const payload = JSON.parse(base64UrlDecode(encodedPayload)) as Partial<CollabifyJwtPayload>;
    const now = Math.floor(Date.now() / 1000);
    if (payload.iss !== JWT_ISSUER) return null;
    if (typeof payload.exp !== 'number' || payload.exp <= now) return null;
    if (typeof payload.sub !== 'string' || typeof payload.tenantId !== 'string') return null;
    if (typeof payload.email !== 'string') return null;

    if (payload.aud === 'agency_admin') {
      if (payload.role !== 'owner' && payload.role !== 'member') return null;
      const principal: AgencyAdminPrincipal = {
        kind: 'agency_admin',
        sub: payload.sub,
        email: payload.email,
        tenantId: payload.tenantId,
        role: payload.role,
      };
      return principal;
    }

    if (payload.aud === 'portal_guest') {
      if (typeof payload.portalId !== 'string' || !Array.isArray(payload.scope)) return null;
      const principal: PortalGuestPrincipal = {
        kind: 'portal_guest',
        sub: payload.sub,
        email: payload.email,
        tenantId: payload.tenantId,
        portalId: payload.portalId,
        scope: payload.scope as PortalGuestScope[],
      };
      return principal;
    }

    return null;
  } catch {
    return null;
  }
}

export function generateOpaqueToken(): string {
  return crypto.randomBytes(32).toString('base64url');
}

export function hashOpaqueToken(rawToken: string): string {
  return crypto.createHash('sha256').update(rawToken).digest('hex');
}

export function verifyPassword(
  plaintext: string,
  storedHash: string,
  allowDemoPrefix = true,
): boolean {
  if (storedHash.startsWith('scrypt:')) {
    const parts = storedHash.split(':');
    if (parts.length !== 3) return false;
    const salt = Buffer.from(parts[1]!, 'hex');
    const expected = Buffer.from(parts[2]!, 'hex');
    const derived = crypto.scryptSync(plaintext, salt, expected.length);
    return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
  }

  if (allowDemoPrefix && storedHash.startsWith('demo:')) {
    const expectedDigest = crypto.createHash('sha256').update(storedHash.slice(5)).digest();
    const providedDigest = crypto.createHash('sha256').update(plaintext).digest();
    return crypto.timingSafeEqual(expectedDigest, providedDigest);
  }

  return false;
}
