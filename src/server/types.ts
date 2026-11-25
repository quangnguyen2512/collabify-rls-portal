export type TenantStatus = 'active' | 'suspended' | 'archived';

export interface Tenant {
  id: string;
  slug: string;
  customDomain: string | null;
  name: string;
  status: TenantStatus;
  createdAt: string;
}

export type AgencyRole = 'owner' | 'member';

export interface User {
  id: string;
  email: string;
  fullName: string;
  passwordHash: string;
  createdAt: string;
}

export interface TenantMembership {
  id: string;
  tenantId: string;
  userId: string;
  role: AgencyRole;
  createdAt: string;
}

export interface AgencyMemberView {
  userId: string;
  tenantId: string;
  email: string;
  fullName: string;
  passwordHash: string;
  role: AgencyRole;
}

export interface ClientPortal {
  id: string;
  tenantId: string;
  name: string;
  clientName: string;
  status: 'active' | 'archived';
  createdAt: string;
}

export interface PortalMagicLink {
  id: string;
  tenantId: string;
  portalId: string;
  clientEmail: string;
  tokenHash: string;
  expiresAt: string;
  consumedAt: string | null;
  createdBy: string | null;
  createdAt: string;
}

export type VideoStatus = 'UPLOADING' | 'READY' | 'FAILED';

export interface VideoAsset {
  id: string;
  tenantId: string;
  portalId: string;
  uploadId: string;
  filename: string;
  objectKey: string;
  contentType: string;
  sizeBytes: number;
  expectedPartCount: number;
  status: VideoStatus;
  manifestSha256: string | null;
  approvedAt: string | null;
  approvedByEmail: string | null;
  createdAt: string;
}

export interface VideoUploadPart {
  id: string;
  tenantId: string;
  videoId: string;
  partNumber: number;
  sizeBytes: number;
  sha256: string;
  etag: string;
  uploadedAt: string;
}

export type ActorKind = 'agency_admin' | 'portal_guest' | 'system';

export interface AuditEvent {
  id: string;
  tenantId: string;
  actorKind: ActorKind;
  actorId: string;
  action: string;
  resourceType: string;
  resourceId: string;
  metadata: Record<string, unknown>;
  createdAt: string;
}

export type PortalGuestScope = 'video:read' | 'portal:comment' | 'video:approve';

export interface AgencyAdminPrincipal {
  kind: 'agency_admin';
  sub: string;
  email: string;
  tenantId: string;
  role: AgencyRole;
}

export interface PortalGuestPrincipal {
  kind: 'portal_guest';
  sub: string;
  email: string;
  tenantId: string;
  portalId: string;
  scope: PortalGuestScope[];
}

export type AuthPrincipal = AgencyAdminPrincipal | PortalGuestPrincipal;

declare global {
  namespace Express {
    interface Request {
      tenant?: Tenant;
      principal?: AuthPrincipal;
      resolvedHost?: string;
    }
  }
}
