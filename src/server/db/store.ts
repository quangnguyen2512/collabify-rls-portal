import type {
  ActorKind,
  AgencyMemberView,
  AuditEvent,
  ClientPortal,
  PortalMagicLink,
  Tenant,
  VideoAsset,
  VideoUploadPart,
} from '../types.js';

export interface ResolveTenantHostInput {
  slug?: string;
  customDomain?: string;
}

export interface CreatePortalInput {
  tenantId: string;
  name: string;
  clientName: string;
}

export interface CreateMagicLinkInput {
  tenantId: string;
  portalId: string;
  clientEmail: string;
  tokenHash: string;
  expiresAt: string;
  createdBy: string | null;
}

export interface CreateVideoAssetInput {
  id: string;
  tenantId: string;
  portalId: string;
  uploadId: string;
  filename: string;
  objectKey: string;
  contentType: string;
  sizeBytes: number;
  expectedPartCount: number;
}

export interface UpsertVideoPartInput {
  tenantId: string;
  videoId: string;
  partNumber: number;
  sizeBytes: number;
  sha256: string;
  etag: string;
  chunkBytes?: Buffer;
}

export interface AppendAuditEventInput {
  tenantId: string;
  actorKind: ActorKind;
  actorId: string;
  action: string;
  resourceType: string;
  resourceId: string;
  metadata?: Record<string, unknown>;
}

/**
 * Storage contract implemented by BOTH:
 * - `MemoryRlsStore` (in-memory fail-closed RLS simulator for zero-DB demo & unit tests)
 * - `PgRlsStore` (real PostgreSQL `pg` Pool executing `SET LOCAL` under `collabify_app` NOBYPASSRLS)
 */
export interface AppStore {
  /**
   * Pre-context subdomain/custom-domain lookup backed by SECURITY DEFINER
   * `resolve_tenant_by_host`. Returns ONLY active tenants (never suspended/archived).
   */
  resolveTenantByHost(input: ResolveTenantHostInput): Promise<Tenant | null>;

  /**
   * Executes `fn` inside a transaction-scoped tenant context (`SET LOCAL app.current_tenant_id`).
   * Cleared automatically upon completion or error.
   */
  withTenantContext<T>(tenantId: string, fn: () => Promise<T>): Promise<T>;

  /** Returns active tenant context UUID if inside `withTenantContext`, else `null`. */
  getCurrentTenantContext(): string | null;

  // --- Tenant-scoped queries (ALL fail-closed when context is missing) ---
  findAgencyMemberByEmail(email: string): Promise<AgencyMemberView | null>;

  listPortals(): Promise<ClientPortal[]>;
  getPortalById(portalId: string): Promise<ClientPortal | null>;
  createPortal(input: CreatePortalInput): Promise<ClientPortal>;

  createMagicLink(input: CreateMagicLinkInput): Promise<PortalMagicLink>;
  consumeMagicLinkByHash(tokenHash: string, nowIso: string): Promise<PortalMagicLink | null>;

  listVideosByPortal(portalId: string): Promise<VideoAsset[]>;
  getVideoById(videoId: string): Promise<VideoAsset | null>;
  getVideoByUploadId(uploadId: string): Promise<VideoAsset | null>;
  createVideoAsset(input: CreateVideoAssetInput): Promise<VideoAsset>;
  completeVideoAsset(videoId: string, manifestSha256: string): Promise<VideoAsset | null>;
  approveVideoAsset(videoId: string, approvedByEmail: string, approvedAt: string): Promise<VideoAsset | null>;

  upsertVideoUploadPart(input: UpsertVideoPartInput): Promise<VideoUploadPart>;
  listVideoUploadParts(videoId: string): Promise<VideoUploadPart[]>;
  readAssembledVideoBytes?(videoId: string): Promise<Buffer | null>;

  appendAuditEvent(input: AppendAuditEventInput): Promise<AuditEvent>;
  listAuditEvents(limit?: number): Promise<AuditEvent[]>;
}
