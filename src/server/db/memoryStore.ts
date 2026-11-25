import { AsyncLocalStorage } from 'node:async_hooks';
import crypto from 'node:crypto';
import type {
  AgencyMemberView,
  AuditEvent,
  ClientPortal,
  PortalMagicLink,
  Tenant,
  TenantMembership,
  User,
  VideoAsset,
  VideoUploadPart,
} from '../types.js';
import type {
  AppendAuditEventInput,
  AppStore,
  CreateMagicLinkInput,
  CreatePortalInput,
  CreateVideoAssetInput,
  ResolveTenantHostInput,
  UpsertVideoPartInput,
} from './store.js';
import {
  assertValidTenantUuid,
  CompositeForeignKeyViolationError,
  RlsPolicyViolationError,
} from './tenantContext.js';

export const SEED_IDS = {
  tenants: {
    acme: '11111111-1111-4111-8111-111111111111',
    velvet: '22222222-2222-4222-8222-222222222222',
    suspended: '33333333-3333-4333-8333-333333333333',
  },
  users: {
    alice: 'aaaa1111-1111-4111-8111-111111111111',
    bob: 'bbbb2222-2222-4222-8222-222222222222',
  },
  portals: {
    acmeLaunch: '10000000-0000-4000-8000-000000000001',
    acmeBrand: '10000000-0000-4000-8000-000000000002',
    velvetTeaser: '20000000-0000-4000-8000-000000000001',
  },
  videos: {
    acmeSeedVideo: '50000000-0000-4000-8000-000000000001',
    velvetSeedVideo: '60000000-0000-4000-8000-000000000001',
  },
} as const;

export const DEMO_ADMIN_PASSWORD = 'collabify-demo-pass';

/**
 * In-Memory RLS-Enforcing Store mirroring PostgreSQL `FORCE ROW LEVEL SECURITY`
 * fail-closed semantics:
 * - Reads outside `withTenantContext` return `[]` or `null` (ZERO rows).
 * - Writes outside `withTenantContext` or targeting another tenant throw `RlsPolicyViolationError` (`42501`).
 * - Composite foreign keys `(tenant_id, portal_id)` and `(tenant_id, video_id)` are strictly enforced.
 */
export class MemoryRlsStore implements AppStore {
  private readonly tenantAls = new AsyncLocalStorage<string | null>();

  private readonly tenants = new Map<string, Tenant>();
  private readonly users = new Map<string, User>();
  private readonly memberships: TenantMembership[] = [];
  private readonly portals = new Map<string, ClientPortal>();
  private readonly magicLinks = new Map<string, PortalMagicLink>();
  private readonly videos = new Map<string, VideoAsset>();
  private readonly parts = new Map<string, VideoUploadPart>();
  private readonly partPayloads = new Map<string, Buffer>();
  private readonly auditEvents: AuditEvent[] = [];

  constructor(seed = true) {
    if (seed) {
      this.seedFixtures();
    }
  }

  private seedFixtures(): void {
    const now = new Date('2026-11-20T10:00:00.000Z').toISOString();

    const tenants: Tenant[] = [
      {
        id: SEED_IDS.tenants.acme,
        slug: 'acme',
        customDomain: 'portal.acmecreative.io',
        name: 'Acme Creative Studio',
        status: 'active',
        createdAt: now,
      },
      {
        id: SEED_IDS.tenants.velvet,
        slug: 'velvet',
        customDomain: 'review.velvetmotion.tv',
        name: 'Velvet Motion Lab',
        status: 'active',
        createdAt: now,
      },
      {
        id: SEED_IDS.tenants.suspended,
        slug: 'suspended-co',
        customDomain: null,
        name: 'Suspended Agency Co',
        status: 'suspended',
        createdAt: now,
      },
    ];
    for (const t of tenants) this.tenants.set(t.id, t);

    const users: User[] = [
      {
        id: SEED_IDS.users.alice,
        email: 'alice@acme.studio',
        fullName: 'Alice Chen (Acme Owner)',
        passwordHash: `demo:${DEMO_ADMIN_PASSWORD}`,
        createdAt: now,
      },
      {
        id: SEED_IDS.users.bob,
        email: 'bob@velvet.tv',
        fullName: 'Bob Ramirez (Velvet Owner)',
        passwordHash: `demo:${DEMO_ADMIN_PASSWORD}`,
        createdAt: now,
      },
    ];
    for (const u of users) this.users.set(u.id, u);

    this.memberships.push(
      {
        id: 'cccc1111-1111-4111-8111-111111111111',
        tenantId: SEED_IDS.tenants.acme,
        userId: SEED_IDS.users.alice,
        role: 'owner',
        createdAt: now,
      },
      {
        id: 'cccc2222-2222-4222-8222-222222222222',
        tenantId: SEED_IDS.tenants.velvet,
        userId: SEED_IDS.users.bob,
        role: 'owner',
        createdAt: now,
      },
    );

    const portals: ClientPortal[] = [
      {
        id: SEED_IDS.portals.acmeLaunch,
        tenantId: SEED_IDS.tenants.acme,
        name: 'Q4 Product Launch Film',
        clientName: 'Northstar Robotics',
        status: 'active',
        createdAt: now,
      },
      {
        id: SEED_IDS.portals.acmeBrand,
        tenantId: SEED_IDS.tenants.acme,
        name: 'Brand Guidelines Cutdowns',
        clientName: 'Solstice Skincare',
        status: 'active',
        createdAt: now,
      },
      {
        id: SEED_IDS.portals.velvetTeaser,
        tenantId: SEED_IDS.tenants.velvet,
        name: 'Series A Investor Teaser (Confidential)',
        clientName: 'Hyperion AI',
        status: 'active',
        createdAt: now,
      },
    ];
    for (const p of portals) this.portals.set(p.id, p);

    const videos: VideoAsset[] = [
      {
        id: SEED_IDS.videos.acmeSeedVideo,
        tenantId: SEED_IDS.tenants.acme,
        portalId: SEED_IDS.portals.acmeLaunch,
        uploadId: 'upl_acme_seed_001',
        filename: 'launch_cut_v3.mp4',
        objectKey: `tenants/${SEED_IDS.tenants.acme}/portals/${SEED_IDS.portals.acmeLaunch}/videos/${SEED_IDS.videos.acmeSeedVideo}/launch_cut_v3.mp4`,
        contentType: 'video/mp4',
        sizeBytes: 262_144_000,
        expectedPartCount: 5,
        status: 'READY',
        manifestSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        approvedAt: null,
        approvedByEmail: null,
        createdAt: now,
      },
      {
        id: SEED_IDS.videos.velvetSeedVideo,
        tenantId: SEED_IDS.tenants.velvet,
        portalId: SEED_IDS.portals.velvetTeaser,
        uploadId: 'upl_velvet_seed_001',
        filename: 'series_a_embargoed_master.mov',
        objectKey: `tenants/${SEED_IDS.tenants.velvet}/portals/${SEED_IDS.portals.velvetTeaser}/videos/${SEED_IDS.videos.velvetSeedVideo}/series_a_embargoed_master.mov`,
        contentType: 'video/quicktime',
        sizeBytes: 1_845_493_760,
        expectedPartCount: 20,
        status: 'READY',
        manifestSha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        approvedAt: null,
        approvedByEmail: null,
        createdAt: now,
      },
    ];
    for (const v of videos) this.videos.set(v.id, v);
  }

  getCurrentTenantContext(): string | null {
    return this.tenantAls.getStore() ?? null;
  }

  private assertWriteRls(table: string, rowTenantId: string): string {
    const activeTenantId = this.getCurrentTenantContext();
    if (!activeTenantId) {
      throw new RlsPolicyViolationError(table, 'app.current_tenant_id is not set (fail-closed)');
    }
    if (rowTenantId !== activeTenantId) {
      throw new RlsPolicyViolationError(
        table,
        `row tenant_id (${rowTenantId}) does not match active app.current_tenant_id (${activeTenantId})`,
      );
    }
    return activeTenantId;
  }

  async resolveTenantByHost(input: ResolveTenantHostInput): Promise<Tenant | null> {
    const slug = input.slug?.toLowerCase();
    const customDomain = input.customDomain?.toLowerCase();

    for (const tenant of this.tenants.values()) {
      if (tenant.status !== 'active') continue;
      if (slug && tenant.slug === slug) return { ...tenant };
      if (customDomain && tenant.customDomain === customDomain) return { ...tenant };
    }
    return null;
  }

  async withTenantContext<T>(tenantId: string, fn: () => Promise<T>): Promise<T> {
    const safeTenantId = assertValidTenantUuid(tenantId);
    return this.tenantAls.run(safeTenantId, fn);
  }

  async findAgencyMemberByEmail(email: string): Promise<AgencyMemberView | null> {
    const activeTenantId = this.getCurrentTenantContext();
    if (!activeTenantId) return null;

    const normalized = email.trim().toLowerCase();
    for (const m of this.memberships) {
      if (m.tenantId !== activeTenantId) continue;
      const user = this.users.get(m.userId);
      if (user && user.email.toLowerCase() === normalized) {
        return {
          userId: user.id,
          tenantId: m.tenantId,
          email: user.email,
          fullName: user.fullName,
          passwordHash: user.passwordHash,
          role: m.role,
        };
      }
    }
    return null;
  }

  async listPortals(): Promise<ClientPortal[]> {
    const activeTenantId = this.getCurrentTenantContext();
    if (!activeTenantId) return [];

    return Array.from(this.portals.values())
      .filter((p) => p.tenantId === activeTenantId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map((p) => ({ ...p }));
  }

  async getPortalById(portalId: string): Promise<ClientPortal | null> {
    const activeTenantId = this.getCurrentTenantContext();
    if (!activeTenantId) return null;

    const portal = this.portals.get(portalId);
    if (!portal || portal.tenantId !== activeTenantId) return null;
    return { ...portal };
  }

  async createPortal(input: CreatePortalInput): Promise<ClientPortal> {
    this.assertWriteRls('client_portals', input.tenantId);

    const portal: ClientPortal = {
      id: crypto.randomUUID(),
      tenantId: input.tenantId,
      name: input.name,
      clientName: input.clientName,
      status: 'active',
      createdAt: new Date().toISOString(),
    };
    this.portals.set(portal.id, portal);
    return { ...portal };
  }

  async createMagicLink(input: CreateMagicLinkInput): Promise<PortalMagicLink> {
    this.assertWriteRls('portal_magic_links', input.tenantId);

    // Composite FK check: (tenant_id, portal_id) -> client_portals (tenant_id, id)
    const portal = this.portals.get(input.portalId);
    if (!portal || portal.tenantId !== input.tenantId) {
      throw new CompositeForeignKeyViolationError(
        'fk_magic_links_tenant_portal',
        `portal (${input.portalId}) does not exist in tenant (${input.tenantId})`,
      );
    }

    const link: PortalMagicLink = {
      id: crypto.randomUUID(),
      tenantId: input.tenantId,
      portalId: input.portalId,
      clientEmail: input.clientEmail.toLowerCase(),
      tokenHash: input.tokenHash,
      expiresAt: input.expiresAt,
      consumedAt: null,
      createdBy: input.createdBy,
      createdAt: new Date().toISOString(),
    };
    this.magicLinks.set(link.tokenHash, link);
    return { ...link };
  }

  async consumeMagicLinkByHash(tokenHash: string, nowIso: string): Promise<PortalMagicLink | null> {
    const activeTenantId = this.getCurrentTenantContext();
    if (!activeTenantId) return null;

    const link = this.magicLinks.get(tokenHash);
    if (!link || link.tenantId !== activeTenantId) return null;
    if (link.consumedAt !== null) return null;
    if (new Date(link.expiresAt).getTime() <= new Date(nowIso).getTime()) return null;

    link.consumedAt = nowIso;
    return { ...link };
  }

  async listVideosByPortal(portalId: string): Promise<VideoAsset[]> {
    const activeTenantId = this.getCurrentTenantContext();
    if (!activeTenantId) return [];

    return Array.from(this.videos.values())
      .filter((v) => v.tenantId === activeTenantId && v.portalId === portalId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map((v) => ({ ...v }));
  }

  async getVideoById(videoId: string): Promise<VideoAsset | null> {
    const activeTenantId = this.getCurrentTenantContext();
    if (!activeTenantId) return null;

    const video = this.videos.get(videoId);
    if (!video || video.tenantId !== activeTenantId) return null;
    return { ...video };
  }

  async getVideoByUploadId(uploadId: string): Promise<VideoAsset | null> {
    const activeTenantId = this.getCurrentTenantContext();
    if (!activeTenantId) return null;

    for (const v of this.videos.values()) {
      if (v.tenantId === activeTenantId && v.uploadId === uploadId) {
        return { ...v };
      }
    }
    return null;
  }

  async createVideoAsset(input: CreateVideoAssetInput): Promise<VideoAsset> {
    this.assertWriteRls('video_assets', input.tenantId);

    // Composite FK check: (tenant_id, portal_id) -> client_portals (tenant_id, id)
    const portal = this.portals.get(input.portalId);
    if (!portal || portal.tenantId !== input.tenantId) {
      throw new CompositeForeignKeyViolationError(
        'fk_video_assets_tenant_portal',
        `portal (${input.portalId}) does not exist in tenant (${input.tenantId})`,
      );
    }

    const expectedPrefix = `tenants/${input.tenantId}/portals/${input.portalId}/videos/`;
    if (!input.objectKey.startsWith(expectedPrefix)) {
      throw new Error('chk_video_assets_object_key_tenant_prefix violated');
    }

    const asset: VideoAsset = {
      id: input.id,
      tenantId: input.tenantId,
      portalId: input.portalId,
      uploadId: input.uploadId,
      filename: input.filename,
      objectKey: input.objectKey,
      contentType: input.contentType,
      sizeBytes: input.sizeBytes,
      expectedPartCount: input.expectedPartCount,
      status: 'UPLOADING',
      manifestSha256: null,
      approvedAt: null,
      approvedByEmail: null,
      createdAt: new Date().toISOString(),
    };
    this.videos.set(asset.id, asset);
    return { ...asset };
  }

  async completeVideoAsset(videoId: string, manifestSha256: string): Promise<VideoAsset | null> {
    const activeTenantId = this.getCurrentTenantContext();
    if (!activeTenantId) return null;

    const video = this.videos.get(videoId);
    if (!video || video.tenantId !== activeTenantId) return null;

    video.status = 'READY';
    video.manifestSha256 = manifestSha256;
    return { ...video };
  }

  async approveVideoAsset(
    videoId: string,
    approvedByEmail: string,
    approvedAt: string,
  ): Promise<VideoAsset | null> {
    const activeTenantId = this.getCurrentTenantContext();
    if (!activeTenantId) return null;

    const video = this.videos.get(videoId);
    if (!video || video.tenantId !== activeTenantId) return null;

    video.approvedAt = approvedAt;
    video.approvedByEmail = approvedByEmail;
    return { ...video };
  }

  async upsertVideoUploadPart(input: UpsertVideoPartInput): Promise<VideoUploadPart> {
    this.assertWriteRls('video_upload_parts', input.tenantId);

    // Composite FK check: (tenant_id, video_id) -> video_assets (tenant_id, id)
    const video = this.videos.get(input.videoId);
    if (!video || video.tenantId !== input.tenantId) {
      throw new CompositeForeignKeyViolationError(
        'fk_video_upload_parts_tenant_video',
        `video (${input.videoId}) does not exist in tenant (${input.tenantId})`,
      );
    }

    const compositeKey = `${input.tenantId}:${input.videoId}:${input.partNumber}`;
    const existing = this.parts.get(compositeKey);
    const part: VideoUploadPart = {
      id: existing?.id ?? crypto.randomUUID(),
      tenantId: input.tenantId,
      videoId: input.videoId,
      partNumber: input.partNumber,
      sizeBytes: input.sizeBytes,
      sha256: input.sha256,
      etag: input.etag,
      uploadedAt: new Date().toISOString(),
    };
    this.parts.set(compositeKey, part);
    if (input.chunkBytes) {
      this.partPayloads.set(compositeKey, Buffer.from(input.chunkBytes));
    }
    return { ...part };
  }

  async listVideoUploadParts(videoId: string): Promise<VideoUploadPart[]> {
    const activeTenantId = this.getCurrentTenantContext();
    if (!activeTenantId) return [];

    return Array.from(this.parts.values())
      .filter((p) => p.tenantId === activeTenantId && p.videoId === videoId)
      .sort((a, b) => a.partNumber - b.partNumber)
      .map((p) => ({ ...p }));
  }

  async readAssembledVideoBytes(videoId: string): Promise<Buffer | null> {
    const activeTenantId = this.getCurrentTenantContext();
    if (!activeTenantId) return null;

    const video = this.videos.get(videoId);
    if (!video || video.tenantId !== activeTenantId || video.status !== 'READY') return null;

    const orderedParts = Array.from(this.parts.values())
      .filter((p) => p.tenantId === activeTenantId && p.videoId === videoId)
      .sort((a, b) => a.partNumber - b.partNumber);

    if (orderedParts.length > 0) {
      const buffers: Buffer[] = [];
      for (const part of orderedParts) {
        const key = `${activeTenantId}:${videoId}:${part.partNumber}`;
        const bytes = this.partPayloads.get(key);
        if (!bytes) return null;
        buffers.push(bytes);
      }
      return Buffer.concat(buffers);
    }

    // Seeded demo video fixture without uploaded raw chunks in memory
    return Buffer.from(
      `COLLABIFY_SEED_PREVIEW|tenant=${video.tenantId}|portal=${video.portalId}|video=${video.id}|file=${video.filename}|manifest=${video.manifestSha256 ?? ''}`,
      'utf8',
    );
  }

  async appendAuditEvent(input: AppendAuditEventInput): Promise<AuditEvent> {
    this.assertWriteRls('audit_events', input.tenantId);

    const event: AuditEvent = {
      id: crypto.randomUUID(),
      tenantId: input.tenantId,
      actorKind: input.actorKind,
      actorId: input.actorId,
      action: input.action,
      resourceType: input.resourceType,
      resourceId: input.resourceId,
      metadata: input.metadata ?? {},
      createdAt: new Date().toISOString(),
    };
    this.auditEvents.push(event);
    return { ...event };
  }

  async listAuditEvents(limit = 50): Promise<AuditEvent[]> {
    const activeTenantId = this.getCurrentTenantContext();
    if (!activeTenantId) return [];

    return this.auditEvents
      .filter((e) => e.tenantId === activeTenantId)
      .slice(-limit)
      .reverse()
      .map((e) => ({ ...e }));
  }
}
