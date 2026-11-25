import { AsyncLocalStorage } from 'node:async_hooks';
import { Pool, type PoolClient, type QueryResultRow } from 'pg';
import type {
  AgencyMemberView,
  AuditEvent,
  ClientPortal,
  PortalMagicLink,
  Tenant,
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
import { withPgTenantContext } from './tenantContext.js';

interface PgTxContext {
  tenantId: string;
  client: PoolClient;
}

/**
 * Production PostgreSQL RLS Store.
 *
 * Connects using the non-superuser `collabify_app` (`NOBYPASSRLS`) role.
 * Every tenant-scoped operation runs inside `withPgTenantContext`, which wraps
 * the transaction in `BEGIN` + `SELECT set_config('app.current_tenant_id', $1, true)`
 * (`SET LOCAL` semantics — 100% safe with PgBouncer transaction pooling).
 */
export class PgRlsStore implements AppStore {
  private readonly txAls = new AsyncLocalStorage<PgTxContext>();

  constructor(private readonly pool: Pool) {}

  static fromConnectionString(connectionString: string): PgRlsStore {
    const pool = new Pool({
      connectionString,
      max: 20,
      idleTimeoutMillis: 30_000,
    });
    return new PgRlsStore(pool);
  }

  getCurrentTenantContext(): string | null {
    return this.txAls.getStore()?.tenantId ?? null;
  }

  private getQueryable(): Pool | PoolClient {
    // If called outside `withTenantContext`, queries run directly against the pool
    // where `app.current_tenant_id` is unset -> PostgreSQL RLS fails closed (0 rows / 42501).
    return this.txAls.getStore()?.client ?? this.pool;
  }

  async resolveTenantByHost(input: ResolveTenantHostInput): Promise<Tenant | null> {
    const res = await this.pool.query<QueryResultRow>(
      `SELECT id, slug, custom_domain, name, status
       FROM resolve_tenant_by_host($1, $2)`,
      [input.slug ?? null, input.customDomain ?? null],
    );
    const row = res.rows[0];
    if (!row) return null;
    return {
      id: String(row.id),
      slug: String(row.slug),
      customDomain: row.custom_domain ? String(row.custom_domain) : null,
      name: String(row.name),
      status: row.status as Tenant['status'],
      createdAt: new Date().toISOString(),
    };
  }

  async withTenantContext<T>(tenantId: string, fn: () => Promise<T>): Promise<T> {
    return withPgTenantContext(this.pool, tenantId, async (client) => {
      return this.txAls.run({ tenantId: tenantId.toLowerCase(), client }, fn);
    });
  }

  async findAgencyMemberByEmail(email: string): Promise<AgencyMemberView | null> {
    const db = this.getQueryable();
    const res = await db.query<QueryResultRow>(
      `SELECT u.id AS user_id, tm.tenant_id, u.email, u.full_name, u.password_hash, tm.role
       FROM tenant_memberships tm
       JOIN users u ON u.id = tm.user_id
       WHERE lower(u.email) = lower($1)
       LIMIT 1`,
      [email.trim()],
    );
    const row = res.rows[0];
    if (!row) return null;
    return {
      userId: String(row.user_id),
      tenantId: String(row.tenant_id),
      email: String(row.email),
      fullName: String(row.full_name),
      passwordHash: String(row.password_hash),
      role: row.role as AgencyMemberView['role'],
    };
  }

  async listPortals(): Promise<ClientPortal[]> {
    const db = this.getQueryable();
    const res = await db.query<QueryResultRow>(
      `SELECT id, tenant_id, name, client_name, status, created_at
       FROM client_portals
       ORDER BY created_at DESC`,
    );
    return res.rows.map(mapPortalRow);
  }

  async getPortalById(portalId: string): Promise<ClientPortal | null> {
    const db = this.getQueryable();
    const res = await db.query<QueryResultRow>(
      `SELECT id, tenant_id, name, client_name, status, created_at
       FROM client_portals
       WHERE id = $1`,
      [portalId],
    );
    return res.rows[0] ? mapPortalRow(res.rows[0]) : null;
  }

  async createPortal(input: CreatePortalInput): Promise<ClientPortal> {
    const db = this.getQueryable();
    const res = await db.query<QueryResultRow>(
      `INSERT INTO client_portals (tenant_id, name, client_name)
       VALUES ($1, $2, $3)
       RETURNING id, tenant_id, name, client_name, status, created_at`,
      [input.tenantId, input.name, input.clientName],
    );
    return mapPortalRow(res.rows[0]!);
  }

  async createMagicLink(input: CreateMagicLinkInput): Promise<PortalMagicLink> {
    const db = this.getQueryable();
    const res = await db.query<QueryResultRow>(
      `INSERT INTO portal_magic_links (tenant_id, portal_id, client_email, token_hash, expires_at, created_by)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, tenant_id, portal_id, client_email, token_hash, expires_at, consumed_at, created_by, created_at`,
      [
        input.tenantId,
        input.portalId,
        input.clientEmail.toLowerCase(),
        input.tokenHash,
        input.expiresAt,
        input.createdBy,
      ],
    );
    return mapMagicLinkRow(res.rows[0]!);
  }

  async consumeMagicLinkByHash(tokenHash: string, nowIso: string): Promise<PortalMagicLink | null> {
    const db = this.getQueryable();
    const res = await db.query<QueryResultRow>(
      `UPDATE portal_magic_links
       SET consumed_at = $2::timestamptz
       WHERE token_hash = $1
         AND consumed_at IS NULL
         AND expires_at > $2::timestamptz
       RETURNING id, tenant_id, portal_id, client_email, token_hash, expires_at, consumed_at, created_by, created_at`,
      [tokenHash, nowIso],
    );
    return res.rows[0] ? mapMagicLinkRow(res.rows[0]) : null;
  }

  async listVideosByPortal(portalId: string): Promise<VideoAsset[]> {
    const db = this.getQueryable();
    const res = await db.query<QueryResultRow>(
      `SELECT id, tenant_id, portal_id, upload_id, filename, object_key, content_type,
              size_bytes, expected_part_count, status, manifest_sha256, approved_at, approved_by_email, created_at
       FROM video_assets
       WHERE portal_id = $1
       ORDER BY created_at DESC`,
      [portalId],
    );
    return res.rows.map(mapVideoRow);
  }

  async getVideoById(videoId: string): Promise<VideoAsset | null> {
    const db = this.getQueryable();
    const res = await db.query<QueryResultRow>(
      `SELECT id, tenant_id, portal_id, upload_id, filename, object_key, content_type,
              size_bytes, expected_part_count, status, manifest_sha256, approved_at, approved_by_email, created_at
       FROM video_assets
       WHERE id = $1`,
      [videoId],
    );
    return res.rows[0] ? mapVideoRow(res.rows[0]) : null;
  }

  async getVideoByUploadId(uploadId: string): Promise<VideoAsset | null> {
    const db = this.getQueryable();
    const res = await db.query<QueryResultRow>(
      `SELECT id, tenant_id, portal_id, upload_id, filename, object_key, content_type,
              size_bytes, expected_part_count, status, manifest_sha256, approved_at, approved_by_email, created_at
       FROM video_assets
       WHERE upload_id = $1`,
      [uploadId],
    );
    return res.rows[0] ? mapVideoRow(res.rows[0]) : null;
  }

  async createVideoAsset(input: CreateVideoAssetInput): Promise<VideoAsset> {
    const db = this.getQueryable();
    const res = await db.query<QueryResultRow>(
      `INSERT INTO video_assets (
         id, tenant_id, portal_id, upload_id, filename, object_key, content_type,
         size_bytes, expected_part_count, status
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'UPLOADING')
       RETURNING id, tenant_id, portal_id, upload_id, filename, object_key, content_type,
                 size_bytes, expected_part_count, status, manifest_sha256, approved_at, approved_by_email, created_at`,
      [
        input.id,
        input.tenantId,
        input.portalId,
        input.uploadId,
        input.filename,
        input.objectKey,
        input.contentType,
        input.sizeBytes,
        input.expectedPartCount,
      ],
    );
    return mapVideoRow(res.rows[0]!);
  }

  async completeVideoAsset(videoId: string, manifestSha256: string): Promise<VideoAsset | null> {
    const db = this.getQueryable();
    const res = await db.query<QueryResultRow>(
      `UPDATE video_assets
       SET status = 'READY', manifest_sha256 = $2, updated_at = now()
       WHERE id = $1
       RETURNING id, tenant_id, portal_id, upload_id, filename, object_key, content_type,
                 size_bytes, expected_part_count, status, manifest_sha256, approved_at, approved_by_email, created_at`,
      [videoId, manifestSha256],
    );
    return res.rows[0] ? mapVideoRow(res.rows[0]) : null;
  }

  async approveVideoAsset(
    videoId: string,
    approvedByEmail: string,
    approvedAt: string,
  ): Promise<VideoAsset | null> {
    const db = this.getQueryable();
    const res = await db.query<QueryResultRow>(
      `UPDATE video_assets
       SET approved_at = $3::timestamptz, approved_by_email = $2, updated_at = now()
       WHERE id = $1
       RETURNING id, tenant_id, portal_id, upload_id, filename, object_key, content_type,
                 size_bytes, expected_part_count, status, manifest_sha256, approved_at, approved_by_email, created_at`,
      [videoId, approvedByEmail, approvedAt],
    );
    return res.rows[0] ? mapVideoRow(res.rows[0]) : null;
  }

  async upsertVideoUploadPart(input: UpsertVideoPartInput): Promise<VideoUploadPart> {
    const db = this.getQueryable();
    const res = await db.query<QueryResultRow>(
      `INSERT INTO video_upload_parts (tenant_id, video_id, part_number, size_bytes, sha256, etag)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (tenant_id, video_id, part_number)
       DO UPDATE SET size_bytes = EXCLUDED.size_bytes,
                     sha256 = EXCLUDED.sha256,
                     etag = EXCLUDED.etag,
                     uploaded_at = now()
       RETURNING id, tenant_id, video_id, part_number, size_bytes, sha256, etag, uploaded_at`,
      [
        input.tenantId,
        input.videoId,
        input.partNumber,
        input.sizeBytes,
        input.sha256,
        input.etag,
      ],
    );
    return mapPartRow(res.rows[0]!);
  }

  async listVideoUploadParts(videoId: string): Promise<VideoUploadPart[]> {
    const db = this.getQueryable();
    const res = await db.query<QueryResultRow>(
      `SELECT id, tenant_id, video_id, part_number, size_bytes, sha256, etag, uploaded_at
       FROM video_upload_parts
       WHERE video_id = $1
       ORDER BY part_number ASC`,
      [videoId],
    );
    return res.rows.map(mapPartRow);
  }

  async appendAuditEvent(input: AppendAuditEventInput): Promise<AuditEvent> {
    const db = this.getQueryable();
    const res = await db.query<QueryResultRow>(
      `INSERT INTO audit_events (tenant_id, actor_kind, actor_id, action, resource_type, resource_id, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
       RETURNING id, tenant_id, actor_kind, actor_id, action, resource_type, resource_id, metadata, created_at`,
      [
        input.tenantId,
        input.actorKind,
        input.actorId,
        input.action,
        input.resourceType,
        input.resourceId,
        JSON.stringify(input.metadata ?? {}),
      ],
    );
    return mapAuditRow(res.rows[0]!);
  }

  async listAuditEvents(limit = 50): Promise<AuditEvent[]> {
    const db = this.getQueryable();
    const res = await db.query<QueryResultRow>(
      `SELECT id, tenant_id, actor_kind, actor_id, action, resource_type, resource_id, metadata, created_at
       FROM audit_events
       ORDER BY created_at DESC
       LIMIT $1`,
      [limit],
    );
    return res.rows.map(mapAuditRow);
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

function mapPortalRow(row: QueryResultRow): ClientPortal {
  return {
    id: String(row.id),
    tenantId: String(row.tenant_id),
    name: String(row.name),
    clientName: String(row.client_name),
    status: row.status as ClientPortal['status'],
    createdAt: new Date(row.created_at).toISOString(),
  };
}

function mapMagicLinkRow(row: QueryResultRow): PortalMagicLink {
  return {
    id: String(row.id),
    tenantId: String(row.tenant_id),
    portalId: String(row.portal_id),
    clientEmail: String(row.client_email),
    tokenHash: String(row.token_hash),
    expiresAt: new Date(row.expires_at).toISOString(),
    consumedAt: row.consumed_at ? new Date(row.consumed_at).toISOString() : null,
    createdBy: row.created_by ? String(row.created_by) : null,
    createdAt: new Date(row.created_at).toISOString(),
  };
}

function mapVideoRow(row: QueryResultRow): VideoAsset {
  return {
    id: String(row.id),
    tenantId: String(row.tenant_id),
    portalId: String(row.portal_id),
    uploadId: String(row.upload_id),
    filename: String(row.filename),
    objectKey: String(row.object_key),
    contentType: String(row.content_type),
    sizeBytes: Number(row.size_bytes),
    expectedPartCount: Number(row.expected_part_count),
    status: row.status as VideoAsset['status'],
    manifestSha256: row.manifest_sha256 ? String(row.manifest_sha256) : null,
    approvedAt: row.approved_at ? new Date(row.approved_at).toISOString() : null,
    approvedByEmail: row.approved_by_email ? String(row.approved_by_email) : null,
    createdAt: new Date(row.created_at).toISOString(),
  };
}

function mapPartRow(row: QueryResultRow): VideoUploadPart {
  return {
    id: String(row.id),
    tenantId: String(row.tenant_id),
    videoId: String(row.video_id),
    partNumber: Number(row.part_number),
    sizeBytes: Number(row.size_bytes),
    sha256: String(row.sha256),
    etag: String(row.etag),
    uploadedAt: new Date(row.uploaded_at).toISOString(),
  };
}

function mapAuditRow(row: QueryResultRow): AuditEvent {
  return {
    id: String(row.id),
    tenantId: String(row.tenant_id),
    actorKind: row.actor_kind as AuditEvent['actorKind'],
    actorId: String(row.actor_id),
    action: String(row.action),
    resourceType: String(row.resource_type),
    resourceId: String(row.resource_id),
    metadata: (row.metadata as Record<string, unknown>) ?? {},
    createdAt: new Date(row.created_at).toISOString(),
  };
}
