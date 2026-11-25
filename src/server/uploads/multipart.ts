import crypto from 'node:crypto';
import express, { Router } from 'express';
import { z } from 'zod';
import { createAuthMiddleware, requireAgencyAdmin, requirePortalAccess } from '../auth/middleware.js';
import type { AppConfig } from '../config.js';
import type { AppStore } from '../db/store.js';
import type { MultipartStoragePresigner } from './presigner.js';

export const ALLOWED_VIDEO_MIME_TYPES = new Set([
  'video/mp4',
  'video/quicktime',
  'video/webm',
  'video/x-matroska',
]);

export function createUploadPartsRouter(
  store: AppStore,
  presigner: MultipartStoragePresigner,
): Router {
  const router = Router();

  /**
   * Step 2: Upload individual chunk via HMAC-signed URL.
   * Mounted before `express.json()` so raw binary payloads stream untouched.
   * Verifies part signature, expiry, tenant isolation, and computes SHA-256 ETag.
   * Optional `X-Content-Sha256` header enforces end-to-end client-to-server integrity.
   */
  router.put(
    '/uploads/:uploadId/parts/:partNumber',
    express.raw({ type: '*/*', limit: '64mb' }),
    async (req, res, next) => {
      try {
        const tenant = req.tenant!;
        const uploadId = String(req.params.uploadId);
        const partNumber = Number(req.params.partNumber);

        if (!Number.isInteger(partNumber) || partNumber < 1 || partNumber > 10_000) {
          res.status(400).json({ error: 'INVALID_PART_NUMBER', message: 'Invalid part number' });
          return;
        }

        const signedTenantId = typeof req.query.tenantId === 'string' ? req.query.tenantId : '';
        const expUnix = Number(req.query.exp);
        const signature = typeof req.query.sig === 'string' ? req.query.sig : '';

        if (!signedTenantId || signedTenantId !== tenant.id) {
          res.status(403).json({
            error: 'TENANT_MISMATCH',
            message: 'Signed upload URL belongs to a different tenant workspace',
          });
          return;
        }

        const verify = presigner.verifyPartUploadSignature({
          uploadId,
          partNumber,
          tenantId: tenant.id,
          expiresAtUnix: expUnix,
          signature,
        });
        if (!verify.ok) {
          res.status(403).json({
            error: verify.code,
            message:
              verify.code === 'UPLOAD_SIGNATURE_EXPIRED'
                ? 'Signed part upload URL has expired'
                : 'Invalid part upload HMAC signature',
          });
          return;
        }

        const chunkBuffer = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body ?? '');
        if (chunkBuffer.length === 0) {
          res.status(400).json({ error: 'EMPTY_PART', message: 'Chunk payload cannot be empty' });
          return;
        }

        const sha256 = crypto.createHash('sha256').update(chunkBuffer).digest('hex');

        const clientChecksum = req.headers['x-content-sha256'];
        if (typeof clientChecksum === 'string' && clientChecksum.trim() !== '') {
          const expectedBuf = Buffer.from(sha256, 'utf8');
          const providedBuf = Buffer.from(clientChecksum.trim().toLowerCase(), 'utf8');
          if (
            expectedBuf.length !== providedBuf.length ||
            !crypto.timingSafeEqual(expectedBuf, providedBuf)
          ) {
            res.status(400).json({
              error: 'CHECKSUM_MISMATCH',
              message: 'Chunk SHA-256 does not match X-Content-Sha256 header',
              expectedSha256: sha256,
            });
            return;
          }
        }

        const saved = await store.withTenantContext(tenant.id, async () => {
          const video = await store.getVideoByUploadId(uploadId);
          if (!video) return { error: 'UPLOAD_NOT_FOUND' as const };
          if (video.status !== 'UPLOADING') return { error: 'UPLOAD_NOT_ACTIVE' as const };
          if (partNumber > video.expectedPartCount) {
            return { error: 'PART_OUT_OF_RANGE' as const };
          }

          const part = await store.upsertVideoUploadPart({
            tenantId: tenant.id,
            videoId: video.id,
            partNumber,
            sizeBytes: chunkBuffer.length,
            sha256,
            etag: sha256,
            chunkBytes: chunkBuffer,
          });
          return { video, part };
        });

        if ('error' in saved) {
          const status = saved.error === 'UPLOAD_NOT_FOUND' ? 404 : 400;
          res.status(status).json({ error: saved.error, message: `Upload part rejected: ${saved.error}` });
          return;
        }

        res.setHeader('ETag', `"${saved.part.etag}"`);
        res.status(200).json({
          uploadId,
          videoId: saved.video.id,
          partNumber: saved.part.partNumber,
          sizeBytes: saved.part.sizeBytes,
          sha256: saved.part.sha256,
          etag: saved.part.etag,
        });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * Local HMAC-verified streaming endpoint with RFC 7233 HTTP Range (206 Partial Content).
   * In production, `S3MultipartPresigner.signPlaybackUrl` redirects directly to Cloudflare R2 /
   * CloudFront signed URLs with identical tenant-scoped object keys.
   */
  router.get('/uploads/stream/:videoId', async (req, res, next) => {
    try {
      const tenant = req.tenant!;
      const videoId = String(req.params.videoId);
      const signedTenantId = typeof req.query.tenantId === 'string' ? req.query.tenantId : '';
      const portalId = typeof req.query.portalId === 'string' ? req.query.portalId : '';
      const objectKey = typeof req.query.key === 'string' ? req.query.key : '';
      const expUnix = Number(req.query.exp);
      const signature = typeof req.query.sig === 'string' ? req.query.sig : '';

      if (!signedTenantId || signedTenantId !== tenant.id) {
        res.status(403).json({
          error: 'TENANT_MISMATCH',
          message: 'Signed playback URL belongs to a different tenant workspace',
        });
        return;
      }

      const verify = presigner.verifyPlaybackSignature({
        tenantId: tenant.id,
        portalId,
        videoId,
        objectKey,
        expiresAtUnix: expUnix,
        signature,
      });
      if (!verify.ok) {
        res.status(403).json({
          error: verify.code,
          message:
            verify.code === 'UPLOAD_SIGNATURE_EXPIRED'
              ? 'Signed playback URL has expired'
              : 'Invalid playback HMAC signature',
        });
        return;
      }

      const assetData = await store.withTenantContext(tenant.id, async () => {
        const video = await store.getVideoById(videoId);
        if (!video || video.portalId !== portalId || video.objectKey !== objectKey) {
          return null;
        }
        if (video.status !== 'READY') {
          return { video, payload: null, notReady: true as const };
        }
        const payload = store.readAssembledVideoBytes
          ? await store.readAssembledVideoBytes(video.id)
          : null;
        return { video, payload, notReady: false as const };
      });

      if (!assetData) {
        res.status(404).json({ error: 'VIDEO_NOT_FOUND', message: 'Video asset not found' });
        return;
      }
      if (assetData.notReady) {
        res.status(409).json({ error: 'VIDEO_NOT_READY', message: 'Video is not ready for playback' });
        return;
      }
      if (!assetData.payload) {
        res.status(501).json({
          error: 'EXTERNAL_OBJECT_STORAGE_REQUIRED',
          message: 'Binary streaming is handled by S3/R2 in postgres storage mode',
        });
        return;
      }

      const total = assetData.payload.length;
      res.setHeader('Accept-Ranges', 'bytes');
      res.setHeader('Content-Type', assetData.video.contentType);
      res.setHeader('Cache-Control', 'private, no-store');
      res.setHeader('X-Collabify-Object-Key', assetData.video.objectKey);
      if (assetData.video.manifestSha256) {
        res.setHeader('X-Collabify-Manifest-Sha256', assetData.video.manifestSha256);
      }

      const rangeHeader = req.headers.range;
      if (typeof rangeHeader === 'string' && rangeHeader.startsWith('bytes=')) {
        const match = /^bytes=(\d+)-(\d*)$/.exec(rangeHeader.trim());
        if (!match) {
          res.status(416).setHeader('Content-Range', `bytes */${total}`).end();
          return;
        }
        const start = Number(match[1]);
        const end = match[2] ? Math.min(Number(match[2]), total - 1) : total - 1;
        if (!Number.isInteger(start) || !Number.isInteger(end) || start > end || start >= total) {
          res.status(416).setHeader('Content-Range', `bytes */${total}`).end();
          return;
        }
        const slice = assetData.payload.subarray(start, end + 1);
        res.status(206);
        res.setHeader('Content-Range', `bytes ${start}-${end}/${total}`);
        res.setHeader('Content-Length', String(slice.length));
        res.send(slice);
        return;
      }

      res.status(200);
      res.setHeader('Content-Length', String(total));
      res.send(assetData.payload);
    } catch (err) {
      next(err);
    }
  });

  return router;
}

export function createMultipartUploadRouter(
  store: AppStore,
  config: AppConfig,
  presigner: MultipartStoragePresigner,
): Router {
  const router = Router();
  const authenticate = createAuthMiddleware(config);

  const initUploadSchema = z.object({
    filename: z.string().min(1).max(255),
    contentType: z.string().refine((v) => ALLOWED_VIDEO_MIME_TYPES.has(v), {
      message: `Unsupported contentType. Allowed: ${Array.from(ALLOWED_VIDEO_MIME_TYPES).join(', ')}`,
    }),
    sizeBytes: z.number().int().positive().max(config.maxVideoSizeBytes),
    partCount: z.number().int().min(1).max(10_000),
  });

  const completeUploadSchema = z.object({
    parts: z
      .array(
        z.object({
          partNumber: z.number().int().min(1).max(10_000),
          etag: z.string().min(8).max(128),
        }),
      )
      .min(1),
  });

  /**
   * Step 1: Initiate multipart video upload (Agency Admin only).
   * Validates MIME/size limits (up to 10GB), issues tenant-isolated object key
   * `tenants/{tenantId}/portals/{portalId}/videos/{videoId}/{sanitizedName}`,
   * and returns HMAC/S3-signed part upload URLs.
   */
  router.post(
    '/portals/:portalId/videos/init',
    authenticate,
    requireAgencyAdmin(),
    async (req, res, next) => {
      try {
        const tenant = req.tenant!;
        const principal = req.principal!;
        const portalId = String(req.params.portalId);

        const parsed = initUploadSchema.safeParse(req.body);
        if (!parsed.success) {
          res.status(400).json({ error: 'VALIDATION_ERROR', details: parsed.error.flatten() });
          return;
        }

        const videoId = crypto.randomUUID();
        const uploadId = `upl_${crypto.randomBytes(16).toString('hex')}`;
        const objectKey = presigner.buildTenantObjectKey(
          tenant.id,
          portalId,
          videoId,
          parsed.data.filename,
        );

        const asset = await store.withTenantContext(tenant.id, async () => {
          const portal = await store.getPortalById(portalId);
          if (!portal) return null;

          const created = await store.createVideoAsset({
            id: videoId,
            tenantId: tenant.id,
            portalId: portal.id,
            uploadId,
            filename: parsed.data.filename,
            objectKey,
            contentType: parsed.data.contentType,
            sizeBytes: parsed.data.sizeBytes,
            expectedPartCount: parsed.data.partCount,
          });

          await store.appendAuditEvent({
            tenantId: tenant.id,
            actorKind: 'agency_admin',
            actorId: principal.sub,
            action: 'video.upload_initiated',
            resourceType: 'video_asset',
            resourceId: created.id,
            metadata: {
              portalId: portal.id,
              objectKey,
              sizeBytes: created.sizeBytes,
              expectedPartCount: created.expectedPartCount,
            },
          });

          return created;
        });

        if (!asset) {
          res.status(404).json({ error: 'PORTAL_NOT_FOUND', message: 'Client portal not found' });
          return;
        }

        const partUrls = Array.from({ length: asset.expectedPartCount }, (_, idx) =>
          presigner.signPartUploadUrl({
            uploadId: asset.uploadId,
            partNumber: idx + 1,
            tenantId: tenant.id,
            objectKey: asset.objectKey,
            ttlSeconds: config.partSignTtlSeconds,
          }),
        );

        res.status(201).json({
          videoId: asset.id,
          uploadId: asset.uploadId,
          objectKey: asset.objectKey,
          status: asset.status,
          presignerMode: presigner.mode,
          partUrls,
        });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * Step 2b: Resumable upload status & missing-part URL re-signing (Agency Admin only).
   * After a network drop or browser reload, the client queries landed parts and receives
   * fresh signed upload URLs ONLY for missing parts — never re-uploading landed gigabytes.
   */
  router.get(
    '/portals/:portalId/videos/:videoId/upload-status',
    authenticate,
    requireAgencyAdmin(),
    async (req, res, next) => {
      try {
        const tenant = req.tenant!;
        const portalId = String(req.params.portalId);
        const videoId = String(req.params.videoId);

        const state = await store.withTenantContext(tenant.id, async () => {
          const video = await store.getVideoById(videoId);
          if (!video || video.portalId !== portalId) return null;
          const uploadedParts = await store.listVideoUploadParts(video.id);
          return { video, uploadedParts };
        });

        if (!state) {
          res.status(404).json({ error: 'VIDEO_NOT_FOUND', message: 'Video upload not found' });
          return;
        }

        const landedSet = new Set(state.uploadedParts.map((p) => p.partNumber));
        const missingPartNumbers: number[] = [];
        for (let i = 1; i <= state.video.expectedPartCount; i++) {
          if (!landedSet.has(i)) missingPartNumbers.push(i);
        }

        const uploadedBytes = state.uploadedParts.reduce((sum, p) => sum + p.sizeBytes, 0);
        const resumePartUrls =
          state.video.status === 'UPLOADING'
            ? missingPartNumbers.map((partNumber) =>
                presigner.signPartUploadUrl({
                  uploadId: state.video.uploadId,
                  partNumber,
                  tenantId: tenant.id,
                  objectKey: state.video.objectKey,
                  ttlSeconds: config.partSignTtlSeconds,
                }),
              )
            : [];

        res.status(200).json({
          videoId: state.video.id,
          uploadId: state.video.uploadId,
          objectKey: state.video.objectKey,
          status: state.video.status,
          sizeBytes: state.video.sizeBytes,
          expectedPartCount: state.video.expectedPartCount,
          uploadedBytes,
          remainingBytes: Math.max(0, state.video.sizeBytes - uploadedBytes),
          uploadedParts: state.uploadedParts.map((p) => ({
            partNumber: p.partNumber,
            sizeBytes: p.sizeBytes,
            etag: p.etag,
            sha256: p.sha256,
          })),
          missingPartNumbers,
          resumePartUrls,
        });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * Step 3: Complete multipart upload (Agency Admin only).
   * Verifies upload is active, every expected part 1..N is present in order with matching
   * server-computed SHA-256 ETags and exact total byte size, computes manifest digest,
   * transitions status -> READY, and appends an audit event.
   */
  router.post(
    '/portals/:portalId/videos/:videoId/complete',
    authenticate,
    requireAgencyAdmin(),
    async (req, res, next) => {
      try {
        const tenant = req.tenant!;
        const principal = req.principal!;
        const portalId = String(req.params.portalId);
        const videoId = String(req.params.videoId);

        const parsed = completeUploadSchema.safeParse(req.body);
        if (!parsed.success) {
          res.status(400).json({ error: 'VALIDATION_ERROR', details: parsed.error.flatten() });
          return;
        }

        const result = await store.withTenantContext(tenant.id, async () => {
          const video = await store.getVideoById(videoId);
          if (!video || video.portalId !== portalId) {
            return { status: 404 as const, error: 'VIDEO_NOT_FOUND', message: 'Video not found' };
          }
          if (video.status !== 'UPLOADING') {
            return {
              status: 409 as const,
              error: 'UPLOAD_ALREADY_COMPLETED',
              message: `Upload is already in terminal state: ${video.status}`,
            };
          }

          const storedParts = await store.listVideoUploadParts(video.id);
          if (
            parsed.data.parts.length !== video.expectedPartCount ||
            storedParts.length !== video.expectedPartCount
          ) {
            return {
              status: 400 as const,
              error: 'INCOMPLETE_PARTS',
              message: `Expected ${video.expectedPartCount} uploaded parts, received ${storedParts.length}`,
            };
          }

          const storedByNum = new Map(storedParts.map((p) => [p.partNumber, p]));
          const canonicalLines: string[] = [];
          let totalUploadedBytes = 0;

          for (let i = 1; i <= video.expectedPartCount; i++) {
            const clientPart = parsed.data.parts[i - 1];
            const storedPart = storedByNum.get(i);
            if (!clientPart || clientPart.partNumber !== i || !storedPart) {
              return {
                status: 400 as const,
                error: 'PART_ORDER_MISMATCH',
                message: `Parts must be strictly contiguous 1..${video.expectedPartCount}`,
              };
            }

            const cleanClientEtag = clientPart.etag.replace(/^"|"$/g, '').toLowerCase();
            if (cleanClientEtag !== storedPart.etag.toLowerCase()) {
              return {
                status: 400 as const,
                error: 'ETAG_MISMATCH',
                message: `ETag mismatch on part ${i}`,
              };
            }
            totalUploadedBytes += storedPart.sizeBytes;
            canonicalLines.push(`${i}:${storedPart.etag}`);
          }

          if (totalUploadedBytes !== video.sizeBytes) {
            return {
              status: 400 as const,
              error: 'SIZE_MISMATCH',
              message: `Uploaded byte sum (${totalUploadedBytes}) does not match declared sizeBytes (${video.sizeBytes})`,
            };
          }

          const manifestSha256 = crypto
            .createHash('sha256')
            .update(canonicalLines.join('|'))
            .digest('hex');

          const updated = await store.completeVideoAsset(video.id, manifestSha256);
          if (!updated) {
            return { status: 404 as const, error: 'VIDEO_NOT_FOUND', message: 'Video not found' };
          }

          await store.appendAuditEvent({
            tenantId: tenant.id,
            actorKind: 'agency_admin',
            actorId: principal.sub,
            action: 'video.upload_completed',
            resourceType: 'video_asset',
            resourceId: updated.id,
            metadata: {
              portalId,
              partCount: storedParts.length,
              totalUploadedBytes,
              manifestSha256,
              objectKey: updated.objectKey,
            },
          });

          return { status: 200 as const, video: updated, parts: storedParts };
        });

        if (result.status !== 200) {
          res.status(result.status).json({ error: result.error, message: result.message });
          return;
        }

        res.status(200).json({
          video: result.video,
          verifiedPartCount: result.parts.length,
          manifestSha256: result.video.manifestSha256,
        });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * Authorized playback URL endpoint (Agency Admin OR Client Guest scoped to this portal).
   */
  router.get(
    '/portals/:portalId/videos/:videoId/playback',
    authenticate,
    requirePortalAccess('video:read'),
    async (req, res, next) => {
      try {
        const tenant = req.tenant!;
        const portalId = String(req.params.portalId);
        const videoId = String(req.params.videoId);

        const video = await store.withTenantContext(tenant.id, async () => {
          const found = await store.getVideoById(videoId);
          if (!found || found.portalId !== portalId) return null;
          return found;
        });

        if (!video) {
          res.status(404).json({ error: 'VIDEO_NOT_FOUND', message: 'Video asset not found' });
          return;
        }
        if (video.status !== 'READY') {
          res.status(409).json({
            error: 'VIDEO_NOT_READY',
            message: `Video status is ${video.status}; playback requires READY`,
          });
          return;
        }

        const signed = presigner.signPlaybackUrl({
          tenantId: tenant.id,
          portalId,
          videoId: video.id,
          objectKey: video.objectKey,
          ttlSeconds: config.playbackSignTtlSeconds,
        });

        res.status(200).json({
          videoId: video.id,
          objectKey: video.objectKey,
          playbackUrl: signed.url,
          expiresAt: signed.expiresAt,
        });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * Client deliverable approval (Agency Admin OR Portal Guest with `video:approve` scope).
   */
  router.post(
    '/portals/:portalId/videos/:videoId/approve',
    authenticate,
    requirePortalAccess('video:approve'),
    async (req, res, next) => {
      try {
        const tenant = req.tenant!;
        const principal = req.principal!;
        const portalId = String(req.params.portalId);
        const videoId = String(req.params.videoId);
        const approvedAt = new Date().toISOString();

        const updated = await store.withTenantContext(tenant.id, async () => {
          const existing = await store.getVideoById(videoId);
          if (!existing || existing.portalId !== portalId) return null;

          const approved = await store.approveVideoAsset(videoId, principal.email, approvedAt);
          if (!approved) return null;

          await store.appendAuditEvent({
            tenantId: tenant.id,
            actorKind: principal.kind,
            actorId: principal.sub,
            action: 'video.approved',
            resourceType: 'video_asset',
            resourceId: approved.id,
            metadata: { portalId, approvedByEmail: principal.email },
          });
          return approved;
        });

        if (!updated) {
          res.status(404).json({ error: 'VIDEO_NOT_FOUND', message: 'Video asset not found' });
          return;
        }

        res.status(200).json({ video: updated });
      } catch (err) {
        next(err);
      }
    },
  );

  return router;
}
