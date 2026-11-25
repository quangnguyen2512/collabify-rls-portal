import crypto from 'node:crypto';

export interface SignedPartUrl {
  partNumber: number;
  url: string;
  expiresAt: string;
}

export interface VerifyPartSignatureInput {
  uploadId: string;
  partNumber: number;
  tenantId: string;
  expiresAtUnix: number;
  signature: string;
  nowUnix?: number;
}

export interface VerifyPlaybackSignatureInput {
  tenantId: string;
  portalId: string;
  videoId: string;
  objectKey: string;
  expiresAtUnix: number;
  signature: string;
  nowUnix?: number;
}

export type VerifySignatureResult =
  | { ok: true }
  | { ok: false; code: 'UPLOAD_SIGNATURE_EXPIRED' | 'INVALID_UPLOAD_SIGNATURE' };

/**
 * Pluggable object-storage presigner interface.
 * - Demo/Local mode: `LocalHmacPresigner` signs chunk upload URLs routed to Express `PUT /api/uploads/:uploadId/parts/:partNumber`.
 * - Production mode: `S3MultipartPresigner` issues direct S3 / Cloudflare R2 presigned `UploadPart` URLs so multi-GB video bytes never traverse Node.js RAM.
 */
export interface MultipartStoragePresigner {
  readonly mode: 'local_hmac' | 's3_r2';
  buildTenantObjectKey(tenantId: string, portalId: string, videoId: string, filename: string): string;
  signPartUploadUrl(params: {
    uploadId: string;
    partNumber: number;
    tenantId: string;
    objectKey: string;
    ttlSeconds: number;
  }): SignedPartUrl;
  verifyPartUploadSignature(input: VerifyPartSignatureInput): VerifySignatureResult;
  signPlaybackUrl(params: {
    tenantId: string;
    portalId: string;
    videoId: string;
    objectKey: string;
    ttlSeconds: number;
  }): { url: string; expiresAt: string };
  verifyPlaybackSignature(input: VerifyPlaybackSignatureInput): VerifySignatureResult;
}

export function sanitizeFilename(rawName: string): string {
  const base = rawName.split(/[\\/]/).pop() ?? 'video.mp4';
  const cleaned = base
    .replace(/\0/g, '')
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .replace(/^\.+/, '')
    .slice(0, 120);
  return cleaned || 'video.mp4';
}

export function buildTenantObjectKey(
  tenantId: string,
  portalId: string,
  videoId: string,
  filename: string,
): string {
  const safeName = sanitizeFilename(filename);
  return `tenants/${tenantId}/portals/${portalId}/videos/${videoId}/${safeName}`;
}

export class LocalHmacPresigner implements MultipartStoragePresigner {
  public readonly mode = 'local_hmac' as const;

  constructor(private readonly signingSecret: string) {}

  buildTenantObjectKey(
    tenantId: string,
    portalId: string,
    videoId: string,
    filename: string,
  ): string {
    return buildTenantObjectKey(tenantId, portalId, videoId, filename);
  }

  private computePartHmac(uploadId: string, partNumber: number, tenantId: string, exp: number): string {
    const canonical = `PUT:${uploadId}:${partNumber}:${tenantId}:${exp}`;
    return crypto.createHmac('sha256', this.signingSecret).update(canonical).digest('hex');
  }

  signPartUploadUrl(params: {
    uploadId: string;
    partNumber: number;
    tenantId: string;
    objectKey: string;
    ttlSeconds: number;
  }): SignedPartUrl {
    const exp = Math.floor(Date.now() / 1000) + params.ttlSeconds;
    const sig = this.computePartHmac(params.uploadId, params.partNumber, params.tenantId, exp);
    const query = new URLSearchParams({
      tenantId: params.tenantId,
      exp: String(exp),
      sig,
    });

    return {
      partNumber: params.partNumber,
      url: `/api/uploads/${encodeURIComponent(params.uploadId)}/parts/${params.partNumber}?${query.toString()}`,
      expiresAt: new Date(exp * 1000).toISOString(),
    };
  }

  verifyPartUploadSignature(input: VerifyPartSignatureInput): VerifySignatureResult {
    const nowUnix = input.nowUnix ?? Math.floor(Date.now() / 1000);
    if (!Number.isFinite(input.expiresAtUnix) || input.expiresAtUnix <= nowUnix) {
      return { ok: false, code: 'UPLOAD_SIGNATURE_EXPIRED' };
    }

    const expectedHex = this.computePartHmac(
      input.uploadId,
      input.partNumber,
      input.tenantId,
      input.expiresAtUnix,
    );

    const expectedBuf = Buffer.from(expectedHex, 'hex');
    const providedBuf = Buffer.from(input.signature, 'hex');

    if (
      expectedBuf.length !== providedBuf.length ||
      !crypto.timingSafeEqual(expectedBuf, providedBuf)
    ) {
      return { ok: false, code: 'INVALID_UPLOAD_SIGNATURE' };
    }

    return { ok: true };
  }

  private computePlaybackHmac(
    tenantId: string,
    portalId: string,
    videoId: string,
    objectKey: string,
    exp: number,
  ): string {
    const canonical = `GET:${tenantId}:${portalId}:${videoId}:${objectKey}:${exp}`;
    return crypto.createHmac('sha256', this.signingSecret).update(canonical).digest('hex');
  }

  signPlaybackUrl(params: {
    tenantId: string;
    portalId: string;
    videoId: string;
    objectKey: string;
    ttlSeconds: number;
  }): { url: string; expiresAt: string } {
    const exp = Math.floor(Date.now() / 1000) + params.ttlSeconds;
    const sig = this.computePlaybackHmac(
      params.tenantId,
      params.portalId,
      params.videoId,
      params.objectKey,
      exp,
    );

    const query = new URLSearchParams({
      tenantId: params.tenantId,
      portalId: params.portalId,
      key: params.objectKey,
      exp: String(exp),
      sig,
    });
    return {
      url: `/api/uploads/stream/${encodeURIComponent(params.videoId)}?${query.toString()}`,
      expiresAt: new Date(exp * 1000).toISOString(),
    };
  }

  verifyPlaybackSignature(input: VerifyPlaybackSignatureInput): VerifySignatureResult {
    const nowUnix = input.nowUnix ?? Math.floor(Date.now() / 1000);
    if (!Number.isFinite(input.expiresAtUnix) || input.expiresAtUnix <= nowUnix) {
      return { ok: false, code: 'UPLOAD_SIGNATURE_EXPIRED' };
    }

    const expectedHex = this.computePlaybackHmac(
      input.tenantId,
      input.portalId,
      input.videoId,
      input.objectKey,
      input.expiresAtUnix,
    );
    const expectedBuf = Buffer.from(expectedHex, 'hex');
    const providedBuf = Buffer.from(input.signature, 'hex');

    if (
      expectedBuf.length !== providedBuf.length ||
      !crypto.timingSafeEqual(expectedBuf, providedBuf)
    ) {
      return { ok: false, code: 'INVALID_UPLOAD_SIGNATURE' };
    }

    return { ok: true };
  }
}

/**
 * Production S3 / Cloudflare R2 presigner configuration contract.
 * Swap in `@aws-sdk/client-s3` + `@aws-sdk/s3-request-presigner` (`UploadPartCommand`,
 * `ChecksumAlgorithm: 'SHA256'`) without changing any API routes or DB RLS layers.
 */
export interface S3PresignerConfig {
  bucket: string;
  region: string;
  endpoint?: string;
  accessKeyId: string;
  secretAccessKey: string;
}
