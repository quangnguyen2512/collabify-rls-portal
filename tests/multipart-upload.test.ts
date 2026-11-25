import crypto from 'node:crypto';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/server/app.js';
import { loadConfig } from '../src/server/config.js';
import { DEMO_ADMIN_PASSWORD, MemoryRlsStore, SEED_IDS } from '../src/server/db/memoryStore.js';
import { sanitizeFilename } from '../src/server/uploads/presigner.js';

function sha256Hex(buf: Buffer): string {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

describe('Resumable Multipart Video Upload Engine', () => {
  async function setupAuthenticatedAcme() {
    const config = loadConfig({ NODE_ENV: 'test', BASE_DOMAIN: 'collabify.local' });
    const ctx = createApp({ store: new MemoryRlsStore(true), config });

    const loginRes = await request(ctx.app)
      .post('/api/auth/agency/login')
      .set('Host', 'acme.collabify.local')
      .send({ email: 'alice@acme.studio', password: DEMO_ADMIN_PASSWORD });

    return { ...ctx, acmeToken: loginRes.body.token as string };
  }

  it('sanitizes filenames against path traversal while isolating object keys per tenant/portal/video', () => {
    expect(sanitizeFilename('../../etc/passwd')).toBe('passwd');
    expect(sanitizeFilename('Q4 Final Cut (4K)!.mp4')).toBe('Q4_Final_Cut__4K__.mp4');
  });

  it('completes full 3-chunk upload lifecycle with SHA-256 verification, audit events, and playback auth', async () => {
    const { app, acmeToken } = await setupAuthenticatedAcme();

    const chunks = [
      Buffer.from('chunk-1-prores-video-header-bytes-0001'),
      Buffer.from('chunk-2-prores-video-frames-bytes-0002'),
      Buffer.from('chunk-3-prores-video-trailer-bytes-0003'),
    ];
    const totalSize = chunks.reduce((sum, c) => sum + c.length, 0);

    // 1. Init multipart upload
    const initRes = await request(app)
      .post(`/api/portals/${SEED_IDS.portals.acmeLaunch}/videos/init`)
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${acmeToken}`)
      .send({
        filename: '../secret/hero_launch_4k.mp4',
        contentType: 'video/mp4',
        sizeBytes: totalSize,
        partCount: chunks.length,
      });

    expect(initRes.status).toBe(201);
    const { videoId, uploadId, objectKey, partUrls } = initRes.body as {
      videoId: string;
      uploadId: string;
      objectKey: string;
      partUrls: Array<{ partNumber: number; url: string }>;
    };

    expect(objectKey).toBe(
      `tenants/${SEED_IDS.tenants.acme}/portals/${SEED_IDS.portals.acmeLaunch}/videos/${videoId}/hero_launch_4k.mp4`,
    );
    expect(partUrls).toHaveLength(3);

    // Playback before READY is rejected with 409
    const earlyPlayback = await request(app)
      .get(`/api/portals/${SEED_IDS.portals.acmeLaunch}/videos/${videoId}/playback`)
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${acmeToken}`);
    expect(earlyPlayback.status).toBe(409);

    // 2. Upload all 3 chunks with client-supplied X-Content-Sha256
    const completedParts: Array<{ partNumber: number; etag: string }> = [];
    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i]!;
      const expectedHash = sha256Hex(chunk);
      const putRes = await request(app)
        .put(partUrls[i]!.url)
        .set('Host', 'acme.collabify.local')
        .set('Content-Type', 'application/octet-stream')
        .set('X-Content-Sha256', expectedHash)
        .send(chunk);

      expect(putRes.status).toBe(200);
      expect(putRes.body.sha256).toBe(expectedHash);
      expect(putRes.body.etag).toBe(expectedHash);
      completedParts.push({ partNumber: i + 1, etag: putRes.body.etag });
    }

    // 3. Complete multipart upload -> verifies ordered ETags & computes manifest SHA-256
    const completeRes = await request(app)
      .post(`/api/portals/${SEED_IDS.portals.acmeLaunch}/videos/${videoId}/complete`)
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${acmeToken}`)
      .send({ parts: completedParts });

    expect(completeRes.status).toBe(200);
    expect(completeRes.body.video.status).toBe('READY');
    expect(completeRes.body.verifiedPartCount).toBe(3);

    const expectedManifest = sha256Hex(
      Buffer.from(completedParts.map((p) => `${p.partNumber}:${p.etag}`).join('|')),
    );
    expect(completeRes.body.manifestSha256).toBe(expectedManifest);

    // 4. Playback URL now authorized for Acme
    const playbackRes = await request(app)
      .get(`/api/portals/${SEED_IDS.portals.acmeLaunch}/videos/${videoId}/playback`)
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${acmeToken}`);
    expect(playbackRes.status).toBe(200);
    expect(playbackRes.body.playbackUrl).toContain(`key=${encodeURIComponent(objectKey)}`);

    // 5. Audit log recorded upload lifecycle under tenant RLS
    const auditRes = await request(app)
      .get('/api/audit-events')
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${acmeToken}`);
    expect(auditRes.status).toBe(200);
    const actions = (auditRes.body.events as Array<{ action: string }>).map((e) => e.action);
    expect(actions).toContain('video.upload_initiated');
    expect(actions).toContain('video.upload_completed');
    expect(uploadId).toMatch(/^upl_/);
  });

  it('rejects tampered/expired HMAC part signatures, cross-tenant replay, checksum tampering, and invalid ETags', async () => {
    const { app, acmeToken } = await setupAuthenticatedAcme();

    // Reject disallowed MIME & > 10 GiB size
    const badMime = await request(app)
      .post(`/api/portals/${SEED_IDS.portals.acmeLaunch}/videos/init`)
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${acmeToken}`)
      .send({
        filename: 'malware.exe',
        contentType: 'application/x-msdownload',
        sizeBytes: 1024,
        partCount: 1,
      });
    expect(badMime.status).toBe(400);

    const tooLarge = await request(app)
      .post(`/api/portals/${SEED_IDS.portals.acmeLaunch}/videos/init`)
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${acmeToken}`)
      .send({
        filename: 'too_big.mp4',
        contentType: 'video/mp4',
        sizeBytes: 10 * 1024 * 1024 * 1024 + 1,
        partCount: 100,
      });
    expect(tooLarge.status).toBe(400);

    // Init valid 1-part upload
    const initRes = await request(app)
      .post(`/api/portals/${SEED_IDS.portals.acmeLaunch}/videos/init`)
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${acmeToken}`)
      .send({
        filename: 'verify_security.mp4',
        contentType: 'video/mp4',
        sizeBytes: 128,
        partCount: 1,
      });
    expect(initRes.status).toBe(201);
    const partUrl: string = initRes.body.partUrls[0].url;
    const videoId: string = initRes.body.videoId;

    // 1. Tampered signature -> 403 INVALID_UPLOAD_SIGNATURE
    const tamperedSigUrl = partUrl.replace(/sig=[0-9a-f]+/, `sig=${'0'.repeat(64)}`);
    const tamperedRes = await request(app)
      .put(tamperedSigUrl)
      .set('Host', 'acme.collabify.local')
      .set('Content-Type', 'application/octet-stream')
      .send(Buffer.from('payload'));
    expect(tamperedRes.status).toBe(403);
    expect(tamperedRes.body.error).toBe('INVALID_UPLOAD_SIGNATURE');

    // 2. Expired signature -> 403 UPLOAD_SIGNATURE_EXPIRED
    const expiredUrl = partUrl.replace(/exp=\d+/, 'exp=1000000000');
    const expiredRes = await request(app)
      .put(expiredUrl)
      .set('Host', 'acme.collabify.local')
      .set('Content-Type', 'application/octet-stream')
      .send(Buffer.from('payload'));
    expect(expiredRes.status).toBe(403);
    expect(expiredRes.body.error).toBe('UPLOAD_SIGNATURE_EXPIRED');

    // 3. Cross-tenant replay (Acme upload URL sent to Velvet host) -> 403 TENANT_MISMATCH
    const crossTenantPart = await request(app)
      .put(partUrl)
      .set('Host', 'velvet.collabify.local')
      .set('Content-Type', 'application/octet-stream')
      .send(Buffer.from('payload'));
    expect(crossTenantPart.status).toBe(403);
    expect(crossTenantPart.body.error).toBe('TENANT_MISMATCH');

    // 4. Client checksum mismatch -> 400 CHECKSUM_MISMATCH
    const badChecksum = await request(app)
      .put(partUrl)
      .set('Host', 'acme.collabify.local')
      .set('Content-Type', 'application/octet-stream')
      .set('X-Content-Sha256', 'f'.repeat(64))
      .send(Buffer.from('authentic-bytes'));
    expect(badChecksum.status).toBe(400);
    expect(badChecksum.body.error).toBe('CHECKSUM_MISMATCH');

    // 5. Upload authentic chunk, then try completing with wrong ETag -> 400 ETAG_MISMATCH
    const okPut = await request(app)
      .put(partUrl)
      .set('Host', 'acme.collabify.local')
      .set('Content-Type', 'application/octet-stream')
      .send(Buffer.from('authentic-bytes'));
    expect(okPut.status).toBe(200);

    const badComplete = await request(app)
      .post(`/api/portals/${SEED_IDS.portals.acmeLaunch}/videos/${videoId}/complete`)
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${acmeToken}`)
      .send({ parts: [{ partNumber: 1, etag: '0'.repeat(64) }] });
    expect(badComplete.status).toBe(400);
    expect(badComplete.body.error).toBe('ETAG_MISMATCH');

    // 6. Valid ETag but uploaded bytes (15B) != declared sizeBytes (128B) -> 400 SIZE_MISMATCH
    const sizeMismatchComplete = await request(app)
      .post(`/api/portals/${SEED_IDS.portals.acmeLaunch}/videos/${videoId}/complete`)
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${acmeToken}`)
      .send({ parts: [{ partNumber: 1, etag: okPut.body.etag }] });
    expect(sizeMismatchComplete.status).toBe(400);
    expect(sizeMismatchComplete.body.error).toBe('SIZE_MISMATCH');
  });

  it('supports resumable upload recovery (/upload-status), prevents double-complete (409), and streams signed HTTP 206 Range slices', async () => {
    const { app, acmeToken } = await setupAuthenticatedAcme();

    const chunks = [
      Buffer.from('PART1-HEADER-BYTES-0123456789'),
      Buffer.from('PART2-MIDDLE-BYTES-ABCDEFGHIJ'),
      Buffer.from('PART3-RESUME-BYTES-KLMNOPQRST'),
      Buffer.from('PART4-TRAIL--BYTES-UVWXYZ9876'),
    ];
    const assembled = Buffer.concat(chunks);

    const initRes = await request(app)
      .post(`/api/portals/${SEED_IDS.portals.acmeLaunch}/videos/init`)
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${acmeToken}`)
      .send({
        filename: 'resumable_4k_cut.mp4',
        contentType: 'video/mp4',
        sizeBytes: assembled.length,
        partCount: chunks.length,
      });
    expect(initRes.status).toBe(201);
    const { videoId, partUrls } = initRes.body as {
      videoId: string;
      partUrls: Array<{ partNumber: number; url: string }>;
    };

    // Upload only parts 1 & 2 before simulating a network drop
    for (const partIdx of [0, 1]) {
      const put = await request(app)
        .put(partUrls[partIdx]!.url)
        .set('Host', 'acme.collabify.local')
        .set('Content-Type', 'application/octet-stream')
        .set('X-Content-Sha256', sha256Hex(chunks[partIdx]!))
        .send(chunks[partIdx]!);
      expect(put.status).toBe(200);
    }

    // Query /upload-status -> must report landed [1,2] and re-sign ONLY missing [3,4]
    const statusRes = await request(app)
      .get(`/api/portals/${SEED_IDS.portals.acmeLaunch}/videos/${videoId}/upload-status`)
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${acmeToken}`);
    expect(statusRes.status).toBe(200);
    expect(statusRes.body.missingPartNumbers).toEqual([3, 4]);
    expect(statusRes.body.uploadedParts.map((p: { partNumber: number }) => p.partNumber)).toEqual([
      1, 2,
    ]);
    expect(statusRes.body.resumePartUrls).toHaveLength(2);

    // Resume ONLY missing parts 3 & 4 using the newly issued resumePartUrls
    const allParts: Array<{ partNumber: number; etag: string }> = statusRes.body.uploadedParts.map(
      (p: { partNumber: number; etag: string }) => ({ partNumber: p.partNumber, etag: p.etag }),
    );
    for (const resumePart of statusRes.body.resumePartUrls as Array<{
      partNumber: number;
      url: string;
    }>) {
      const chunk = chunks[resumePart.partNumber - 1]!;
      const put = await request(app)
        .put(resumePart.url)
        .set('Host', 'acme.collabify.local')
        .set('Content-Type', 'application/octet-stream')
        .set('X-Content-Sha256', sha256Hex(chunk))
        .send(chunk);
      expect(put.status).toBe(200);
      allParts.push({ partNumber: resumePart.partNumber, etag: put.body.etag });
    }
    allParts.sort((a, b) => a.partNumber - b.partNumber);

    // Complete upload
    const completeRes = await request(app)
      .post(`/api/portals/${SEED_IDS.portals.acmeLaunch}/videos/${videoId}/complete`)
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${acmeToken}`)
      .send({ parts: allParts });
    expect(completeRes.status).toBe(200);
    expect(completeRes.body.video.status).toBe('READY');

    // Double-complete rejected with 409 UPLOAD_ALREADY_COMPLETED
    const doubleComplete = await request(app)
      .post(`/api/portals/${SEED_IDS.portals.acmeLaunch}/videos/${videoId}/complete`)
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${acmeToken}`)
      .send({ parts: allParts });
    expect(doubleComplete.status).toBe(409);
    expect(doubleComplete.body.error).toBe('UPLOAD_ALREADY_COMPLETED');

    // Fetch signed playback URL and verify live 206 Partial Content byte-range streaming
    const playbackRes = await request(app)
      .get(`/api/portals/${SEED_IDS.portals.acmeLaunch}/videos/${videoId}/playback`)
      .set('Host', 'acme.collabify.local')
      .set('Authorization', `Bearer ${acmeToken}`);
    expect(playbackRes.status).toBe(200);
    const playbackUrl: string = playbackRes.body.playbackUrl;

    const rangeRes = await request(app)
      .get(playbackUrl)
      .set('Host', 'acme.collabify.local')
      .set('Range', 'bytes=0-19')
      .buffer(true)
      .parse((res, cb) => {
        const data: Buffer[] = [];
        res.on('data', (chunk: Buffer) => data.push(chunk));
        res.on('end', () => cb(null, Buffer.concat(data)));
      });
    expect(rangeRes.status).toBe(206);
    expect(rangeRes.headers['content-range']).toBe(`bytes 0-19/${assembled.length}`);
    expect(rangeRes.headers['x-collabify-manifest-sha256']).toBe(completeRes.body.manifestSha256);
    expect((rangeRes.body as Buffer).toString('utf8')).toBe(
      assembled.subarray(0, 20).toString('utf8'),
    );

    // Cross-tenant replay of signed playback URL on Velvet -> 403 TENANT_MISMATCH
    const crossTenantStream = await request(app)
      .get(playbackUrl)
      .set('Host', 'velvet.collabify.local');
    expect(crossTenantStream.status).toBe(403);
    expect(crossTenantStream.body.error).toBe('TENANT_MISMATCH');

    // Tampered playback signature -> 403 INVALID_UPLOAD_SIGNATURE
    const tamperedPlayback = await request(app)
      .get(playbackUrl.replace(/sig=[0-9a-f]+/, `sig=${'0'.repeat(64)}`))
      .set('Host', 'acme.collabify.local');
    expect(tamperedPlayback.status).toBe(403);
    expect(tamperedPlayback.body.error).toBe('INVALID_UPLOAD_SIGNATURE');
  });
});
