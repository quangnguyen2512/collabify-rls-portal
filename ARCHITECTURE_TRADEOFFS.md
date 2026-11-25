# Collabify Architecture Trade-Offs

Concise staff-level engineering notes on the four foundational design choices in Collabify.

---

## 1. Multi-Tenancy Model: Shared Schema + RLS vs Schema-per-Tenant vs DB-per-Tenant

| Dimension | Shared Schema + PostgreSQL RLS (Chosen Default) | Schema-per-Tenant | Database-per-Tenant |
| :--- | :--- | :--- | :--- |
| **Schema Migrations** | O(1) — single transactional DDL run | O(N) — partial failures & version drift across 1,000+ tenants | O(N) + orchestrator complexity |
| **Connection Pooling** | Single PgBouncer pool shared across all tenants | Pool fragmentation (`search_path` switching) | Separate pools per DB; expensive idle RAM |
| **Blast Radius / Isolation** | Strong **if** `NOBYPASSRLS` + `FORCE RLS` + composite FKs + CI negative tests | Medium (still shared superuser/catalog unless strict grants) | Strongest physical isolation |
| **Operational Cost at 10–5,000 Agencies** | Lowest; scales vertically + read replicas cleanly | Catalog bloat (`pg_class` / `pg_attribute`) degrades planning >1k schemas | High baseline $/tenant |
| **Noisy Neighbor / Enterprise Compliance** | Needs query timeouts, per-tenant rate limits, leading `tenant_id` indexes | Same Postgres instance unless sharded | Native per-tenant backups & residency |

### Why Shared Schema + RLS Wins for Collabify (with an Escape Hatch)
Agencies on Collabify range from solo freelancers to 50-person studios — thousands of small-to-medium tenants with spiky video-review traffic. Shared Schema + RLS gives O(1) migrations and high connection density while making a missing `WHERE tenant_id = $1` clause **non-catastrophic**.

**Five non-negotiable guardrails implemented in this repo:**
1. **Separate least-privilege roles:** `collabify_migrator` owns schema DDL, runtime `collabify_app` has `NOSUPERUSER NOBYPASSRLS`, and a zero-login `collabify_host_resolver (NOLOGIN NOBYPASSRLS)` owns `resolve_tenant_by_host` with column-scoped `SELECT` + active-only RLS policy (solving the `FORCE RLS` trap where non-superuser migrators break `SECURITY DEFINER` lookups).
2. **`ENABLE` + `FORCE ROW LEVEL SECURITY`** on every tenant table (even table owners cannot accidentally bypass RLS).
3. **Fail-closed predicate:** `tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid`. Missing GUC evaluates to `NULL` -> `0` rows on `SELECT`, SQLSTATE `42501` on `INSERT`/`UPDATE`.
4. **Composite Foreign Keys `(tenant_id, id)`:** Enforces referential tenant integrity inside PostgreSQL itself (`fk_video_assets_tenant_portal`, `fk_video_upload_parts_tenant_video`), preventing cross-tenant object linking even from buggy backfills.
5. **Leading `tenant_id` B-tree indexes:** `(tenant_id, portal_id, created_at DESC)` guarantees RLS predicates drive index scans instead of sequential table scans.

**Escape hatch for future Enterprise tier:** Keep `tenant_id` on every table and route `Pool` lookup via a lightweight tenant-to-cluster map later. Moving an Enterprise agency to a dedicated Postgres cluster requires zero query rewrites.

---

## 2. PgBouncer Transaction Pooling: `SET LOCAL` vs Session-Level `SET`

Under PgBouncer `pool_mode = transaction` (standard for Node.js/Next.js serverless and containerized backends):
- Physical Postgres backend connections are reassigned between requests at every `COMMIT`/`ROLLBACK`.
- **Session-level `SET app.current_tenant_id = '...'` is a critical data-leak vulnerability:** if a pooled connection finishes Tenant A's request and Tenant B runs a query that forgets to call `SET` (e.g., a health check, background worker, or buggy endpoint), Postgres silently serves **Tenant A's rows to Tenant B**.
- **Our pattern (`src/server/db/tenantContext.ts`):**
  ```sql
  BEGIN;
  SELECT set_config('app.current_tenant_id', $1, true); -- 3rd arg `is_local = true` == SET LOCAL
  -- tenant-scoped queries
  COMMIT;
  ```
- Why `set_config(..., true)` instead of `SET LOCAL app.current_tenant_id = '...'`?
  1. `SET LOCAL` does not accept `$1` bind parameters in Postgres, tempting string interpolation. `set_config` is 100% parameterized.
  2. When the transaction ends (`COMMIT` or `ROLLBACK` on exception), PostgreSQL automatically resets the GUC to empty/unset before PgBouncer hands the backend connection to another client.
- **Additional PgBouncer production detail:** Disable unnamed/named session-level prepared statements when using PgBouncer <1.21 (or set `max_prepared_statements` explicitly in PgBouncer 1.21+). Never hold transactions open across external HTTP calls (like S3 or email APIs) — do external I/O outside `withTenantContext`.

---

## 3. Large Video Uploads: Direct S3/R2 Multipart + Tus Resumability vs API Proxy

### Never Proxy Multi-GB Video Through Node.js / Next.js
Streaming a 5 GB 4K ProRes or MP4 deliverable through an API server saturates event-loop buffers, blows container memory/egress budgets, breaks serverless payload limits (4.5 MB on Vercel / 10 MB on API Gateway), and forces full restarts on dropped Wi-Fi.

### Recommended Production Pipeline
1. **Control Plane (Collabify API):**
   - `POST /init`: Authorizes Agency Admin, enforces tenant storage quota + MIME allowlist + 10 GiB cap, generates a deterministic tenant-isolated key `tenants/{tenantId}/portals/{portalId}/videos/{videoId}/{sanitizedName}`, creates the `video_assets` row (`UPLOADING`), calls S3/R2 `CreateMultipartUpload`, and mints short-lived (15 min) presigned `UploadPart` URLs.
   - **Dynamic part sizing:** S3/R2 caps multipart uploads at 10,000 parts (min 5 MiB/part except final). Use `partSize = max(8 MiB, ceil(fileSize / 10000))` (e.g., 16 MiB parts for 4K files, 3–4 concurrent PUTs in browser).
   - **Checksum integrity:** Pass `ChecksumAlgorithm: 'SHA256'` (or `x-amz-checksum-sha256` per part). For browser uploads, compute WebCrypto `crypto.subtle.digest('SHA-256', chunk)` per slice before uploading.
   - `POST /complete`: Re-verifies tenant/portal ownership under RLS, validates ordered part ETags, calls `CompleteMultipartUpload`, transitions video `UPLOADING -> READY`, and triggers an async media pipeline (FFmpeg / Mux / Cloudflare Stream HLS transcoding + thumbnail/waveform extraction).
2. **Resumability across flaky agency uploads:**
   - Persist completed `(part_number, etag, sha256)` in `video_upload_parts` (and local browser `IndexedDB` keyed by `fileFingerprint`). On reconnect, query uploaded parts and upload only missing chunks — zero re-upload of already-landed gigabytes.
   - If mobile/unreliable field uploads become primary, layer **tus** (`@tus/server` + `@tus/s3-store` or Cloudflare Stream Direct Creator Uploads) directly over the same `video_assets` state machine.
3. **Storage Economics & Cleanup:**
   - **Cloudflare R2** eliminates egress fees for client review playback (massive cost win over AWS S3 for video SaaS).
   - Attach an S3/R2 Lifecycle rule: `AbortIncompleteMultipartUpload` after 48 hours so abandoned uploads never accrue silent storage bills.
4. **Playback Authorization:**
   - Bucket stays **100% private** (no public ACLs). Playback requires an authorized Agency Admin OR a Portal Guest whose token matches `(tenantId, portalId)` -> API returns a short-lived (5–10 min) signed URL / signed CloudFront/R2 Worker cookie scoped strictly to that `objectKey`.

---

## 4. Subdomain Client Portals, Custom Domains & Cookie Isolation

### Routing & TLS
- **Default Agency Subdomains (`*.collabify.app`):** Single wildcard DNS (`*.collabify.app -> edge`) + wildcard TLS cert. Zero per-tenant DNS provisioning delay on signup.
- **Custom Agency Domains (`portal.acmecreative.io`):** Use **Cloudflare for SaaS (Custom Hostnames)**. Agencies add one `CNAME` (`portal.acmecreative.io -> customers.collabify.app`); Cloudflare automates HTTP/TXT DCV validation, issues/renews per-hostname TLS certs at the edge, and forwards verified traffic to origin.
- **Edge Caching:** Cache tenant host lookup (`host -> { id, slug, status }`) in Redis/in-process LRU for 30–60s with immediate pub/sub invalidation on tenant suspension or custom-domain change.

### Subtle Security Pitfalls Prevented in This Repo
1. **Cookie Domain Scoping:** **Never** set `Domain=.collabify.app` on session cookies! A wildcard parent-domain cookie lets a session from `acme.collabify.app` automatically attach to `velvet.collabify.app` (and opens subdomain cookie-tossing). Always omit `Domain` so cookies are **host-only** (`acme.collabify.app` only), `HttpOnly`, `SameSite=Lax`, `Secure`.
2. **`X-Forwarded-Host` Spoofing:** Accepting `X-Forwarded-Host` blindly lets any attacker send `Host: acme.collabify.app` + `X-Forwarded-Host: velvet.collabify.app` to bypass WAF/edge rules. Only accept `X-Forwarded-Host` when `socket.remoteAddress` is in an explicit `TRUSTED_PROXY_IPS` CIDR/list, and reject comma-chained values.
3. **Tenant Enumeration:** Return an identical `404 PORTAL_NOT_FOUND` for both nonexistent and suspended agency slugs.
4. **Dual-Auth Separation:** Agency Admin sessions (`aud: 'agency_admin'`) and Client Magic-Link Guest sessions (`aud: 'portal_guest'`) are distinct principal types. Magic links store only `SHA-256(token)` in Postgres, expire in 15 min, consume atomically via `UPDATE ... WHERE consumed_at IS NULL RETURNING *`, and mint a guest token locked to ONE `(tenantId, portalId)` with least-privilege scopes (`video:read`, `portal:comment`, `video:approve`).
