# Collabify — Multi-Tenant Client Portal & Video Upload Reference App

A runnable, test-verified TypeScript + Node.js + PostgreSQL reference implementation built specifically around Collabify's four core backend challenges:

1. **Tenant Isolation on a Shared PostgreSQL Schema with RLS** (`db/migrations/001_multi_tenant_rls.sql`, `src/server/db/tenantContext.ts`, `src/server/db/pgAdapter.ts`)
2. **Dual Authentication Flows** — Agency Admin session vs single-use, portal-scoped Client Magic Link (`src/server/auth/`)
3. **Subdomain & Custom-Domain Client Portals** (`src/server/middleware/subdomain.ts`)
4. **Large Resumable Multipart Video Uploads** with per-part SHA-256 verification, tenant-isolated object keys, and authorized playback (`src/server/uploads/`)

---

## Quickstart (Zero External Dependencies)

The server ships with an **In-Memory RLS-Enforcing Store** (`MemoryRlsStore`) backed by `AsyncLocalStorage` that mirrors PostgreSQL's exact fail-closed RLS behavior (`0` rows without context, SQLSTATE `42501` on cross-tenant write, SQLSTATE `23503` on composite FK mismatch).

```powershell
npm install
npx tsc --noEmit
npm test
npm run dev
```

Open **`http://localhost:3090`** to use the single-screen interactive workbench:
- Switch live between `acme.collabify.local`, `velvet.collabify.local`, `portal.acmecreative.io` (custom domain), and `suspended-co.collabify.local` (uniform `404` anti-enumeration).
- Sign in via **Flow A (Agency Admin)** or mint + exchange a single-use **Flow B (Client Portal Magic Link)**.
- Fire live **Cross-Tenant Attack Simulations** (JWT replay -> `403 TENANT_MISMATCH`, Portal Escape -> `403 PORTAL_SCOPE_MISMATCH`, Fail-Closed RLS Probe -> `0 rows` / `42501`, Spoofed `X-Forwarded-Host` -> `400`).
- Run a **Multi-Chunk Video Upload** (select any local video OR click *"Upload Synthetic 2.5MB Sample"* to stream 5 SHA-256 verified parts and verify the completed manifest).

### Seeded Local Sandbox Credentials
| Tenant | Subdomain / Custom Domain | Agency Admin Email | Demo Password |
| :--- | :--- | :--- | :--- |
| Acme Creative Studio | `acme.collabify.local` / `portal.acmecreative.io` | `alice@acme.studio` | `collabify-demo-pass` |
| Velvet Motion Lab | `velvet.collabify.local` / `review.velvetmotion.tv` | `bob@velvet.tv` | `collabify-demo-pass` |
| Suspended Agency Co | `suspended-co.collabify.local` | *(returns 404)* | — |

---

## Running Against Real PostgreSQL 16 + PgBouncer (Transaction Pooling)

```powershell
docker compose up -d
```

Docker Compose automatically mounts and runs:
1. `db/migrations/001_multi_tenant_rls.sql` (provisions `collabify_migrator` + non-superuser `collabify_app NOBYPASSRLS`, tables with composite FKs `(tenant_id, id)`, `ENABLE` + `FORCE ROW LEVEL SECURITY`, fail-closed policies, and `resolve_tenant_by_host`).
2. `db/seed.sql` (loads Acme, Velvet, and Suspended fixtures).
3. **PgBouncer** on port `6432` in `POOL_MODE=transaction` to validate `set_config('app.current_tenant_id', $1, true)` (`SET LOCAL` semantics).

Copy `.env.example` to `.env`, set `STORAGE_MODE=postgres` and `DATABASE_URL=postgres://collabify_app:local_dev_app_only@localhost:6432/collabify`, and run `npm run dev`.

---

## API Surface Summary

All `/api/*` endpoints require a valid tenant `Host` (e.g., `Host: acme.collabify.local`).

| Method & Path | Auth | Behavior |
| :--- | :--- | :--- |
| `GET /api/tenant/context` | Public | Returns resolved active tenant metadata (`404` for unknown/suspended) |
| `POST /api/auth/agency/login` | Public | Flow A: Agency Admin login bound to resolved subdomain tenant (host-only `HttpOnly` cookie + JWT) |
| `POST /api/auth/logout` | Public | Clears host-only `collabify_session` cookie (`Max-Age=0`) |
| `POST /api/portals/:portalId/magic-links` | Agency Admin | Flow B (1): Mints single-use, short-TTL magic link (stores SHA-256 hash only) |
| `POST /api/auth/portal/exchange` | Public | Flow B (2): Atomically consumes magic link -> returns `(tenantId, portalId)` guest JWT |
| `GET /api/portals` | Admin / Guest | Admin sees all tenant portals; Guest sees only their single scoped portal |
| `POST /api/portals` | Agency Admin | Creates a client portal inside active tenant RLS context |
| `GET /api/portals/:portalId/videos` | Admin / Scoped Guest | Lists videos for `:portalId` under RLS + portal-scope guard |
| `POST /api/portals/:portalId/videos/init` | Agency Admin | Validates MIME/size (<=10 GiB), issues `tenants/{tid}/portals/{pid}/videos/{vid}/{name}` key + signed part URLs |
| `GET /api/portals/:portalId/videos/:videoId/upload-status` | Agency Admin | Resumable upload recovery: returns landed parts + re-signs fresh URLs ONLY for missing parts |
| `PUT /api/uploads/:uploadId/parts/:partNumber` | HMAC Signed URL | Verifies signature, expiry, tenant match & SHA-256 chunk integrity |
| `POST /api/portals/:portalId/videos/:videoId/complete` | Agency Admin | Verifies active state (`409` on replay), ordered part ETags, exact byte sum, computes manifest SHA-256, sets `READY` |
| `GET /api/portals/:portalId/videos/:videoId/playback` | Admin / Scoped Guest | Issues short-lived signed playback URL for `READY` videos |
| `GET /api/uploads/stream/:videoId` | HMAC Signed URL | Local signed playback endpoint verifying tenant + signature and serving RFC 7233 `206 Partial Content` Range requests |
| `POST /api/portals/:portalId/videos/:videoId/approve` | Admin / Scoped Guest | Records client approval and appends audit event |
| `GET /api/audit-events` | Agency Admin | Returns append-only tenant audit log |
| `POST /api/demo/rls-probe` | Authenticated (dev/test only) | Executes live negative RLS assertions (`404` disabled in `NODE_ENV=production`) |

---

## Companion Docs
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — Module map, invariants, and request DAG
- [`ARCHITECTURE_TRADEOFFS.md`](./ARCHITECTURE_TRADEOFFS.md) — Engineering trade-offs for scaling Collabify
