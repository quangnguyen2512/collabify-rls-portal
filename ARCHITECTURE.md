# ARCHITECTURE — Collabify Multi-Tenant Reference App

Production-grade reference architecture implementing Collabify's 4 core backend engineering challenges: PostgreSQL shared-schema Row-Level Security (RLS), subdomain/custom-domain client portals, dual authentication flows, and resumable multipart video uploads.

## Core Security Invariants
1. **Fail-Closed PostgreSQL RLS:** Runtime role `collabify_app` has `NOSUPERUSER NOBYPASSRLS`; pre-context `resolve_tenant_by_host` runs under `collabify_host_resolver` (`NOLOGIN NOBYPASSRLS`) with column-scoped `SELECT` and active-only RLS policy so `FORCE ROW LEVEL SECURITY` stays intact even under non-superuser migrators. Missing `app.current_tenant_id` returns `0` rows on reads and throws SQLSTATE `42501` on writes.
2. **PgBouncer Transaction-Pooling Safety:** Tenant context is ALWAYS set via `SELECT set_config('app.current_tenant_id', $1, true)` (`SET LOCAL` semantics) inside explicit `BEGIN ... COMMIT/ROLLBACK` blocks — never session-level `SET`.
3. **Composite Foreign-Key Lock:** Child tables (`portal_magic_links`, `video_assets`, `video_upload_parts`) reference composite keys `(tenant_id, id)` so cross-tenant foreign-key references fail at the DB constraint layer (`23503`).
4. **Zero Cross-Tenant Token Replay:** Both Agency Admin JWTs and Client Portal Guest JWTs carry `tenantId` (and `portalId` for guests). Middleware enforces `principal.tenantId === req.tenant.id` (`403 TENANT_MISMATCH`) and `guest.portalId === req.params.portalId` (`403 PORTAL_SCOPE_MISMATCH`).
5. **Host-Header Trust Boundary:** `X-Forwarded-Host` is rejected (`400`) unless the socket peer IP matches `TRUSTED_PROXY_IPS`. Unknown and suspended tenants return identical `404 PORTAL_NOT_FOUND` (anti-enumeration).

## Directory Boundaries
```text
collabify-rls-portal/
├── ARCHITECTURE.md                  # System map & invariants
├── README.md                        # Quickstart, Docker Postgres+PgBouncer, API docs
├── ARCHITECTURE_TRADEOFFS.md        # Multi-tenancy, PgBouncer, S3/R2 & Wildcard TLS analysis
├── docker-compose.yml               # PostgreSQL 16 + PgBouncer (transaction pool mode)
├── db/
│   ├── migrations/001_multi_tenant_rls.sql  # Roles, composite FKs, ENABLE+FORCE RLS, policies
│   └── seed.sql                             # Acme, Velvet, and Suspended tenant fixtures
├── public/index.html                # Single-screen interactive Demo & Red-Team Workbench
├── src/server/
│   ├── config.ts                    # Typed env loader & production secret guardrails
│   ├── types.ts                     # Domain models & Express request augmentation
│   ├── db/
│   │   ├── tenantContext.ts         # PgBouncer-safe `withPgTenantContext` (`set_config` local)
│   │   ├── store.ts                 # Shared `AppStore` repository contract
│   │   ├── memoryStore.ts           # AsyncLocalStorage fail-closed RLS simulator (zero-DB demo)
│   │   └── pgAdapter.ts             # Real `pg.Pool` adapter targeting `collabify_app`
│   ├── middleware/subdomain.ts      # Strict Host / custom-domain parser & proxy trust check
│   ├── auth/
│   │   ├── tokens.ts                # Zero-dependency HS256 JWT + scrypt + SHA-256 token hashing
│   │   ├── middleware.ts            # Tenant binding + RBAC (`agency_admin` vs `portal_guest`)
│   │   └── routes.ts                # Agency login + single-use magic-link mint & exchange
│   ├── uploads/
│   │   ├── presigner.ts             # Tenant-prefixed object keys + HMAC / S3-R2 upload & playback presigner
│   │   └── multipart.ts             # Init, signed chunk PUT (SHA-256), /upload-status resume, complete, signed 206 stream, approve
│   ├── routes/portals.ts            # RLS-scoped portals, audit events & fail-closed RLS probe
│   ├── app.ts                       # Express app factory (testable via Supertest)
│   └── index.ts                     # Local/production HTTP server entrypoint
└── tests/                           # Vitest suite (SQL static RLS, subdomain, RLS, auth, uploads)
```

## Request Execution DAG
```text
HTTP Request
  -> subdomainTenantResolver (Host / trusted X-Forwarded-Host -> resolve_tenant_by_host -> req.tenant)
  -> [PUT /api/uploads/:uploadId/parts/:partNumber] -> HMAC + tenantId + SHA-256 -> withTenantContext -> DB
  -> [JSON API] -> authenticatePrincipal (JWT verify + principal.tenantId === req.tenant.id)
                 -> RBAC / Portal Scope Guard (agency_admin | portal_guest[portalId])
                 -> store.withTenantContext(req.tenant.id, BEGIN -> set_config(..., true) -> SQL -> COMMIT)
```

<!-- AUTO-KG-STATS:START -->
- **Knowledge Graph Live Sync:** `2026-11-25 16:26 UTC` | Nodes: **34** | Edges: **24** | Layers: **5** | Languages: `markdown, sql, typescript`
- **Top Connected Hubs:** `README.md` (2), `ARCHITECTURE.md` (1), `ARCHITECTURE_TRADEOFFS.md` (1), `db/seed.sql` (1), `db/migrations/001_multi_tenant_rls.sql` (1)
<!-- AUTO-KG-STATS:END -->
