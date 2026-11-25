import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import { createAuthRouter } from './auth/routes.js';
import { loadConfig, type AppConfig } from './config.js';
import { MemoryRlsStore } from './db/memoryStore.js';
import type { AppStore } from './db/store.js';
import {
  CompositeForeignKeyViolationError,
  RlsPolicyViolationError,
} from './db/tenantContext.js';
import { createSubdomainTenantMiddleware } from './middleware/subdomain.js';
import { createPortalsRouter } from './routes/portals.js';
import { createMultipartUploadRouter, createUploadPartsRouter } from './uploads/multipart.js';
import { LocalHmacPresigner, type MultipartStoragePresigner } from './uploads/presigner.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PUBLIC_DIR = path.resolve(__dirname, '../../public');

export interface CreateAppOptions {
  store?: AppStore;
  config?: AppConfig;
  presigner?: MultipartStoragePresigner;
}

export function createApp(options: CreateAppOptions = {}): {
  app: Express;
  store: AppStore;
  config: AppConfig;
  presigner: MultipartStoragePresigner;
} {
  const config = options.config ?? loadConfig();
  const store = options.store ?? new MemoryRlsStore(true);
  const presigner = options.presigner ?? new LocalHmacPresigner(config.uploadSigningSecret);

  const app = express();
  app.disable('x-powered-by');

  // Health probe (no tenant subdomain required)
  app.get('/healthz', (_req, res) => {
    res.status(200).json({
      status: 'ok',
      storageMode: config.storageMode,
      baseDomain: config.baseDomain,
      demoHostHeaderEnabled: config.allowDemoHostHeader,
    });
  });

  // Static Demo UI workbench (served at `/` so the founder can inspect all 4 challenges in 1 screen)
  app.use(express.static(PUBLIC_DIR));

  // All tenant API routes MUST resolve a valid active subdomain/custom-domain first
  const apiRouter = express.Router();
  apiRouter.use(createSubdomainTenantMiddleware(store, config));

  // Public workspace metadata for resolved subdomain (no credentials required)
  apiRouter.get('/tenant/context', (req, res) => {
    res.status(200).json({
      tenant: req.tenant,
      resolvedHost: req.resolvedHost,
    });
  });

  // Mount raw binary chunk upload endpoint BEFORE express.json()
  apiRouter.use(createUploadPartsRouter(store, presigner));

  // JSON parser for structured API endpoints
  apiRouter.use(express.json({ limit: '1mb' }));

  apiRouter.use(createAuthRouter(store, config));
  apiRouter.use(createPortalsRouter(store, config));
  apiRouter.use(createMultipartUploadRouter(store, config, presigner));

  app.use('/api', apiRouter);

  // Centralized error boundary (never leaks stack traces in JSON responses)
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof RlsPolicyViolationError) {
      res.status(403).json({ error: 'RLS_POLICY_VIOLATION', sqlstate: err.code, message: err.message });
      return;
    }
    if (err instanceof CompositeForeignKeyViolationError) {
      res.status(400).json({ error: 'CROSS_TENANT_REFERENCE', sqlstate: err.code, message: err.message });
      return;
    }
    const status = typeof (err as { status?: number })?.status === 'number' ? (err as { status: number }).status : 500;
    const message = err instanceof Error ? err.message : 'Internal server error';
    res.status(status).json({ error: 'INTERNAL_ERROR', message });
  });

  return { app, store, config, presigner };
}
