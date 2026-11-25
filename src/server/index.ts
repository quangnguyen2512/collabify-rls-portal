import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { MemoryRlsStore } from './db/memoryStore.js';
import { PgRlsStore } from './db/pgAdapter.js';

const config = loadConfig({
  ...process.env,
  // Enable the local workbench switcher header by default ONLY in local development
  ALLOW_DEMO_HOST_HEADER:
    process.env.ALLOW_DEMO_HOST_HEADER ??
    (process.env.NODE_ENV === 'production' ? 'false' : 'true'),
});

const store =
  config.storageMode === 'postgres'
    ? (() => {
        if (!config.databaseUrl) {
          throw new Error('DATABASE_URL is required when STORAGE_MODE=postgres');
        }
        return PgRlsStore.fromConnectionString(config.databaseUrl);
      })()
    : new MemoryRlsStore(true);

const { app } = createApp({ store, config });

app.listen(config.port, () => {
  console.log(
    `[collabify-reference] listening on http://localhost:${config.port} (storage=${config.storageMode}, baseDomain=*.${config.baseDomain})`,
  );
});
