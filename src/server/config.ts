import crypto from 'node:crypto';

export interface AppConfig {
  nodeEnv: 'development' | 'test' | 'production';
  port: number;
  baseDomain: string;
  storageMode: 'memory' | 'postgres';
  databaseUrl: string | undefined;
  authSigningSecret: string;
  uploadSigningSecret: string;
  trustedProxyIps: string[];
  allowDemoHostHeader: boolean;
  maxVideoSizeBytes: number;
  partSignTtlSeconds: number;
  playbackSignTtlSeconds: number;
  magicLinkTtlSeconds: number;
}

const TEN_GIB = 10 * 1024 * 1024 * 1024;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const rawEnv = env.NODE_ENV ?? 'development';
  const nodeEnv: AppConfig['nodeEnv'] =
    rawEnv === 'production' || rawEnv === 'test' ? rawEnv : 'development';

  const authSigningSecret =
    env.AUTH_SIGNING_SECRET ??
    (nodeEnv === 'production'
      ? ''
      : crypto.createHash('sha256').update('collabify-local-dev-auth-secret').digest('hex'));

  const uploadSigningSecret =
    env.UPLOAD_SIGNING_SECRET ??
    (nodeEnv === 'production'
      ? ''
      : crypto.createHash('sha256').update('collabify-local-dev-upload-secret').digest('hex'));

  if (nodeEnv === 'production') {
    if (authSigningSecret.length < 32) {
      throw new Error('AUTH_SIGNING_SECRET must be at least 32 characters in production');
    }
    if (uploadSigningSecret.length < 32) {
      throw new Error('UPLOAD_SIGNING_SECRET must be at least 32 characters in production');
    }
  }

  const trustedProxyIps = (env.TRUSTED_PROXY_IPS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  // Never permit demo host header override in production
  const allowDemoHostHeader =
    nodeEnv !== 'production' && (env.ALLOW_DEMO_HOST_HEADER ?? 'false').toLowerCase() === 'true';

  return {
    nodeEnv,
    port: Number(env.PORT ?? 3090),
    baseDomain: (env.BASE_DOMAIN ?? 'collabify.local').toLowerCase(),
    storageMode: env.STORAGE_MODE === 'postgres' ? 'postgres' : 'memory',
    databaseUrl: env.DATABASE_URL,
    authSigningSecret,
    uploadSigningSecret,
    trustedProxyIps,
    allowDemoHostHeader,
    maxVideoSizeBytes: TEN_GIB,
    partSignTtlSeconds: 15 * 60,
    playbackSignTtlSeconds: 10 * 60,
    magicLinkTtlSeconds: 15 * 60,
  };
}
