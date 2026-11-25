import type { Pool, PoolClient } from 'pg';

const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * PostgreSQL SQLSTATE error codes mirrored by the in-memory RLS adapter.
 */
export class RlsPolicyViolationError extends Error {
  public readonly code = '42501';

  constructor(table: string, detail: string) {
    super(`new row violates row-level security policy for table "${table}": ${detail}`);
    this.name = 'RlsPolicyViolationError';
  }
}

export class CompositeForeignKeyViolationError extends Error {
  public readonly code = '23503';

  constructor(constraint: string, detail: string) {
    super(`insert or update violates composite foreign key constraint "${constraint}": ${detail}`);
    this.name = 'CompositeForeignKeyViolationError';
  }
}

export function assertValidTenantUuid(tenantId: string): string {
  if (!UUID_REGEX.test(tenantId)) {
    throw new Error(`Invalid tenant UUID: "${tenantId}"`);
  }
  return tenantId.toLowerCase();
}

/**
 * Transaction-scoped tenant context GUC setter (`SET LOCAL` semantics).
 *
 * WHY `set_config('app.current_tenant_id', $1, true)` (is_local = true)
 * INSTEAD OF SESSION-LEVEL `SET app.current_tenant_id = ...`?
 *
 * 1. PgBouncer Transaction Pooling Safety:
 *    Under PgBouncer `pool_mode = transaction`, physical PostgreSQL backend
 *    connections are multiplexed across arbitrary client requests on every
 *    COMMIT/ROLLBACK. A session-level `SET` persists on the underlying Postgres
 *    backend after the transaction ends and silently leaks Tenant A's context
 *    into Tenant B's next transaction if a code path ever forgets to reset it.
 * 2. Parameterized SQL Safety:
 *    PostgreSQL's `SET LOCAL` utility statement does not accept bind parameters
 *    (`$1`), tempting engineers into string interpolation. `set_config(name, val, true)`
 *    has identical transaction-local (`SET LOCAL`) lifetime while remaining 100%
 *    parameterized.
 * 3. Automatic Fail-Closed Reset:
 *    When the transaction commits or rolls back, PostgreSQL automatically clears
 *    the local GUC. Any subsequent query outside `withPgTenantContext` sees
 *    `current_setting('app.current_tenant_id', true)` as NULL -> ZERO rows returned.
 */
export const SET_LOCAL_TENANT_SQL = `SELECT set_config('app.current_tenant_id', $1, true)`;

export async function withPgTenantContext<T>(
  pool: Pick<Pool, 'connect'>,
  tenantId: string,
  fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const safeTenantId = assertValidTenantUuid(tenantId);
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    await client.query(SET_LOCAL_TENANT_SQL, [safeTenantId]);
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // Preserve original error if rollback also fails on broken socket
    }
    throw err;
  } finally {
    client.release();
  }
}
