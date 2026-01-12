import { Env } from '../worker';
import { withRetry } from './retry';

export interface QueryTimings {
  query: string;
  duration: number;
  timestamp: string;
}

export class D1QueryBuilder {
  private env: Env;
  private slowQueryThreshold = 100;

  constructor(env: Env) {
    this.env = env;
  }

  async executeWithTiming<T>(
    stmt: D1PreparedStatement,
    operationName: string
  ): Promise<{ data: T; timing: QueryTimings }> {
    const start = Date.now();
    const data = await stmt.first<T>();
    const duration = Date.now() - start;

    if (duration > this.slowQueryThreshold) {
      console.warn(`Slow query detected (${operationName}): ${duration}ms`);
    }

    return {
      data: data as T,
      timing: {
        query: operationName,
        duration,
        timestamp: new Date().toISOString()
      }
    };
  }

  async batchInsert(
    table: string,
    columns: string[],
    values: any[][],
    chunkSize = 25
  ): Promise<void> {
    const chunks = [];
    for (let i = 0; i < values.length; i += chunkSize) {
      chunks.push(values.slice(i, i + chunkSize));
    }

    for (const chunk of chunks) {
      const statements = chunk.map(row => {
        const placeholders = columns.map(() => '?').join(', ');
        return this.env.DB.prepare(
          `INSERT INTO ${table} (${columns.join(', ')}) VALUES (${placeholders})`
        ).bind(...row);
      });

      await withRetry(async () => {
        await this.env.DB.batch(statements);
      }, 3);
    }
  }

  async batchUpdate(
    table: string,
    updates: Array<{ id: string; tenantId: string; data: Record<string, any> }>,
    chunkSize = 25
  ): Promise<void> {
    const chunks = [];
    for (let i = 0; i < updates.length; i += chunkSize) {
      chunks.push(updates.slice(i, i + chunkSize));
    }

    for (const chunk of chunks) {
      const statements = chunk.map(update => {
        const setClause = Object.keys(update.data)
          .map(key => `${key} = ?`)
          .join(', ');

        return this.env.DB.prepare(
          `UPDATE ${table} SET ${setClause}, updated_at = datetime('now') WHERE tenant_id = ? AND id = ?`
        ).bind(...Object.values(update.data), update.tenantId, update.id);
      });

      await withRetry(async () => {
        await this.env.DB.batch(statements);
      }, 3);
    }
  }

  async paginatedQuery<T>(
    stmt: D1PreparedStatement,
    limit: number,
    offset: number
  ): Promise<{ results: T[]; hasMore: boolean }> {
    const cappedLimit = Math.min(limit, 200);

    const result = await withRetry(async () => {
      return stmt.bind(cappedLimit + 1, offset).all();
    }, 3);

    const hasMore = result.results.length > cappedLimit;
    const results = hasMore ? result.results.slice(0, cappedLimit) : result.results;

    return {
      results: results as T[],
      hasMore
    };
  }
}

export async function getCachedOrCompute<T>(
  kv: KVNamespace,
  key: string,
  ttl: number,
  compute: () => Promise<T>
): Promise<T> {
  const cached = await kv.get(key, 'json');

  if (cached !== null) {
    return cached as T;
  }

  const fresh = await compute();

  await kv.put(key, JSON.stringify(fresh), {
    expirationTtl: ttl
  });

  return fresh;
}

export function buildCacheKey(
  prefix: string,
  params: Record<string, string | number | boolean>
): string {
  const sortedParams = Object.keys(params)
    .sort()
    .map(key => `${key}:${params[key]}`)
    .join('|');

  return `${prefix}:${sortedParams}`;
}

export async function invalidateCache(
  kv: KVNamespace,
  pattern: string
): Promise<void> {
  const list = await kv.list({ prefix: pattern });
  const deletePromises = list.keys.map(key => kv.delete(key.name));
  await Promise.all(deletePromises);
}

export interface AggregationResult {
  count: number;
  sum: number;
  avg: number;
  min: number;
  max: number;
}

export async function computeAggregation(
  env: Env,
  tenantId: string,
  table: string,
  column: string,
  filters?: Record<string, any>
): Promise<AggregationResult> {
  let whereClause = 'WHERE tenant_id = ?';
  const bindings: any[] = [tenantId];

  if (filters) {
    Object.entries(filters).forEach(([key, value]) => {
      whereClause += ` AND ${key} = ?`;
      bindings.push(value);
    });
  }

  const stmt = env.DB.prepare(`
    SELECT
      COUNT(*) as count,
      COALESCE(SUM(${column}), 0) as sum,
      COALESCE(AVG(${column}), 0) as avg,
      COALESCE(MIN(${column}), 0) as min,
      COALESCE(MAX(${column}), 0) as max
    FROM ${table}
    ${whereClause}
  `).bind(...bindings);

  const result = await withRetry(async () => {
    return stmt.first<AggregationResult>();
  }, 3);

  return result || { count: 0, sum: 0, avg: 0, min: 0, max: 0 };
}
