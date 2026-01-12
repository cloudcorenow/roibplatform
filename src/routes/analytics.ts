import { Hono } from 'hono';
import { Env } from '../worker';
import { TimeEntriesQueries } from '../utils/d1-queries';
import { getCachedOrCompute, buildCacheKey, invalidateCache } from '../utils/d1-helpers';
import { requirePermission, createSecurityContext } from '../utils/security';
import { dateRangeSchema } from '../utils/validation';

const analyticsRouter = new Hono<{ Bindings: Env }>();

analyticsRouter.get('/dashboard', async (c) => {
  try {
    const tenantId = c.get('tenant_id');
    const securityContext = createSecurityContext(c);

    requirePermission(securityContext, 'analytics:read');

    const from = c.req.query('from') ?? '0000-01-01';
    const to = c.req.query('to') ?? '9999-12-31';

    const dateRange = dateRangeSchema.safeParse({ from, to });
    if (!dateRange.success) {
      return c.json({
        error: 'Invalid date range',
        details: dateRange.error.errors.map(e => e.message).join(', '),
        code: 'VALIDATION_ERROR'
      }, 400);
    }

    const cacheKey = buildCacheKey('analytics:dashboard', {
      tenantId,
      from,
      to
    });

    const queries = new TimeEntriesQueries(c.env);

    const data = await getCachedOrCompute(
      c.env.KV,
      cacheKey,
      300,
      async () => {
        const [stats, projectBreakdown] = await Promise.all([
          queries.getAggregatedStats(tenantId, from, to),
          queries.getProjectBreakdown(tenantId, from, to, 20)
        ]);

        return {
          stats,
          projectBreakdown,
          generatedAt: new Date().toISOString()
        };
      }
    );

    return c.json({
      data,
      cached: true,
      ttl: 300
    });
  } catch (error) {
    console.error('Error fetching analytics:', error);
    return c.json({
      error: 'Failed to fetch analytics',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'ANALYTICS_ERROR'
    }, 500);
  }
});

analyticsRouter.get('/time-summary', async (c) => {
  try {
    const tenantId = c.get('tenant_id');
    const securityContext = createSecurityContext(c);

    requirePermission(securityContext, 'analytics:read');

    const from = c.req.query('from') ?? '0000-01-01';
    const to = c.req.query('to') ?? '9999-12-31';

    const dateRange = dateRangeSchema.safeParse({ from, to });
    if (!dateRange.success) {
      return c.json({
        error: 'Invalid date range',
        code: 'VALIDATION_ERROR'
      }, 400);
    }

    const cacheKey = buildCacheKey('analytics:time-summary', {
      tenantId,
      from,
      to
    });

    const queries = new TimeEntriesQueries(c.env);

    const data = await getCachedOrCompute(
      c.env.KV,
      cacheKey,
      600,
      async () => {
        const stats = await queries.getAggregatedStats(tenantId, from, to);

        return {
          totalHours: Math.round((stats.totalMinutes / 60) * 100) / 100,
          totalRnDHours: Math.round((stats.totalRnDMinutes / 60) * 100) / 100,
          totalEntries: stats.totalEntries,
          projectCount: stats.projectCount,
          clientCount: stats.clientCount,
          rndPercentage: stats.totalMinutes > 0
            ? Math.round((stats.totalRnDMinutes / stats.totalMinutes) * 100)
            : 0,
          generatedAt: new Date().toISOString()
        };
      }
    );

    return c.json({ data });
  } catch (error) {
    console.error('Error fetching time summary:', error);
    return c.json({
      error: 'Failed to fetch time summary',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'ANALYTICS_ERROR'
    }, 500);
  }
});

analyticsRouter.post('/invalidate-cache', async (c) => {
  try {
    const tenantId = c.get('tenant_id');
    const securityContext = createSecurityContext(c);

    requirePermission(securityContext, 'analytics:write');

    const prefix = `analytics:${tenantId}`;
    await invalidateCache(c.env.KV, prefix);

    return c.json({
      success: true,
      message: 'Analytics cache invalidated'
    });
  } catch (error) {
    console.error('Error invalidating cache:', error);
    return c.json({
      error: 'Failed to invalidate cache',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'CACHE_ERROR'
    }, 500);
  }
});

export { analyticsRouter };
