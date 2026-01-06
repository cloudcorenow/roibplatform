import { Hono } from 'hono';
import type { HonoEnv } from '../types';

export const analyticsRouter = new Hono<HonoEnv>();

analyticsRouter.get('/dashboard', async (c) => {
  const tenantId = c.get('tenant_id');

  try {
    const timeEntriesCount = await c.env.DB.prepare(
      'SELECT COUNT(*) as count FROM time_entries WHERE tenant_id = ?'
    ).bind(tenantId).first();

    const documentsCount = await c.env.DB.prepare(
      'SELECT COUNT(*) as count FROM documents WHERE tenant_id = ?'
    ).bind(tenantId).first();

    const assessmentsCount = await c.env.DB.prepare(
      'SELECT COUNT(*) as count FROM assessments WHERE tenant_id = ?'
    ).bind(tenantId).first();

    return c.json({
      timeEntries: timeEntriesCount?.count || 0,
      documents: documentsCount?.count || 0,
      assessments: assessmentsCount?.count || 0
    });
  } catch (error) {
    console.error('Analytics fetch failed:', error);
    return c.json({ error: 'Failed to fetch analytics' }, 500);
  }
});

analyticsRouter.get('/audit-log', async (c) => {
  const tenantId = c.get('tenant_id');
  const limit = parseInt(c.req.query('limit') || '50', 10);

  try {
    const { results } = await c.env.DB.prepare(
      `SELECT * FROM audit_log
       WHERE tenant_id = ?
       ORDER BY timestamp DESC
       LIMIT ?`
    ).bind(tenantId, limit).all();

    return c.json({ data: results });
  } catch (error) {
    console.error('Audit log fetch failed:', error);
    return c.json({ error: 'Failed to fetch audit log' }, 500);
  }
});
