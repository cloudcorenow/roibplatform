import { Hono } from 'hono';
import type { HonoEnv } from '../types';

export const timeEntriesRouter = new Hono<HonoEnv>();

timeEntriesRouter.get('/', async (c) => {
  const tenantId = c.get('tenant_id');
  const userId = c.get('user_id');

  try {
    const { results } = await c.env.DB.prepare(
      'SELECT * FROM time_entries WHERE tenant_id = ? ORDER BY created_at DESC'
    ).bind(tenantId).all();

    return c.json({ data: results });
  } catch (error) {
    console.error('Failed to fetch time entries:', error);
    return c.json({ error: 'Failed to fetch time entries' }, 500);
  }
});

timeEntriesRouter.post('/', async (c) => {
  const tenantId = c.get('tenant_id');
  const userId = c.get('user_id');
  const body = await c.req.json();

  try {
    const result = await c.env.DB.prepare(
      `INSERT INTO time_entries (tenant_id, user_id, client_id, date, hours, description, created_at)
       VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`
    ).bind(
      tenantId,
      userId,
      body.client_id,
      body.date,
      body.hours,
      body.description
    ).run();

    return c.json({ success: true, id: result.meta.last_row_id });
  } catch (error) {
    console.error('Failed to create time entry:', error);
    return c.json({ error: 'Failed to create time entry' }, 500);
  }
});
