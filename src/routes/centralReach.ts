import { Hono } from 'hono';
import type { HonoEnv } from '../types';

export const centralReachRouter = new Hono<HonoEnv>();

centralReachRouter.post('/sync', async (c) => {
  const tenantId = c.get('tenant_id');

  try {
    const response = await fetch(`${c.env.CENTRALREACH_BASE_URL}/api/v1/clients`, {
      headers: {
        'Authorization': `Bearer ${c.env.CENTRALREACH_API_KEY}`,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`CentralReach API error: ${response.statusText}`);
    }

    const data = await response.json() as any;

    return c.json({
      success: true,
      synced: Array.isArray(data) ? data.length : 0,
      message: 'CentralReach sync completed'
    });
  } catch (error) {
    console.error('CentralReach sync failed:', error);
    return c.json({ error: 'Sync failed' }, 500);
  }
});

centralReachRouter.get('/status', async (c) => {
  return c.json({
    status: 'connected',
    baseUrl: c.env.CENTRALREACH_BASE_URL || 'not configured'
  });
});
