import { Hono } from 'hono';
import type { Env, HonoEnv } from '../types';
import { auditLogger } from '../utils/audit';

const router = new Hono<HonoEnv>();

router.get('/', async (c) => {
  const userId = c.get('user_id');
  const tenantId = c.req.query('tenant_id') || 'default';

  try {
    const result = await c.env.DB.prepare(`
      SELECT
        id,
        tenant_id,
        client_id,
        status,
        responses,
        results,
        score,
        completed_at,
        created_by,
        created_at,
        updated_at
      FROM assessments
      WHERE tenant_id = ? AND created_by = ?
      ORDER BY created_at DESC
    `).bind(tenantId, userId).all();

    const assessments = result.results.map((row: any) => ({
      ...row,
      responses: JSON.parse(row.responses),
      results: JSON.parse(row.results),
      created_at: new Date(row.created_at * 1000).toISOString(),
      updated_at: new Date(row.updated_at * 1000).toISOString(),
      completed_at: row.completed_at ? new Date(row.completed_at * 1000).toISOString() : null,
    }));

    await auditLogger(c.env, {
      tenant_id: tenantId,
      user_id: userId,
      action: 'list',
      resource_type: 'assessments',
      ip_address: c.get('user_ip'),
      details: JSON.stringify({ count: assessments.length })
    });

    return c.json(assessments);
  } catch (error: any) {
    console.error('Failed to fetch assessments:', error);
    return c.json({ error: 'Failed to fetch assessments' }, 500);
  }
});

router.get('/client/:clientId', async (c) => {
  const userId = c.get('user_id');
  const tenantId = c.req.query('tenant_id') || 'default';
  const clientId = c.req.param('clientId');

  try {
    const result = await c.env.DB.prepare(`
      SELECT
        id,
        tenant_id,
        client_id,
        status,
        responses,
        results,
        score,
        completed_at,
        created_by,
        created_at,
        updated_at
      FROM assessments
      WHERE tenant_id = ? AND client_id = ? AND created_by = ?
      ORDER BY created_at DESC
    `).bind(tenantId, clientId, userId).all();

    const assessments = result.results.map((row: any) => ({
      ...row,
      responses: JSON.parse(row.responses),
      results: JSON.parse(row.results),
      created_at: new Date(row.created_at * 1000).toISOString(),
      updated_at: new Date(row.updated_at * 1000).toISOString(),
      completed_at: row.completed_at ? new Date(row.completed_at * 1000).toISOString() : null,
    }));

    await auditLogger(c.env, {
      tenant_id: tenantId,
      user_id: userId,
      action: 'list_by_client',
      resource_type: 'assessments',
      resource_id: clientId,
      ip_address: c.get('user_ip'),
      details: JSON.stringify({ count: assessments.length, client_id: clientId })
    });

    return c.json(assessments);
  } catch (error: any) {
    console.error('Failed to fetch client assessments:', error);
    return c.json({ error: 'Failed to fetch client assessments' }, 500);
  }
});

router.get('/:id', async (c) => {
  const userId = c.get('user_id');
  const id = c.req.param('id');

  try {
    const result = await c.env.DB.prepare(`
      SELECT
        id,
        tenant_id,
        client_id,
        status,
        responses,
        results,
        score,
        completed_at,
        created_by,
        created_at,
        updated_at
      FROM assessments
      WHERE id = ? AND created_by = ?
    `).bind(id, userId).first();

    if (!result) {
      return c.json({ error: 'Assessment not found' }, 404);
    }

    const assessment = {
      ...result,
      responses: JSON.parse(result.responses as string),
      results: JSON.parse(result.results as string),
      created_at: new Date((result.created_at as number) * 1000).toISOString(),
      updated_at: new Date((result.updated_at as number) * 1000).toISOString(),
      completed_at: result.completed_at ? new Date((result.completed_at as number) * 1000).toISOString() : null,
    };

    await auditLogger(c.env, {
      tenant_id: result.tenant_id as string,
      user_id: userId,
      action: 'read',
      resource_type: 'assessment',
      resource_id: id,
      ip_address: c.get('user_ip')
    });

    return c.json(assessment);
  } catch (error: any) {
    console.error('Failed to fetch assessment:', error);
    return c.json({ error: 'Failed to fetch assessment' }, 500);
  }
});

router.post('/', async (c) => {
  const userId = c.get('user_id');
  const body = await c.req.json();

  const { tenant_id, client_id, responses, results } = body;

  if (!client_id || !responses || !results) {
    return c.json({ error: 'Missing required fields' }, 400);
  }

  try {
    const id = crypto.randomUUID().replace(/-/g, '').toLowerCase();
    const score = results.totalCredit || 0;
    const tenantId = tenant_id || 'default';
    const now = Math.floor(Date.now() / 1000);

    await c.env.DB.prepare(`
      INSERT INTO assessments (
        id, tenant_id, client_id, status, responses, results, score, created_by, created_at, updated_at
      ) VALUES (?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      tenantId,
      client_id,
      JSON.stringify(responses),
      JSON.stringify(results),
      score,
      userId,
      now,
      now
    ).run();

    await auditLogger(c.env, {
      tenant_id: tenantId,
      user_id: userId,
      action: 'create',
      resource_type: 'assessment',
      resource_id: id,
      ip_address: c.get('user_ip'),
      user_agent: c.req.header('User-Agent')
    });

    const assessment = {
      id,
      tenant_id: tenantId,
      client_id,
      status: 'draft',
      responses,
      results,
      score,
      completed_at: null,
      created_by: userId,
      created_at: new Date(now * 1000).toISOString(),
      updated_at: new Date(now * 1000).toISOString(),
    };

    return c.json(assessment);
  } catch (error: any) {
    console.error('Failed to create assessment:', error);
    return c.json({ error: 'Failed to create assessment' }, 500);
  }
});

router.patch('/:id', async (c) => {
  const userId = c.get('user_id');
  const id = c.req.param('id');
  const body = await c.req.json();

  try {
    const existing = await c.env.DB.prepare(`
      SELECT tenant_id FROM assessments WHERE id = ? AND created_by = ?
    `).bind(id, userId).first();

    if (!existing) {
      return c.json({ error: 'Assessment not found' }, 404);
    }

    const updates: string[] = [];
    const bindings: any[] = [];

    if (body.responses !== undefined) {
      updates.push('responses = ?');
      bindings.push(JSON.stringify(body.responses));
    }

    if (body.results !== undefined) {
      updates.push('results = ?');
      bindings.push(JSON.stringify(body.results));
      updates.push('score = ?');
      bindings.push(body.results.totalCredit || 0);
    }

    if (body.status !== undefined) {
      updates.push('status = ?');
      bindings.push(body.status);

      if (body.status === 'completed' && !body.results) {
        updates.push('completed_at = ?');
        bindings.push(Math.floor(Date.now() / 1000));
      }
    }

    if (updates.length === 0) {
      return c.json({ error: 'No updates provided' }, 400);
    }

    const now = Math.floor(Date.now() / 1000);
    updates.push('updated_at = ?');
    bindings.push(now);

    bindings.push(id);

    await c.env.DB.prepare(`
      UPDATE assessments
      SET ${updates.join(', ')}
      WHERE id = ?
    `).bind(...bindings).run();

    await auditLogger(c.env, {
      tenant_id: existing.tenant_id as string,
      user_id: userId,
      action: 'update',
      resource_type: 'assessment',
      resource_id: id,
      ip_address: c.get('user_ip'),
      user_agent: c.req.header('User-Agent')
    });

    const result = await c.env.DB.prepare(`
      SELECT
        id,
        tenant_id,
        client_id,
        status,
        responses,
        results,
        score,
        completed_at,
        created_by,
        created_at,
        updated_at
      FROM assessments
      WHERE id = ?
    `).bind(id).first();

    const assessment = {
      ...result,
      responses: JSON.parse(result!.responses as string),
      results: JSON.parse(result!.results as string),
      created_at: new Date((result!.created_at as number) * 1000).toISOString(),
      updated_at: new Date((result!.updated_at as number) * 1000).toISOString(),
      completed_at: result!.completed_at ? new Date((result!.completed_at as number) * 1000).toISOString() : null,
    };

    return c.json(assessment);
  } catch (error: any) {
    console.error('Failed to update assessment:', error);
    return c.json({ error: 'Failed to update assessment' }, 500);
  }
});

router.delete('/:id', async (c) => {
  const userId = c.get('user_id');
  const id = c.req.param('id');

  try {
    const existing = await c.env.DB.prepare(`
      SELECT tenant_id FROM assessments WHERE id = ? AND created_by = ?
    `).bind(id, userId).first();

    if (!existing) {
      return c.json({ error: 'Assessment not found' }, 404);
    }

    await c.env.DB.prepare(`
      DELETE FROM assessments WHERE id = ?
    `).bind(id).run();

    await auditLogger(c.env, {
      tenant_id: existing.tenant_id as string,
      user_id: userId,
      action: 'delete',
      resource_type: 'assessment',
      resource_id: id,
      ip_address: c.get('user_ip'),
      user_agent: c.req.header('User-Agent')
    });

    return c.json({ success: true });
  } catch (error: any) {
    console.error('Failed to delete assessment:', error);
    return c.json({ error: 'Failed to delete assessment' }, 500);
  }
});

export const assessmentsRouter = router;
