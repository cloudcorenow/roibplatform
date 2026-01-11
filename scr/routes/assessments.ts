import { Hono } from 'hono';
import type { Env } from '../worker';

const router = new Hono<{ Bindings: Env }>();

router.get('/', async (c) => {
  const userId = c.get('userId') || c.get('user_id');
  const tenantId = c.get('tenantId') || c.req.query('tenant_id') || 'default';
  const auditLogger = c.get('auditLogger');
  const rbacManager = c.get('rbacManager');
  const ipAddress = c.get('ipAddress');
  const userAgent = c.get('userAgent');
  const requestId = c.get('requestId');
  const db = c.get('db');

  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: 'assessment',
      action: 'read',
      resourceId: 'list'
    });

    if (!access.allowed) {
      await auditLogger.log({
        tenantId,
        userId,
        action: 'READ',
        resourceType: 'assessment',
        resourceId: 'list',
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });

      return c.json({ error: access.reason || 'Access denied' }, 403);
    }

    const result = await db.prepare(`
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

    await auditLogger.log({
      tenantId,
      userId,
      action: 'READ',
      resourceType: 'assessment',
      resourceId: 'list',
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        recordCount: assessments.length,
        phiFields: ['responses', 'results']
      }
    });

    return c.json(assessments);
  } catch (error: any) {
    await auditLogger.log({
      tenantId,
      userId,
      action: 'READ',
      resourceType: 'assessment',
      resourceId: 'list',
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error.message,
      phiAccessed: false
    });

    console.error('Failed to fetch assessments:', error);
    return c.json({ error: 'Failed to fetch assessments' }, 500);
  }
});

router.get('/client/:clientId', async (c) => {
  const userId = c.get('userId') || c.get('user_id');
  const tenantId = c.get('tenantId') || c.req.query('tenant_id') || 'default';
  const clientId = c.req.param('clientId');
  const auditLogger = c.get('auditLogger');
  const rbacManager = c.get('rbacManager');
  const ipAddress = c.get('ipAddress');
  const userAgent = c.get('userAgent');
  const requestId = c.get('requestId');
  const db = c.get('db');

  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: 'assessment',
      action: 'read',
      resourceId: clientId
    });

    if (!access.allowed) {
      await auditLogger.log({
        tenantId,
        userId,
        action: 'READ',
        resourceType: 'assessment',
        resourceId: clientId,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });

      return c.json({ error: access.reason || 'Access denied' }, 403);
    }

    const result = await db.prepare(`
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

    await auditLogger.log({
      tenantId,
      userId,
      action: 'READ',
      resourceType: 'assessment',
      resourceId: clientId,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        recordCount: assessments.length,
        phiFields: ['responses', 'results'],
        clientId
      }
    });

    return c.json(assessments);
  } catch (error: any) {
    await auditLogger.log({
      tenantId,
      userId,
      action: 'READ',
      resourceType: 'assessment',
      resourceId: clientId,
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error.message,
      phiAccessed: false
    });

    console.error('Failed to fetch client assessments:', error);
    return c.json({ error: 'Failed to fetch client assessments' }, 500);
  }
});

router.get('/:id', async (c) => {
  const userId = c.get('userId') || c.get('user_id');
  const id = c.req.param('id');
  const auditLogger = c.get('auditLogger');
  const rbacManager = c.get('rbacManager');
  const tenantId = c.get('tenantId');
  const ipAddress = c.get('ipAddress');
  const userAgent = c.get('userAgent');
  const requestId = c.get('requestId');
  const db = c.get('db');

  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: 'assessment',
      action: 'read',
      resourceId: id
    });

    if (!access.allowed) {
      await auditLogger.log({
        tenantId,
        userId,
        action: 'READ',
        resourceType: 'assessment',
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });

      return c.json({ error: access.reason || 'Access denied' }, 403);
    }

    const result = await db.prepare(`
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
      await auditLogger.log({
        tenantId,
        userId,
        action: 'READ',
        resourceType: 'assessment',
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: 'Assessment not found',
        phiAccessed: false
      });

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

    await auditLogger.log({
      tenantId: result.tenant_id as string,
      userId,
      action: 'READ',
      resourceType: 'assessment',
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        phiFields: ['responses', 'results']
      }
    });

    return c.json(assessment);
  } catch (error: any) {
    await auditLogger.log({
      tenantId,
      userId,
      action: 'READ',
      resourceType: 'assessment',
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error.message,
      phiAccessed: false
    });

    console.error('Failed to fetch assessment:', error);
    return c.json({ error: 'Failed to fetch assessment' }, 500);
  }
});

router.post('/', async (c) => {
  const userId = c.get('userId') || c.get('user_id');
  const tenantId = c.get('tenantId');
  const auditLogger = c.get('auditLogger');
  const rbacManager = c.get('rbacManager');
  const ipAddress = c.get('ipAddress');
  const userAgent = c.get('userAgent');
  const requestId = c.get('requestId');
  const db = c.get('db');

  const body = await c.req.json();
  const { tenant_id, client_id, responses, results } = body;

  if (!client_id || !responses || !results) {
    return c.json({ error: 'Missing required fields' }, 400);
  }

  const finalTenantId = tenant_id || tenantId || 'default';

  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId: finalTenantId,
      resourceType: 'assessment',
      action: 'create',
      resourceId: 'new'
    });

    if (!access.allowed) {
      await auditLogger.log({
        tenantId: finalTenantId,
        userId,
        action: 'CREATE',
        resourceType: 'assessment',
        resourceId: 'new',
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });

      return c.json({ error: access.reason || 'Access denied' }, 403);
    }

    const id = crypto.randomUUID().replace(/-/g, '').toLowerCase();
    const score = results.totalCredit || 0;
    const now = Math.floor(Date.now() / 1000);

    await db.prepare(`
      INSERT INTO assessments (
        id, tenant_id, client_id, status, responses, results, score, created_by, created_at, updated_at
      ) VALUES (?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      finalTenantId,
      client_id,
      JSON.stringify(responses),
      JSON.stringify(results),
      score,
      userId,
      now,
      now
    ).run();

    await auditLogger.log({
      tenantId: finalTenantId,
      userId,
      action: 'CREATE',
      resourceType: 'assessment',
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        phiFields: ['responses', 'results'],
        clientId: client_id
      }
    });

    const assessment = {
      id,
      tenant_id: finalTenantId,
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
    await auditLogger.log({
      tenantId: finalTenantId,
      userId,
      action: 'CREATE',
      resourceType: 'assessment',
      resourceId: 'new',
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error.message,
      phiAccessed: false
    });

    console.error('Failed to create assessment:', error);
    return c.json({ error: 'Failed to create assessment' }, 500);
  }
});

router.patch('/:id', async (c) => {
  const userId = c.get('userId') || c.get('user_id');
  const id = c.req.param('id');
  const auditLogger = c.get('auditLogger');
  const rbacManager = c.get('rbacManager');
  const tenantId = c.get('tenantId');
  const ipAddress = c.get('ipAddress');
  const userAgent = c.get('userAgent');
  const requestId = c.get('requestId');
  const db = c.get('db');

  const body = await c.req.json();

  try {
    const existing = await db.prepare(`
      SELECT tenant_id FROM assessments WHERE id = ? AND created_by = ?
    `).bind(id, userId).first();

    if (!existing) {
      await auditLogger.log({
        tenantId,
        userId,
        action: 'UPDATE',
        resourceType: 'assessment',
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: 'Assessment not found',
        phiAccessed: false
      });

      return c.json({ error: 'Assessment not found' }, 404);
    }

    const access = await rbacManager.checkAccess({
      userId,
      tenantId: existing.tenant_id as string,
      resourceType: 'assessment',
      action: 'update',
      resourceId: id
    });

    if (!access.allowed) {
      await auditLogger.log({
        tenantId: existing.tenant_id as string,
        userId,
        action: 'UPDATE',
        resourceType: 'assessment',
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });

      return c.json({ error: access.reason || 'Access denied' }, 403);
    }

    const updates: string[] = [];
    const bindings: any[] = [];
    const phiFieldsModified: string[] = [];

    if (body.responses !== undefined) {
      updates.push('responses = ?');
      bindings.push(JSON.stringify(body.responses));
      phiFieldsModified.push('responses');
    }

    if (body.results !== undefined) {
      updates.push('results = ?');
      bindings.push(JSON.stringify(body.results));
      updates.push('score = ?');
      bindings.push(body.results.totalCredit || 0);
      phiFieldsModified.push('results');
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

    await db.prepare(`
      UPDATE assessments
      SET ${updates.join(', ')}
      WHERE id = ?
    `).bind(...bindings).run();

    await auditLogger.log({
      tenantId: existing.tenant_id as string,
      userId,
      action: 'UPDATE',
      resourceType: 'assessment',
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: phiFieldsModified.length > 0,
      metadata: {
        phiFields: phiFieldsModified.length > 0 ? phiFieldsModified : undefined,
        fieldsUpdated: updates.length
      }
    });

    const result = await db.prepare(`
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
    await auditLogger.log({
      tenantId,
      userId,
      action: 'UPDATE',
      resourceType: 'assessment',
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error.message,
      phiAccessed: false
    });

    console.error('Failed to update assessment:', error);
    return c.json({ error: 'Failed to update assessment' }, 500);
  }
});

router.delete('/:id', async (c) => {
  const userId = c.get('userId') || c.get('user_id');
  const id = c.req.param('id');
  const auditLogger = c.get('auditLogger');
  const rbacManager = c.get('rbacManager');
  const tenantId = c.get('tenantId');
  const ipAddress = c.get('ipAddress');
  const userAgent = c.get('userAgent');
  const requestId = c.get('requestId');
  const db = c.get('db');

  try {
    const existing = await db.prepare(`
      SELECT tenant_id FROM assessments WHERE id = ? AND created_by = ?
    `).bind(id, userId).first();

    if (!existing) {
      await auditLogger.log({
        tenantId,
        userId,
        action: 'DELETE',
        resourceType: 'assessment',
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: 'Assessment not found',
        phiAccessed: false
      });

      return c.json({ error: 'Assessment not found' }, 404);
    }

    const access = await rbacManager.checkAccess({
      userId,
      tenantId: existing.tenant_id as string,
      resourceType: 'assessment',
      action: 'delete',
      resourceId: id
    });

    if (!access.allowed) {
      await auditLogger.log({
        tenantId: existing.tenant_id as string,
        userId,
        action: 'DELETE',
        resourceType: 'assessment',
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });

      return c.json({ error: access.reason || 'Access denied' }, 403);
    }

    await db.prepare(`
      DELETE FROM assessments WHERE id = ?
    `).bind(id).run();

    await auditLogger.log({
      tenantId: existing.tenant_id as string,
      userId,
      action: 'DELETE',
      resourceType: 'assessment',
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        note: 'Assessment with PHI data deleted'
      }
    });

    return c.json({ success: true });
  } catch (error: any) {
    await auditLogger.log({
      tenantId,
      userId,
      action: 'DELETE',
      resourceType: 'assessment',
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error.message,
      phiAccessed: false
    });

    console.error('Failed to delete assessment:', error);
    return c.json({ error: 'Failed to delete assessment' }, 500);
  }
});

export const assessmentsRouter = router;
