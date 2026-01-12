import { Hono } from 'hono';
import { z } from 'zod';
import { Env } from '../worker';
import { TimeEntryCreateSchema, dateRangeSchema, sanitizeInput } from '../utils/validation';
import { TimeEntriesQueries } from '../utils/d1-queries';
import { invalidateCache } from '../utils/d1-helpers';

const timeEntriesRouter = new Hono<{ Bindings: Env }>();


// GET /api/time-entries - List time entries with HARD CAP and tenant isolation
timeEntriesRouter.get('/', async (c) => {
  const tenantId = c.get('tenantId') || c.get('tenant_id');
  const userId = c.get('userId') || c.get('user_id');
  const auditLogger = c.get('auditLogger');
  const rbacManager = c.get('rbacManager');
  const ipAddress = c.get('ipAddress');
  const userAgent = c.get('userAgent');
  const requestId = c.get('requestId');

  try {
    // Check RBAC permission
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: 'time_entry',
      action: 'read',
      resourceId: 'list'
    });

    if (!access.allowed) {
      await auditLogger.log({
        tenantId,
        userId,
        action: 'READ',
        resourceType: 'time_entry',
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

    const from = c.req.query('from') ?? '0000-01-01';
    const to = c.req.query('to') ?? '9999-12-31';
    const limit = Math.min(parseInt(c.req.query('limit') ?? '50', 10), 200);
    const offset = Math.max(parseInt(c.req.query('offset') ?? '0', 10), 0);

    const dateRange = dateRangeSchema.safeParse({ from, to });
    if (!dateRange.success) {
      return c.json({
        error: 'Invalid date range',
        details: dateRange.error.errors.map(e => e.message).join(', '),
        code: 'VALIDATION_ERROR'
      }, 400);
    }

    const queries = new TimeEntriesQueries(c.env);
    const result = await queries.listWithPagination(tenantId, { limit, offset, from, to });

    await auditLogger.log({
      tenantId,
      userId,
      action: 'READ',
      resourceType: 'time_entry',
      resourceId: 'list',
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        recordCount: result.items.length,
        phiFields: ['notes', 'client', 'project'],
        limit,
        offset
      }
    });

    return c.json({
      items: result.items,
      paging: {
        from, to, limit, offset,
        prevOffset: offset > 0 ? Math.max(0, offset - limit) : null,
        nextOffset: result.hasMore ? offset + limit : null
      },
      total: result.total
    });
  } catch (error) {
    await auditLogger.log({
      tenantId,
      userId,
      action: 'READ',
      resourceType: 'time_entry',
      resourceId: 'list',
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error instanceof Error ? error.message : 'Unknown error',
      phiAccessed: false
    });

    console.error('Error fetching time entries:', error);
    return c.json({
      error: 'Failed to fetch time entries',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'FETCH_ERROR'
    }, 500);
  }
});

// GET /api/time-entries/:id - Get single time entry with tenant isolation
timeEntriesRouter.get('/:id', async (c) => {
  const tenantId = c.get('tenantId') || c.get('tenant_id');
  const userId = c.get('userId') || c.get('user_id');
  const id = c.req.param('id');
  const auditLogger = c.get('auditLogger');
  const rbacManager = c.get('rbacManager');
  const ipAddress = c.get('ipAddress');
  const userAgent = c.get('userAgent');
  const requestId = c.get('requestId');

  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: 'time_entry',
      action: 'read',
      resourceId: id
    });

    if (!access.allowed) {
      await auditLogger.log({
        tenantId,
        userId,
        action: 'READ',
        resourceType: 'time_entry',
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

    const queries = new TimeEntriesQueries(c.env);
    const row = await queries.getById(tenantId, id);

    if (!row) {
      await auditLogger.log({
        tenantId,
        userId,
        action: 'READ',
        resourceType: 'time_entry',
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: 'Time entry not found',
        phiAccessed: false
      });

      return c.json({
        error: 'Time entry not found',
        code: 'NOT_FOUND'
      }, 404);
    }

    await auditLogger.log({
      tenantId,
      userId,
      action: 'READ',
      resourceType: 'time_entry',
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        phiFields: ['notes', 'client', 'project']
      }
    });

    return c.json({ data: { ...row, tenantId } });
  } catch (error) {
    await auditLogger.log({
      tenantId,
      userId,
      action: 'READ',
      resourceType: 'time_entry',
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error instanceof Error ? error.message : 'Unknown error',
      phiAccessed: false
    });

    console.error('Error fetching time entry:', error);
    return c.json({
      error: 'Failed to fetch time entry',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'FETCH_ERROR'
    }, 500);
  }
});

// POST /api/time-entries - Create new time entry with tenant isolation
timeEntriesRouter.post('/', async (c) => {
  const tenantId = c.get('tenantId') || c.get('tenant_id');
  const userId = c.get('userId') || c.get('user_id');
  const auditLogger = c.get('auditLogger');
  const rbacManager = c.get('rbacManager');
  const ipAddress = c.get('ipAddress');
  const userAgent = c.get('userAgent');
  const requestId = c.get('requestId');

  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: 'time_entry',
      action: 'create',
      resourceId: 'new'
    });

    if (!access.allowed) {
      await auditLogger.log({
        tenantId,
        userId,
        action: 'CREATE',
        resourceType: 'time_entry',
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

    const body = await c.req.json();
    const validatedData = TimeEntryCreateSchema.parse(body);

    const sanitizedData = {
      ...validatedData,
      client: sanitizeInput(validatedData.client, 255),
      project: sanitizeInput(validatedData.project, 255),
      service: sanitizeInput(validatedData.service, 255),
      notes: validatedData.notes ? sanitizeInput(validatedData.notes, 10000) : undefined
    };

    const id = crypto.randomUUID();
    const queries = new TimeEntriesQueries(c.env);

    await queries.create(tenantId, userId, {
      id,
      date: sanitizedData.date,
      client: sanitizedData.client,
      project: sanitizedData.project,
      service: sanitizedData.service,
      durationMin: sanitizedData.durationMin,
      notes: sanitizedData.notes,
      isRnD: sanitizedData.isRnD
    });

    await invalidateCache(c.env.KV, `analytics:${tenantId}`);

    await auditLogger.log({
      tenantId,
      userId,
      action: 'CREATE',
      resourceType: 'time_entry',
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        phiFields: ['notes', 'client', 'project'],
        data: sanitizedData
      }
    });

    const created = await queries.getById(tenantId, id);

    return c.json({ data: { ...created, tenantId } }, 201);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({
        error: 'Validation failed',
        details: error.errors.map(e => e.message).join(', '),
        code: 'VALIDATION_ERROR'
      }, 400);
    }

    await auditLogger.log({
      tenantId,
      userId,
      action: 'CREATE',
      resourceType: 'time_entry',
      resourceId: 'new',
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error instanceof Error ? error.message : 'Unknown error',
      phiAccessed: false
    });

    console.error('Error creating time entry:', error);
    return c.json({
      error: 'Failed to create time entry',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'CREATE_ERROR'
    }, 500);
  }
});

// DELETE /api/time-entries/:id - Delete time entry with tenant isolation
timeEntriesRouter.delete('/:id', async (c) => {
  const tenantId = c.get('tenantId') || c.get('tenant_id');
  const userId = c.get('userId') || c.get('user_id');
  const id = c.req.param('id');
  const auditLogger = c.get('auditLogger');
  const rbacManager = c.get('rbacManager');
  const ipAddress = c.get('ipAddress');
  const userAgent = c.get('userAgent');
  const requestId = c.get('requestId');

  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: 'time_entry',
      action: 'delete',
      resourceId: id
    });

    if (!access.allowed) {
      await auditLogger.log({
        tenantId,
        userId,
        action: 'DELETE',
        resourceType: 'time_entry',
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

    const queries = new TimeEntriesQueries(c.env);
    const existing = await queries.delete(tenantId, id);

    if (!existing) {
      await auditLogger.log({
        tenantId,
        userId,
        action: 'DELETE',
        resourceType: 'time_entry',
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: 'Time entry not found',
        phiAccessed: false
      });

      return c.json({
        error: 'Time entry not found',
        code: 'NOT_FOUND'
      }, 404);
    }

    await invalidateCache(c.env.KV, `analytics:${tenantId}`);

    await auditLogger.log({
      tenantId,
      userId,
      action: 'DELETE',
      resourceType: 'time_entry',
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        note: 'Time entry with PHI data deleted',
        oldData: existing
      }
    });

    return c.json({ success: true });
  } catch (error) {
    await auditLogger.log({
      tenantId,
      userId,
      action: 'DELETE',
      resourceType: 'time_entry',
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error instanceof Error ? error.message : 'Unknown error',
      phiAccessed: false
    });

    console.error('Error deleting time entry:', error);
    return c.json({
      error: 'Failed to delete time entry',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'DELETE_ERROR'
    }, 500);
  }
});

timeEntriesRouter.post('/batch', async (c) => {
  const tenantId = c.get('tenantId') || c.get('tenant_id');
  const userId = c.get('userId') || c.get('user_id');
  const auditLogger = c.get('auditLogger');
  const rbacManager = c.get('rbacManager');
  const ipAddress = c.get('ipAddress');
  const userAgent = c.get('userAgent');
  const requestId = c.get('requestId');

  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: 'time_entry',
      action: 'create',
      resourceId: 'batch'
    });

    if (!access.allowed) {
      await auditLogger.log({
        tenantId,
        userId,
        action: 'BATCH_CREATE',
        resourceType: 'time_entry',
        resourceId: 'batch',
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });

      return c.json({ error: access.reason || 'Access denied' }, 403);
    }

    const body = await c.req.json();

    if (!Array.isArray(body.entries) || body.entries.length === 0) {
      return c.json({
        error: 'Request must include entries array',
        code: 'VALIDATION_ERROR'
      }, 400);
    }

    if (body.entries.length > 100) {
      return c.json({
        error: 'Maximum 100 entries per batch',
        code: 'VALIDATION_ERROR'
      }, 400);
    }

    const sanitizedEntries = body.entries.map((entry: any) => {
      const validatedData = TimeEntryCreateSchema.parse(entry);
      return {
        id: crypto.randomUUID(),
        date: validatedData.date,
        client: sanitizeInput(validatedData.client, 255),
        project: sanitizeInput(validatedData.project, 255),
        service: sanitizeInput(validatedData.service, 255),
        durationMin: validatedData.durationMin,
        notes: validatedData.notes ? sanitizeInput(validatedData.notes, 10000) : undefined,
        isRnD: validatedData.isRnD
      };
    });

    const queries = new TimeEntriesQueries(c.env);
    await queries.batchCreate(tenantId, userId, sanitizedEntries);

    await invalidateCache(c.env.KV, `analytics:${tenantId}`);

    await auditLogger.log({
      tenantId,
      userId,
      action: 'BATCH_CREATE',
      resourceType: 'time_entry',
      resourceId: 'batch',
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        phiFields: ['notes', 'client', 'project'],
        count: sanitizedEntries.length,
        ids: sanitizedEntries.map(e => e.id)
      }
    });

    return c.json({
      success: true,
      count: sanitizedEntries.length,
      ids: sanitizedEntries.map(e => e.id)
    }, 201);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({
        error: 'Validation failed',
        details: error.errors.map(e => e.message).join(', '),
        code: 'VALIDATION_ERROR'
      }, 400);
    }

    await auditLogger.log({
      tenantId,
      userId,
      action: 'BATCH_CREATE',
      resourceType: 'time_entry',
      resourceId: 'batch',
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error instanceof Error ? error.message : 'Unknown error',
      phiAccessed: false
    });

    console.error('Error creating batch time entries:', error);
    return c.json({
      error: 'Failed to create batch time entries',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'CREATE_ERROR'
    }, 500);
  }
});

export { timeEntriesRouter };
