import { Hono } from 'hono';
import { z } from 'zod';
import { Env } from '../worker';
import { withRetry } from '../utils/retry';
import { auditLogger } from '../utils/audit';
import { requirePermission, createSecurityContext } from '../utils/security';

const centralReachRouter = new Hono<{ Bindings: Env }>();

// Validation schemas
const syncRequestSchema = z.object({
  syncType: z.enum(['clients', 'staff', 'timeentries', 'all'])
});

interface CentralReachRequestOptions {
  method?: string;
  body?: string;
  retries?: number;
}

async function makeCentralReachRequest(
  env: Env,
  endpoint: string,
  options: CentralReachRequestOptions = {}
): Promise<Response> {
  const { method = 'GET', body } = options;
  const url = `${env.CENTRALREACH_BASE_URL}/${endpoint}`;

  return withRetry(async () => {
    const response = await fetch(url, {
      method,
      headers: {
        'Authorization': `Bearer ${env.CENTRALREACH_API_KEY}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body,
      signal: AbortSignal.timeout(30000), // 30 second timeout
    });

    if (!response.ok) {
      // Handle rate limiting
      if (response.status === 429) {
        const retryAfter = response.headers.get('Retry-After');
        const delay = retryAfter ? parseInt(retryAfter) * 1000 : 5000;
        const error = new Error(`Rate limited. Retry after ${delay}ms`);
        (error as any).cause = 'rate_limit';
        throw error;
      }
      
      // Don't retry on client errors (4xx)
      if (response.status >= 400 && response.status < 500) {
        const error = new Error(`CentralReach API Error: ${response.status} ${response.statusText}`);
        (error as any).cause = 'client_error';
        throw error;
      }
      
      throw new Error(`CentralReach API Error: ${response.status} ${response.statusText}`);
    }

    return response;
  }, 3, (attempt, error) => {
    // Custom delay for rate limiting
    if (error instanceof Error && (error as any).cause === 'rate_limit') {
      const match = error.message.match(/Retry after (\d+)ms/);
      return match ? parseInt(match[1]) : 5000;
    }
    // Exponential backoff with max 10s
    return Math.min(1000 * Math.pow(2, attempt - 1), 10000);
  });
}

// GET /api/centralreach/clients - Fetch clients with caching
centralReachRouter.get('/clients', async (c) => {
  try {
    const tenantId = c.get('tenant_id');
    const securityContext = createSecurityContext(c);
    
    // Check permissions
    requirePermission(securityContext, 'clients:read');
    
    // Check KV cache first
    const cacheKey = `centralreach:clients:${tenantId}`;
    const cached = await c.env.KV.get(cacheKey);
    if (cached) {
      return c.json(JSON.parse(cached));
    }

    const response = await makeCentralReachRequest(c.env, 'clients');
    const data = await response.json();
    
    // Cache for 1 hour
    await c.env.KV.put(cacheKey, JSON.stringify(data), { expirationTtl: 3600 });
    
    return c.json(data);
  } catch (error) {
    console.error('CentralReach clients error:', error);
    const status = error instanceof Error && (error as any).cause === 'client_error' ? 400 : 500;
    return c.json({ 
      error: 'Failed to fetch clients from CentralReach',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'CENTRALREACH_ERROR'
    }, status);
  }
});

// GET /api/centralreach/staff - Fetch staff with caching
centralReachRouter.get('/staff', async (c) => {
  try {
    const tenantId = c.get('tenant_id');
    const securityContext = createSecurityContext(c);
    
    // Check permissions
    requirePermission(securityContext, 'users:read');
    
    // Check KV cache first
    const cacheKey = `centralreach:staff:${tenantId}`;
    const cached = await c.env.KV.get(cacheKey);
    if (cached) {
      return c.json(JSON.parse(cached));
    }

    const response = await makeCentralReachRequest(c.env, 'staff');
    const data = await response.json();
    
    // Cache for 1 hour
    await c.env.KV.put(cacheKey, JSON.stringify(data), { expirationTtl: 3600 });
    
    return c.json(data);
  } catch (error) {
    console.error('CentralReach staff error:', error);
    const status = error instanceof Error && (error as any).cause === 'client_error' ? 400 : 500;
    return c.json({ 
      error: 'Failed to fetch staff from CentralReach',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'CENTRALREACH_ERROR'
    }, status);
  }
});

// GET /api/centralreach/timeentries - Fetch time entries with caching
centralReachRouter.get('/timeentries', async (c) => {
  try {
    const tenantId = c.get('tenant_id');
    const securityContext = createSecurityContext(c);
    
    // Check permissions
    requirePermission(securityContext, 'time:read');
    
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');
    const clientId = c.req.query('clientId');

    // Build cache key
    const cacheKey = `centralreach:timeentries:${tenantId}:${startDate}:${endDate}:${clientId}`;
    const cached = await c.env.KV.get(cacheKey);
    if (cached) {
      return c.json(JSON.parse(cached));
    }

    let endpoint = 'timeentries';
    const params = new URLSearchParams();
    
    if (startDate) params.append('startDate', startDate);
    if (endDate) params.append('endDate', endDate);
    if (clientId) params.append('clientId', clientId);

    if (params.toString()) {
      endpoint += `?${params.toString()}`;
    }

    const response = await makeCentralReachRequest(c.env, endpoint);
    const data = await response.json();
    
    // Cache for 30 minutes (shorter TTL for time data)
    await c.env.KV.put(cacheKey, JSON.stringify(data), { expirationTtl: 1800 });
    
    return c.json(data);
  } catch (error) {
    console.error('CentralReach time entries error:', error);
    const status = error instanceof Error && (error as any).cause === 'client_error' ? 400 : 500;
    return c.json({ 
      error: 'Failed to fetch time entries from CentralReach',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'CENTRALREACH_ERROR'
    }, status);
  }
});

// POST /api/centralreach/sync - Sync data from CentralReach with tenant isolation
centralReachRouter.post('/sync', async (c) => {
  try {
    const tenantId = c.get('tenant_id');
    const userId = c.get('user_id');
    const securityContext = createSecurityContext(c);
    
    // Check permissions
    requirePermission(securityContext, 'system:manage');
    
    const body = await c.req.json();
    const { syncType } = syncRequestSchema.parse(body);

    const results = [];

    if (syncType === 'clients' || syncType === 'all') {
      const response = await makeCentralReachRequest(c.env, 'clients');
      const clients = await response.json();
      
      // Store in KV for caching with tenant isolation
      await c.env.KV.put(`centralreach:clients:${tenantId}`, JSON.stringify(clients), {
        expirationTtl: 3600 // 1 hour cache
      });

      results.push({
        type: 'clients',
        success: true,
        count: clients.length,
        message: `Synced ${clients.length} clients`
      });
    }

    if (syncType === 'timeentries' || syncType === 'all') {
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - 30);
      const endDate = new Date();

      const response = await makeCentralReachRequest(
        c.env, 
        `timeentries?startDate=${startDate.toISOString().split('T')[0]}&endDate=${endDate.toISOString().split('T')[0]}`
      );
      const timeEntries = await response.json();

      // Convert and store in D1 with tenant isolation
      const batchStatements = timeEntries.map((entry: any) => 
        c.env.DB.prepare(`
          INSERT OR REPLACE INTO time_entries (
            id, tenant_id, date, client, project, service,
            duration_min, notes, is_rnd, external_id, external_source,
            created_by, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        `).bind(
          crypto.randomUUID(),
          tenantId, // TENANT ISOLATION
          entry.date || new Date().toISOString().split('T')[0],
          entry.clientName || 'Unknown Client',
          entry.serviceName || 'Unknown Service',
          entry.description || 'CentralReach Activity',
          entry.duration || 0,
          entry.notes || null,
          true, // Assume R&D for now
          entry.id,
          'centralreach',
          userId
        )
      );

      // Execute batch with retry
      await withRetry(async () => {
        return c.env.DB.batch(batchStatements);
      }, 3);

      results.push({
        type: 'timeentries',
        success: true,
        count: timeEntries.length,
        message: `Synced ${timeEntries.length} time entries`
      });
    }

    // Audit log for sync operation
    await auditLogger(c.env, {
      tenant_id: tenantId,
      user_id: userId,
      action: 'sync',
      resource_type: 'centralreach',
      ip_address: c.get('user_ip'),
      new_values: JSON.stringify({ syncType, results })
    });

    return c.json({
      success: true,
      results,
      syncedAt: new Date().toISOString()
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({ 
        error: 'Invalid sync request', 
        details: error.errors.map(e => e.message).join(', '),
        code: 'VALIDATION_ERROR'
      }, 400);
    }
    console.error('CentralReach sync error:', error);
    return c.json({ 
      error: 'Sync failed',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'SYNC_ERROR'
    }, 500);
  }
});

export { centralReachRouter };