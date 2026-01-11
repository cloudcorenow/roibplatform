import { Hono } from 'hono';
import { z } from 'zod';
import { Env } from '../worker';
import { withRetry } from '../utils/retry';
import { auditLogger } from '../utils/audit';
import { requirePermission, createSecurityContext } from '../utils/security';

const quickBooksRouter = new Hono<{ Bindings: Env }>();

// Validation schemas
const configSchema = z.object({
  companyId: z.string().min(1),
  accessToken: z.string().min(1),
  refreshToken: z.string().optional(),
  sandbox: z.boolean().default(true)
});

interface QuickBooksRequestOptions {
  method?: string;
  body?: string;
}

async function makeQuickBooksRequest(
  env: Env,
  endpoint: string,
  companyId: string,
  accessToken: string,
  options: QuickBooksRequestOptions = {}
): Promise<Response> {
  const { method = 'GET', body } = options;
  const baseUrl = 'https://sandbox-quickbooks.api.intuit.com'; // Use sandbox for demo
  const url = `${baseUrl}/v3/company/${companyId}/${endpoint}`;

  return withRetry(async () => {
    const response = await fetch(url, {
      method,
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json',
        'Content-Type': 'application/json',
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
        const error = new Error(`QuickBooks API Error: ${response.status} ${response.statusText}`);
        (error as any).cause = 'client_error';
        throw error;
      }
      
      throw new Error(`QuickBooks API Error: ${response.status} ${response.statusText}`);
    }

    return response;
  }, 3, (attempt, error) => {
    // Custom delay for rate limiting
    if (error instanceof Error && (error as any).cause === 'rate_limit') {
      const match = error.message.match(/Retry after (\d+)ms/);
      return match ? parseInt(match[1]) : 5000;
    }
    return Math.min(1000 * Math.pow(2, attempt - 1), 10000);
  });
}

// GET /api/quickbooks/customers - Fetch customers with tenant isolation
quickBooksRouter.get('/customers', async (c) => {
  try {
    const tenantId = c.get('tenant_id');
    const securityContext = createSecurityContext(c);
    
    // Check permissions
    requirePermission(securityContext, 'clients:read');
    
    // Get QuickBooks config from KV with tenant isolation
    const configKey = `quickbooks:config:${tenantId}`;
    const configData = await c.env.KV.get(configKey);
    
    if (!configData) {
      return c.json({ 
        error: 'QuickBooks not configured',
        code: 'NOT_CONFIGURED'
      }, 400);
    }

    const config = configSchema.parse(JSON.parse(configData));
    
    // Check cache first
    const cacheKey = `quickbooks:customers:${tenantId}`;
    const cached = await c.env.KV.get(cacheKey);
    if (cached) {
      return c.json(JSON.parse(cached));
    }
    
    const response = await makeQuickBooksRequest(
      c.env, 
      'customers', 
      config.companyId, 
      config.accessToken
    );
    
    const data = await response.json();
    
    // Cache for 2 hours
    await c.env.KV.put(cacheKey, JSON.stringify(data), { expirationTtl: 7200 });
    
    return c.json(data);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({ 
        error: 'Invalid QuickBooks configuration', 
        details: error.errors.map(e => e.message).join(', '),
        code: 'VALIDATION_ERROR'
      }, 400);
    }
    console.error('QuickBooks customers error:', error);
    const status = error instanceof Error && (error as any).cause === 'client_error' ? 400 : 500;
    return c.json({ 
      error: 'Failed to fetch customers from QuickBooks',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'QUICKBOOKS_ERROR'
    }, status);
  }
});

// GET /api/quickbooks/employees - Fetch employees with tenant isolation
quickBooksRouter.get('/employees', async (c) => {
  try {
    const tenantId = c.get('tenant_id');
    const securityContext = createSecurityContext(c);
    
    // Check permissions
    requirePermission(securityContext, 'users:read');
    
    // Get QuickBooks config from KV with tenant isolation
    const configKey = `quickbooks:config:${tenantId}`;
    const configData = await c.env.KV.get(configKey);
    
    if (!configData) {
      return c.json({ 
        error: 'QuickBooks not configured',
        code: 'NOT_CONFIGURED'
      }, 400);
    }

    const config = configSchema.parse(JSON.parse(configData));
    
    // Check cache first
    const cacheKey = `quickbooks:employees:${tenantId}`;
    const cached = await c.env.KV.get(cacheKey);
    if (cached) {
      return c.json(JSON.parse(cached));
    }
    
    const response = await makeQuickBooksRequest(
      c.env, 
      'employees', 
      config.companyId, 
      config.accessToken
    );
    
    const data = await response.json();
    
    // Cache for 4 hours (employee data changes less frequently)
    await c.env.KV.put(cacheKey, JSON.stringify(data), { expirationTtl: 14400 });
    
    return c.json(data);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({ 
        error: 'Invalid QuickBooks configuration', 
        details: error.errors.map(e => e.message).join(', '),
        code: 'VALIDATION_ERROR'
      }, 400);
    }
    console.error('QuickBooks employees error:', error);
    const status = error instanceof Error && (error as any).cause === 'client_error' ? 400 : 500;
    return c.json({ 
      error: 'Failed to fetch employees from QuickBooks',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'QUICKBOOKS_ERROR'
    }, status);
  }
});

// POST /api/quickbooks/config - Store QuickBooks configuration with tenant isolation
quickBooksRouter.post('/config', async (c) => {
  try {
    const tenantId = c.get('tenant_id');
    const userId = c.get('user_id');
    const securityContext = createSecurityContext(c);
    
    // Check permissions
    requirePermission(securityContext, 'system:manage');
    
    const body = await c.req.json();
    const config = configSchema.parse(body);

    // Store config in KV with tenant isolation
    const configKey = `quickbooks:config:${tenantId}`;
    await c.env.KV.put(configKey, JSON.stringify(config));

    // Audit log for configuration change
    await auditLogger(c.env, {
      tenant_id: tenantId,
      user_id: userId,
      action: 'update',
      resource_type: 'quickbooks_config',
      ip_address: c.get('user_ip'),
      new_values: JSON.stringify({ companyId: config.companyId, sandbox: config.sandbox })
    });

    return c.json({ success: true });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({ 
        error: 'Invalid configuration', 
        details: error.errors.map(e => e.message).join(', '),
        code: 'VALIDATION_ERROR'
      }, 400);
    }
    console.error('QuickBooks config error:', error);
    return c.json({ 
      error: 'Failed to save configuration',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'CONFIG_ERROR'
    }, 500);
  }
});

export { quickBooksRouter };