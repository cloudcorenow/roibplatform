import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { timeEntriesRouter } from './routes/timeEntries';
import { centralReachRouter } from './routes/centralReach';
import { quickBooksRouter } from './routes/quickBooks';
import { authRouter } from './routes/auth';
import { analyticsRouter } from './routes/analytics';
import { documentsRouter } from './routes/documents';
import { assessmentsRouter } from './routes/assessments';
import { auditLogger } from './utils/audit';
import { createCorsHeaders, handlePreflight } from './utils/cors';
import { validateUserId, rateLimitCheck } from './utils/security';
import { verifyJWT } from './utils/auth';
import { sessionTimeoutMiddleware, sessionCleanupMiddleware } from './middleware/sessionTimeout';
import type { Env, HonoEnv } from './types';

export type { Env } from './types';

const app = new Hono<HonoEnv>();

// Global CORS middleware with environment-specific origins
app.use('*', async (c, next) => {
  const origin = c.req.header('Origin') || '';
  const allowedOrigins = [
    'http://localhost:5173',
    'https://localhost:5173',
    'https://meek-cheesecake-1382d7.netlify.app',
    c.env.APP_ORIGIN
  ].filter(Boolean);

  // Handle preflight requests
  if (c.req.method === 'OPTIONS') {
    return handlePreflight(origin, allowedOrigins);
  }

  await next();

  // Add CORS headers to all responses
  const corsHeaders = createCorsHeaders(origin, allowedOrigins);
  Object.entries(corsHeaders).forEach(([key, value]) => {
    c.res.headers.set(key, value);
  });
});

// Session cleanup middleware (runs periodically)
app.use('/api/*', sessionCleanupMiddleware);

// Rate limiting middleware
app.use('/api/*', async (c, next) => {
  const ip = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown';
  const rateLimitKey = `api:${ip}`;

  const allowed = await rateLimitCheck(c.env, rateLimitKey, 1000, 60000); // 1000 requests per minute
  if (!allowed) {
    return c.json({
      error: 'Rate limit exceeded',
      code: 'RATE_LIMIT_EXCEEDED'
    }, 429);
  }

  await next();
});

// JWT middleware for protected routes (skip auth routes)
app.use('/api/*', async (c, next) => {
  // Skip auth middleware for auth routes and health check
  if (c.req.path.startsWith('/api/auth/') || c.req.path === '/health') {
    return next();
  }

  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({
      error: 'Missing or invalid authorization header',
      code: 'UNAUTHORIZED'
    }, 401);
  }

  const token = authHeader.substring(7);
  try {
    const payload = await verifyJWT(token, c.env.JWT_SECRET);

    const userId = payload.user_id;
    const userRole = payload.role;
    const userEmail = payload.email;
    const userType = payload.user_type;
    const tenantId = payload.tenant_id;
    const readOnly = payload.read_only || false;

    if (!validateUserId(userId)) {
      return c.json({
        error: 'Invalid user ID format',
        code: 'INVALID_USER'
      }, 400);
    }

    if (userType === 'platform' && !tenantId) {
      return c.json({
        error: 'Tenant context required for platform admin',
        code: 'TENANT_CONTEXT_REQUIRED'
      }, 400);
    }

    if (readOnly && !['GET', 'HEAD', 'OPTIONS'].includes(c.req.method)) {
      return c.json({
        error: 'Read-only mode active. Write operations are not permitted.',
        code: 'READ_ONLY_MODE'
      }, 403);
    }

    c.set('user_id', userId);
    c.set('user_role', userRole);
    c.set('user_email', userEmail);
    c.set('user_type', userType);
    c.set('tenant_id', tenantId || 'default');
    c.set('read_only', readOnly);
    c.set('user_ip', c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown');

    await auditLogger(c.env, {
      tenant_id: tenantId || 'default',
      user_id: userId,
      action: 'api_access',
      resource_type: 'api',
      resource_id: c.req.path,
      ip_address: c.get('user_ip'),
      user_agent: c.req.header('User-Agent'),
      details: userType === 'platform' ? JSON.stringify({ acting_as_tenant: tenantId, read_only: readOnly }) : undefined
    }).catch(error => {
      console.error('Audit logging failed:', error);
    });

  } catch (error) {
    return c.json({
      error: 'Invalid or expired token',
      code: 'TOKEN_INVALID'
    }, 401);
  }

  await next();
});

// Session timeout middleware (checks for inactive sessions)
app.use('/api/*', sessionTimeoutMiddleware);

// Routes
app.route('/api/auth', authRouter);
app.route('/api/time-entries', timeEntriesRouter);
app.route('/api/analytics', analyticsRouter);
app.route('/api/documents', documentsRouter);
app.route('/api/assessments', assessmentsRouter);
app.route('/api/centralreach', centralReachRouter);
app.route('/api/quickbooks', quickBooksRouter);

// Health check
app.get('/health', (c) => {
  return c.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    environment: c.env.ENVIRONMENT || 'unknown'
  });
});

// Global error handler
app.onError((err, c) => {
  console.error('Unhandled error:', err);
  
  return c.json({
    error: 'Internal server error',
    code: 'INTERNAL_ERROR',
    timestamp: new Date().toISOString()
  }, 500);
});

// 404 handler
app.notFound((c) => {
  return c.json({
    error: 'Not found',
    code: 'NOT_FOUND',
    path: c.req.path
  }, 404);
});

export default app;