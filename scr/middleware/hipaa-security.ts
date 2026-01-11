import { Context, Next } from 'hono';
import { createSessionManager } from '../utils/session-manager';
import { createAuditLogger } from '../utils/audit-logger';
import { createRBACManager } from '../utils/rbac';
import { createPHIBoundary } from '../utils/phi-boundary';

export interface HIPAAContext {
  sessionManager: ReturnType<typeof createSessionManager>;
  auditLogger: ReturnType<typeof createAuditLogger>;
  rbacManager: ReturnType<typeof createRBACManager>;
  phiBoundary: ReturnType<typeof createPHIBoundary>;
  userId?: string;
  tenantId?: string;
  sessionId?: string;
  ipAddress?: string;
  userAgent?: string;
}

export function initializeHIPAASecurity(encryptionKey: string) {
  return async (c: Context, next: Next) => {
    const db = c.env.DB;

    if (!db) {
      return c.json({ error: 'Database not configured' }, 500);
    }

    const sessionManager = createSessionManager(db);
    const auditLogger = createAuditLogger(db);
    const rbacManager = createRBACManager(db);
    const phiBoundary = createPHIBoundary(db, encryptionKey);

    const ipAddress =
      c.req.header('CF-Connecting-IP') ||
      c.req.header('X-Forwarded-For') ||
      c.req.header('X-Real-IP');

    const userAgent = c.req.header('User-Agent');

    c.set('sessionManager', sessionManager);
    c.set('auditLogger', auditLogger);
    c.set('rbacManager', rbacManager);
    c.set('phiBoundary', phiBoundary);
    c.set('ipAddress', ipAddress);
    c.set('userAgent', userAgent);

    await next();
  };
}

export function requireSession() {
  return async (c: Context, next: Next) => {
    const sessionManager = c.get('sessionManager');
    const ipAddress = c.get('ipAddress');
    const userAgent = c.get('userAgent');

    const sessionId = c.req.header('X-Session-ID');

    if (!sessionId) {
      return c.json({ error: 'Session required' }, 401);
    }

    const validation = await sessionManager.validateSession(
      sessionId,
      ipAddress,
      userAgent
    );

    if (!validation.valid) {
      return c.json(
        {
          error: 'Invalid session',
          reason: validation.reason,
          requiresReauth: validation.requiresReauth,
          requiresMfa: validation.requiresMfa
        },
        401
      );
    }

    c.set('sessionId', sessionId);

    await next();
  };
}

export function requirePermission(resourceType: string, action: string) {
  return async (c: Context, next: Next) => {
    const rbacManager = c.get('rbacManager');
    const userId = c.get('userId');
    const tenantId = c.get('tenantId');
    const auditLogger = c.get('auditLogger');
    const ipAddress = c.get('ipAddress');
    const userAgent = c.get('userAgent');

    if (!userId || !tenantId) {
      return c.json({ error: 'Authentication required' }, 401);
    }

    const resourceId = c.req.param('id');

    const decision = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: resourceType as any,
      action: action as any,
      resourceId
    });

    if (!decision.allowed) {
      await auditLogger.log({
        tenantId,
        userId,
        action: action.toUpperCase() as any,
        resourceType,
        resourceId,
        ipAddress,
        userAgent,
        success: false,
        failureReason: decision.reason
      });

      return c.json(
        {
          error: 'Permission denied',
          reason: decision.reason
        },
        403
      );
    }

    c.set('accessDecision', decision);

    await next();
  };
}

export function requireReauth(resourceType: string, action: string) {
  return async (c: Context, next: Next) => {
    const sessionManager = c.get('sessionManager');
    const userId = c.get('userId');

    if (!userId) {
      return c.json({ error: 'Authentication required' }, 401);
    }

    const requiresReauth = await sessionManager.requiresReauthentication(
      userId,
      resourceType,
      action
    );

    if (requiresReauth) {
      return c.json(
        {
          error: 'Re-authentication required',
          message: `This action requires recent authentication verification`
        },
        403
      );
    }

    await next();
  };
}

export function auditRequest(action: string, resourceType: string) {
  return async (c: Context, next: Next) => {
    const auditLogger = c.get('auditLogger');
    const userId = c.get('userId');
    const tenantId = c.get('tenantId');
    const ipAddress = c.get('ipAddress');
    const userAgent = c.get('userAgent');

    if (!userId || !tenantId) {
      await next();
      return;
    }

    const resourceId = c.req.param('id');
    const requestId = crypto.randomUUID();

    c.set('requestId', requestId);

    try {
      await next();

      await auditLogger.log({
        tenantId,
        userId,
        action: action.toUpperCase() as any,
        resourceType,
        resourceId,
        ipAddress,
        userAgent,
        requestId,
        success: true
      });
    } catch (error) {
      await auditLogger.log({
        tenantId,
        userId,
        action: action.toUpperCase() as any,
        resourceType,
        resourceId,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: error instanceof Error ? error.message : 'Unknown error'
      });

      throw error;
    }
  };
}
