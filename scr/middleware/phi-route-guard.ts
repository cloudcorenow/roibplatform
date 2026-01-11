import { Context, Next } from 'hono';
import { getTablePHIFields } from '../types/phi-registry';

export const PHI_BEARING_ROUTES = {
  assessments: {
    basePath: '/api/assessments',
    operations: ['read', 'create', 'update', 'delete', 'export'],
    phiFields: getTablePHIFields('assessments'),
    requiresAuth: true,
    requiresAudit: true
  },
  documents: {
    basePath: '/api/documents',
    operations: ['read', 'create', 'update', 'delete', 'share'],
    phiFields: getTablePHIFields('documents'),
    requiresAuth: true,
    requiresAudit: true
  },
  timeEntries: {
    basePath: '/api/time-entries',
    operations: ['read', 'create', 'update', 'delete'],
    phiFields: getTablePHIFields('time_entries'),
    requiresAuth: true,
    requiresAudit: true
  },
  users: {
    basePath: '/api/users',
    operations: ['read', 'update', 'delete'],
    phiFields: getTablePHIFields('users'),
    requiresAuth: true,
    requiresAudit: true
  },
  clients: {
    basePath: '/api/clients',
    operations: ['read', 'create', 'update', 'delete'],
    phiFields: getTablePHIFields('clients'),
    requiresAuth: true,
    requiresAudit: true
  }
} as const;

export type PHIRoute = keyof typeof PHI_BEARING_ROUTES;

export interface RouteSecurityMetadata {
  route: string;
  method: string;
  phiRoute?: PHIRoute;
  requiresHIPAAMiddleware: boolean;
  requiresSession: boolean;
  requiresPermission?: { resource: string; action: string };
  requiresAudit: boolean;
}

const SUSPICIOUS_PHI_PATTERNS = [
  /\/api\/patient/i,
  /\/api\/health/i,
  /\/api\/medical/i,
  /\/api\/diagnosis/i,
  /\/api\/treatment/i,
  /\/api\/prescription/i,
  /\/api\/insurance/i,
  /\/api\/billing/i,
  /\/api\/claim/i,
  /\/api\/encounter/i,
  /\/api\/vital/i,
  /\/api\/lab/i,
  /\/api\/record/i,
  /\/api\/chart/i
];

const NON_PHI_ROUTES = new Set([
  '/api/health',
  '/api/healthcheck',
  '/api/status',
  '/api/ping',
  '/api/auth/login',
  '/api/auth/logout',
  '/api/auth/register',
  '/api/auth/refresh',
  '/api/session/ping'
]);

const registeredRoutes: Map<string, RouteSecurityMetadata> = new Map();

export function registerPHIRoute(metadata: RouteSecurityMetadata) {
  const key = `${metadata.method}:${metadata.route}`;
  registeredRoutes.set(key, metadata);
}

export function getPHIRouteMetadata(method: string, path: string): RouteSecurityMetadata | null {
  const key = `${method}:${path}`;
  return registeredRoutes.get(key) || null;
}

export function isPHIBearingRoute(path: string): PHIRoute | null {
  for (const [route, config] of Object.entries(PHI_BEARING_ROUTES)) {
    if (path.startsWith(config.basePath)) {
      return route as PHIRoute;
    }
  }
  return null;
}

export function isSuspiciousPHIRoute(path: string): boolean {
  if (NON_PHI_ROUTES.has(path)) {
    return false;
  }

  for (const pattern of SUSPICIOUS_PHI_PATTERNS) {
    if (pattern.test(path)) {
      return true;
    }
  }

  return false;
}

export function declareNonPHIRoute(path: string): void {
  NON_PHI_ROUTES.add(path);
}

export function enforceHIPAAMiddleware() {
  return async (c: Context, next: Next) => {
    const path = c.req.path;
    const method = c.req.method;
    const phiRoute = isPHIBearingRoute(path);
    const suspicious = isSuspiciousPHIRoute(path);
    const metadata = registeredRoutes.get(`${method}:${path}`);

    if (suspicious && !phiRoute && !metadata) {
      console.error(`CRITICAL SECURITY VIOLATION: Suspicious PHI route ${method} ${path} not explicitly registered!`);
      return c.json(
        {
          error: 'Security configuration error',
          message: 'This route matches PHI patterns but is not registered. If this route does not contain PHI, use declareNonPHIRoute(). Otherwise, register it in PHI_BEARING_ROUTES.',
          route: path,
          patterns: SUSPICIOUS_PHI_PATTERNS.filter(p => p.test(path)).map(p => p.toString()),
          action: 'Contact security team to register this route properly'
        },
        500
      );
    }

    if (phiRoute || (metadata?.requiresHIPAAMiddleware)) {
      const hasSessionManager = c.get('sessionManager');
      const hasAuditLogger = c.get('auditLogger');
      const hasRBACManager = c.get('rbacManager');
      const hasPHIBoundary = c.get('phiBoundary');

      if (!hasSessionManager || !hasAuditLogger || !hasRBACManager || !hasPHIBoundary) {
        console.error(`CRITICAL SECURITY VIOLATION: PHI route ${method} ${path} accessed without HIPAA security middleware!`);
        return c.json(
          {
            error: 'Security configuration error',
            message: 'This route requires HIPAA security middleware but it was not initialized',
            route: path,
            phiRoute
          },
          500
        );
      }

      const sessionId = c.req.header('X-Session-ID');
      const userId = c.get('userId');
      const tenantId = c.get('tenantId');

      if (!sessionId) {
        console.error(`CRITICAL SECURITY VIOLATION: PHI route ${method} ${path} accessed without session!`);
        return c.json(
          {
            error: 'Session required',
            message: 'PHI routes require active session with X-Session-ID header',
            route: path,
            phiRoute
          },
          401
        );
      }

      const sessionValid = await hasSessionManager.validateSession(
        sessionId,
        c.get('ipAddress'),
        c.get('userAgent'),
        userId
      );

      if (!sessionValid.valid) {
        console.error(`PHI route ${method} ${path} accessed with invalid session: ${sessionValid.reason}`);
        return c.json(
          {
            error: 'Session invalid',
            message: sessionValid.reason || 'Your session is invalid or expired',
            code: sessionValid.reason === 'Session expired due to idle timeout' ? 'SESSION_IDLE_TIMEOUT' :
                  sessionValid.reason === 'Session expired (absolute timeout)' ? 'SESSION_ABSOLUTE_TIMEOUT' :
                  'SESSION_INVALID',
            route: path
          },
          401
        );
      }

      if (metadata && !metadata.requiresHIPAAMiddleware) {
        console.error(`CRITICAL SECURITY VIOLATION: PHI route ${method} ${path} is not registered with HIPAA middleware requirement!`);
        return c.json(
          {
            error: 'Security configuration error',
            message: 'This PHI-bearing route must be registered with requiresHIPAAMiddleware: true',
            route: path,
            phiRoute
          },
          500
        );
      }
    }

    await next();
  };
}

export function auditRouteAccess() {
  return async (c: Context, next: Next) => {
    const path = c.req.path;
    const phiRoute = isPHIBearingRoute(path);

    if (phiRoute) {
      const startTime = Date.now();
      let error: Error | null = null;
      let statusCode = 200;

      try {
        await next();
        statusCode = c.res.status;
      } catch (e) {
        error = e as Error;
        statusCode = 500;
        throw e;
      } finally {
        const duration = Date.now() - startTime;
        const auditLogger = c.get('auditLogger');
        const userId = c.get('userId');
        const tenantId = c.get('tenantId');

        if (!auditLogger) {
          console.error('CRITICAL: Audit logger not available for PHI route access');
        }

        if (!userId || !tenantId) {
          console.error('CRITICAL: User/tenant context missing for PHI route access');
        }

        if (auditLogger && userId && tenantId) {
          const config = PHI_BEARING_ROUTES[phiRoute];
          try {
            await auditLogger.log({
              tenantId,
              userId,
              action: 'PHI_ACCESS',
              resourceType: phiRoute,
              resourceId: c.req.param('id') || 'list',
              ipAddress: c.get('ipAddress') || 'unknown',
              userAgent: c.get('userAgent') || 'unknown',
              requestId: c.get('requestId'),
              success: !error && statusCode < 400,
              failureReason: error?.message || (statusCode >= 400 ? `HTTP ${statusCode}` : undefined),
              metadata: {
                method: c.req.method,
                path: c.req.path,
                duration,
                statusCode,
                phiFields: config.phiFields,
                sessionId: c.req.header('X-Session-ID')
              }
            });
          } catch (auditError) {
            console.error('CRITICAL: Failed to write audit log for PHI access:', auditError);
          }
        }
      }
    } else {
      await next();
    }
  };
}

export function validatePHIRouteRegistration() {
  const unregisteredRoutes: string[] = [];

  for (const [route, config] of Object.entries(PHI_BEARING_ROUTES)) {
    for (const operation of config.operations) {
      const methods = getMethodsForOperation(operation);

      for (const method of methods) {
        const patterns = getPathPatternsForOperation(config.basePath, operation);

        for (const pattern of patterns) {
          const key = `${method}:${pattern}`;
          const metadata = registeredRoutes.get(key);

          if (!metadata) {
            unregisteredRoutes.push(`${method} ${pattern} (${route})`);
          } else if (!metadata.requiresHIPAAMiddleware) {
            unregisteredRoutes.push(`${method} ${pattern} (missing HIPAA middleware requirement)`);
          }
        }
      }
    }
  }

  if (unregisteredRoutes.length > 0) {
    console.error('CRITICAL SECURITY WARNING: The following PHI-bearing routes are not properly secured:');
    unregisteredRoutes.forEach(route => console.error(`  - ${route}`));
    throw new Error(`${unregisteredRoutes.length} PHI-bearing routes are not properly secured. See console for details.`);
  }

  console.log('✓ All PHI-bearing routes are properly registered and secured');
}

function getMethodsForOperation(operation: string): string[] {
  switch (operation) {
    case 'read':
      return ['GET'];
    case 'create':
      return ['POST'];
    case 'update':
      return ['PUT', 'PATCH'];
    case 'delete':
      return ['DELETE'];
    case 'export':
    case 'share':
      return ['POST'];
    default:
      return [];
  }
}

function getPathPatternsForOperation(basePath: string, operation: string): string[] {
  switch (operation) {
    case 'read':
      return [basePath, `${basePath}/:id`];
    case 'create':
      return [basePath];
    case 'update':
    case 'delete':
      return [`${basePath}/:id`];
    case 'export':
      return [`${basePath}/export`, `${basePath}/:id/export`];
    case 'share':
      return [`${basePath}/:id/share`];
    default:
      return [];
  }
}

export function secureRoute(
  route: string,
  method: string,
  phiRoute: PHIRoute,
  operation: string
) {
  const config = PHI_BEARING_ROUTES[phiRoute];

  registerPHIRoute({
    route,
    method,
    phiRoute,
    requiresHIPAAMiddleware: true,
    requiresSession: config.requiresAuth,
    requiresPermission: {
      resource: phiRoute,
      action: operation
    },
    requiresAudit: config.requiresAudit
  });
}
