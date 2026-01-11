import { Env } from '../worker';

export interface SecurityContext {
  tenantId: string;
  userId: string;
  role: string;
  permissions: string[];
  ipAddress: string;
  userAgent?: string;
}

export function createSecurityContext(c: any): SecurityContext {
  return {
    tenantId: c.get('tenant_id'),
    userId: c.get('user_id'),
    role: c.get('user_role'),
    permissions: c.get('user_permissions') || [],
    ipAddress: c.get('user_ip'),
    userAgent: c.req.header('User-Agent')
  };
}

export function requirePermission(context: SecurityContext, permission: string): void {
  if (context.role === 'admin') return; // Admin has all permissions
  
  if (!context.permissions.includes(permission) && !context.permissions.includes('*')) {
    throw new Error(`Permission denied: ${permission} required`);
  }
}

export function requireTenantAccess(context: SecurityContext, resourceTenantId: string): void {
  if (context.role === 'admin' && context.permissions.includes('*')) {
    // Master admin can access any tenant - AUDIT THIS HEAVILY
    console.warn(`🚨 MASTER ADMIN ACCESS: User ${context.userId} accessing tenant ${resourceTenantId} from IP ${context.ipAddress}`);
    return;
  }
  
  if (context.tenantId !== resourceTenantId) {
    throw new Error('Access denied: Cross-tenant access not allowed');
  }
}

export function requireAdminAccess(context: SecurityContext, requestedScope?: string): void {
  if (context.role !== 'admin') {
    throw new Error('Admin access required');
  }
  
  // For cross-tenant access, require explicit scope and audit heavily
  if (requestedScope === '*') {
    console.warn(`🚨 MASTER ADMIN SCOPE: User ${context.userId} granted cross-tenant access from IP ${context.ipAddress}`);
  } else if (requestedScope && requestedScope !== context.tenantId) {
    console.warn(`🚨 CROSS-TENANT ADMIN: User ${context.userId} accessing tenant ${requestedScope} from IP ${context.ipAddress}`);
  }
}

export function sanitizeInput(input: string, maxLength: number = 1000): string {
  return input
    .trim()
    .substring(0, maxLength)
    .replace(/[<>]/g, '') // Basic XSS protection
    .replace(/\0/g, ''); // Remove null bytes
}

export function validateTenantId(tenantId: string): boolean {
  // Tenant IDs should be alphanumeric with hyphens/underscores
  return /^[a-zA-Z0-9_-]+$/.test(tenantId) && tenantId.length <= 50;
}

export function validateUserId(userId: string): boolean {
  // User IDs should be alphanumeric with hyphens/underscores
  return /^[a-zA-Z0-9_-]+$/.test(userId) && userId.length <= 50;
}

export async function rateLimitCheck(
  env: Env, 
  key: string, 
  limit: number = 100, 
  windowMs: number = 60000
): Promise<boolean> {
  const now = Date.now();
  const windowStart = now - windowMs;
  
  // Get current count from KV
  const currentData = await env.KV.get(`ratelimit:${key}`);
  const requests = currentData ? JSON.parse(currentData) : [];
  
  // Filter requests within the current window
  const recentRequests = requests.filter((timestamp: number) => timestamp > windowStart);
  
  if (recentRequests.length >= limit) {
    return false; // Rate limit exceeded
  }
  
  // Add current request and store back
  recentRequests.push(now);
  await env.KV.put(`ratelimit:${key}`, JSON.stringify(recentRequests), {
    expirationTtl: Math.ceil(windowMs / 1000)
  });
  
  return true;
}