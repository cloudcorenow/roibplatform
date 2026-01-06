import type { Env } from '../types';
import type { Context } from 'hono';

export function validateUserId(userId: string): boolean {
  if (!userId || typeof userId !== 'string') {
    return false;
  }

  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(userId);
}

export async function rateLimitCheck(
  env: Env,
  key: string,
  limit: number,
  windowMs: number
): Promise<boolean> {
  try {
    const now = Date.now();
    const windowKey = `ratelimit:${key}:${Math.floor(now / windowMs)}`;

    const current = await env.KV.get(windowKey);
    const count = current ? parseInt(current, 10) : 0;

    if (count >= limit) {
      return false;
    }

    await env.KV.put(windowKey, String(count + 1), {
      expirationTtl: Math.ceil(windowMs / 1000)
    });

    return true;
  } catch (error) {
    console.error('Rate limit check failed:', error);
    return true;
  }
}

export interface SecurityContext {
  userId: string;
  tenantId: string;
  userRole: string;
  ipAddress: string;
}

export function createSecurityContext(c: Context): SecurityContext {
  return {
    userId: c.get('user_id') as string,
    tenantId: c.get('tenant_id') as string,
    userRole: c.get('user_role') as string,
    ipAddress: c.get('user_ip') as string
  };
}

export function requirePermission(permission: string) {
  return async (c: Context, next: () => Promise<void>) => {
    const userRole = c.get('user_role') as string;

    const adminRoles = ['admin', 'platform_admin'];
    if (adminRoles.includes(userRole)) {
      return next();
    }

    return c.json({ error: 'Permission denied', code: 'FORBIDDEN' }, 403);
  };
}
