import { Context, Next } from 'hono';
import { Env } from '../worker';
import { verifyJWT, JWTPayload } from '../utils/auth';

export interface AuthContext {
  user: JWTPayload;
}

export async function authMiddleware(
  c: Context<{ Bindings: Env }>,
  next: Next
) {
  try {
    const authHeader = c.req.header('Authorization');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Missing or invalid authorization header' }, 401);
    }

    const token = authHeader.substring(7);
    const payload = await verifyJWT(token, c.env.JWT_SECRET);

    c.set('user', payload);

    await next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    return c.json({
      error: 'Unauthorized',
      message: error instanceof Error ? error.message : 'Invalid token'
    }, 401);
  }
}

export async function adminMiddleware(
  c: Context<{ Bindings: Env }>,
  next: Next
) {
  const user = c.get('user') as JWTPayload;

  if (!user || user.role !== 'admin') {
    return c.json({ error: 'Admin access required' }, 403);
  }

  await next();
}
