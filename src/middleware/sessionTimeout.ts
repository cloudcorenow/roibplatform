import { Context, Next } from 'hono';
import { Env } from '../worker';
import { checkSessionTimeout, updateSessionActivity, cleanupExpiredSessions } from '../utils/sessionManager';

export async function sessionTimeoutMiddleware(
  c: Context<{ Bindings: Env }>,
  next: Next
) {
  try {
    const authHeader = c.req.header('Authorization');

    if (authHeader && authHeader.startsWith('Bearer ')) {
      const refreshTokenHeader = c.req.header('X-Refresh-Token');

      if (refreshTokenHeader) {
        const sessionStatus = await checkSessionTimeout(c.env.DB, refreshTokenHeader);

        if (!sessionStatus.valid) {
          return c.json({
            error: 'Session expired',
            reason: sessionStatus.reason,
            requiresReauth: true
          }, 401);
        }

        const ipAddress = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For');
        const userAgent = c.req.header('User-Agent');

        await updateSessionActivity(c.env.DB, sessionStatus.session!.id, ipAddress, userAgent);
      }
    }

    await next();
  } catch (error) {
    console.error('Session timeout middleware error:', error);
    return c.json({
      error: 'Session validation failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
}

export async function sessionCleanupMiddleware(
  c: Context<{ Bindings: Env }>,
  next: Next
) {
  try {
    await cleanupExpiredSessions(c.env.DB);
    await next();
  } catch (error) {
    console.error('Session cleanup error:', error);
    await next();
  }
}
