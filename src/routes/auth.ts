import { Hono } from 'hono';
import { z } from 'zod';
import { Env } from '../worker';
import {
  signJWT,
  verifyJWT,
  signRefreshToken,
  verifyRefreshToken,
  hashPassword,
  verifyPassword,
  generateTokenId,
  JWTPayload,
  determinUserType,
  createScopedToken,
  isPlatformAdmin
} from '../utils/auth';
import { auditLogger } from '../utils/audit';

const authRouter = new Hono<{ Bindings: Env }>();

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().optional()
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6)
});

const refreshTokenSchema = z.object({
  refreshToken: z.string()
});

authRouter.post('/register', async (c) => {
  try {
    const body = await c.req.json();
    const { email, password, name } = registerSchema.parse(body);

    const existingUser = await c.env.DB.prepare(
      'SELECT id FROM users WHERE email = ?'
    ).bind(email).first();

    if (existingUser) {
      return c.json({ error: 'Email already registered' }, 400);
    }

    const passwordHash = await hashPassword(password);
    const userId = generateTokenId();
    const userType = determinUserType(email);
    const tenantId = userType === 'tenant' ? 'default' : null;

    await c.env.DB.prepare(
      'INSERT INTO users (id, email, password_hash, name, role, user_type, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(userId, email, passwordHash, name || '', 'user', userType, tenantId).run();

    const now = Math.floor(Date.now() / 1000);

    if (userType === 'platform') {
      await auditLogger(c.env, {
        tenant_id: 'platform',
        user_id: userId,
        action: 'register',
        resource_type: 'auth',
        ip_address: c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown',
        user_agent: c.req.header('User-Agent')
      });

      return c.json({
        success: true,
        requiresTenantSelection: true,
        user: {
          id: userId,
          email,
          name: name || '',
          role: 'user',
          user_type: userType
        }
      });
    }

    const accessTokenPayload: JWTPayload = {
      user_id: userId,
      email,
      role: 'user',
      user_type: userType,
      tenant_id: tenantId!,
      exp: now + (60 * 60),
      iat: now
    };

    const accessToken = await signJWT(accessTokenPayload, c.env.JWT_SECRET);

    await auditLogger(c.env, {
      tenant_id: tenantId!,
      user_id: userId,
      action: 'register',
      resource_type: 'auth',
      ip_address: c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown',
      user_agent: c.req.header('User-Agent')
    });

    return c.json({
      success: true,
      accessToken,
      user: {
        id: userId,
        email,
        name: name || '',
        role: 'user',
        user_type: userType,
        tenant_id: tenantId
      }
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({ error: 'Invalid request data', details: error.errors }, 400);
    }
    console.error('Registration error:', error);
    return c.json({ error: 'Registration failed' }, 500);
  }
});

authRouter.post('/login', async (c) => {
  try {
    const body = await c.req.json();
    const { email, password } = loginSchema.parse(body);

    const user = await c.env.DB.prepare(
      'SELECT id, email, password_hash, name, role, user_type, tenant_id FROM users WHERE email = ?'
    ).bind(email).first();

    if (!user) {
      return c.json({ error: 'Invalid email or password' }, 401);
    }

    const isValidPassword = await verifyPassword(password, user.password_hash as string);
    if (!isValidPassword) {
      return c.json({ error: 'Invalid email or password' }, 401);
    }

    const now = Math.floor(Date.now() / 1000);
    const userType = user.user_type as 'tenant' | 'platform';

    if (userType === 'platform') {
      await auditLogger(c.env, {
        tenant_id: 'platform',
        user_id: user.id as string,
        action: 'login',
        resource_type: 'auth',
        ip_address: c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown',
        user_agent: c.req.header('User-Agent')
      });

      return c.json({
        success: true,
        requiresTenantSelection: true,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          user_type: userType
        }
      });
    }

    const sessionId = generateTokenId();

    const accessTokenPayload: JWTPayload = {
      user_id: user.id as string,
      email: user.email as string,
      role: user.role as string,
      user_type: userType,
      tenant_id: user.tenant_id as string,
      exp: now + (60 * 60),
      iat: now
    };

    const refreshTokenPayload = {
      user_id: user.id as string,
      session_id: sessionId,
      exp: now + (60 * 60 * 24 * 7),
      iat: now
    };

    const accessToken = await signJWT(accessTokenPayload, c.env.JWT_SECRET);
    const refreshToken = await signRefreshToken(refreshTokenPayload, c.env.JWT_SECRET);

    await c.env.DB.prepare(
      'INSERT INTO sessions (id, user_id, refresh_token, expires_at) VALUES (?, ?, ?, ?)'
    ).bind(sessionId, user.id, refreshToken, now + (60 * 60 * 24 * 7)).run();

    await auditLogger(c.env, {
      tenant_id: user.tenant_id as string,
      user_id: user.id as string,
      action: 'login',
      resource_type: 'auth',
      ip_address: c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown',
      user_agent: c.req.header('User-Agent')
    });

    return c.json({
      success: true,
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        user_type: userType,
        tenant_id: user.tenant_id
      }
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({ error: 'Invalid request data', details: error.errors }, 400);
    }
    console.error('Login error:', error);
    return c.json({ error: 'Login failed' }, 500);
  }
});

authRouter.post('/refresh', async (c) => {
  try {
    const body = await c.req.json();
    const { refreshToken } = refreshTokenSchema.parse(body);

    const payload = await verifyRefreshToken(refreshToken, c.env.JWT_SECRET);

    const session = await c.env.DB.prepare(
      'SELECT id, user_id, expires_at FROM sessions WHERE id = ? AND refresh_token = ?'
    ).bind(payload.session_id, refreshToken).first();

    if (!session) {
      return c.json({ error: 'Invalid refresh token' }, 401);
    }

    const now = Math.floor(Date.now() / 1000);
    if ((session.expires_at as number) < now) {
      await c.env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(session.id).run();
      return c.json({ error: 'Refresh token expired' }, 401);
    }

    const user = await c.env.DB.prepare(
      'SELECT id, email, role FROM users WHERE id = ?'
    ).bind(session.user_id).first();

    if (!user) {
      return c.json({ error: 'User not found' }, 401);
    }

    const accessTokenPayload: JWTPayload = {
      user_id: user.id as string,
      email: user.email as string,
      role: user.role as string,
      exp: now + (60 * 60),
      iat: now
    };

    const newAccessToken = await signJWT(accessTokenPayload, c.env.JWT_SECRET);

    return c.json({
      success: true,
      accessToken: newAccessToken
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({ error: 'Invalid request data', details: error.errors }, 400);
    }
    console.error('Token refresh error:', error);
    return c.json({ error: 'Token refresh failed' }, 401);
  }
});

authRouter.post('/logout', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Missing authorization header' }, 401);
    }

    const token = authHeader.substring(7);
    const payload = await verifyJWT(token, c.env.JWT_SECRET);

    await c.env.DB.prepare(
      'DELETE FROM sessions WHERE user_id = ?'
    ).bind(payload.user_id).run();

    await auditLogger(c.env, {
      tenant_id: 'default',
      user_id: payload.user_id,
      action: 'logout',
      resource_type: 'auth',
      ip_address: c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown',
      user_agent: c.req.header('User-Agent')
    });

    return c.json({ success: true });
  } catch (error) {
    console.error('Logout error:', error);
    return c.json({ error: 'Logout failed' }, 500);
  }
});

authRouter.get('/me', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Missing authorization header' }, 401);
    }

    const token = authHeader.substring(7);
    const payload = await verifyJWT(token, c.env.JWT_SECRET);

    const user = await c.env.DB.prepare(
      'SELECT id, email, name, role, user_type, tenant_id FROM users WHERE id = ?'
    ).bind(payload.user_id).first();

    if (!user) {
      return c.json({ error: 'User not found' }, 404);
    }

    return c.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        user_type: user.user_type,
        tenant_id: user.tenant_id,
        current_tenant_id: payload.tenant_id,
        read_only: payload.read_only || false
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    return c.json({ error: 'Failed to get user info' }, 401);
  }
});

const tenantSelectionSchema = z.object({
  userId: z.string(),
  tenantId: z.string(),
  readOnly: z.boolean().optional()
});

authRouter.get('/tenants', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const payload = await verifyJWT(token, c.env.JWT_SECRET);

      if (payload.user_type !== 'platform') {
        return c.json({ error: 'Only platform admins can list tenants' }, 403);
      }
    }

    const result = await c.env.DB.prepare(
      'SELECT id, name, domain, active, created_at FROM tenants WHERE active = 1 ORDER BY name'
    ).all();

    return c.json({
      success: true,
      tenants: result.results || []
    });
  } catch (error) {
    console.error('List tenants error:', error);
    return c.json({ error: 'Failed to list tenants' }, 500);
  }
});

authRouter.post('/select-tenant', async (c) => {
  try {
    const body = await c.req.json();
    const { userId, tenantId, readOnly } = tenantSelectionSchema.parse(body);

    const user = await c.env.DB.prepare(
      'SELECT id, email, name, role, user_type FROM users WHERE id = ?'
    ).bind(userId).first();

    if (!user) {
      return c.json({ error: 'User not found' }, 404);
    }

    if (user.user_type !== 'platform') {
      return c.json({ error: 'Only platform admins can select tenants' }, 403);
    }

    const tenant = await c.env.DB.prepare(
      'SELECT id, name FROM tenants WHERE id = ?'
    ).bind(tenantId).first();

    if (!tenant) {
      return c.json({ error: 'Tenant not found' }, 404);
    }

    const previousTenant = await c.env.DB.prepare(
      'SELECT to_tenant_id FROM tenant_switches WHERE admin_id = ? ORDER BY switched_at DESC LIMIT 1'
    ).bind(userId).first();

    await c.env.DB.prepare(
      'INSERT INTO tenant_switches (admin_id, from_tenant_id, to_tenant_id, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)'
    ).bind(
      userId,
      previousTenant?.to_tenant_id || null,
      tenantId,
      c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown',
      c.req.header('User-Agent')
    ).run();

    const scopedToken = await createScopedToken(
      user.id as string,
      user.email as string,
      user.role as string,
      'platform',
      tenantId,
      c.env.JWT_SECRET,
      readOnly || false,
      30
    );

    await auditLogger(c.env, {
      tenant_id: tenantId,
      user_id: userId,
      action: 'tenant_selected',
      resource_type: 'auth',
      resource_id: tenantId,
      ip_address: c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown',
      user_agent: c.req.header('User-Agent'),
      details: JSON.stringify({
        tenant_name: tenant.name,
        read_only: readOnly || false,
        from_tenant: previousTenant?.to_tenant_id
      })
    });

    return c.json({
      success: true,
      accessToken: scopedToken,
      tenant: {
        id: tenant.id,
        name: tenant.name
      },
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        user_type: user.user_type
      }
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({ error: 'Invalid request data', details: error.errors }, 400);
    }
    console.error('Tenant selection error:', error);
    return c.json({ error: 'Tenant selection failed' }, 500);
  }
});

authRouter.post('/switch-tenant', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Missing authorization header' }, 401);
    }

    const token = authHeader.substring(7);
    const payload = await verifyJWT(token, c.env.JWT_SECRET);

    if (payload.user_type !== 'platform') {
      return c.json({ error: 'Only platform admins can switch tenants' }, 403);
    }

    const body = await c.req.json();
    const { tenantId, readOnly } = z.object({
      tenantId: z.string(),
      readOnly: z.boolean().optional()
    }).parse(body);

    const tenant = await c.env.DB.prepare(
      'SELECT id, name FROM tenants WHERE id = ?'
    ).bind(tenantId).first();

    if (!tenant) {
      return c.json({ error: 'Tenant not found' }, 404);
    }

    await c.env.DB.prepare(
      'INSERT INTO tenant_switches (admin_id, from_tenant_id, to_tenant_id, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)'
    ).bind(
      payload.user_id,
      payload.tenant_id || null,
      tenantId,
      c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown',
      c.req.header('User-Agent')
    ).run();

    const scopedToken = await createScopedToken(
      payload.user_id,
      payload.email,
      payload.role,
      'platform',
      tenantId,
      c.env.JWT_SECRET,
      readOnly || false,
      30
    );

    await auditLogger(c.env, {
      tenant_id: tenantId,
      user_id: payload.user_id,
      action: 'tenant_switched',
      resource_type: 'auth',
      resource_id: tenantId,
      ip_address: c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown',
      user_agent: c.req.header('User-Agent'),
      details: JSON.stringify({
        tenant_name: tenant.name,
        read_only: readOnly || false,
        from_tenant: payload.tenant_id
      })
    });

    return c.json({
      success: true,
      accessToken: scopedToken,
      tenant: {
        id: tenant.id,
        name: tenant.name
      }
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({ error: 'Invalid request data', details: error.errors }, 400);
    }
    console.error('Tenant switch error:', error);
    return c.json({ error: 'Tenant switch failed' }, 500);
  }
});

export { authRouter };
