import { Hono } from 'hono';
import { z } from 'zod';
import type { Env, HonoEnv } from '../types';
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
import {
  validatePasswordComplexity,
  checkPasswordHistory,
  addPasswordToHistory,
  calculatePasswordExpiry,
  checkAccountLockout,
  incrementFailedLoginAttempts,
  resetFailedLoginAttempts,
  checkPasswordExpiry
} from '../utils/passwordPolicy';
import { createSession, checkSessionTimeout, updateSessionActivity } from '../utils/sessionManager';
import {
  setupMFA,
  enableMFA,
  disableMFA,
  verifyMFAToken,
  isMFAEnabled,
  getRemainingBackupCodes
} from '../utils/mfa';

const authRouter = new Hono<HonoEnv>();

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

    const passwordValidation = validatePasswordComplexity(password);
    if (!passwordValidation.valid) {
      return c.json({
        error: 'Password does not meet complexity requirements',
        details: passwordValidation.errors
      }, 400);
    }

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
    const passwordExpiresAt = calculatePasswordExpiry();
    const now = Math.floor(Date.now() / 1000);

    await c.env.DB.prepare(
      `INSERT INTO users (id, email, password_hash, name, role, user_type, tenant_id, password_changed_at, password_expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(userId, email, passwordHash, name || '', 'user', userType, tenantId, now, passwordExpiresAt).run();

    await addPasswordToHistory(c.env.DB, userId, passwordHash);

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
    const { email, password, mfaToken } = z.object({
      email: z.string().email(),
      password: z.string(),
      mfaToken: z.string().optional()
    }).parse(body);

    const user = await c.env.DB.prepare(
      'SELECT id, email, password_hash, name, role, user_type, tenant_id, password_expires_at FROM users WHERE email = ?'
    ).bind(email).first();

    if (!user) {
      return c.json({ error: 'Invalid email or password' }, 401);
    }

    const lockoutStatus = await checkAccountLockout(c.env.DB, user.id as string);
    if (lockoutStatus.locked) {
      const remainingTime = Math.ceil(((lockoutStatus.lockedUntil || 0) - Math.floor(Date.now() / 1000)) / 60);
      return c.json({
        error: 'Account is locked due to too many failed login attempts',
        details: `Please try again in ${remainingTime} minutes`
      }, 403);
    }

    const isValidPassword = await verifyPassword(password, user.password_hash as string);
    if (!isValidPassword) {
      const lockoutResult = await incrementFailedLoginAttempts(c.env.DB, user.id as string);
      if (lockoutResult.locked) {
        return c.json({
          error: 'Account is locked due to too many failed login attempts',
          details: 'Please try again in 30 minutes'
        }, 403);
      }
      return c.json({
        error: 'Invalid email or password',
        details: `${5 - lockoutResult.attempts} attempts remaining`
      }, 401);
    }

    await resetFailedLoginAttempts(c.env.DB, user.id as string);

    const passwordExpiryStatus = await checkPasswordExpiry(c.env.DB, user.id as string);
    if (passwordExpiryStatus.expired) {
      return c.json({
        error: 'Password has expired',
        requiresPasswordChange: true,
        userId: user.id
      }, 403);
    }

    const mfaEnabled = await isMFAEnabled(c.env.DB, user.id as string);
    if (mfaEnabled) {
      if (!mfaToken) {
        return c.json({
          error: 'MFA token required',
          requiresMFA: true,
          userId: user.id
        }, 403);
      }

      const mfaValid = await verifyMFAToken(c.env.DB, user.id as string, mfaToken);
      if (!mfaValid) {
        return c.json({ error: 'Invalid MFA token' }, 401);
      }
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
      session_id: crypto.randomUUID(),
      exp: now + (60 * 60 * 24 * 7),
      iat: now
    };

    const accessToken = await signJWT(accessTokenPayload, c.env.JWT_SECRET);
    const refreshToken = await signRefreshToken(refreshTokenPayload, c.env.JWT_SECRET);

    const ipAddress = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown';
    const userAgent = c.req.header('User-Agent');

    await createSession(
      c.env.DB,
      user.id as string,
      refreshToken,
      ipAddress,
      userAgent
    );

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

    const sessionStatus = await checkSessionTimeout(c.env.DB, refreshToken);
    if (!sessionStatus.valid) {
      return c.json({
        error: sessionStatus.reason || 'Session invalid',
        requiresReauth: true
      }, 401);
    }

    const ipAddress = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For');
    const userAgent = c.req.header('User-Agent');

    await updateSessionActivity(c.env.DB, sessionStatus.session!.id, ipAddress, userAgent);

    const user = await c.env.DB.prepare(
      'SELECT id, email, role, user_type, tenant_id FROM users WHERE id = ?'
    ).bind(sessionStatus.session!.userId).first();

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

authRouter.post('/mfa/setup', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Missing authorization header' }, 401);
    }

    const token = authHeader.substring(7);
    const payload = await verifyJWT(token, c.env.JWT_SECRET);

    const { secret, backupCodes, qrCodeURL } = await setupMFA(c.env.DB, payload.user_id);

    return c.json({
      success: true,
      secret,
      backupCodes,
      qrCodeURL
    });
  } catch (error) {
    console.error('MFA setup error:', error);
    return c.json({ error: 'MFA setup failed' }, 500);
  }
});

authRouter.post('/mfa/enable', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Missing authorization header' }, 401);
    }

    const token = authHeader.substring(7);
    const payload = await verifyJWT(token, c.env.JWT_SECRET);

    const body = await c.req.json();
    const { token: mfaToken } = z.object({
      token: z.string()
    }).parse(body);

    const success = await enableMFA(c.env.DB, payload.user_id, mfaToken);

    if (!success) {
      return c.json({ error: 'Invalid MFA token' }, 400);
    }

    await auditLogger(c.env, {
      tenant_id: payload.tenant_id || 'platform',
      user_id: payload.user_id,
      action: 'mfa_enabled',
      resource_type: 'auth',
      ip_address: c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown',
      user_agent: c.req.header('User-Agent')
    });

    return c.json({ success: true });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({ error: 'Invalid request data', details: error.errors }, 400);
    }
    console.error('MFA enable error:', error);
    return c.json({ error: 'Failed to enable MFA' }, 500);
  }
});

authRouter.post('/mfa/disable', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Missing authorization header' }, 401);
    }

    const token = authHeader.substring(7);
    const payload = await verifyJWT(token, c.env.JWT_SECRET);

    const body = await c.req.json();
    const { token: mfaToken } = z.object({
      token: z.string()
    }).parse(body);

    const isValid = await verifyMFAToken(c.env.DB, payload.user_id, mfaToken);
    if (!isValid) {
      return c.json({ error: 'Invalid MFA token' }, 401);
    }

    await disableMFA(c.env.DB, payload.user_id);

    await auditLogger(c.env, {
      tenant_id: payload.tenant_id || 'platform',
      user_id: payload.user_id,
      action: 'mfa_disabled',
      resource_type: 'auth',
      ip_address: c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown',
      user_agent: c.req.header('User-Agent')
    });

    return c.json({ success: true });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({ error: 'Invalid request data', details: error.errors }, 400);
    }
    console.error('MFA disable error:', error);
    return c.json({ error: 'Failed to disable MFA' }, 500);
  }
});

authRouter.get('/mfa/status', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Missing authorization header' }, 401);
    }

    const token = authHeader.substring(7);
    const payload = await verifyJWT(token, c.env.JWT_SECRET);

    const enabled = await isMFAEnabled(c.env.DB, payload.user_id);
    const backupCodes = enabled ? await getRemainingBackupCodes(c.env.DB, payload.user_id) : [];

    return c.json({
      success: true,
      enabled,
      backupCodesRemaining: backupCodes.length
    });
  } catch (error) {
    console.error('MFA status error:', error);
    return c.json({ error: 'Failed to get MFA status' }, 500);
  }
});

export { authRouter };
