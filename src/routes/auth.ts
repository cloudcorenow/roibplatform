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
import {
  validatePassword,
  isAccountLocked,
  calculateLockoutEnd,
  shouldResetFailedAttempts,
  isSessionExpired,
  HIPAA_LOCKOUT_POLICY
} from '../utils/hipaa-security';

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

    const passwordValidation = validatePassword(password, { name, email });
    if (!passwordValidation.valid) {
      return c.json({
        error: 'Password does not meet security requirements',
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
    const now = Math.floor(Date.now() / 1000);

    await c.env.DB.prepare(
      'INSERT INTO users (id, email, password_hash, name, role, user_type, tenant_id, password_last_changed) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(userId, email, passwordHash, name || '', 'user', userType, tenantId, now).run();

    await c.env.DB.prepare(
      'INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)'
    ).bind(userId, passwordHash).run();

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
    const now = Math.floor(Date.now() / 1000);

    const user = await c.env.DB.prepare(
      'SELECT id, email, password_hash, name, role, user_type, tenant_id, status, failed_login_attempts, account_locked_until, mfa_enabled, mfa_secret FROM users WHERE email = ?'
    ).bind(email).first();

    if (!user) {
      await auditLogger(c.env, {
        tenant_id: 'system',
        user_id: 'anonymous',
        action: 'login_failed',
        resource_type: 'auth',
        ip_address: c.req.header('CF-Connecting-IP') || 'unknown',
        user_agent: c.req.header('User-Agent'),
        details: JSON.stringify({ reason: 'user_not_found', email })
      });
      return c.json({ error: 'Invalid email or password' }, 401);
    }

    if (user.status !== 'active') {
      return c.json({ error: 'Account is not active' }, 403);
    }

    if (isAccountLocked(user.account_locked_until as number)) {
      const lockedUntil = new Date((user.account_locked_until as number) * 1000);
      await auditLogger(c.env, {
        tenant_id: user.tenant_id as string || 'platform',
        user_id: user.id as string,
        action: 'login_blocked',
        resource_type: 'auth',
        ip_address: c.req.header('CF-Connecting-IP') || 'unknown',
        user_agent: c.req.header('User-Agent'),
        details: JSON.stringify({ reason: 'account_locked', locked_until: lockedUntil.toISOString() })
      });
      return c.json({
        error: 'Account is temporarily locked due to multiple failed login attempts',
        locked_until: lockedUntil.toISOString()
      }, 403);
    }

    const isValidPassword = await verifyPassword(password, user.password_hash as string);
    if (!isValidPassword) {
      const currentAttempts = (user.failed_login_attempts as number || 0) + 1;
      const shouldLock = currentAttempts >= HIPAA_LOCKOUT_POLICY.maxFailedAttempts;
      const lockedUntil = shouldLock ? calculateLockoutEnd() : null;

      await c.env.DB.prepare(
        'UPDATE users SET failed_login_attempts = ?, account_locked_until = ? WHERE id = ?'
      ).bind(currentAttempts, lockedUntil, user.id).run();

      await auditLogger(c.env, {
        tenant_id: user.tenant_id as string || 'platform',
        user_id: user.id as string,
        action: 'login_failed',
        resource_type: 'auth',
        ip_address: c.req.header('CF-Connecting-IP') || 'unknown',
        user_agent: c.req.header('User-Agent'),
        details: JSON.stringify({
          reason: 'invalid_password',
          attempts: currentAttempts,
          locked: shouldLock
        })
      });

      if (shouldLock) {
        return c.json({
          error: 'Account has been locked due to multiple failed login attempts',
          locked_until: new Date(lockedUntil! * 1000).toISOString()
        }, 403);
      }

      return c.json({
        error: 'Invalid email or password',
        attempts_remaining: HIPAA_LOCKOUT_POLICY.maxFailedAttempts - currentAttempts
      }, 401);
    }

    await c.env.DB.prepare(
      'UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL, last_login_at = ?, last_login_ip = ? WHERE id = ?'
    ).bind(now, c.req.header('CF-Connecting-IP') || 'unknown', user.id).run();

    const userType = user.user_type as 'tenant' | 'platform';

    if (user.mfa_enabled) {
      return c.json({
        success: true,
        requiresMFA: true,
        userId: user.id,
        email: user.email
      });
    }

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
      'INSERT INTO sessions (id, user_id, refresh_token, expires_at, last_activity, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(
      sessionId,
      user.id,
      refreshToken,
      now + (60 * 60 * 24 * 7),
      now,
      c.req.header('CF-Connecting-IP') || 'unknown',
      c.req.header('User-Agent')
    ).run();

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
      sessionId,
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
      'SELECT id, user_id, expires_at, last_activity, created_at FROM sessions WHERE id = ? AND refresh_token = ?'
    ).bind(payload.session_id, refreshToken).first();

    if (!session) {
      return c.json({ error: 'Invalid refresh token' }, 401);
    }

    const now = Math.floor(Date.now() / 1000);
    if ((session.expires_at as number) < now) {
      await c.env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(session.id).run();
      return c.json({ error: 'Refresh token expired' }, 401);
    }

    const sessionExpiry = isSessionExpired(
      session.last_activity as number,
      session.created_at as number
    );

    if (sessionExpiry.expired) {
      await c.env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(session.id).run();
      await auditLogger(c.env, {
        tenant_id: 'system',
        user_id: session.user_id as string,
        action: 'session_expired',
        resource_type: 'auth',
        ip_address: c.req.header('CF-Connecting-IP') || 'unknown',
        user_agent: c.req.header('User-Agent'),
        details: JSON.stringify({ reason: sessionExpiry.reason })
      });
      return c.json({
        error: `Session expired due to ${sessionExpiry.reason}`,
        reason: sessionExpiry.reason
      }, 401);
    }

    await c.env.DB.prepare(
      'UPDATE sessions SET last_activity = ? WHERE id = ?'
    ).bind(now, session.id).run();

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

const mfaSetupSchema = z.object({
  userId: z.string()
});

const mfaVerifySchema = z.object({
  userId: z.string(),
  token: z.string().length(6)
});

const mfaLoginSchema = z.object({
  userId: z.string(),
  token: z.string().length(6)
});

authRouter.post('/mfa/setup', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Missing authorization header' }, 401);
    }

    const jwtToken = authHeader.substring(7);
    const payload = await verifyJWT(jwtToken, c.env.JWT_SECRET);

    const { generateMFASecret, generateMFABackupCodes } = await import('../utils/hipaa-security');
    const secret = generateMFASecret();
    const backupCodes = generateMFABackupCodes();

    await c.env.DB.prepare(
      'UPDATE users SET mfa_secret = ?, mfa_backup_codes = ? WHERE id = ?'
    ).bind(secret, JSON.stringify(backupCodes), payload.user_id).run();

    const user = await c.env.DB.prepare(
      'SELECT email FROM users WHERE id = ?'
    ).bind(payload.user_id).first();

    const otpauthUrl = `otpauth://totp/ROI%20Blueprint:${encodeURIComponent(user?.email as string)}?secret=${secret}&issuer=ROI%20Blueprint`;

    await auditLogger(c.env, {
      tenant_id: payload.tenant_id || 'platform',
      user_id: payload.user_id,
      action: 'mfa_setup_initiated',
      resource_type: 'auth',
      ip_address: c.req.header('CF-Connecting-IP') || 'unknown',
      user_agent: c.req.header('User-Agent')
    });

    return c.json({
      success: true,
      secret,
      otpauthUrl,
      backupCodes
    });
  } catch (error) {
    console.error('MFA setup error:', error);
    return c.json({ error: 'Failed to setup MFA' }, 500);
  }
});

authRouter.post('/mfa/verify-setup', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Missing authorization header' }, 401);
    }

    const jwtToken = authHeader.substring(7);
    const payload = await verifyJWT(jwtToken, c.env.JWT_SECRET);

    const body = await c.req.json();
    const { token } = z.object({ token: z.string().length(6) }).parse(body);

    const user = await c.env.DB.prepare(
      'SELECT mfa_secret FROM users WHERE id = ?'
    ).bind(payload.user_id).first();

    if (!user || !user.mfa_secret) {
      return c.json({ error: 'MFA not set up' }, 400);
    }

    const { verifyTOTP } = await import('../utils/hipaa-security');
    const isValid = verifyTOTP(user.mfa_secret as string, token);

    if (!isValid) {
      return c.json({ error: 'Invalid MFA token' }, 401);
    }

    const now = Math.floor(Date.now() / 1000);
    await c.env.DB.prepare(
      'UPDATE users SET mfa_enabled = 1, mfa_enabled_at = ? WHERE id = ?'
    ).bind(now, payload.user_id).run();

    await auditLogger(c.env, {
      tenant_id: payload.tenant_id || 'platform',
      user_id: payload.user_id,
      action: 'mfa_enabled',
      resource_type: 'auth',
      ip_address: c.req.header('CF-Connecting-IP') || 'unknown',
      user_agent: c.req.header('User-Agent')
    });

    return c.json({
      success: true,
      message: 'MFA enabled successfully'
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({ error: 'Invalid request data', details: error.errors }, 400);
    }
    console.error('MFA verification error:', error);
    return c.json({ error: 'Failed to verify MFA' }, 500);
  }
});

authRouter.post('/mfa/verify-login', async (c) => {
  try {
    const body = await c.req.json();
    const { userId, token } = mfaLoginSchema.parse(body);

    const user = await c.env.DB.prepare(
      'SELECT id, email, name, role, user_type, tenant_id, mfa_secret, mfa_backup_codes, mfa_enabled FROM users WHERE id = ?'
    ).bind(userId).first();

    if (!user || !user.mfa_enabled) {
      return c.json({ error: 'MFA not enabled for this account' }, 400);
    }

    const { verifyTOTP } = await import('../utils/hipaa-security');
    let isValid = verifyTOTP(user.mfa_secret as string, token);

    if (!isValid && user.mfa_backup_codes) {
      const backupCodes = JSON.parse(user.mfa_backup_codes as string);
      const codeIndex = backupCodes.indexOf(token);
      if (codeIndex !== -1) {
        isValid = true;
        backupCodes.splice(codeIndex, 1);
        await c.env.DB.prepare(
          'UPDATE users SET mfa_backup_codes = ? WHERE id = ?'
        ).bind(JSON.stringify(backupCodes), userId).run();
      }
    }

    if (!isValid) {
      await auditLogger(c.env, {
        tenant_id: user.tenant_id as string || 'platform',
        user_id: userId,
        action: 'mfa_verification_failed',
        resource_type: 'auth',
        ip_address: c.req.header('CF-Connecting-IP') || 'unknown',
        user_agent: c.req.header('User-Agent')
      });
      return c.json({ error: 'Invalid MFA token' }, 401);
    }

    const now = Math.floor(Date.now() / 1000);
    const userType = user.user_type as 'tenant' | 'platform';

    if (userType === 'platform') {
      await auditLogger(c.env, {
        tenant_id: 'platform',
        user_id: user.id as string,
        action: 'mfa_login_success',
        resource_type: 'auth',
        ip_address: c.req.header('CF-Connecting-IP') || 'unknown',
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
      'INSERT INTO sessions (id, user_id, refresh_token, expires_at, last_activity, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(
      sessionId,
      user.id,
      refreshToken,
      now + (60 * 60 * 24 * 7),
      now,
      c.req.header('CF-Connecting-IP') || 'unknown',
      c.req.header('User-Agent')
    ).run();

    await auditLogger(c.env, {
      tenant_id: user.tenant_id as string,
      user_id: user.id as string,
      action: 'mfa_login_success',
      resource_type: 'auth',
      ip_address: c.req.header('CF-Connecting-IP') || 'unknown',
      user_agent: c.req.header('User-Agent')
    });

    return c.json({
      success: true,
      accessToken,
      refreshToken,
      sessionId,
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
    console.error('MFA login verification error:', error);
    return c.json({ error: 'MFA verification failed' }, 500);
  }
});

authRouter.post('/mfa/disable', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Missing authorization header' }, 401);
    }

    const jwtToken = authHeader.substring(7);
    const payload = await verifyJWT(jwtToken, c.env.JWT_SECRET);

    await c.env.DB.prepare(
      'UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, mfa_backup_codes = NULL, mfa_enabled_at = NULL WHERE id = ?'
    ).bind(payload.user_id).run();

    await auditLogger(c.env, {
      tenant_id: payload.tenant_id || 'platform',
      user_id: payload.user_id,
      action: 'mfa_disabled',
      resource_type: 'auth',
      ip_address: c.req.header('CF-Connecting-IP') || 'unknown',
      user_agent: c.req.header('User-Agent')
    });

    return c.json({
      success: true,
      message: 'MFA disabled successfully'
    });
  } catch (error) {
    console.error('MFA disable error:', error);
    return c.json({ error: 'Failed to disable MFA' }, 500);
  }
});

authRouter.get('/mfa/backup-codes', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Missing authorization header' }, 401);
    }

    const jwtToken = authHeader.substring(7);
    const payload = await verifyJWT(jwtToken, c.env.JWT_SECRET);

    const user = await c.env.DB.prepare(
      'SELECT mfa_backup_codes FROM users WHERE id = ?'
    ).bind(payload.user_id).first();

    if (!user || !user.mfa_backup_codes) {
      return c.json({ error: 'No backup codes available' }, 404);
    }

    const backupCodes = JSON.parse(user.mfa_backup_codes as string);

    return c.json({
      success: true,
      backupCodes
    });
  } catch (error) {
    console.error('Get backup codes error:', error);
    return c.json({ error: 'Failed to get backup codes' }, 500);
  }
});

authRouter.post('/session/ping', async (c) => {
  try {
    const sessionId = c.req.header('X-Session-ID');
    const authHeader = c.req.header('Authorization');

    if (!sessionId) {
      return c.json({ error: 'Missing session ID' }, 401);
    }

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Missing authorization header' }, 401);
    }

    const token = authHeader.substring(7);
    const payload = await verifyJWT(token, c.env.JWT_SECRET);

    const session = await c.env.DB.prepare(
      'SELECT id, user_id, expires_at, last_activity, created_at FROM sessions WHERE id = ? AND user_id = ?'
    ).bind(sessionId, payload.user_id).first();

    if (!session) {
      return c.json({ error: 'Session not found' }, 404);
    }

    const now = Math.floor(Date.now() / 1000);

    if ((session.expires_at as number) < now) {
      await c.env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sessionId).run();
      return c.json({ error: 'Session expired' }, 401);
    }

    const sessionExpiry = isSessionExpired(
      session.last_activity as number,
      session.created_at as number
    );

    if (sessionExpiry.expired) {
      await c.env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sessionId).run();
      return c.json({
        error: 'Session expired',
        reason: sessionExpiry.reason
      }, 401);
    }

    await c.env.DB.prepare(
      'UPDATE sessions SET last_activity = ? WHERE id = ?'
    ).bind(now, sessionId).run();

    return c.json({
      success: true,
      message: 'Session updated',
      expiresIn: {
        absolute: (session.created_at as number) + (8 * 60 * 60) - now,
        idle: (session.last_activity as number) + (15 * 60) - now
      }
    });
  } catch (error) {
    console.error('Session ping error:', error);
    return c.json({ error: 'Failed to update session' }, 500);
  }
});

export { authRouter };
