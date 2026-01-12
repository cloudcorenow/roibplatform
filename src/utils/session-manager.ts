import { D1Database } from '@cloudflare/workers-types';

export interface SessionConfig {
  idleTimeoutSeconds: number;
  absoluteTimeoutSeconds: number;
  privilegedTimeoutSeconds: number;
  requireMFA: boolean;
}

export const DEFAULT_SESSION_CONFIG: SessionConfig = {
  idleTimeoutSeconds: 900,
  absoluteTimeoutSeconds: 28800,
  privilegedTimeoutSeconds: 300,
  requireMFA: true
};

export interface Session {
  id: string;
  userId: string;
  refreshToken: string;
  expiresAt: number;
  lastActivity: number;
  ipAddress?: string;
  userAgent?: string;
  requiresMfa: boolean;
  mfaVerifiedAt?: number;
  privileged: boolean;
  privilegedExpiresAt?: number;
  createdAt: number;
}

export interface SessionValidation {
  valid: boolean;
  reason?: string;
  requiresReauth?: boolean;
  requiresMfa?: boolean;
}

export class SessionManager {
  private config: SessionConfig;

  constructor(
    private db: D1Database,
    config: Partial<SessionConfig> = {}
  ) {
    this.config = { ...DEFAULT_SESSION_CONFIG, ...config };
  }

  async createSession(
    userId: string,
    ipAddress?: string,
    userAgent?: string,
    requiresMfa: boolean = false
  ): Promise<Session> {
    const id = crypto.randomUUID();
    const refreshToken = this.generateSecureToken();
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + this.config.absoluteTimeoutSeconds;

    await this.db
      .prepare(
        `INSERT INTO sessions (
          id, user_id, refresh_token, expires_at, last_activity,
          ip_address, user_agent, requires_mfa, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        id,
        userId,
        refreshToken,
        expiresAt,
        now,
        ipAddress || null,
        userAgent || null,
        requiresMfa ? 1 : 0,
        now
      )
      .run();

    await this.logActivity(id, 'login', ipAddress);

    return {
      id,
      userId,
      refreshToken,
      expiresAt,
      lastActivity: now,
      ipAddress,
      userAgent,
      requiresMfa,
      privileged: false,
      createdAt: now
    };
  }

  async validateSession(
    sessionId: string,
    ipAddress?: string,
    userAgent?: string,
    expectedUserId?: string
  ): Promise<SessionValidation> {
    const session = await this.getSession(sessionId);

    if (!session) {
      return {
        valid: false,
        reason: 'Session not found'
      };
    }

    if (expectedUserId && session.userId !== expectedUserId) {
      await this.logActivity(sessionId, 'access', ipAddress, {
        reason: 'User ID mismatch',
        expected: expectedUserId,
        actual: session.userId
      });
      return {
        valid: false,
        reason: 'Session does not belong to authenticated user'
      };
    }

    const now = Math.floor(Date.now() / 1000);

    if (session.expiresAt < now) {
      await this.logActivity(sessionId, 'timeout', ipAddress);
      await this.deleteSession(sessionId);
      return {
        valid: false,
        reason: 'Session expired (absolute timeout)'
      };
    }

    const idleTimeout = session.lastActivity + this.config.idleTimeoutSeconds;
    if (idleTimeout < now) {
      await this.logActivity(sessionId, 'timeout', ipAddress);
      await this.deleteSession(sessionId);
      return {
        valid: false,
        reason: 'Session expired (idle timeout)'
      };
    }

    if (session.ipAddress && ipAddress && session.ipAddress !== ipAddress) {
      await this.logActivity(sessionId, 'access', ipAddress, {
        reason: 'IP address mismatch',
        expected: session.ipAddress,
        actual: ipAddress
      });
      return {
        valid: false,
        reason: 'Session IP address mismatch'
      };
    }

    if (session.userAgent && userAgent && session.userAgent !== userAgent) {
      await this.logActivity(sessionId, 'access', ipAddress, {
        reason: 'User agent mismatch'
      });
      return {
        valid: false,
        reason: 'Session user agent mismatch'
      };
    }

    if (session.requiresMfa && !session.mfaVerifiedAt) {
      return {
        valid: false,
        requiresMfa: true,
        reason: 'MFA verification required'
      };
    }

    if (session.privileged && session.privilegedExpiresAt) {
      if (session.privilegedExpiresAt < now) {
        await this.revokePrivilegedAccess(sessionId);
        await this.logActivity(sessionId, 'privilege_expire', ipAddress);
      }
    }

    await this.updateLastActivity(sessionId);
    await this.logActivity(sessionId, 'access', ipAddress);

    return {
      valid: true
    };
  }

  async requiresReauthentication(
    userId: string,
    resourceType: string,
    action: string
  ): Promise<boolean> {
    const result = await this.db
      .prepare(
        `SELECT max_age_seconds, requires_mfa
         FROM reauth_requirements
         WHERE resource_type = ? AND action = ?`
      )
      .bind(resourceType, action)
      .first();

    if (!result) {
      return false;
    }

    const sessions = await this.db
      .prepare(
        `SELECT mfa_verified_at, created_at
         FROM sessions
         WHERE user_id = ?
         ORDER BY created_at DESC
         LIMIT 1`
      )
      .bind(userId)
      .first();

    if (!sessions) {
      return true;
    }

    const now = Math.floor(Date.now() / 1000);
    const maxAge = result.max_age_seconds as number;

    if (result.requires_mfa) {
      const mfaVerifiedAt = sessions.mfa_verified_at as number | null;
      if (!mfaVerifiedAt || now - mfaVerifiedAt > maxAge) {
        return true;
      }
    }

    return false;
  }

  async grantPrivilegedAccess(sessionId: string, ipAddress?: string): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    const privilegedExpiresAt = now + this.config.privilegedTimeoutSeconds;

    await this.db
      .prepare(
        `UPDATE sessions
         SET privileged = 1, privileged_expires_at = ?
         WHERE id = ?`
      )
      .bind(privilegedExpiresAt, sessionId)
      .run();

    await this.logActivity(sessionId, 'privilege_grant', ipAddress, {
      expires_at: privilegedExpiresAt
    });
  }

  async revokePrivilegedAccess(sessionId: string): Promise<void> {
    await this.db
      .prepare(
        `UPDATE sessions
         SET privileged = 0, privileged_expires_at = NULL
         WHERE id = ?`
      )
      .bind(sessionId)
      .run();
  }

  async verifyMFA(sessionId: string, ipAddress?: string): Promise<void> {
    const now = Math.floor(Date.now() / 1000);

    await this.db
      .prepare(
        `UPDATE sessions
         SET mfa_verified_at = ?
         WHERE id = ?`
      )
      .bind(now, sessionId)
      .run();

    await this.logActivity(sessionId, 'mfa_verify', ipAddress);
  }

  async deleteSession(sessionId: string): Promise<void> {
    await this.db
      .prepare('DELETE FROM sessions WHERE id = ?')
      .bind(sessionId)
      .run();
  }

  async terminateAllUserSessions(userId: string, exceptSessionId?: string): Promise<void> {
    if (exceptSessionId) {
      await this.db
        .prepare('DELETE FROM sessions WHERE user_id = ? AND id != ?')
        .bind(userId, exceptSessionId)
        .run();
    } else {
      await this.db
        .prepare('DELETE FROM sessions WHERE user_id = ?')
        .bind(userId)
        .run();
    }
  }

  async cleanupExpiredSessions(): Promise<number> {
    const now = Math.floor(Date.now() / 1000);
    const idleThreshold = now - this.config.idleTimeoutSeconds;

    const result = await this.db
      .prepare(
        `DELETE FROM sessions
         WHERE expires_at < ? OR last_activity < ?`
      )
      .bind(now, idleThreshold)
      .run();

    return result.meta?.changes || 0;
  }

  private async getSession(sessionId: string): Promise<Session | null> {
    const result = await this.db
      .prepare(
        `SELECT
          id, user_id, refresh_token, expires_at, last_activity,
          ip_address, user_agent, requires_mfa, mfa_verified_at,
          privileged, privileged_expires_at, created_at
        FROM sessions
        WHERE id = ?`
      )
      .bind(sessionId)
      .first();

    if (!result) {
      return null;
    }

    return {
      id: result.id as string,
      userId: result.user_id as string,
      refreshToken: result.refresh_token as string,
      expiresAt: result.expires_at as number,
      lastActivity: result.last_activity as number,
      ipAddress: result.ip_address as string | undefined,
      userAgent: result.user_agent as string | undefined,
      requiresMfa: Boolean(result.requires_mfa),
      mfaVerifiedAt: result.mfa_verified_at as number | undefined,
      privileged: Boolean(result.privileged),
      privilegedExpiresAt: result.privileged_expires_at as number | undefined,
      createdAt: result.created_at as number
    };
  }

  private async updateLastActivity(sessionId: string): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    await this.db
      .prepare('UPDATE sessions SET last_activity = ? WHERE id = ?')
      .bind(now, sessionId)
      .run();
  }

  private async logActivity(
    sessionId: string,
    activityType: string,
    ipAddress?: string,
    metadata?: Record<string, any>
  ): Promise<void> {
    const id = crypto.randomUUID();
    const now = Math.floor(Date.now() / 1000);
    const metadataJson = metadata ? JSON.stringify(metadata) : null;

    await this.db
      .prepare(
        `INSERT INTO session_activities (id, session_id, activity_type, ip_address, metadata, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
      .bind(id, sessionId, activityType, ipAddress || null, metadataJson, now)
      .run();
  }

  private generateSecureToken(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }
}

export function createSessionManager(
  db: D1Database,
  config?: Partial<SessionConfig>
): SessionManager {
  return new SessionManager(db, config);
}
