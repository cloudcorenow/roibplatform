const MAX_INACTIVITY_SECONDS = 15 * 60;
const SESSION_ABSOLUTE_TIMEOUT_SECONDS = 8 * 60 * 60;

export interface SessionInfo {
  id: string;
  userId: string;
  lastActivity: number;
  createdAt: number;
  expiresAt: number;
  ipAddress?: string;
  userAgent?: string;
}

export async function checkSessionTimeout(
  db: D1Database,
  refreshToken: string
): Promise<{ valid: boolean; reason?: string; session?: SessionInfo }> {
  const session = await db.prepare(`
    SELECT id, user_id, last_activity, created_at, expires_at, ip_address, user_agent
    FROM sessions
    WHERE refresh_token = ?
  `).bind(refreshToken).first();

  if (!session) {
    return { valid: false, reason: 'Session not found' };
  }

  const now = Math.floor(Date.now() / 1000);
  const expiresAt = session.expires_at as number;

  if (expiresAt < now) {
    await invalidateSession(db, session.id as string);
    return { valid: false, reason: 'Session expired' };
  }

  const inactivityDuration = now - (session.last_activity as number);
  if (inactivityDuration > MAX_INACTIVITY_SECONDS) {
    await invalidateSession(db, session.id as string);
    return {
      valid: false,
      reason: `Session expired due to inactivity (${Math.floor(inactivityDuration / 60)} minutes)`
    };
  }

  const sessionAge = now - (session.created_at as number);
  if (sessionAge > SESSION_ABSOLUTE_TIMEOUT_SECONDS) {
    await invalidateSession(db, session.id as string);
    return {
      valid: false,
      reason: 'Session exceeded maximum duration'
    };
  }

  return {
    valid: true,
    session: {
      id: session.id as string,
      userId: session.user_id as string,
      lastActivity: session.last_activity as number,
      createdAt: session.created_at as number,
      expiresAt: session.expires_at as number,
      ipAddress: session.ip_address as string | undefined,
      userAgent: session.user_agent as string | undefined
    }
  };
}

export async function updateSessionActivity(
  db: D1Database,
  sessionId: string,
  ipAddress?: string,
  userAgent?: string
): Promise<void> {
  const now = Math.floor(Date.now() / 1000);

  await db.prepare(`
    UPDATE sessions
    SET last_activity = ?,
        ip_address = COALESCE(?, ip_address),
        user_agent = COALESCE(?, user_agent)
    WHERE id = ?
  `).bind(now, ipAddress, userAgent, sessionId).run();
}

export async function createSession(
  db: D1Database,
  userId: string,
  refreshToken: string,
  ipAddress?: string,
  userAgent?: string
): Promise<SessionInfo> {
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + SESSION_ABSOLUTE_TIMEOUT_SECONDS;

  const sessionId = crypto.randomUUID();

  await db.prepare(`
    INSERT INTO sessions (id, user_id, refresh_token, expires_at, last_activity, ip_address, user_agent, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(sessionId, userId, refreshToken, expiresAt, now, ipAddress, userAgent, now).run();

  return {
    id: sessionId,
    userId,
    lastActivity: now,
    createdAt: now,
    expiresAt,
    ipAddress,
    userAgent
  };
}

export async function invalidateSession(
  db: D1Database,
  sessionId: string
): Promise<void> {
  await db.prepare(`
    DELETE FROM sessions WHERE id = ?
  `).bind(sessionId).run();
}

export async function invalidateAllUserSessions(
  db: D1Database,
  userId: string
): Promise<void> {
  await db.prepare(`
    DELETE FROM sessions WHERE user_id = ?
  `).bind(userId).run();
}

export async function cleanupExpiredSessions(
  db: D1Database
): Promise<number> {
  const now = Math.floor(Date.now() / 1000);

  const result = await db.prepare(`
    DELETE FROM sessions
    WHERE expires_at < ?
    OR (last_activity IS NOT NULL AND last_activity < ?)
  `).bind(now, now - MAX_INACTIVITY_SECONDS).run();

  return result.meta.changes || 0;
}

export async function detectSuspiciousActivity(
  db: D1Database,
  userId: string,
  ipAddress: string
): Promise<{ suspicious: boolean; reason?: string }> {
  const recentSessions = await db.prepare(`
    SELECT ip_address, COUNT(*) as session_count
    FROM sessions
    WHERE user_id = ?
    AND created_at > ?
    GROUP BY ip_address
  `).bind(userId, Math.floor(Date.now() / 1000) - 3600).all();

  if (recentSessions.results.length > 5) {
    return {
      suspicious: true,
      reason: 'Multiple IP addresses detected in short time period'
    };
  }

  return { suspicious: false };
}

export const SESSION_CONFIG = {
  maxInactivitySeconds: MAX_INACTIVITY_SECONDS,
  absoluteTimeoutSeconds: SESSION_ABSOLUTE_TIMEOUT_SECONDS,
  maxInactivityMinutes: Math.floor(MAX_INACTIVITY_SECONDS / 60),
  absoluteTimeoutHours: Math.floor(SESSION_ABSOLUTE_TIMEOUT_SECONDS / 3600)
};
