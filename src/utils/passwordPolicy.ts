const COMMON_PASSWORDS = [
  'password', 'password123', '12345678', 'qwerty', 'abc123', 'monkey',
  'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master',
  'sunshine', 'ashley', 'bailey', 'passw0rd', 'shadow', 'superman',
  'qazwsx', 'welcome', 'admin', 'password1', '123456789', '1234567890'
];

const PASSWORD_MIN_LENGTH = 12;
const PASSWORD_MAX_AGE_DAYS = 90;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MINUTES = 30;
const PASSWORD_HISTORY_COUNT = 5;

export interface PasswordValidationResult {
  valid: boolean;
  errors: string[];
}

export function validatePasswordComplexity(password: string): PasswordValidationResult {
  const errors: string[] = [];

  if (password.length < PASSWORD_MIN_LENGTH) {
    errors.push(`Password must be at least ${PASSWORD_MIN_LENGTH} characters long`);
  }

  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }

  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }

  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }

  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }

  if (COMMON_PASSWORDS.includes(password.toLowerCase())) {
    errors.push('Password is too common. Please choose a more unique password');
  }

  const repeatingChars = /(.)\1{2,}/.test(password);
  if (repeatingChars) {
    errors.push('Password should not contain repeated characters (e.g., "aaa", "111")');
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

export async function checkPasswordHistory(
  db: D1Database,
  userId: string,
  newPasswordHash: string
): Promise<boolean> {
  const history = await db.prepare(`
    SELECT password_hash FROM password_history
    WHERE user_id = ?
    ORDER BY created_at DESC
    LIMIT ?
  `).bind(userId, PASSWORD_HISTORY_COUNT).all();

  for (const record of history.results) {
    if (record.password_hash === newPasswordHash) {
      return false;
    }
  }

  return true;
}

export async function addPasswordToHistory(
  db: D1Database,
  userId: string,
  passwordHash: string
): Promise<void> {
  await db.prepare(`
    INSERT INTO password_history (user_id, password_hash)
    VALUES (?, ?)
  `).bind(userId, passwordHash).run();

  await db.prepare(`
    DELETE FROM password_history
    WHERE user_id = ?
    AND id NOT IN (
      SELECT id FROM password_history
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT ?
    )
  `).bind(userId, userId, PASSWORD_HISTORY_COUNT).run();
}

export function calculatePasswordExpiry(): number {
  return Math.floor(Date.now() / 1000) + (PASSWORD_MAX_AGE_DAYS * 24 * 60 * 60);
}

export async function checkAccountLockout(
  db: D1Database,
  userId: string
): Promise<{ locked: boolean; lockedUntil?: number }> {
  const user = await db.prepare(`
    SELECT locked_until FROM users WHERE id = ?
  `).bind(userId).first();

  if (!user) {
    return { locked: false };
  }

  const now = Math.floor(Date.now() / 1000);
  const lockedUntil = user.locked_until as number | null;
  if (lockedUntil && lockedUntil > now) {
    return { locked: true, lockedUntil };
  }

  return { locked: false };
}

export async function incrementFailedLoginAttempts(
  db: D1Database,
  userId: string
): Promise<{ locked: boolean; attempts: number }> {
  const user = await db.prepare(`
    SELECT failed_login_attempts FROM users WHERE id = ?
  `).bind(userId).first();

  if (!user) {
    throw new Error('User not found');
  }

  const attempts = (user.failed_login_attempts as number || 0) + 1;

  if (attempts >= MAX_FAILED_ATTEMPTS) {
    const lockedUntil = Math.floor(Date.now() / 1000) + (LOCKOUT_DURATION_MINUTES * 60);
    await db.prepare(`
      UPDATE users
      SET failed_login_attempts = ?,
          locked_until = ?
      WHERE id = ?
    `).bind(attempts, lockedUntil, userId).run();

    return { locked: true, attempts };
  }

  await db.prepare(`
    UPDATE users
    SET failed_login_attempts = ?
    WHERE id = ?
  `).bind(attempts, userId).run();

  return { locked: false, attempts };
}

export async function resetFailedLoginAttempts(
  db: D1Database,
  userId: string
): Promise<void> {
  await db.prepare(`
    UPDATE users
    SET failed_login_attempts = 0,
        locked_until = NULL
    WHERE id = ?
  `).bind(userId).run();
}

export async function checkPasswordExpiry(
  db: D1Database,
  userId: string
): Promise<{ expired: boolean; expiresAt?: number }> {
  const user = await db.prepare(`
    SELECT password_expires_at FROM users WHERE id = ?
  `).bind(userId).first();

  if (!user) {
    return { expired: false };
  }

  const now = Math.floor(Date.now() / 1000);
  const expiresAt = user.password_expires_at as number | null;
  if (expiresAt && expiresAt < now) {
    return { expired: true, expiresAt };
  }

  return { expired: false, expiresAt: expiresAt || undefined };
}

export const PASSWORD_POLICY = {
  minLength: PASSWORD_MIN_LENGTH,
  maxAgeDays: PASSWORD_MAX_AGE_DAYS,
  maxFailedAttempts: MAX_FAILED_ATTEMPTS,
  lockoutDurationMinutes: LOCKOUT_DURATION_MINUTES,
  historyCount: PASSWORD_HISTORY_COUNT,
  requireUppercase: true,
  requireLowercase: true,
  requireNumber: true,
  requireSpecialChar: true
};
