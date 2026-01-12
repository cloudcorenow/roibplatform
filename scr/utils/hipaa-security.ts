import { createHmac, randomBytes } from 'node:crypto';

export interface PasswordValidationResult {
  valid: boolean;
  errors: string[];
  strength: 'weak' | 'medium' | 'strong' | 'very-strong';
}

export interface PasswordPolicy {
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSpecialChars: boolean;
  preventCommonPasswords: boolean;
  preventUserInfo: boolean;
  maxAge: number;
  preventReuse: number;
}

export const HIPAA_PASSWORD_POLICY: PasswordPolicy = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  preventCommonPasswords: true,
  preventUserInfo: true,
  maxAge: 90,
  preventReuse: 5,
};

const COMMON_PASSWORDS = [
  'password', 'password123', '123456', '12345678', 'qwerty', 'abc123',
  'monkey', '1234567', 'letmein', 'trustno1', 'dragon', 'baseball',
  'iloveyou', 'master', 'sunshine', 'ashley', 'bailey', 'passw0rd',
  'shadow', '123123', '654321', 'superman', 'qazwsx', 'michael',
  'football', 'welcome', 'jesus', 'ninja', 'mustang', 'password1'
];

export function validatePassword(
  password: string,
  userInfo?: { name?: string; email?: string },
  policy: PasswordPolicy = HIPAA_PASSWORD_POLICY
): PasswordValidationResult {
  const errors: string[] = [];

  if (password.length < policy.minLength) {
    errors.push(`Password must be at least ${policy.minLength} characters long`);
  }

  if (policy.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }

  if (policy.requireLowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }

  if (policy.requireNumbers && !/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }

  if (policy.requireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }

  if (policy.preventCommonPasswords) {
    const lowerPassword = password.toLowerCase();
    if (COMMON_PASSWORDS.some(common => lowerPassword.includes(common))) {
      errors.push('Password is too common or easily guessable');
    }
  }

  if (policy.preventUserInfo && userInfo) {
    const lowerPassword = password.toLowerCase();
    if (userInfo.name && lowerPassword.includes(userInfo.name.toLowerCase())) {
      errors.push('Password cannot contain your name');
    }
    if (userInfo.email) {
      const emailPrefix = userInfo.email.split('@')[0].toLowerCase();
      if (lowerPassword.includes(emailPrefix)) {
        errors.push('Password cannot contain your email address');
      }
    }
  }

  const strength = calculatePasswordStrength(password);

  return {
    valid: errors.length === 0,
    errors,
    strength,
  };
}

function calculatePasswordStrength(password: string): 'weak' | 'medium' | 'strong' | 'very-strong' {
  let score = 0;

  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  if (/[a-z]/.test(password)) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password) && password.length >= 14) score++;

  if (score <= 3) return 'weak';
  if (score <= 5) return 'medium';
  if (score <= 7) return 'strong';
  return 'very-strong';
}

export function generateSecureToken(length: number = 32): string {
  return randomBytes(length).toString('hex');
}

export function generateMFASecret(): string {
  return randomBytes(20).toString('base64').replace(/[^A-Z0-9]/gi, '').substring(0, 32);
}

export function generateMFABackupCodes(count: number = 10): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const code = randomBytes(4).toString('hex').toUpperCase();
    codes.push(`${code.substring(0, 4)}-${code.substring(4, 8)}`);
  }
  return codes;
}

export function verifyTOTP(secret: string, token: string): boolean {
  const window = 1;
  const timeStep = 30;
  const currentTime = Math.floor(Date.now() / 1000);

  for (let i = -window; i <= window; i++) {
    const time = currentTime + (i * timeStep);
    const expectedToken = generateTOTP(secret, time);
    if (expectedToken === token) {
      return true;
    }
  }

  return false;
}

function generateTOTP(secret: string, time: number): string {
  const timeHex = Math.floor(time / 30).toString(16).padStart(16, '0');
  const timeBuffer = Buffer.from(timeHex, 'hex');

  const hmac = createHmac('sha1', Buffer.from(secret, 'base64'));
  hmac.update(timeBuffer);
  const hash = hmac.digest();

  const offset = hash[hash.length - 1] & 0xf;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  const otp = binary % 1000000;
  return otp.toString().padStart(6, '0');
}

export function calculateDocumentChecksum(data: ArrayBuffer): Promise<string> {
  return crypto.subtle.digest('SHA-256', data).then(hashBuffer => {
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  });
}

export function verifyDocumentIntegrity(
  data: ArrayBuffer,
  expectedChecksum: string
): Promise<boolean> {
  return calculateDocumentChecksum(data).then(
    actualChecksum => actualChecksum === expectedChecksum
  );
}

export interface SessionTimeoutConfig {
  maxInactivityMinutes: number;
  absoluteTimeoutMinutes: number;
  warningMinutesBeforeTimeout: number;
}

export const HIPAA_SESSION_CONFIG: SessionTimeoutConfig = {
  maxInactivityMinutes: 15,
  absoluteTimeoutMinutes: 480,
  warningMinutesBeforeTimeout: 2,
};

export function isSessionExpired(
  lastActivity: number,
  sessionStart: number,
  config: SessionTimeoutConfig = HIPAA_SESSION_CONFIG
): { expired: boolean; reason?: 'inactivity' | 'absolute' } {
  const now = Date.now() / 1000;
  const inactivitySeconds = now - lastActivity;
  const absoluteSeconds = now - sessionStart;

  const maxInactivitySeconds = config.maxInactivityMinutes * 60;
  const maxAbsoluteSeconds = config.absoluteTimeoutMinutes * 60;

  if (inactivitySeconds > maxInactivitySeconds) {
    return { expired: true, reason: 'inactivity' };
  }

  if (absoluteSeconds > maxAbsoluteSeconds) {
    return { expired: true, reason: 'absolute' };
  }

  return { expired: false };
}

export function getSessionTimeoutWarning(
  lastActivity: number,
  config: SessionTimeoutConfig = HIPAA_SESSION_CONFIG
): { shouldWarn: boolean; secondsRemaining?: number } {
  const now = Date.now() / 1000;
  const inactivitySeconds = now - lastActivity;
  const maxInactivitySeconds = config.maxInactivityMinutes * 60;
  const warningSeconds = config.warningMinutesBeforeTimeout * 60;

  const secondsRemaining = maxInactivitySeconds - inactivitySeconds;

  if (secondsRemaining <= warningSeconds && secondsRemaining > 0) {
    return { shouldWarn: true, secondsRemaining: Math.floor(secondsRemaining) };
  }

  return { shouldWarn: false };
}

export interface AccountLockoutPolicy {
  maxFailedAttempts: number;
  lockoutDurationMinutes: number;
  resetAfterMinutes: number;
}

export const HIPAA_LOCKOUT_POLICY: AccountLockoutPolicy = {
  maxFailedAttempts: 5,
  lockoutDurationMinutes: 30,
  resetAfterMinutes: 60,
};

export function isAccountLocked(
  accountLockedUntil: number | null | undefined
): boolean {
  if (!accountLockedUntil) return false;
  const now = Date.now() / 1000;
  return accountLockedUntil > now;
}

export function calculateLockoutEnd(
  policy: AccountLockoutPolicy = HIPAA_LOCKOUT_POLICY
): number {
  const now = Date.now() / 1000;
  return now + (policy.lockoutDurationMinutes * 60);
}

export function shouldResetFailedAttempts(
  lastFailedAttempt: number,
  policy: AccountLockoutPolicy = HIPAA_LOCKOUT_POLICY
): boolean {
  const now = Date.now() / 1000;
  const timeSinceLastAttempt = now - lastFailedAttempt;
  return timeSinceLastAttempt > (policy.resetAfterMinutes * 60);
}

export interface AuditLogEntry {
  tenantId: string;
  userId: string;
  action: string;
  resourceType: string;
  resourceId?: string;
  ipAddress?: string;
  userAgent?: string;
  details?: Record<string, unknown>;
}

export function createAuditLog(entry: AuditLogEntry): AuditLogEntry & { timestamp: number } {
  return {
    ...entry,
    timestamp: Math.floor(Date.now() / 1000),
  };
}

export function sanitizeAuditDetails(details: Record<string, unknown>): Record<string, unknown> {
  const sanitized = { ...details };
  const sensitiveKeys = ['password', 'password_hash', 'secret', 'token', 'api_key', 'mfa_secret'];

  for (const key of Object.keys(sanitized)) {
    if (sensitiveKeys.some(sensitive => key.toLowerCase().includes(sensitive))) {
      sanitized[key] = '[REDACTED]';
    }
  }

  return sanitized;
}
