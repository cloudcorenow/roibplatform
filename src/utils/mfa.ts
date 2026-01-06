function base32Encode(buffer: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;

    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }

  return output;
}

function base32Decode(str: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  str = str.toUpperCase().replace(/=+$/, '');

  let bits = 0;
  let value = 0;
  let index = 0;
  const output = new Uint8Array(Math.ceil(str.length * 5 / 8));

  for (let i = 0; i < str.length; i++) {
    const idx = alphabet.indexOf(str[i]);
    if (idx === -1) continue;

    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      output[index++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
    }
  }

  return output.slice(0, index);
}

async function hmacSha1(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', cryptoKey, message);
  return new Uint8Array(signature);
}

async function generateHOTP(secret: Uint8Array, counter: number): Promise<string> {
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setBigUint64(0, BigInt(counter), false);

  const hmac = await hmacSha1(secret, new Uint8Array(buffer));
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary = (
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff)
  );

  const otp = binary % 1000000;
  return otp.toString().padStart(6, '0');
}

function getCurrentCounter(timeStep: number = 30): number {
  return Math.floor(Date.now() / 1000 / timeStep);
}

export async function generateTOTP(secret: string, timeStep: number = 30): Promise<string> {
  const secretBytes = base32Decode(secret);
  const counter = getCurrentCounter(timeStep);
  return generateHOTP(secretBytes, counter);
}

export async function verifyTOTP(
  secret: string,
  token: string,
  window: number = 1,
  timeStep: number = 30
): Promise<boolean> {
  const counter = getCurrentCounter(timeStep);

  for (let i = -window; i <= window; i++) {
    const expectedToken = await generateHOTP(base32Decode(secret), counter + i);
    if (expectedToken === token) {
      return true;
    }
  }

  return false;
}

export function generateSecret(): string {
  const buffer = new Uint8Array(20);
  crypto.getRandomValues(buffer);
  return base32Encode(buffer);
}

export function generateBackupCodes(count: number = 10): string[] {
  const codes: string[] = [];

  for (let i = 0; i < count; i++) {
    const buffer = new Uint8Array(5);
    crypto.getRandomValues(buffer);
    const code = Array.from(buffer)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .substring(0, 8)
      .toUpperCase();
    codes.push(code);
  }

  return codes;
}

export function generateQRCodeURL(
  secret: string,
  email: string,
  issuer: string = 'ROI Blueprint'
): string {
  const label = encodeURIComponent(`${issuer}:${email}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30'
  });

  const otpauthURL = `otpauth://totp/${label}?${params.toString()}`;
  return `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(otpauthURL)}`;
}

export async function setupMFA(
  db: D1Database,
  userId: string
): Promise<{ secret: string; backupCodes: string[]; qrCodeURL: string }> {
  const secret = generateSecret();
  const backupCodes = generateBackupCodes();

  const user = await db.prepare(`
    SELECT email FROM users WHERE id = ?
  `).bind(userId).first();

  if (!user) {
    throw new Error('User not found');
  }

  const now = Math.floor(Date.now() / 1000);

  await db.prepare(`
    INSERT OR REPLACE INTO mfa_tokens (user_id, secret, backup_codes, enabled, created_at)
    VALUES (?, ?, ?, 0, ?)
  `).bind(userId, secret, JSON.stringify(backupCodes), now).run();

  const qrCodeURL = generateQRCodeURL(secret, user.email as string);

  return { secret, backupCodes, qrCodeURL };
}

export async function enableMFA(
  db: D1Database,
  userId: string,
  token: string
): Promise<boolean> {
  const mfaRecord = await db.prepare(`
    SELECT secret FROM mfa_tokens WHERE user_id = ?
  `).bind(userId).first();

  if (!mfaRecord) {
    throw new Error('MFA not set up for this user');
  }

  const isValid = await verifyTOTP(mfaRecord.secret as string, token);

  if (isValid) {
    const now = Math.floor(Date.now() / 1000);
    await db.prepare(`
      UPDATE mfa_tokens
      SET enabled = 1, last_used = ?
      WHERE user_id = ?
    `).bind(now, userId).run();
    return true;
  }

  return false;
}

export async function disableMFA(
  db: D1Database,
  userId: string
): Promise<void> {
  await db.prepare(`
    DELETE FROM mfa_tokens WHERE user_id = ?
  `).bind(userId).run();
}

export async function verifyMFAToken(
  db: D1Database,
  userId: string,
  token: string
): Promise<boolean> {
  const mfaRecord = await db.prepare(`
    SELECT secret, backup_codes, enabled FROM mfa_tokens WHERE user_id = ?
  `).bind(userId).first();

  if (!mfaRecord || !mfaRecord.enabled) {
    return false;
  }

  const isValidTOTP = await verifyTOTP(mfaRecord.secret as string, token);

  if (isValidTOTP) {
    const now = Math.floor(Date.now() / 1000);
    await db.prepare(`
      UPDATE mfa_tokens SET last_used = ? WHERE user_id = ?
    `).bind(now, userId).run();
    return true;
  }

  if (mfaRecord.backup_codes) {
    const backupCodes = JSON.parse(mfaRecord.backup_codes as string) as string[];
    const codeIndex = backupCodes.indexOf(token.toUpperCase());

    if (codeIndex !== -1) {
      backupCodes.splice(codeIndex, 1);
      await db.prepare(`
        UPDATE mfa_tokens SET backup_codes = ? WHERE user_id = ?
      `).bind(JSON.stringify(backupCodes), userId).run();
      return true;
    }
  }

  return false;
}

export async function isMFAEnabled(
  db: D1Database,
  userId: string
): Promise<boolean> {
  const mfaRecord = await db.prepare(`
    SELECT enabled FROM mfa_tokens WHERE user_id = ?
  `).bind(userId).first();

  return mfaRecord?.enabled === 1;
}

export async function getRemainingBackupCodes(
  db: D1Database,
  userId: string
): Promise<string[]> {
  const mfaRecord = await db.prepare(`
    SELECT backup_codes FROM mfa_tokens WHERE user_id = ?
  `).bind(userId).first();

  if (!mfaRecord || !mfaRecord.backup_codes) {
    return [];
  }

  return JSON.parse(mfaRecord.backup_codes as string) as string[];
}
