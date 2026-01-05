import { Env } from '../worker';

export interface JWTPayload {
  user_id: string;
  email: string;
  role: string;
  user_type: 'tenant' | 'platform';
  tenant_id?: string;
  acting_as?: 'tenant';
  read_only?: boolean;
  exp: number;
  iat: number;
}

export interface RefreshTokenPayload {
  user_id: string;
  session_id: string;
  exp: number;
  iat: number;
}

async function base64UrlEncode(buffer: ArrayBuffer): Promise<string> {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function base64UrlDecode(str: string): Uint8Array {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function importKey(secret: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  return await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

export async function signJWT(payload: JWTPayload, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const enc = new TextEncoder();

  const encodedHeader = await base64UrlEncode(enc.encode(JSON.stringify(header)));
  const encodedPayload = await base64UrlEncode(enc.encode(JSON.stringify(payload)));

  const key = await importKey(secret);
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    enc.encode(`${encodedHeader}.${encodedPayload}`)
  );

  const encodedSignature = await base64UrlEncode(signature);
  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}

export async function verifyJWT(token: string, secret: string): Promise<JWTPayload> {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid token format');
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const enc = new TextEncoder();

  const key = await importKey(secret);
  const signature = base64UrlDecode(encodedSignature);

  const isValid = await crypto.subtle.verify(
    'HMAC',
    key,
    signature,
    enc.encode(`${encodedHeader}.${encodedPayload}`)
  );

  if (!isValid) {
    throw new Error('Invalid signature');
  }

  const payload: JWTPayload = JSON.parse(
    new TextDecoder().decode(base64UrlDecode(encodedPayload))
  );

  if (payload.exp && payload.exp < Date.now() / 1000) {
    throw new Error('Token expired');
  }

  return payload;
}

export async function signRefreshToken(payload: RefreshTokenPayload, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const enc = new TextEncoder();

  const encodedHeader = await base64UrlEncode(enc.encode(JSON.stringify(header)));
  const encodedPayload = await base64UrlEncode(enc.encode(JSON.stringify(payload)));

  const key = await importKey(secret);
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    enc.encode(`${encodedHeader}.${encodedPayload}`)
  );

  const encodedSignature = await base64UrlEncode(signature);
  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}

export async function verifyRefreshToken(token: string, secret: string): Promise<RefreshTokenPayload> {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid token format');
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const enc = new TextEncoder();

  const key = await importKey(secret);
  const signature = base64UrlDecode(encodedSignature);

  const isValid = await crypto.subtle.verify(
    'HMAC',
    key,
    signature,
    enc.encode(`${encodedHeader}.${encodedPayload}`)
  );

  if (!isValid) {
    throw new Error('Invalid signature');
  }

  const payload: RefreshTokenPayload = JSON.parse(
    new TextDecoder().decode(base64UrlDecode(encodedPayload))
  );

  if (payload.exp && payload.exp < Date.now() / 1000) {
    throw new Error('Token expired');
  }

  return payload;
}

export async function hashPassword(password: string): Promise<string> {
  const enc = new TextEncoder();
  const hash = await crypto.subtle.digest('SHA-256', enc.encode(password));
  return await base64UrlEncode(hash);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  const passwordHash = await hashPassword(password);
  return passwordHash === hash;
}

export function generateTokenId(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

export function requireAdminAccess(role: string): void {
  if (role !== 'admin') {
    throw new Error('Admin access required');
  }
}

export function isPlatformAdmin(userType: string): boolean {
  return userType === 'platform';
}

export function requirePlatformAdmin(userType: string): void {
  if (!isPlatformAdmin(userType)) {
    throw new Error('Platform admin access required');
  }
}

export function requireTenantContext(payload: JWTPayload): void {
  if (isPlatformAdmin(payload.user_type) && !payload.tenant_id) {
    throw new Error('Tenant context required for platform admin');
  }
}

export async function createScopedToken(
  userId: string,
  email: string,
  role: string,
  userType: 'tenant' | 'platform',
  tenantId: string,
  secret: string,
  readOnly: boolean = false,
  expiryMinutes: number = 30
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: JWTPayload = {
    user_id: userId,
    email,
    role,
    user_type: userType,
    tenant_id: tenantId,
    acting_as: 'tenant',
    read_only: readOnly,
    exp: now + (expiryMinutes * 60),
    iat: now
  };
  return signJWT(payload, secret);
}

export function determinUserType(email: string): 'tenant' | 'platform' {
  const lowercaseEmail = email.toLowerCase();
  return lowercaseEmail.endsWith('@roiblueprint.com') ? 'platform' : 'tenant';
}
