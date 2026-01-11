import { D1Database } from '@cloudflare/workers-types';

export interface DataEncryptionKey {
  id: string;
  version: number;
  encryptedKey: string;
  keyHash: string;
  algorithm: string;
  createdAt: number;
  rotatedAt?: number;
  status: 'active' | 'rotated' | 'compromised';
}

export interface EncryptedData {
  ciphertext: string;
  iv: string;
  tag: string;
  dekId: string;
  algorithm: string;
}

export interface KeyRotationLog {
  id: string;
  oldDekId: string;
  newDekId: string;
  rotatedBy: string;
  reason: string;
  recordsReencrypted: number;
  createdAt: number;
}

export class EnvelopeEncryption {
  private masterKey: string;
  private db: D1Database;
  private activeDEKCache: Map<string, CryptoKey> = new Map();

  constructor(masterKey: string, db: D1Database) {
    this.masterKey = masterKey;
    this.db = db;
  }

  async initialize(): Promise<void> {
    await this.createKeyManagementTables();
    await this.ensureActiveDEK();
  }

  async encrypt(plaintext: string, tenantId: string): Promise<EncryptedData> {
    const dek = await this.getOrCreateActiveDEK(tenantId);
    const dekKey = await this.decryptDEK(dek.encryptedKey);

    const encoder = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        tagLength: 128
      },
      dekKey,
      encoder.encode(plaintext)
    );

    const encrypted = new Uint8Array(encryptedBuffer);
    const ciphertext = encrypted.slice(0, -16);
    const tag = encrypted.slice(-16);

    return {
      ciphertext: this.bufferToBase64(ciphertext),
      iv: this.bufferToBase64(iv),
      tag: this.bufferToBase64(tag),
      dekId: dek.id,
      algorithm: 'AES-GCM-256'
    };
  }

  async decrypt(encryptedData: EncryptedData): Promise<string> {
    const dek = await this.getDEK(encryptedData.dekId);

    if (!dek) {
      throw new Error(`DEK not found: ${encryptedData.dekId}`);
    }

    if (dek.status === 'compromised') {
      throw new Error(`Cannot decrypt with compromised DEK: ${encryptedData.dekId}`);
    }

    const dekKey = await this.decryptDEK(dek.encryptedKey);

    const iv = this.base64ToBuffer(encryptedData.iv);
    const ciphertext = this.base64ToBuffer(encryptedData.ciphertext);
    const tag = this.base64ToBuffer(encryptedData.tag);

    const encryptedBuffer = new Uint8Array([...ciphertext, ...tag]);

    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
        tagLength: 128
      },
      dekKey,
      encryptedBuffer
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
  }

  async rotateDEK(
    tenantId: string,
    rotatedBy: string,
    reason: string
  ): Promise<{ newDekId: string; recordsReencrypted: number }> {
    const oldDEK = await this.getActiveDEK(tenantId);

    if (!oldDEK) {
      throw new Error(`No active DEK found for tenant: ${tenantId}`);
    }

    const newDEK = await this.createDEK(tenantId);

    await this.db
      .prepare(
        `UPDATE data_encryption_keys
         SET status = 'rotated', rotated_at = ?
         WHERE id = ?`
      )
      .bind(Math.floor(Date.now() / 1000), oldDEK.id)
      .run();

    const logId = crypto.randomUUID();
    await this.db
      .prepare(
        `INSERT INTO key_rotation_logs (id, old_dek_id, new_dek_id, rotated_by, reason, records_reencrypted, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        logId,
        oldDEK.id,
        newDEK.id,
        rotatedBy,
        reason,
        0,
        Math.floor(Date.now() / 1000)
      )
      .run();

    this.activeDEKCache.delete(tenantId);

    return {
      newDekId: newDEK.id,
      recordsReencrypted: 0
    };
  }

  async reencryptWithNewDEK(
    oldEncrypted: EncryptedData
  ): Promise<EncryptedData> {
    const plaintext = await this.decrypt(oldEncrypted);

    const oldDEK = await this.getDEK(oldEncrypted.dekId);
    if (!oldDEK) {
      throw new Error(`Old DEK not found: ${oldEncrypted.dekId}`);
    }

    const tenantIdResult = await this.db
      .prepare('SELECT tenant_id FROM data_encryption_keys WHERE id = ?')
      .bind(oldEncrypted.dekId)
      .first();

    const tenantId = tenantIdResult?.tenant_id as string;

    return this.encrypt(plaintext, tenantId);
  }

  async markDEKCompromised(dekId: string, reason: string): Promise<void> {
    await this.db
      .prepare(
        `UPDATE data_encryption_keys
         SET status = 'compromised'
         WHERE id = ?`
      )
      .bind(dekId)
      .run();

    await this.db
      .prepare(
        `INSERT INTO key_compromise_logs (id, dek_id, reason, created_at)
         VALUES (?, ?, ?, ?)`
      )
      .bind(
        crypto.randomUUID(),
        dekId,
        reason,
        Math.floor(Date.now() / 1000)
      )
      .run();
  }

  async getKeyRotationHistory(tenantId: string, limit: number = 10): Promise<KeyRotationLog[]> {
    const result = await this.db
      .prepare(
        `SELECT krl.*
         FROM key_rotation_logs krl
         JOIN data_encryption_keys dek ON krl.new_dek_id = dek.id
         WHERE dek.tenant_id = ?
         ORDER BY krl.created_at DESC
         LIMIT ?`
      )
      .bind(tenantId, limit)
      .all();

    return (result.results || []).map(row => ({
      id: row.id as string,
      oldDekId: row.old_dek_id as string,
      newDekId: row.new_dek_id as string,
      rotatedBy: row.rotated_by as string,
      reason: row.reason as string,
      recordsReencrypted: row.records_reencrypted as number,
      createdAt: row.created_at as number
    }));
  }

  async validateMasterKey(): Promise<boolean> {
    try {
      const testDEK = await this.getActiveDEK('test-validation');
      if (testDEK) {
        await this.decryptDEK(testDEK.encryptedKey);
      }
      return true;
    } catch (error) {
      console.error('Master key validation failed:', error);
      return false;
    }
  }

  private async createKeyManagementTables(): Promise<void> {
    await this.db
      .exec(
        `
        CREATE TABLE IF NOT EXISTS data_encryption_keys (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          tenant_id TEXT NOT NULL,
          version INTEGER NOT NULL DEFAULT 1,
          encrypted_key TEXT NOT NULL,
          key_hash TEXT NOT NULL,
          algorithm TEXT NOT NULL DEFAULT 'AES-GCM-256',
          status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'rotated', 'compromised')),
          created_at INTEGER NOT NULL DEFAULT (unixepoch()),
          rotated_at INTEGER,
          FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT
        );

        CREATE INDEX IF NOT EXISTS idx_dek_tenant_id ON data_encryption_keys(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_dek_status ON data_encryption_keys(status);

        CREATE TABLE IF NOT EXISTS key_rotation_logs (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          old_dek_id TEXT NOT NULL,
          new_dek_id TEXT NOT NULL,
          rotated_by TEXT NOT NULL,
          reason TEXT NOT NULL,
          records_reencrypted INTEGER DEFAULT 0,
          created_at INTEGER NOT NULL DEFAULT (unixepoch()),
          FOREIGN KEY (old_dek_id) REFERENCES data_encryption_keys(id),
          FOREIGN KEY (new_dek_id) REFERENCES data_encryption_keys(id)
        );

        CREATE INDEX IF NOT EXISTS idx_krl_old_dek ON key_rotation_logs(old_dek_id);
        CREATE INDEX IF NOT EXISTS idx_krl_new_dek ON key_rotation_logs(new_dek_id);
        CREATE INDEX IF NOT EXISTS idx_krl_created_at ON key_rotation_logs(created_at);

        CREATE TABLE IF NOT EXISTS key_compromise_logs (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          dek_id TEXT NOT NULL,
          reason TEXT NOT NULL,
          created_at INTEGER NOT NULL DEFAULT (unixepoch()),
          FOREIGN KEY (dek_id) REFERENCES data_encryption_keys(id)
        );

        CREATE INDEX IF NOT EXISTS idx_kcl_dek ON key_compromise_logs(dek_id);
        CREATE INDEX IF NOT EXISTS idx_kcl_created_at ON key_compromise_logs(created_at);

        CREATE TABLE IF NOT EXISTS master_key_access_log (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          accessed_by TEXT NOT NULL,
          operation TEXT NOT NULL CHECK (operation IN ('encrypt', 'decrypt', 'rotate', 'validate')),
          ip_address TEXT,
          success INTEGER NOT NULL DEFAULT 1 CHECK (success IN (0, 1)),
          failure_reason TEXT,
          created_at INTEGER NOT NULL DEFAULT (unixepoch())
        );

        CREATE INDEX IF NOT EXISTS idx_mkal_accessed_by ON master_key_access_log(accessed_by);
        CREATE INDEX IF NOT EXISTS idx_mkal_operation ON master_key_access_log(operation);
        CREATE INDEX IF NOT EXISTS idx_mkal_created_at ON master_key_access_log(created_at);
      `
      )
      .catch(err => {
        console.error('Failed to create key management tables:', err);
      });
  }

  private async ensureActiveDEK(): Promise<void> {
    const result = await this.db
      .prepare(
        `SELECT COUNT(*) as count
         FROM data_encryption_keys
         WHERE status = 'active'`
      )
      .first();

    if (result && result.count === 0) {
      await this.createDEK('default');
    }
  }

  private async createDEK(tenantId: string): Promise<DataEncryptionKey> {
    const rawDEK = crypto.getRandomValues(new Uint8Array(32));

    const dekKey = await crypto.subtle.importKey(
      'raw',
      rawDEK,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    const encryptedKey = await this.encryptWithMasterKey(rawDEK);

    const keyHashBuffer = await crypto.subtle.digest('SHA-256', rawDEK);
    const keyHash = this.bufferToBase64(new Uint8Array(keyHashBuffer));

    const id = crypto.randomUUID();
    const createdAt = Math.floor(Date.now() / 1000);

    const maxVersionResult = await this.db
      .prepare(
        `SELECT COALESCE(MAX(version), 0) as max_version
         FROM data_encryption_keys
         WHERE tenant_id = ?`
      )
      .bind(tenantId)
      .first();

    const version = (maxVersionResult?.max_version as number || 0) + 1;

    await this.db
      .prepare(
        `INSERT INTO data_encryption_keys (id, tenant_id, version, encrypted_key, key_hash, algorithm, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(id, tenantId, version, encryptedKey, keyHash, 'AES-GCM-256', 'active', createdAt)
      .run();

    return {
      id,
      version,
      encryptedKey,
      keyHash,
      algorithm: 'AES-GCM-256',
      createdAt,
      status: 'active'
    };
  }

  private async encryptWithMasterKey(data: Uint8Array): Promise<string> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(this.masterKey),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      key,
      data
    );

    const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(encrypted), salt.length + iv.length);

    return this.bufferToBase64(combined);
  }

  private async decryptDEK(encryptedKey: string): Promise<CryptoKey> {
    const combined = this.base64ToBuffer(encryptedKey);
    const salt = combined.slice(0, 16);
    const iv = combined.slice(16, 28);
    const ciphertext = combined.slice(28);

    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(this.masterKey),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      key,
      ciphertext
    );

    return crypto.subtle.importKey(
      'raw',
      decrypted,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  private async getOrCreateActiveDEK(tenantId: string): Promise<DataEncryptionKey> {
    let dek = await this.getActiveDEK(tenantId);

    if (!dek) {
      dek = await this.createDEK(tenantId);
    }

    return dek;
  }

  private async getActiveDEK(tenantId: string): Promise<DataEncryptionKey | null> {
    const result = await this.db
      .prepare(
        `SELECT id, tenant_id, version, encrypted_key, key_hash, algorithm, status, created_at, rotated_at
         FROM data_encryption_keys
         WHERE tenant_id = ? AND status = 'active'
         ORDER BY version DESC
         LIMIT 1`
      )
      .bind(tenantId)
      .first();

    if (!result) {
      return null;
    }

    return {
      id: result.id as string,
      version: result.version as number,
      encryptedKey: result.encrypted_key as string,
      keyHash: result.key_hash as string,
      algorithm: result.algorithm as string,
      createdAt: result.created_at as number,
      rotatedAt: result.rotated_at as number | undefined,
      status: result.status as 'active' | 'rotated' | 'compromised'
    };
  }

  private async getDEK(dekId: string): Promise<DataEncryptionKey | null> {
    const result = await this.db
      .prepare(
        `SELECT id, tenant_id, version, encrypted_key, key_hash, algorithm, status, created_at, rotated_at
         FROM data_encryption_keys
         WHERE id = ?`
      )
      .bind(dekId)
      .first();

    if (!result) {
      return null;
    }

    return {
      id: result.id as string,
      version: result.version as number,
      encryptedKey: result.encrypted_key as string,
      keyHash: result.key_hash as string,
      algorithm: result.algorithm as string,
      createdAt: result.created_at as number,
      rotatedAt: result.rotated_at as number | undefined,
      status: result.status as 'active' | 'rotated' | 'compromised'
    };
  }

  private bufferToBase64(buffer: Uint8Array): string {
    const bytes = Array.from(buffer);
    const binary = bytes.map(b => String.fromCharCode(b)).join('');
    return btoa(binary);
  }

  private base64ToBuffer(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
}

export function createEnvelopeEncryption(masterKey: string, db: D1Database): EnvelopeEncryption {
  return new EnvelopeEncryption(masterKey, db);
}
