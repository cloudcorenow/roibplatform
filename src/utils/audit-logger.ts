import { D1Database } from '@cloudflare/workers-types';

export type AuditAction =
  | 'CREATE'
  | 'READ'
  | 'UPDATE'
  | 'DELETE'
  | 'ACCESS'
  | 'LOGIN'
  | 'LOGOUT'
  | 'EXPORT'
  | 'PRINT';

export interface AuditLogEntry {
  tenantId: string;
  userId: string;
  action: AuditAction;
  resourceType: string;
  resourceId?: string;
  phiAccessed?: string[];
  ipAddress?: string;
  userAgent?: string;
  requestId?: string;
  success?: boolean;
  failureReason?: string;
  metadata?: Record<string, any>;
}

export interface AuditLogQuery {
  tenantId: string;
  userId?: string;
  action?: AuditAction;
  resourceType?: string;
  resourceId?: string;
  startDate?: number;
  endDate?: number;
  limit?: number;
  offset?: number;
}

export class AuditLogger {
  constructor(private db: D1Database) {}

  async log(entry: AuditLogEntry): Promise<string> {
    const id = crypto.randomUUID();
    const createdAt = Math.floor(Date.now() / 1000);

    const checksum = await this.generateChecksum({
      ...entry,
      id,
      createdAt
    });

    const phiAccessedJson = entry.phiAccessed
      ? JSON.stringify(entry.phiAccessed)
      : null;
    const metadataJson = entry.metadata
      ? JSON.stringify(entry.metadata)
      : null;

    await this.db
      .prepare(
        `INSERT INTO audit_logs (
          id, tenant_id, user_id, action, resource_type, resource_id,
          phi_accessed, ip_address, user_agent, request_id, success,
          failure_reason, metadata, checksum, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        id,
        entry.tenantId,
        entry.userId,
        entry.action,
        entry.resourceType,
        entry.resourceId || null,
        phiAccessedJson,
        entry.ipAddress || null,
        entry.userAgent || null,
        entry.requestId || null,
        entry.success !== false ? 1 : 0,
        entry.failureReason || null,
        metadataJson,
        checksum,
        createdAt
      )
      .run();

    await this.addToChain(id, entry.tenantId);

    return id;
  }

  async logPHIAccess(
    tenantId: string,
    userId: string,
    patientId: string | null,
    fieldsAccessed: string[],
    justification?: string,
    approvedBy?: string,
    ipAddress?: string
  ): Promise<string> {
    const id = crypto.randomUUID();
    const createdAt = Math.floor(Date.now() / 1000);

    await this.db
      .prepare(
        `INSERT INTO phi_access_log (
          id, tenant_id, user_id, patient_id, fields_accessed,
          justification, approved_by, ip_address, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        id,
        tenantId,
        userId,
        patientId,
        JSON.stringify(fieldsAccessed),
        justification || null,
        approvedBy || null,
        ipAddress || null,
        createdAt
      )
      .run();

    return id;
  }

  async query(query: AuditLogQuery): Promise<any[]> {
    let sql = `
      SELECT
        id, tenant_id, user_id, action, resource_type, resource_id,
        phi_accessed, ip_address, user_agent, request_id, success,
        failure_reason, metadata, checksum, created_at
      FROM audit_logs
      WHERE tenant_id = ?
    `;
    const params: any[] = [query.tenantId];

    if (query.userId) {
      sql += ' AND user_id = ?';
      params.push(query.userId);
    }

    if (query.action) {
      sql += ' AND action = ?';
      params.push(query.action);
    }

    if (query.resourceType) {
      sql += ' AND resource_type = ?';
      params.push(query.resourceType);
    }

    if (query.resourceId) {
      sql += ' AND resource_id = ?';
      params.push(query.resourceId);
    }

    if (query.startDate) {
      sql += ' AND created_at >= ?';
      params.push(query.startDate);
    }

    if (query.endDate) {
      sql += ' AND created_at <= ?';
      params.push(query.endDate);
    }

    sql += ' ORDER BY created_at DESC';

    if (query.limit) {
      sql += ' LIMIT ?';
      params.push(query.limit);
    }

    if (query.offset) {
      sql += ' OFFSET ?';
      params.push(query.offset);
    }

    const result = await this.db.prepare(sql).bind(...params).all();
    return result.results || [];
  }

  async verifyIntegrity(tenantId: string): Promise<{
    valid: boolean;
    errors: string[];
  }> {
    const errors: string[] = [];

    const chainResult = await this.db
      .prepare(
        `SELECT
          ac.id, ac.audit_log_id, ac.previous_hash, ac.current_hash,
          al.id as log_id, al.tenant_id, al.user_id, al.action,
          al.resource_type, al.resource_id, al.checksum, al.created_at
        FROM audit_chain ac
        JOIN audit_logs al ON ac.audit_log_id = al.id
        WHERE ac.tenant_id = ?
        ORDER BY ac.created_at ASC`
      )
      .bind(tenantId)
      .all();

    const chain = chainResult.results || [];

    for (let i = 0; i < chain.length; i++) {
      const entry = chain[i];

      const calculatedChecksum = await this.generateChecksum({
        id: entry.log_id,
        tenantId: entry.tenant_id,
        userId: entry.user_id,
        action: entry.action,
        resourceType: entry.resource_type,
        resourceId: entry.resource_id,
        createdAt: entry.created_at
      });

      if (calculatedChecksum !== entry.checksum) {
        errors.push(
          `Checksum mismatch for audit log ${entry.log_id}: expected ${entry.checksum}, got ${calculatedChecksum}`
        );
      }

      const calculatedHash = await this.generateChainHash(
        entry.audit_log_id,
        entry.previous_hash || '',
        entry.checksum,
        entry.created_at,
        entry.tenant_id
      );

      if (calculatedHash !== entry.current_hash) {
        errors.push(
          `Chain hash mismatch for entry ${entry.id}: expected ${entry.current_hash}, got ${calculatedHash}`
        );
      }

      if (i > 0) {
        const prevEntry = chain[i - 1];
        if (entry.previous_hash !== prevEntry.current_hash) {
          errors.push(
            `Chain break between ${prevEntry.id} and ${entry.id}: previous_hash ${entry.previous_hash} != ${prevEntry.current_hash}`
          );
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  private async addToChain(auditLogId: string, tenantId: string): Promise<void> {
    const lastChainResult = await this.db
      .prepare(
        `SELECT current_hash
         FROM audit_chain
         WHERE tenant_id = ?
         ORDER BY created_at DESC
         LIMIT 1`
      )
      .bind(tenantId)
      .first();

    const auditLogResult = await this.db
      .prepare(
        `SELECT checksum, created_at FROM audit_logs WHERE id = ?`
      )
      .bind(auditLogId)
      .first();

    if (!auditLogResult) {
      throw new Error(`Audit log ${auditLogId} not found for chain entry`);
    }

    const previousHash = lastChainResult?.current_hash || null;
    const currentHash = await this.generateChainHash(
      auditLogId,
      previousHash || '',
      auditLogResult.checksum as string,
      auditLogResult.created_at as number,
      tenantId
    );

    const createdAt = Math.floor(Date.now() / 1000);

    await this.db
      .prepare(
        `INSERT INTO audit_chain (id, tenant_id, audit_log_id, previous_hash, current_hash, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
      .bind(
        crypto.randomUUID(),
        tenantId,
        auditLogId,
        previousHash,
        currentHash,
        createdAt
      )
      .run();
  }

  private async generateChecksum(data: any): Promise<string> {
    const sortedData = JSON.stringify(data, Object.keys(data).sort());
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(sortedData);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  private async generateChainHash(
    auditLogId: string,
    previousHash: string,
    checksum: string,
    createdAt: number,
    tenantId: string
  ): Promise<string> {
    const data = `${previousHash}|${auditLogId}|${checksum}|${createdAt}|${tenantId}`;
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }
}

export function createAuditLogger(db: D1Database): AuditLogger {
  return new AuditLogger(db);
}
