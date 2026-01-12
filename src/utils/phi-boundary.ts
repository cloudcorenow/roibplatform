import { D1Database } from '@cloudflare/workers-types';
import { PHIEncryption, type PHIField, isPHIField } from './phi-encryption';
import { RBACManager, type ResourceType, type Action } from './rbac';
import { AuditLogger } from './audit-logger';

export interface PHIAccessRequest {
  userId: string;
  tenantId: string;
  resourceType: ResourceType;
  resourceId: string;
  requestedFields: string[];
  justification?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface PHIAccessResponse<T = any> {
  success: boolean;
  data?: Partial<T>;
  deniedFields?: string[];
  error?: string;
  auditLogId?: string;
}

export class PHIBoundary {
  private rbac: RBACManager;
  private audit: AuditLogger;
  private encryptionKey: string;

  constructor(
    private db: D1Database,
    encryptionKey: string
  ) {
    this.rbac = new RBACManager(db);
    this.audit = new AuditLogger(db);
    this.encryptionKey = encryptionKey;
  }

  async read<T extends Record<string, any>>(
    request: PHIAccessRequest
  ): Promise<PHIAccessResponse<T>> {
    const phiFields = request.requestedFields.filter(isPHIField);
    const nonPhiFields = request.requestedFields.filter(f => !isPHIField(f));

    if (phiFields.length > 0) {
      const accessDecision = await this.rbac.checkAccess({
        userId: request.userId,
        tenantId: request.tenantId,
        resourceType: request.resourceType,
        action: 'read',
        resourceId: request.resourceId,
        requestedFields: phiFields
      });

      if (!accessDecision.allowed) {
        const auditLogId = await this.audit.log({
          tenantId: request.tenantId,
          userId: request.userId,
          action: 'READ',
          resourceType: request.resourceType,
          resourceId: request.resourceId,
          phiAccessed: phiFields,
          ipAddress: request.ipAddress,
          userAgent: request.userAgent,
          success: false,
          failureReason: accessDecision.reason
        });

        return {
          success: false,
          deniedFields: phiFields,
          error: accessDecision.reason,
          auditLogId
        };
      }

      const allowedPhiFields = phiFields.filter(
        field => !accessDecision.allowedFields || accessDecision.allowedFields.includes(field)
      );
      const deniedPhiFields = phiFields.filter(
        field => accessDecision.allowedFields && !accessDecision.allowedFields.includes(field)
      );

      await this.audit.logPHIAccess(
        request.tenantId,
        request.userId,
        request.resourceId,
        allowedPhiFields,
        request.justification,
        undefined,
        request.ipAddress
      );

      const data = await this.fetchData<T>(
        request.resourceType,
        request.resourceId,
        [...nonPhiFields, ...allowedPhiFields]
      );

      if (!data) {
        return {
          success: false,
          error: 'Resource not found'
        };
      }

      // Use selective field decryption for performance optimization
      const decryptedData = await this.decryptPHIFields(data, allowedPhiFields);

      const auditLogId = await this.audit.log({
        tenantId: request.tenantId,
        userId: request.userId,
        action: 'READ',
        resourceType: request.resourceType,
        resourceId: request.resourceId,
        phiAccessed: allowedPhiFields,
        ipAddress: request.ipAddress,
        userAgent: request.userAgent,
        success: true
      });

      return {
        success: true,
        data: decryptedData,
        deniedFields: deniedPhiFields.length > 0 ? deniedPhiFields : undefined,
        auditLogId
      };
    }

    const data = await this.fetchData<T>(
      request.resourceType,
      request.resourceId,
      nonPhiFields
    );

    if (!data) {
      return {
        success: false,
        error: 'Resource not found'
      };
    }

    return {
      success: true,
      data
    };
  }

  async write<T extends Record<string, any>>(
    request: Omit<PHIAccessRequest, 'requestedFields'> & { data: T }
  ): Promise<PHIAccessResponse> {
    const fields = Object.keys(request.data);
    const phiFields = fields.filter(isPHIField);

    if (phiFields.length > 0) {
      const accessDecision = await this.rbac.checkAccess({
        userId: request.userId,
        tenantId: request.tenantId,
        resourceType: request.resourceType,
        action: 'update',
        resourceId: request.resourceId,
        requestedFields: phiFields
      });

      if (!accessDecision.allowed) {
        const auditLogId = await this.audit.log({
          tenantId: request.tenantId,
          userId: request.userId,
          action: 'UPDATE',
          resourceType: request.resourceType,
          resourceId: request.resourceId,
          phiAccessed: phiFields,
          ipAddress: request.ipAddress,
          userAgent: request.userAgent,
          success: false,
          failureReason: accessDecision.reason
        });

        return {
          success: false,
          error: accessDecision.reason,
          auditLogId
        };
      }

      const encryptedData = await this.encryptPHIFields(request.data);

      await this.updateData(
        request.resourceType,
        request.resourceId,
        encryptedData
      );

      const auditLogId = await this.audit.log({
        tenantId: request.tenantId,
        userId: request.userId,
        action: 'UPDATE',
        resourceType: request.resourceType,
        resourceId: request.resourceId,
        phiAccessed: phiFields,
        ipAddress: request.ipAddress,
        userAgent: request.userAgent,
        success: true
      });

      await this.audit.logPHIAccess(
        request.tenantId,
        request.userId,
        request.resourceId,
        phiFields,
        request.justification,
        undefined,
        request.ipAddress
      );

      return {
        success: true,
        auditLogId
      };
    }

    await this.updateData(
      request.resourceType,
      request.resourceId,
      request.data
    );

    return {
      success: true
    };
  }

  async bulkRead<T extends Record<string, any>>(
    request: Omit<PHIAccessRequest, 'resourceId'> & {
      query?: Record<string, any>;
      limit?: number;
      offset?: number;
    }
  ): Promise<PHIAccessResponse<T[]>> {
    const phiFields = request.requestedFields.filter(isPHIField);
    const nonPhiFields = request.requestedFields.filter(f => !isPHIField(f));

    if (phiFields.length > 0) {
      const accessDecision = await this.rbac.checkAccess({
        userId: request.userId,
        tenantId: request.tenantId,
        resourceType: request.resourceType,
        action: 'read',
        resourceId: '*',
        requestedFields: phiFields
      });

      if (!accessDecision.allowed) {
        const auditLogId = await this.audit.log({
          tenantId: request.tenantId,
          userId: request.userId,
          action: 'BULK_READ',
          resourceType: request.resourceType,
          resourceId: '*',
          phiAccessed: phiFields,
          ipAddress: request.ipAddress,
          userAgent: request.userAgent,
          success: false,
          failureReason: accessDecision.reason
        });

        return {
          success: false,
          deniedFields: phiFields,
          error: accessDecision.reason,
          auditLogId
        };
      }

      const allowedPhiFields = phiFields.filter(
        field => !accessDecision.allowedFields || accessDecision.allowedFields.includes(field)
      );

      const records = await this.fetchBulkData<T>(
        request.resourceType,
        [...nonPhiFields, ...allowedPhiFields],
        request.query,
        request.limit,
        request.offset
      );

      // Batch decryption: process all records in parallel
      const decryptedRecords = await Promise.all(
        records.map(record => this.decryptPHIFields(record, allowedPhiFields))
      );

      await this.audit.log({
        tenantId: request.tenantId,
        userId: request.userId,
        action: 'BULK_READ',
        resourceType: request.resourceType,
        resourceId: `bulk:${decryptedRecords.length}`,
        phiAccessed: allowedPhiFields,
        ipAddress: request.ipAddress,
        userAgent: request.userAgent,
        success: true,
        metadata: {
          recordCount: decryptedRecords.length
        }
      });

      return {
        success: true,
        data: decryptedRecords as T[]
      };
    }

    const records = await this.fetchBulkData<T>(
      request.resourceType,
      nonPhiFields,
      request.query,
      request.limit,
      request.offset
    );

    return {
      success: true,
      data: records as T[]
    };
  }

  async export(request: PHIAccessRequest): Promise<PHIAccessResponse> {
    const accessDecision = await this.rbac.checkAccess({
      userId: request.userId,
      tenantId: request.tenantId,
      resourceType: request.resourceType,
      action: 'export',
      resourceId: request.resourceId
    });

    if (!accessDecision.allowed) {
      const auditLogId = await this.audit.log({
        tenantId: request.tenantId,
        userId: request.userId,
        action: 'EXPORT',
        resourceType: request.resourceType,
        resourceId: request.resourceId,
        ipAddress: request.ipAddress,
        userAgent: request.userAgent,
        success: false,
        failureReason: accessDecision.reason
      });

      return {
        success: false,
        error: accessDecision.reason,
        auditLogId
      };
    }

    const auditLogId = await this.audit.log({
      tenantId: request.tenantId,
      userId: request.userId,
      action: 'EXPORT',
      resourceType: request.resourceType,
      resourceId: request.resourceId,
      phiAccessed: request.requestedFields.filter(isPHIField),
      ipAddress: request.ipAddress,
      userAgent: request.userAgent,
      success: true,
      metadata: {
        justification: request.justification
      }
    });

    return {
      success: true,
      auditLogId
    };
  }

  async filterResponse<T extends Record<string, any>>(
    data: T,
    userId: string,
    tenantId: string,
    resourceType: ResourceType
  ): Promise<Partial<T>> {
    return this.rbac.filterPHIFields(data, userId, tenantId, resourceType);
  }

  private async encryptPHIFields<T extends Record<string, any>>(
    data: T
  ): Promise<T> {
    return PHIEncryption.encryptObject(data, this.encryptionKey);
  }

  private async decryptPHIFields<T extends Record<string, any>>(
    data: T,
    selectiveFields?: string[]
  ): Promise<T> {
    // Use selective field decryption for performance optimization
    if (selectiveFields) {
      return PHIEncryption.decryptObject(data, this.encryptionKey, {
        fields: selectiveFields
      });
    }
    return PHIEncryption.decryptObject(data, this.encryptionKey);
  }

  private async fetchData<T>(
    resourceType: ResourceType,
    resourceId: string,
    fields: string[]
  ): Promise<T | null> {
    const tableName = this.getTableName(resourceType);
    const fieldsList = fields.join(', ');

    const result = await this.db
      .prepare(`SELECT ${fieldsList} FROM ${tableName} WHERE id = ?`)
      .bind(resourceId)
      .first();

    return result as T | null;
  }

  private async updateData(
    resourceType: ResourceType,
    resourceId: string,
    data: Record<string, any>
  ): Promise<void> {
    const tableName = this.getTableName(resourceType);
    const fields = Object.keys(data);
    const setClause = fields.map(f => `${f} = ?`).join(', ');
    const values = fields.map(f => {
      const value = data[f];
      return typeof value === 'object' ? JSON.stringify(value) : value;
    });

    await this.db
      .prepare(`UPDATE ${tableName} SET ${setClause} WHERE id = ?`)
      .bind(...values, resourceId)
      .run();
  }

  private async fetchBulkData<T>(
    resourceType: ResourceType,
    fields: string[],
    query?: Record<string, any>,
    limit: number = 100,
    offset: number = 0
  ): Promise<T[]> {
    const tableName = this.getTableName(resourceType);
    const fieldsList = fields.join(', ');

    let sql = `SELECT ${fieldsList} FROM ${tableName}`;
    const bindings: any[] = [];

    if (query && Object.keys(query).length > 0) {
      const whereClause = Object.keys(query)
        .map(key => `${key} = ?`)
        .join(' AND ');
      sql += ` WHERE ${whereClause}`;
      bindings.push(...Object.values(query));
    }

    sql += ` LIMIT ? OFFSET ?`;
    bindings.push(limit, offset);

    const result = await this.db
      .prepare(sql)
      .bind(...bindings)
      .all();

    return (result.results as T[]) || [];
  }

  private getTableName(resourceType: ResourceType): string {
    const tableMap: Record<ResourceType, string> = {
      patient: 'patients',
      document: 'documents',
      assessment: 'assessments',
      time_entry: 'time_entries',
      user: 'users'
    };

    return tableMap[resourceType] || resourceType;
  }
}

export function createPHIBoundary(
  db: D1Database,
  encryptionKey: string
): PHIBoundary {
  return new PHIBoundary(db, encryptionKey);
}

export function validatePHIAccessJustification(justification: string): boolean {
  return justification.length >= 20;
}

export function redactPHI<T extends Record<string, any>>(data: T): T {
  const redacted = { ...data };

  for (const key of Object.keys(redacted)) {
    if (isPHIField(key)) {
      redacted[key] = '[REDACTED]' as any;
    }
  }

  return redacted;
}
