import { D1Database, D1PreparedStatement } from '@cloudflare/workers-types';
import { isPHIField, type PHIField } from '../utils/phi-encryption';
import { PHI_BEARING_TABLES, isPHITable, type PHITable, PHI_FIELDS, getTablePHIFields } from '../types/phi-registry';

function detectPHIFieldsInQuery(sql: string, table: string | null): PHIField[] {
  if (!table) return [];

  const phiFields: PHIField[] = [];
  const sqlLower = sql.toLowerCase();
  const tablePHIFields = getTablePHIFields(table);

  for (const field of tablePHIFields) {
    if (sqlLower.includes(field)) {
      phiFields.push(field);
    }
  }

  return phiFields;
}

function detectTableInQuery(sql: string): string | null {
  const sqlLower = sql.toLowerCase();

  const fromMatch = sqlLower.match(/from\s+(\w+)/);
  if (fromMatch) {
    return fromMatch[1];
  }

  const intoMatch = sqlLower.match(/into\s+(\w+)/);
  if (intoMatch) {
    return intoMatch[1];
  }

  const updateMatch = sqlLower.match(/update\s+(\w+)/);
  if (updateMatch) {
    return updateMatch[1];
  }

  const deleteMatch = sqlLower.match(/delete\s+from\s+(\w+)/);
  if (deleteMatch) {
    return deleteMatch[1];
  }

  return null;
}

function isAllowedBypassQuery(sql: string): boolean {
  const sqlLower = sql.toLowerCase();

  const allowedPatterns = [
    /^select.*from\s+audit_logs/,
    /^insert\s+into\s+audit_logs/,
    /^select.*from\s+audit_chain/,
    /^insert\s+into\s+audit_chain/,
    /^select.*from\s+phi_access_log/,
    /^insert\s+into\s+phi_access_log/,
    /^select.*from\s+session_activities/,
    /^insert\s+into\s+session_activities/,
    /^select.*from\s+roles/,
    /^select.*from\s+permissions/,
    /^select.*from\s+role_permissions/,
    /^select.*from\s+user_roles/,
    /^select.*from\s+sessions\s+where/,
    /^update\s+sessions\s+set\s+last_activity/,
    /^update\s+sessions\s+set\s+privileged/,
    /^update\s+sessions\s+set\s+mfa_verified_at/,
    /^delete\s+from\s+sessions\s+where/,
  ];

  return allowedPatterns.some(pattern => pattern.test(sqlLower));
}

export class SecureD1Database {
  private db: D1Database;
  private phiBoundaryRequired: boolean;
  private auditLogger?: any;
  private context?: {
    userId?: string;
    tenantId?: string;
    requestId?: string;
  };

  constructor(
    db: D1Database,
    options: {
      phiBoundaryRequired?: boolean;
      auditLogger?: any;
      context?: {
        userId?: string;
        tenantId?: string;
        requestId?: string;
      };
    } = {}
  ) {
    this.db = db;
    this.phiBoundaryRequired = options.phiBoundaryRequired ?? true;
    this.auditLogger = options.auditLogger;
    this.context = options.context;
  }

  prepare(sql: string): D1PreparedStatement {
    if (this.phiBoundaryRequired) {
      const table = detectTableInQuery(sql);
      const phiFields = detectPHIFieldsInQuery(sql, table);

      if (table && isPHITable(table) && phiFields.length > 0) {
        const isAllowed = isAllowedBypassQuery(sql);

        if (!isAllowed) {
          const error = new Error(
            `CRITICAL SECURITY VIOLATION: Direct database query with PHI fields detected!\n` +
            `Table: ${table}\n` +
            `PHI Fields: ${phiFields.join(', ')}\n` +
            `Request ID: ${this.context?.requestId || 'N/A'}\n\n` +
            `All PHI operations must go through the PHIBoundary layer.\n` +
            `Use: phiBoundary.read() or phiBoundary.write() instead of direct DB queries.\n\n` +
            `If you need to bypass this check for system operations, use:\n` +
            `  new SecureD1Database(db, { phiBoundaryRequired: false })`
          );

          console.error(`[SECURITY] PHI access violation - Table: ${table}, Fields: ${phiFields.join(', ')}, Request: ${this.context?.requestId || 'N/A'}`);

          if (this.auditLogger && this.context?.userId && this.context?.tenantId) {
            this.auditLogger.log({
              tenantId: this.context.tenantId,
              userId: this.context.userId,
              action: 'ACCESS',
              resourceType: table,
              phiAccessed: phiFields,
              requestId: this.context.requestId,
              success: false,
              failureReason: 'Direct PHI database access attempted',
              metadata: {
                table,
                phiFields: phiFields.join(', '),
                queryLength: sql.length
              }
            }).catch(console.error);
          }

          throw error;
        }
      }
    }

    return this.db.prepare(sql);
  }

  batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
    return this.db.batch(statements);
  }

  dump(): Promise<ArrayBuffer> {
    return this.db.dump();
  }

  exec(query: string): Promise<D1ExecResult> {
    return this.db.exec(query);
  }

  setAuditContext(context: { userId: string; tenantId: string; requestId?: string }) {
    this.context = context;
  }

  static createSystemDB(db: D1Database, auditLogger?: any): SecureD1Database {
    return new SecureD1Database(db, {
      phiBoundaryRequired: false,
      auditLogger
    });
  }
}

export function wrapD1Database(
  db: D1Database,
  options?: {
    phiBoundaryRequired?: boolean;
    auditLogger?: any;
    context?: {
      userId?: string;
      tenantId?: string;
      requestId?: string;
    };
  }
): SecureD1Database {
  return new SecureD1Database(db, options);
}

declare global {
  interface D1Result<T = unknown> {
    results?: T[];
    success: boolean;
    error?: string;
    meta?: {
      duration?: number;
      last_row_id?: number;
      changes?: number;
      served_by?: string;
      internal_stats?: unknown;
    };
  }

  interface D1ExecResult {
    count: number;
    duration: number;
  }
}
