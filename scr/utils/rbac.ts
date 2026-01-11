import { D1Database } from '@cloudflare/workers-types';
import { isPHIField, type PHIField } from './phi-encryption';

export type ResourceType = 'patient' | 'document' | 'assessment' | 'time_entry' | 'user';
export type Action = 'create' | 'read' | 'update' | 'delete' | 'export' | 'print' | 'share';

export interface Permission {
  id: string;
  resourceType: ResourceType;
  action: Action;
  fieldLevel: boolean;
  allowedFields?: PHIField[];
  description?: string;
}

export interface Role {
  id: string;
  tenantId: string;
  name: string;
  description?: string;
  isSystemRole: boolean;
  permissions: Permission[];
}

export interface AccessContext {
  userId: string;
  tenantId: string;
  resourceType: ResourceType;
  action: Action;
  resourceId?: string;
  resourceOwnerId?: string;
  requestedFields?: string[];
}

export interface AccessDecision {
  allowed: boolean;
  reason?: string;
  allowedFields?: string[];
  constraints?: Record<string, any>;
}

export class RBACManager {
  constructor(private db: D1Database) {}

  async getUserRoles(userId: string, tenantId: string): Promise<Role[]> {
    const now = Math.floor(Date.now() / 1000);

    const result = await this.db
      .prepare(
        `SELECT
          r.id, r.tenant_id, r.name, r.description, r.is_system_role
        FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = ?
          AND ur.tenant_id = ?
          AND (ur.expires_at IS NULL OR ur.expires_at > ?)
        ORDER BY r.name`
      )
      .bind(userId, tenantId, now)
      .all();

    const roles: Role[] = [];

    for (const row of result.results || []) {
      const permissions = await this.getRolePermissions(row.id as string);
      roles.push({
        id: row.id as string,
        tenantId: row.tenant_id as string,
        name: row.name as string,
        description: row.description as string | undefined,
        isSystemRole: Boolean(row.is_system_role),
        permissions
      });
    }

    return roles;
  }

  async getRolePermissions(roleId: string): Promise<Permission[]> {
    const result = await this.db
      .prepare(
        `SELECT
          p.id, p.resource_type, p.action, p.field_level,
          p.allowed_fields, p.description,
          rp.constraints
        FROM permissions p
        JOIN role_permissions rp ON p.id = rp.permission_id
        WHERE rp.role_id = ?`
      )
      .bind(roleId)
      .all();

    return (result.results || []).map(row => ({
      id: row.id as string,
      resourceType: row.resource_type as ResourceType,
      action: row.action as Action,
      fieldLevel: Boolean(row.field_level),
      allowedFields: row.allowed_fields
        ? JSON.parse(row.allowed_fields as string)
        : undefined,
      description: row.description as string | undefined
    }));
  }

  async checkAccess(context: AccessContext): Promise<AccessDecision> {
    const roles = await this.getUserRoles(context.userId, context.tenantId);

    if (roles.length === 0) {
      return {
        allowed: false,
        reason: 'User has no roles assigned'
      };
    }

    let hasPermission = false;
    let allowedFields: Set<string> = new Set();
    let constraints: Record<string, any> = {};

    for (const role of roles) {
      for (const permission of role.permissions) {
        if (
          permission.resourceType === context.resourceType &&
          permission.action === context.action
        ) {
          hasPermission = true;

          if (permission.fieldLevel && permission.allowedFields) {
            permission.allowedFields.forEach(field => allowedFields.add(field));
          }

          const permConstraints = await this.getPermissionConstraints(
            role.id,
            permission.id
          );
          constraints = { ...constraints, ...permConstraints };
        }
      }
    }

    if (!hasPermission) {
      return {
        allowed: false,
        reason: `No permission for ${context.action} on ${context.resourceType}`
      };
    }

    if (constraints.own_records_only && context.resourceOwnerId) {
      if (context.userId !== context.resourceOwnerId) {
        return {
          allowed: false,
          reason: 'Access restricted to own records only'
        };
      }
    }

    if (context.requestedFields && context.requestedFields.length > 0) {
      const filteredFields = context.requestedFields.filter(field => {
        if (!isPHIField(field)) return true;
        return allowedFields.has(field);
      });

      if (filteredFields.length < context.requestedFields.length) {
        const deniedFields = context.requestedFields.filter(
          f => !filteredFields.includes(f)
        );
        return {
          allowed: false,
          reason: `Access denied to PHI fields: ${deniedFields.join(', ')}`
        };
      }

      return {
        allowed: true,
        allowedFields: filteredFields,
        constraints
      };
    }

    return {
      allowed: true,
      allowedFields: Array.from(allowedFields),
      constraints
    };
  }

  async filterPHIFields<T extends Record<string, any>>(
    data: T,
    userId: string,
    tenantId: string,
    resourceType: ResourceType
  ): Promise<T> {
    const decision = await this.checkAccess({
      userId,
      tenantId,
      resourceType,
      action: 'read',
      requestedFields: Object.keys(data)
    });

    if (!decision.allowed) {
      const filtered: any = { ...data };
      for (const key of Object.keys(filtered)) {
        if (isPHIField(key)) {
          delete filtered[key];
        }
      }
      return filtered;
    }

    if (decision.allowedFields && decision.allowedFields.length > 0) {
      const filtered: any = { ...data };
      for (const key of Object.keys(filtered)) {
        if (isPHIField(key) && !decision.allowedFields.includes(key)) {
          delete filtered[key];
        }
      }
      return filtered;
    }

    return data;
  }

  async assignRole(
    userId: string,
    roleId: string,
    tenantId: string,
    grantedBy: string,
    expiresAt?: number
  ): Promise<void> {
    const id = crypto.randomUUID();
    const grantedAt = Math.floor(Date.now() / 1000);

    await this.db
      .prepare(
        `INSERT INTO user_roles (id, user_id, role_id, tenant_id, granted_by, granted_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(id, userId, roleId, tenantId, grantedBy, grantedAt, expiresAt || null)
      .run();
  }

  async revokeRole(userId: string, roleId: string, tenantId: string): Promise<void> {
    await this.db
      .prepare(
        `DELETE FROM user_roles
         WHERE user_id = ? AND role_id = ? AND tenant_id = ?`
      )
      .bind(userId, roleId, tenantId)
      .run();
  }

  private async getPermissionConstraints(
    roleId: string,
    permissionId: string
  ): Promise<Record<string, any>> {
    const result = await this.db
      .prepare(
        `SELECT constraints
         FROM role_permissions
         WHERE role_id = ? AND permission_id = ?`
      )
      .bind(roleId, permissionId)
      .first();

    if (result?.constraints) {
      return JSON.parse(result.constraints as string);
    }

    return {};
  }
}

export function createRBACManager(db: D1Database): RBACManager {
  return new RBACManager(db);
}
