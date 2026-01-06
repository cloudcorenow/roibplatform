import { Env } from '../worker';

export interface AuditLogEntry {
  tenant_id: string;
  user_id: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  old_values?: string;
  new_values?: string;
  ip_address?: string;
  user_agent?: string;
  details?: string;
}

export async function auditLogger(env: Env, entry: AuditLogEntry): Promise<void> {
  try {
    const id = crypto.randomUUID();
    const timestamp = new Date().toISOString();
    
    // Store in both D1 (permanent) and KV (fast access)
    const auditEntry = {
      id,
      ...entry,
      created_at: timestamp
    };

    const now = Math.floor(Date.now() / 1000);

    const stmt = env.DB.prepare(`
      INSERT INTO audit_log (
        tenant_id, user_id, action, resource_type, resource_id,
        ip_address, user_agent, details, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    await stmt.bind(
      entry.tenant_id,
      entry.user_id,
      entry.action,
      entry.resource_type,
      entry.resource_id || null,
      entry.ip_address || null,
      entry.user_agent || null,
      entry.details || null,
      now
    ).run();

    // Store in KV for fast recent access (30 days)
    const kvKey = `audit:${entry.tenant_id}:${id}`;
    await env.KV.put(kvKey, JSON.stringify(auditEntry), {
      expirationTtl: 60 * 60 * 24 * 30 // 30 days
    });

  } catch (error) {
    // Don't fail the main operation if audit logging fails
    console.error('Audit logging failed:', error);
  }
}

export async function getAuditLogs(
  env: Env, 
  tenantId: string, 
  options: {
    limit?: number;
    offset?: number;
    userId?: string;
    resourceType?: string;
    action?: string;
  } = {}
): Promise<{ logs: any[]; total: number }> {
  const { limit = 50, offset = 0, userId, resourceType, action } = options;
  
  let query = `
    SELECT * FROM audit_log 
    WHERE tenant_id = ?
  `;
  const params = [tenantId];

  if (userId) {
    query += ` AND user_id = ?`;
    params.push(userId);
  }

  if (resourceType) {
    query += ` AND resource_type = ?`;
    params.push(resourceType);
  }

  if (action) {
    query += ` AND action = ?`;
    params.push(action);
  }

  // Get total count
  const countQuery = query.replace('SELECT *', 'SELECT COUNT(*) as total');
  const countResult = await env.DB.prepare(countQuery).bind(...params).first() as { total: number } | null;
  const total = countResult?.total || 0;

  // Get paginated results
  query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
  params.push(String(limit), String(offset));

  const { results } = await env.DB.prepare(query).bind(...params).all();

  return { logs: results, total };
}

export async function auditRead(
  env: Env,
  tenantId: string,
  userId: string,
  resourceType: string,
  resourceIds: string[],
  ipAddress?: string,
  userAgent?: string
): Promise<void> {
  await auditLogger(env, {
    tenant_id: tenantId,
    user_id: userId,
    action: 'READ',
    resource_type: resourceType,
    details: JSON.stringify({
      resource_ids: resourceIds,
      count: resourceIds.length,
      timestamp: new Date().toISOString()
    }),
    ip_address: ipAddress,
    user_agent: userAgent
  });
}

export async function auditBulkRead(
  env: Env,
  tenantId: string,
  userId: string,
  resourceType: string,
  count: number,
  filters?: Record<string, any>,
  ipAddress?: string,
  userAgent?: string
): Promise<void> {
  await auditLogger(env, {
    tenant_id: tenantId,
    user_id: userId,
    action: 'BULK_READ',
    resource_type: resourceType,
    details: JSON.stringify({
      count,
      filters,
      timestamp: new Date().toISOString()
    }),
    ip_address: ipAddress,
    user_agent: userAgent
  });
}

export async function auditExport(
  env: Env,
  tenantId: string,
  userId: string,
  resourceType: string,
  count: number,
  format: string,
  ipAddress?: string,
  userAgent?: string
): Promise<void> {
  await auditLogger(env, {
    tenant_id: tenantId,
    user_id: userId,
    action: 'EXPORT',
    resource_type: resourceType,
    details: JSON.stringify({
      count,
      format,
      timestamp: new Date().toISOString()
    }),
    ip_address: ipAddress,
    user_agent: userAgent
  });
}