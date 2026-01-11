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

    // Store in D1 for permanent audit trail
    const stmt = env.DB.prepare(`
      INSERT INTO audit_log (
        id, tenant_id, user_id, action, resource_type, resource_id,
        old_values, new_values, ip_address, user_agent, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    await stmt.bind(
      id,
      entry.tenant_id,
      entry.user_id,
      entry.action,
      entry.resource_type,
      entry.resource_id || null,
      entry.old_values || null,
      entry.new_values || null,
      entry.ip_address || null,
      entry.user_agent || null,
      timestamp
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
  const countResult = await env.DB.prepare(countQuery).bind(...params).first();
  const total = countResult?.total || 0;

  // Get paginated results
  query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
  params.push(limit, offset);

  const { results } = await env.DB.prepare(query).bind(...params).all();

  return { logs: results, total };
}