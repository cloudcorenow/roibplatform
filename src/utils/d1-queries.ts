import { Env } from '../worker';
import { withRetry } from './retry';

export interface TimeEntryRow {
  id: string;
  date: string;
  client: string;
  project: string;
  service: string;
  durationMin: number;
  notes: string | null;
  isRnD: boolean;
  employeeId: string | null;
  employeeName: string | null;
  createdAt: string;
}

export interface PaginationParams {
  limit: number;
  offset: number;
  from?: string;
  to?: string;
}

export interface PaginatedResult<T> {
  items: T[];
  total: number;
  hasMore: boolean;
}

export class TimeEntriesQueries {
  private env: Env;
  private static readonly MAX_LIMIT = 200;
  private static readonly DEFAULT_LIMIT = 50;

  constructor(env: Env) {
    this.env = env;
  }

  async listWithPagination(
    tenantId: string,
    params: PaginationParams
  ): Promise<PaginatedResult<TimeEntryRow>> {
    const {
      limit = TimeEntriesQueries.DEFAULT_LIMIT,
      offset = 0,
      from = '0000-01-01',
      to = '9999-12-31'
    } = params;

    const cappedLimit = Math.min(limit, TimeEntriesQueries.MAX_LIMIT);

    const [items, totalResult] = await Promise.all([
      withRetry(async () => {
        const result = await this.env.DB.prepare(`
          SELECT
            id, date, client, project, service,
            duration_min as durationMin, notes, is_rnd as isRnD,
            employee_id as employeeId, employee_name as employeeName,
            created_at as createdAt
          FROM time_entries
          WHERE tenant_id = ? AND date BETWEEN ? AND ?
          ORDER BY date DESC, created_at DESC
          LIMIT ? OFFSET ?
        `).bind(tenantId, from, to, cappedLimit + 1, offset).all();

        return result.results as TimeEntryRow[];
      }, 3),

      withRetry(async () => {
        const result = await this.env.DB.prepare(`
          SELECT COUNT(*) as total
          FROM time_entries
          WHERE tenant_id = ? AND date BETWEEN ? AND ?
        `).bind(tenantId, from, to).first<{ total: number }>();

        return result?.total || 0;
      }, 3)
    ]);

    const hasMore = items.length > cappedLimit;
    const resultItems = hasMore ? items.slice(0, cappedLimit) : items;

    return {
      items: resultItems,
      total: totalResult,
      hasMore
    };
  }

  async getById(tenantId: string, id: string): Promise<TimeEntryRow | null> {
    return withRetry(async () => {
      const result = await this.env.DB.prepare(`
        SELECT
          id, date, client, project, service,
          duration_min as durationMin, notes, is_rnd as isRnD,
          employee_id as employeeId, employee_name as employeeName,
          created_at as createdAt
        FROM time_entries
        WHERE tenant_id = ? AND id = ?
      `).bind(tenantId, id).first<TimeEntryRow>();

      return result || null;
    }, 3);
  }

  async create(tenantId: string, userId: string, data: {
    id: string;
    date: string;
    client: string;
    project: string;
    service: string;
    durationMin: number;
    notes?: string;
    isRnD: boolean;
  }): Promise<void> {
    await withRetry(async () => {
      await this.env.DB.prepare(`
        INSERT INTO time_entries (
          id, tenant_id, date, client, project, service,
          duration_min, notes, is_rnd, created_by,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
      `).bind(
        data.id,
        tenantId,
        data.date,
        data.client,
        data.project,
        data.service,
        data.durationMin,
        data.notes || null,
        data.isRnD ? 1 : 0,
        userId
      ).run();
    }, 3);
  }

  async batchCreate(tenantId: string, userId: string, entries: Array<{
    id: string;
    date: string;
    client: string;
    project: string;
    service: string;
    durationMin: number;
    notes?: string;
    isRnD: boolean;
  }>): Promise<void> {
    const BATCH_SIZE = 25;

    for (let i = 0; i < entries.length; i += BATCH_SIZE) {
      const batch = entries.slice(i, i + BATCH_SIZE);
      const statements = batch.map(entry =>
        this.env.DB.prepare(`
          INSERT INTO time_entries (
            id, tenant_id, date, client, project, service,
            duration_min, notes, is_rnd, created_by,
            created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        `).bind(
          entry.id,
          tenantId,
          entry.date,
          entry.client,
          entry.project,
          entry.service,
          entry.durationMin,
          entry.notes || null,
          entry.isRnD ? 1 : 0,
          userId
        )
      );

      await withRetry(async () => {
        await this.env.DB.batch(statements);
      }, 3);
    }
  }

  async update(tenantId: string, id: string, data: Partial<{
    date: string;
    client: string;
    project: string;
    service: string;
    durationMin: number;
    notes: string;
    isRnD: boolean;
  }>): Promise<boolean> {
    const fields = Object.keys(data);
    if (fields.length === 0) return false;

    const setClause = fields.map(field => {
      const dbField = field === 'durationMin' ? 'duration_min' :
                      field === 'isRnD' ? 'is_rnd' : field;
      return `${dbField} = ?`;
    }).join(', ');

    const result = await withRetry(async () => {
      return this.env.DB.prepare(`
        UPDATE time_entries
        SET ${setClause}, updated_at = datetime('now')
        WHERE tenant_id = ? AND id = ?
      `).bind(...Object.values(data), tenantId, id).run();
    }, 3);

    return result.meta.changes > 0;
  }

  async delete(tenantId: string, id: string): Promise<TimeEntryRow | null> {
    const existing = await this.getById(tenantId, id);
    if (!existing) return null;

    await withRetry(async () => {
      await this.env.DB.prepare(`
        DELETE FROM time_entries
        WHERE tenant_id = ? AND id = ?
      `).bind(tenantId, id).run();
    }, 3);

    return existing;
  }

  async getAggregatedStats(
    tenantId: string,
    from: string,
    to: string
  ): Promise<{
    totalEntries: number;
    totalMinutes: number;
    totalRnDMinutes: number;
    projectCount: number;
    clientCount: number;
  }> {
    const result = await withRetry(async () => {
      return this.env.DB.prepare(`
        SELECT
          COUNT(*) as totalEntries,
          COALESCE(SUM(duration_min), 0) as totalMinutes,
          COALESCE(SUM(CASE WHEN is_rnd = 1 THEN duration_min ELSE 0 END), 0) as totalRnDMinutes,
          COUNT(DISTINCT project) as projectCount,
          COUNT(DISTINCT client) as clientCount
        FROM time_entries
        WHERE tenant_id = ? AND date BETWEEN ? AND ?
      `).bind(tenantId, from, to).first<{
        totalEntries: number;
        totalMinutes: number;
        totalRnDMinutes: number;
        projectCount: number;
        clientCount: number;
      }>();
    }, 3);

    return result || {
      totalEntries: 0,
      totalMinutes: 0,
      totalRnDMinutes: 0,
      projectCount: 0,
      clientCount: 0
    };
  }

  async getProjectBreakdown(
    tenantId: string,
    from: string,
    to: string,
    limit = 20
  ): Promise<Array<{ project: string; totalMinutes: number; entryCount: number }>> {
    const result = await withRetry(async () => {
      return this.env.DB.prepare(`
        SELECT
          project,
          SUM(duration_min) as totalMinutes,
          COUNT(*) as entryCount
        FROM time_entries
        WHERE tenant_id = ? AND date BETWEEN ? AND ?
        GROUP BY project
        ORDER BY totalMinutes DESC
        LIMIT ?
      `).bind(tenantId, from, to, limit).all();
    }, 3);

    return result.results as Array<{ project: string; totalMinutes: number; entryCount: number }>;
  }
}

export class ClientQueries {
  private env: Env;

  constructor(env: Env) {
    this.env = env;
  }

  async listActive(tenantId: string): Promise<Array<{
    id: string;
    name: string;
    industry: string | null;
    contactPerson: string | null;
    email: string | null;
  }>> {
    const result = await withRetry(async () => {
      return this.env.DB.prepare(`
        SELECT id, name, industry, contact_person as contactPerson, email
        FROM clients
        WHERE tenant_id = ? AND status = 'active'
        ORDER BY name COLLATE NOCASE
        LIMIT 200
      `).bind(tenantId).all();
    }, 3);

    return result.results as Array<{
      id: string;
      name: string;
      industry: string | null;
      contactPerson: string | null;
      email: string | null;
    }>;
  }
}

export class ProjectQueries {
  private env: Env;

  constructor(env: Env) {
    this.env = env;
  }

  async listActive(tenantId: string): Promise<Array<{
    id: string;
    name: string;
    description: string | null;
    isRnD: boolean;
  }>> {
    const result = await withRetry(async () => {
      return this.env.DB.prepare(`
        SELECT id, name, description, is_rnd as isRnD
        FROM projects
        WHERE tenant_id = ? AND status = 'active'
        ORDER BY name COLLATE NOCASE
        LIMIT 200
      `).bind(tenantId).all();
    }, 3);

    return result.results as Array<{
      id: string;
      name: string;
      description: string | null;
      isRnD: boolean;
    }>;
  }
}
