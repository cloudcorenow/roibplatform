import { Hono } from 'hono';
import { z } from 'zod';
import type { Env, HonoEnv } from '../types';
import { auditLogger } from '../utils/audit';
import { checkPermission, createSecurityContext } from '../utils/security';
import { withRetry } from '../utils/retry';
import { sanitizeInput } from '../utils/validation';
import { calculateChecksum } from '../utils/documentIntegrity';

const documentsRouter = new Hono<HonoEnv>();

const ALLOWED_MIME_TYPES = [
  'application/pdf',
  'image/jpeg',
  'image/png',
  'image/jpg',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'text/csv'
];

const MAX_FILE_SIZE = 10 * 1024 * 1024;

const CATEGORY_TYPES = [
  'general',
  'invoice',
  'contract',
  'report',
  'receipt',
  'tax_document',
  'financial_statement',
  'rnd_documentation'
] as const;

documentsRouter.post('/upload', async (c) => {
  try {
    const tenantId = c.get('tenant_id');
    const userId = c.get('user_id');
    const securityContext = createSecurityContext(c);

    if (!checkPermission(securityContext, 'documents:create')) {
      return c.json({ error: 'Permission denied', code: 'FORBIDDEN' }, 403);
    }

    const formData = await c.req.formData();
    const file = formData.get('file') as File | null;

    if (!file || typeof file === 'string') {
      return c.json({ error: 'No valid file provided', code: 'VALIDATION_ERROR' }, 400);
    }
    const category = (formData.get('category') as string) || 'general';
    const description = formData.get('description') as string | null;

    if (!file) {
      return c.json({
        error: 'No file provided',
        code: 'VALIDATION_ERROR'
      }, 400);
    }

    if (!ALLOWED_MIME_TYPES.includes(file.type)) {
      return c.json({
        error: `File type not allowed. Allowed types: ${ALLOWED_MIME_TYPES.join(', ')}`,
        code: 'INVALID_FILE_TYPE'
      }, 400);
    }

    if (file.size > MAX_FILE_SIZE) {
      return c.json({
        error: `File too large. Maximum size: ${MAX_FILE_SIZE / 1024 / 1024}MB`,
        code: 'FILE_TOO_LARGE'
      }, 400);
    }

    if (!CATEGORY_TYPES.includes(category as any)) {
      return c.json({
        error: `Invalid category. Allowed: ${CATEGORY_TYPES.join(', ')}`,
        code: 'INVALID_CATEGORY'
      }, 400);
    }

    const fileId = crypto.randomUUID();
    const fileExtension = file.name.split('.').pop() || 'bin';
    const r2Key = `${tenantId}/documents/${fileId}.${fileExtension}`;

    const fileBuffer = await file.arrayBuffer();
    const checksum = await calculateChecksum(fileBuffer);

    const uploadStart = Date.now();
    await c.env.DOCUMENTS.put(r2Key, fileBuffer, {
      httpMetadata: {
        contentType: file.type,
      },
      customMetadata: {
        tenantId,
        userId,
        fileName: file.name,
        uploadedAt: new Date().toISOString(),
        checksum
      }
    });
    const uploadDuration = Date.now() - uploadStart;

    if (uploadDuration > 5000) {
      console.warn(`Slow R2 upload: ${uploadDuration}ms for ${file.size} bytes`);
    }

    const now = Math.floor(Date.now() / 1000);

    await withRetry(async () => {
      await c.env.DB.prepare(`
        INSERT INTO documents (
          id, tenant_id, file_name, file_size, file_type,
          r2_key, description, category, uploaded_by, checksum,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        fileId,
        tenantId,
        sanitizeInput(file.name, 255),
        file.size,
        file.type,
        r2Key,
        description ? sanitizeInput(description, 1000) : null,
        category,
        userId,
        checksum,
        now,
        now
      ).run();
    }, 3);

    await withRetry(async () => {
      await c.env.DB.prepare(`
        INSERT INTO document_versions (document_id, version, checksum, changed_by, changed_at)
        VALUES (?, 1, ?, ?, ?)
      `).bind(fileId, checksum, userId, now).run();
    }, 3);

    await auditLogger(c.env, {
      tenant_id: tenantId,
      user_id: userId,
      action: 'upload',
      resource_type: 'document',
      resource_id: fileId,
      ip_address: c.get('user_ip'),
      new_values: JSON.stringify({
        fileName: file.name,
        fileSize: file.size,
        category
      })
    });

    return c.json({
      id: fileId,
      fileName: file.name,
      fileSize: file.size,
      fileType: file.type,
      category,
      uploadDuration
    }, 201);
  } catch (error) {
    console.error('Error uploading document:', error);
    return c.json({
      error: 'Failed to upload document',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'UPLOAD_ERROR'
    }, 500);
  }
});

documentsRouter.get('/', async (c) => {
  try {
    const tenantId = c.get('tenant_id');
    const securityContext = createSecurityContext(c);

    if (!checkPermission(securityContext, 'documents:read')) {
      return c.json({ error: 'Permission denied', code: 'FORBIDDEN' }, 403);
    }

    const category = c.req.query('category');
    const limit = Math.min(parseInt(c.req.query('limit') ?? '50', 10), 200);
    const offset = Math.max(parseInt(c.req.query('offset') ?? '0', 10), 0);

    let query = `
      SELECT
        id, file_name as fileName, file_size as fileSize,
        file_type as fileType, description, category,
        uploaded_by as uploadedBy, created_at as createdAt
      FROM documents
      WHERE tenant_id = ?
    `;
    const bindings: any[] = [tenantId];

    if (category) {
      query += ` AND category = ?`;
      bindings.push(category);
    }

    query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    bindings.push(limit, offset);

    const [items, totalResult] = await Promise.all([
      withRetry(async () => {
        const result = await c.env.DB.prepare(query).bind(...bindings).all();
        return result.results;
      }, 3),
      withRetry(async () => {
        let countQuery = `SELECT COUNT(*) as total FROM documents WHERE tenant_id = ?`;
        const countBindings: any[] = [tenantId];
        if (category) {
          countQuery += ` AND category = ?`;
          countBindings.push(category);
        }
        const result = await c.env.DB.prepare(countQuery).bind(...countBindings).first<{ total: number }>();
        return result?.total || 0;
      }, 3)
    ]);

    await auditLogger(c.env, {
      tenant_id: tenantId,
      user_id: c.get('user_id'),
      action: 'list',
      resource_type: 'documents',
      ip_address: c.get('user_ip'),
      details: JSON.stringify({ count: items.length, category, limit, offset })
    });

    return c.json({
      items,
      paging: {
        limit,
        offset,
        total: totalResult,
        hasMore: items.length === limit
      }
    });
  } catch (error) {
    console.error('Error listing documents:', error);
    return c.json({
      error: 'Failed to list documents',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'LIST_ERROR'
    }, 500);
  }
});

documentsRouter.get('/:id', async (c) => {
  try {
    const tenantId = c.get('tenant_id');
    const userId = c.get('user_id');
    const id = c.req.param('id');
    const securityContext = createSecurityContext(c);

    if (!checkPermission(securityContext, 'documents:read')) {
      return c.json({ error: 'Permission denied', code: 'FORBIDDEN' }, 403);
    }

    const doc = await withRetry(async () => {
      return c.env.DB.prepare(`
        SELECT r2_key, file_name, file_type
        FROM documents
        WHERE tenant_id = ? AND id = ?
      `).bind(tenantId, id).first<{
        r2_key: string;
        file_name: string;
        file_type: string;
      }>();
    }, 3);

    if (!doc) {
      return c.json({
        error: 'Document not found',
        code: 'NOT_FOUND'
      }, 404);
    }

    const object = await c.env.DOCUMENTS.get(doc.r2_key);

    if (!object) {
      return c.json({
        error: 'File not found in storage',
        code: 'FILE_NOT_FOUND'
      }, 404);
    }

    await auditLogger(c.env, {
      tenant_id: tenantId,
      user_id: userId,
      action: 'download',
      resource_type: 'document',
      resource_id: id,
      ip_address: c.get('user_ip')
    });

    return new Response(object.body, {
      headers: {
        'Content-Type': doc.file_type,
        'Content-Disposition': `attachment; filename="${doc.file_name}"`,
        'Cache-Control': 'private, max-age=3600'
      }
    });
  } catch (error) {
    console.error('Error downloading document:', error);
    return c.json({
      error: 'Failed to download document',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'DOWNLOAD_ERROR'
    }, 500);
  }
});

documentsRouter.delete('/:id', async (c) => {
  try {
    const tenantId = c.get('tenant_id');
    const userId = c.get('user_id');
    const id = c.req.param('id');
    const securityContext = createSecurityContext(c);

    if (!checkPermission(securityContext, 'documents:delete')) {
      return c.json({ error: 'Permission denied', code: 'FORBIDDEN' }, 403);
    }

    const doc = await withRetry(async () => {
      return c.env.DB.prepare(`
        SELECT r2_key, file_name
        FROM documents
        WHERE tenant_id = ? AND id = ?
      `).bind(tenantId, id).first<{
        r2_key: string;
        file_name: string;
      }>();
    }, 3);

    if (!doc) {
      return c.json({
        error: 'Document not found',
        code: 'NOT_FOUND'
      }, 404);
    }

    await c.env.DOCUMENTS.delete(doc.r2_key);

    await withRetry(async () => {
      await c.env.DB.prepare(`
        DELETE FROM documents
        WHERE tenant_id = ? AND id = ?
      `).bind(tenantId, id).run();
    }, 3);

    await auditLogger(c.env, {
      tenant_id: tenantId,
      user_id: userId,
      action: 'delete',
      resource_type: 'document',
      resource_id: id,
      ip_address: c.get('user_ip'),
      old_values: JSON.stringify({ fileName: doc.file_name })
    });

    return c.json({ success: true });
  } catch (error) {
    console.error('Error deleting document:', error);
    return c.json({
      error: 'Failed to delete document',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'DELETE_ERROR'
    }, 500);
  }
});

documentsRouter.get('/:id/metadata', async (c) => {
  try {
    const tenantId = c.get('tenant_id');
    const id = c.req.param('id');
    const securityContext = createSecurityContext(c);

    if (!checkPermission(securityContext, 'documents:read')) {
      return c.json({ error: 'Permission denied', code: 'FORBIDDEN' }, 403);
    }

    const doc = await withRetry(async () => {
      return c.env.DB.prepare(`
        SELECT
          id, file_name as fileName, file_size as fileSize,
          file_type as fileType, description, category,
          uploaded_by as uploadedBy, created_at as createdAt
        FROM documents
        WHERE tenant_id = ? AND id = ?
      `).bind(tenantId, id).first();
    }, 3);

    if (!doc) {
      return c.json({
        error: 'Document not found',
        code: 'NOT_FOUND'
      }, 404);
    }

    await auditLogger(c.env, {
      tenant_id: tenantId,
      user_id: c.get('user_id'),
      action: 'read_metadata',
      resource_type: 'document',
      resource_id: id,
      ip_address: c.get('user_ip')
    });

    return c.json({ data: doc });
  } catch (error) {
    console.error('Error fetching document metadata:', error);
    return c.json({
      error: 'Failed to fetch document metadata',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'METADATA_ERROR'
    }, 500);
  }
});

export { documentsRouter };
