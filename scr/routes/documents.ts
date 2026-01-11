import { Hono } from 'hono';
import { z } from 'zod';
import { Env } from '../worker';
import { withRetry } from '../utils/retry';
import { sanitizeInput } from '../utils/validation';
import { calculateDocumentChecksum } from '../utils/hipaa-security';

const documentsRouter = new Hono<{ Bindings: Env }>();

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
  const tenantId = c.get('tenantId') || c.get('tenant_id');
  const userId = c.get('userId') || c.get('user_id');
  const auditLogger = c.get('auditLogger');
  const rbacManager = c.get('rbacManager');
  const ipAddress = c.get('ipAddress');
  const userAgent = c.get('userAgent');
  const requestId = c.get('requestId');
  const db = c.get('db');

  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: 'document',
      action: 'create',
      resourceId: 'new'
    });

    if (!access.allowed) {
      await auditLogger.log({
        tenantId,
        userId,
        action: 'CREATE',
        resourceType: 'document',
        resourceId: 'new',
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });

      return c.json({ error: access.reason || 'Access denied' }, 403);
    }

    const formData = await c.req.formData();
    const file = formData.get('file') as File;
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
    const checksum = await calculateDocumentChecksum(fileBuffer);
    const now = Math.floor(Date.now() / 1000);

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

    await withRetry(async () => {
      await db.prepare(`
        INSERT INTO documents (
          id, tenant_id, user_id, filename, size_bytes, mime_type,
          r2_key, category, checksum, current_version, verified_at,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
      `).bind(
        fileId,
        tenantId,
        userId,
        sanitizeInput(file.name, 255),
        file.size,
        file.type,
        r2Key,
        category,
        checksum,
        now,
        now,
        now
      ).run();

      await db.prepare(`
        INSERT INTO document_versions (
          document_id, tenant_id, version, filename, mime_type,
          size_bytes, r2_key, checksum, uploaded_by, verified,
          change_description, created_at
        ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, 1, 'Initial version', ?)
      `).bind(
        fileId,
        tenantId,
        sanitizeInput(file.name, 255),
        file.type,
        file.size,
        r2Key,
        checksum,
        userId,
        now
      ).run();
    }, 3);

    await auditLogger.log({
      tenantId,
      userId,
      action: 'CREATE',
      resourceType: 'document',
      resourceId: fileId,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        fileName: file.name,
        fileSize: file.size,
        category,
        checksum,
        phiFields: ['filename', 'category']
      }
    });

    return c.json({
      id: fileId,
      fileName: file.name,
      fileSize: file.size,
      fileType: file.type,
      category,
      checksum,
      version: 1,
      uploadDuration
    }, 201);
  } catch (error) {
    await auditLogger.log({
      tenantId,
      userId,
      action: 'CREATE',
      resourceType: 'document',
      resourceId: 'new',
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error instanceof Error ? error.message : 'Unknown error',
      phiAccessed: false
    });

    console.error('Error uploading document:', error);
    return c.json({
      error: 'Failed to upload document',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'UPLOAD_ERROR'
    }, 500);
  }
});

documentsRouter.get('/', async (c) => {
  const tenantId = c.get('tenantId') || c.get('tenant_id');
  const userId = c.get('userId') || c.get('user_id');
  const auditLogger = c.get('auditLogger');
  const rbacManager = c.get('rbacManager');
  const ipAddress = c.get('ipAddress');
  const userAgent = c.get('userAgent');
  const requestId = c.get('requestId');
  const db = c.get('db');

  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: 'document',
      action: 'read',
      resourceId: 'list'
    });

    if (!access.allowed) {
      await auditLogger.log({
        tenantId,
        userId,
        action: 'READ',
        resourceType: 'document',
        resourceId: 'list',
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });

      return c.json({ error: access.reason || 'Access denied' }, 403);
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
        const result = await db.prepare(query).bind(...bindings).all();
        return result.results;
      }, 3),
      withRetry(async () => {
        let countQuery = `SELECT COUNT(*) as total FROM documents WHERE tenant_id = ?`;
        const countBindings: any[] = [tenantId];
        if (category) {
          countQuery += ` AND category = ?`;
          countBindings.push(category);
        }
        const result = await db.prepare(countQuery).bind(...countBindings).first<{ total: number }>();
        return result?.total || 0;
      }, 3)
    ]);

    await auditLogger.log({
      tenantId,
      userId,
      action: 'READ',
      resourceType: 'document',
      resourceId: 'list',
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        recordCount: items.length,
        category,
        phiFields: ['fileName', 'category']
      }
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
    await auditLogger.log({
      tenantId,
      userId,
      action: 'READ',
      resourceType: 'document',
      resourceId: 'list',
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error instanceof Error ? error.message : 'Unknown error',
      phiAccessed: false
    });

    console.error('Error listing documents:', error);
    return c.json({
      error: 'Failed to list documents',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'LIST_ERROR'
    }, 500);
  }
});

documentsRouter.get('/:id', async (c) => {
  const tenantId = c.get('tenantId') || c.get('tenant_id');
  const userId = c.get('userId') || c.get('user_id');
  const id = c.req.param('id');
  const auditLogger = c.get('auditLogger');
  const rbacManager = c.get('rbacManager');
  const ipAddress = c.get('ipAddress');
  const userAgent = c.get('userAgent');
  const requestId = c.get('requestId');
  const db = c.get('db');

  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: 'document',
      action: 'read',
      resourceId: id
    });

    if (!access.allowed) {
      await auditLogger.log({
        tenantId,
        userId,
        action: 'READ',
        resourceType: 'document',
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });

      return c.json({ error: access.reason || 'Access denied' }, 403);
    }

    const doc = await withRetry(async () => {
      return db.prepare(`
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
      await auditLogger.log({
        tenantId,
        userId,
        action: 'READ',
        resourceType: 'document',
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: 'Document not found',
        phiAccessed: false
      });

      return c.json({
        error: 'Document not found',
        code: 'NOT_FOUND'
      }, 404);
    }

    const object = await c.env.DOCUMENTS.get(doc.r2_key);

    if (!object) {
      await auditLogger.log({
        tenantId,
        userId,
        action: 'READ',
        resourceType: 'document',
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: 'File not found in storage',
        phiAccessed: false
      });

      return c.json({
        error: 'File not found in storage',
        code: 'FILE_NOT_FOUND'
      }, 404);
    }

    await auditLogger.log({
      tenantId,
      userId,
      action: 'READ',
      resourceType: 'document',
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        fileName: doc.file_name,
        action: 'download',
        phiFields: ['file_name', 'file_content']
      }
    });

    return new Response(object.body, {
      headers: {
        'Content-Type': doc.file_type,
        'Content-Disposition': `attachment; filename="${doc.file_name}"`,
        'Cache-Control': 'private, max-age=3600'
      }
    });
  } catch (error) {
    await auditLogger.log({
      tenantId,
      userId,
      action: 'READ',
      resourceType: 'document',
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error instanceof Error ? error.message : 'Unknown error',
      phiAccessed: false
    });

    console.error('Error downloading document:', error);
    return c.json({
      error: 'Failed to download document',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'DOWNLOAD_ERROR'
    }, 500);
  }
});

documentsRouter.delete('/:id', async (c) => {
  const tenantId = c.get('tenantId') || c.get('tenant_id');
  const userId = c.get('userId') || c.get('user_id');
  const id = c.req.param('id');
  const auditLogger = c.get('auditLogger');
  const rbacManager = c.get('rbacManager');
  const ipAddress = c.get('ipAddress');
  const userAgent = c.get('userAgent');
  const requestId = c.get('requestId');
  const db = c.get('db');

  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: 'document',
      action: 'delete',
      resourceId: id
    });

    if (!access.allowed) {
      await auditLogger.log({
        tenantId,
        userId,
        action: 'DELETE',
        resourceType: 'document',
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });

      return c.json({ error: access.reason || 'Access denied' }, 403);
    }

    const doc = await withRetry(async () => {
      return db.prepare(`
        SELECT r2_key, file_name
        FROM documents
        WHERE tenant_id = ? AND id = ?
      `).bind(tenantId, id).first<{
        r2_key: string;
        file_name: string;
      }>();
    }, 3);

    if (!doc) {
      await auditLogger.log({
        tenantId,
        userId,
        action: 'DELETE',
        resourceType: 'document',
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: 'Document not found',
        phiAccessed: false
      });

      return c.json({
        error: 'Document not found',
        code: 'NOT_FOUND'
      }, 404);
    }

    await c.env.DOCUMENTS.delete(doc.r2_key);

    await withRetry(async () => {
      await db.prepare(`
        DELETE FROM documents
        WHERE tenant_id = ? AND id = ?
      `).bind(tenantId, id).run();
    }, 3);

    await auditLogger.log({
      tenantId,
      userId,
      action: 'DELETE',
      resourceType: 'document',
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        fileName: doc.file_name,
        note: 'Document with PHI data deleted',
        phiFields: ['file_name', 'file_content']
      }
    });

    return c.json({ success: true });
  } catch (error) {
    await auditLogger.log({
      tenantId,
      userId,
      action: 'DELETE',
      resourceType: 'document',
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error instanceof Error ? error.message : 'Unknown error',
      phiAccessed: false
    });

    console.error('Error deleting document:', error);
    return c.json({
      error: 'Failed to delete document',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'DELETE_ERROR'
    }, 500);
  }
});

documentsRouter.get('/:id/metadata', async (c) => {
  const tenantId = c.get('tenantId') || c.get('tenant_id');
  const userId = c.get('userId') || c.get('user_id');
  const id = c.req.param('id');
  const auditLogger = c.get('auditLogger');
  const rbacManager = c.get('rbacManager');
  const ipAddress = c.get('ipAddress');
  const userAgent = c.get('userAgent');
  const requestId = c.get('requestId');
  const db = c.get('db');

  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: 'document',
      action: 'read',
      resourceId: id
    });

    if (!access.allowed) {
      await auditLogger.log({
        tenantId,
        userId,
        action: 'READ',
        resourceType: 'document',
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });

      return c.json({ error: access.reason || 'Access denied' }, 403);
    }

    const doc = await withRetry(async () => {
      return db.prepare(`
        SELECT
          id, file_name as fileName, file_size as fileSize,
          file_type as fileType, description, category,
          uploaded_by as uploadedBy, created_at as createdAt
        FROM documents
        WHERE tenant_id = ? AND id = ?
      `).bind(tenantId, id).first();
    }, 3);

    if (!doc) {
      await auditLogger.log({
        tenantId,
        userId,
        action: 'READ',
        resourceType: 'document',
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: 'Document not found',
        phiAccessed: false
      });

      return c.json({
        error: 'Document not found',
        code: 'NOT_FOUND'
      }, 404);
    }

    await auditLogger.log({
      tenantId,
      userId,
      action: 'READ',
      resourceType: 'document',
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        action: 'metadata_access',
        phiFields: ['fileName', 'category']
      }
    });

    return c.json({ data: doc });
  } catch (error) {
    await auditLogger.log({
      tenantId,
      userId,
      action: 'READ',
      resourceType: 'document',
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error instanceof Error ? error.message : 'Unknown error',
      phiAccessed: false
    });

    console.error('Error fetching document metadata:', error);
    return c.json({
      error: 'Failed to fetch document metadata',
      details: error instanceof Error ? error.message : 'Unknown error',
      code: 'METADATA_ERROR'
    }, 500);
  }
});

export { documentsRouter };
