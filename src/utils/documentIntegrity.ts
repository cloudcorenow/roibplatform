export async function calculateChecksum(data: ArrayBuffer): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function verifyChecksum(
  data: ArrayBuffer,
  expectedChecksum: string
): Promise<boolean> {
  const actualChecksum = await calculateChecksum(data);
  return actualChecksum === expectedChecksum;
}

export interface DocumentMetadata {
  id: string;
  filename: string;
  checksum: string;
  sizeBytes: number;
  mimeType: string;
  r2Key: string;
}

export async function storeDocumentWithIntegrity(
  db: D1Database,
  r2: R2Bucket,
  tenantId: string,
  userId: string,
  file: File
): Promise<DocumentMetadata> {
  const buffer = await file.arrayBuffer();
  const checksum = await calculateChecksum(buffer);

  const docId = crypto.randomUUID();
  const r2Key = `${tenantId}/${docId}/${file.name}`;

  await r2.put(r2Key, buffer, {
    httpMetadata: {
      contentType: file.type
    },
    customMetadata: {
      checksum,
      tenantId,
      userId,
      uploadedAt: new Date().toISOString()
    }
  });

  const now = Math.floor(Date.now() / 1000);

  await db.prepare(`
    INSERT INTO documents (
      id, tenant_id, user_id, filename, mime_type, size_bytes, r2_key, checksum, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    docId,
    tenantId,
    userId,
    file.name,
    file.type,
    file.size,
    r2Key,
    checksum,
    now,
    now
  ).run();

  await createDocumentVersion(db, docId, checksum, userId);

  return {
    id: docId,
    filename: file.name,
    checksum,
    sizeBytes: file.size,
    mimeType: file.type,
    r2Key
  };
}

export async function retrieveAndVerifyDocument(
  db: D1Database,
  r2: R2Bucket,
  documentId: string
): Promise<{ valid: boolean; data?: ArrayBuffer; metadata?: DocumentMetadata; error?: string }> {
  const doc = await db.prepare(`
    SELECT id, filename, checksum, size_bytes, mime_type, r2_key
    FROM documents
    WHERE id = ?
  `).bind(documentId).first();

  if (!doc) {
    return { valid: false, error: 'Document not found' };
  }

  const r2Object = await r2.get(doc.r2_key as string);
  if (!r2Object) {
    return { valid: false, error: 'Document file not found in storage' };
  }

  const data = await r2Object.arrayBuffer();
  const isValid = await verifyChecksum(data, doc.checksum as string);

  if (!isValid) {
    return {
      valid: false,
      error: 'Document integrity check failed - possible tampering detected'
    };
  }

  await updateDocumentVerification(db, documentId);

  return {
    valid: true,
    data,
    metadata: {
      id: doc.id as string,
      filename: doc.filename as string,
      checksum: doc.checksum as string,
      sizeBytes: doc.size_bytes as number,
      mimeType: doc.mime_type as string,
      r2Key: doc.r2_key as string
    }
  };
}

async function createDocumentVersion(
  db: D1Database,
  documentId: string,
  checksum: string,
  userId: string
): Promise<void> {
  const currentVersion = await db.prepare(`
    SELECT COALESCE(MAX(version), 0) as max_version
    FROM document_versions
    WHERE document_id = ?
  `).bind(documentId).first();

  const newVersion = ((currentVersion?.max_version as number) || 0) + 1;
  const now = Math.floor(Date.now() / 1000);

  await db.prepare(`
    INSERT INTO document_versions (document_id, version, checksum, changed_by, changed_at)
    VALUES (?, ?, ?, ?, ?)
  `).bind(documentId, newVersion, checksum, userId, now).run();
}

async function updateDocumentVerification(
  db: D1Database,
  documentId: string
): Promise<void> {
  const now = Math.floor(Date.now() / 1000);

  await db.prepare(`
    UPDATE documents
    SET verified_at = ?
    WHERE id = ?
  `).bind(now, documentId).run();
}

export async function getDocumentVersionHistory(
  db: D1Database,
  documentId: string
): Promise<any[]> {
  const { results } = await db.prepare(`
    SELECT v.*, u.name as changed_by_name, u.email as changed_by_email
    FROM document_versions v
    LEFT JOIN users u ON v.changed_by = u.id
    WHERE v.document_id = ?
    ORDER BY v.version DESC
  `).bind(documentId).all();

  return results;
}

export async function performIntegrityAudit(
  db: D1Database,
  r2: R2Bucket,
  tenantId: string
): Promise<{
  total: number;
  verified: number;
  failed: number;
  errors: Array<{ documentId: string; filename: string; error: string }>;
}> {
  const { results: documents } = await db.prepare(`
    SELECT id, filename, checksum, r2_key
    FROM documents
    WHERE tenant_id = ?
  `).bind(tenantId).all();

  let verified = 0;
  let failed = 0;
  const errors: Array<{ documentId: string; filename: string; error: string }> = [];

  for (const doc of documents) {
    try {
      const r2Object = await r2.get(doc.r2_key as string);
      if (!r2Object) {
        failed++;
        errors.push({
          documentId: doc.id as string,
          filename: doc.filename as string,
          error: 'File not found in storage'
        });
        continue;
      }

      const data = await r2Object.arrayBuffer();
      const isValid = await verifyChecksum(data, doc.checksum as string);

      if (isValid) {
        verified++;
        await updateDocumentVerification(db, doc.id as string);
      } else {
        failed++;
        errors.push({
          documentId: doc.id as string,
          filename: doc.filename as string,
          error: 'Checksum mismatch - integrity compromised'
        });
      }
    } catch (error) {
      failed++;
      errors.push({
        documentId: doc.id as string,
        filename: doc.filename as string,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  return {
    total: documents.length,
    verified,
    failed,
    errors
  };
}
