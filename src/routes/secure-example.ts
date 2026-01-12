import { Hono } from 'hono';
import {
  initializeHIPAASecurity,
  requireSession,
  requirePermission,
  requireReauth,
  auditRequest
} from '../middleware/hipaa-security';

const app = new Hono();

const ENCRYPTION_KEY = 'your-encryption-key-from-env';

app.use('*', initializeHIPAASecurity(ENCRYPTION_KEY));

app.get(
  '/patients/:id',
  requireSession(),
  requirePermission('patient', 'read'),
  auditRequest('READ', 'patient'),
  async c => {
    const phiBoundary = c.get('phiBoundary');
    const userId = c.get('userId');
    const tenantId = c.get('tenantId');
    const ipAddress = c.get('ipAddress');
    const userAgent = c.get('userAgent');
    const patientId = c.req.param('id');

    const requestedFields = [
      'id',
      'name',
      'date_of_birth',
      'ssn',
      'medical_record_number',
      'diagnosis_codes'
    ];

    const response = await phiBoundary.read({
      userId,
      tenantId,
      resourceType: 'patient',
      resourceId: patientId,
      requestedFields,
      justification: 'Clinical review',
      ipAddress,
      userAgent
    });

    if (!response.success) {
      return c.json(
        {
          error: response.error,
          deniedFields: response.deniedFields,
          auditLogId: response.auditLogId
        },
        403
      );
    }

    return c.json({
      data: response.data,
      deniedFields: response.deniedFields,
      auditLogId: response.auditLogId
    });
  }
);

app.put(
  '/patients/:id',
  requireSession(),
  requirePermission('patient', 'update'),
  requireReauth('patient', 'update'),
  auditRequest('UPDATE', 'patient'),
  async c => {
    const phiBoundary = c.get('phiBoundary');
    const userId = c.get('userId');
    const tenantId = c.get('tenantId');
    const ipAddress = c.get('ipAddress');
    const userAgent = c.get('userAgent');
    const patientId = c.req.param('id');

    const body = await c.req.json();

    const response = await phiBoundary.write({
      userId,
      tenantId,
      resourceType: 'patient',
      resourceId: patientId,
      data: body,
      justification: body.justification || 'Patient record update',
      ipAddress,
      userAgent
    });

    if (!response.success) {
      return c.json(
        {
          error: response.error,
          auditLogId: response.auditLogId
        },
        403
      );
    }

    return c.json({
      success: true,
      auditLogId: response.auditLogId
    });
  }
);

app.post(
  '/patients/:id/export',
  requireSession(),
  requirePermission('patient', 'export'),
  requireReauth('patient', 'export'),
  auditRequest('EXPORT', 'patient'),
  async c => {
    const phiBoundary = c.get('phiBoundary');
    const userId = c.get('userId');
    const tenantId = c.get('tenantId');
    const ipAddress = c.get('ipAddress');
    const userAgent = c.get('userAgent');
    const patientId = c.req.param('id');

    const body = await c.req.json();

    if (!body.justification || body.justification.length < 20) {
      return c.json(
        {
          error: 'Export justification required (minimum 20 characters)'
        },
        400
      );
    }

    const response = await phiBoundary.export({
      userId,
      tenantId,
      resourceType: 'patient',
      resourceId: patientId,
      requestedFields: body.fields || [],
      justification: body.justification,
      ipAddress,
      userAgent
    });

    if (!response.success) {
      return c.json(
        {
          error: response.error,
          auditLogId: response.auditLogId
        },
        403
      );
    }

    return c.json({
      success: true,
      message: 'Export logged and authorized',
      auditLogId: response.auditLogId
    });
  }
);

app.get(
  '/audit-logs',
  requireSession(),
  requirePermission('audit', 'read'),
  async c => {
    const auditLogger = c.get('auditLogger');
    const tenantId = c.get('tenantId');

    const query = {
      tenantId,
      userId: c.req.query('userId'),
      action: c.req.query('action') as any,
      resourceType: c.req.query('resourceType'),
      resourceId: c.req.query('resourceId'),
      startDate: c.req.query('startDate')
        ? parseInt(c.req.query('startDate')!)
        : undefined,
      endDate: c.req.query('endDate')
        ? parseInt(c.req.query('endDate')!)
        : undefined,
      limit: c.req.query('limit') ? parseInt(c.req.query('limit')!) : 100,
      offset: c.req.query('offset') ? parseInt(c.req.query('offset')!) : 0
    };

    const logs = await auditLogger.query(query);

    return c.json({
      logs,
      count: logs.length
    });
  }
);

app.post('/audit-logs/verify-integrity', requireSession(), async c => {
  const auditLogger = c.get('auditLogger');
  const tenantId = c.get('tenantId');

  const result = await auditLogger.verifyIntegrity(tenantId);

  return c.json({
    valid: result.valid,
    errors: result.errors,
    message: result.valid
      ? 'Audit log integrity verified'
      : 'Audit log integrity compromised'
  });
});

app.get('/sessions/validate', requireSession(), async c => {
  const sessionManager = c.get('sessionManager');
  const sessionId = c.get('sessionId');
  const ipAddress = c.get('ipAddress');
  const userAgent = c.get('userAgent');

  const validation = await sessionManager.validateSession(
    sessionId,
    ipAddress,
    userAgent
  );

  return c.json({
    valid: validation.valid,
    reason: validation.reason,
    requiresReauth: validation.requiresReauth,
    requiresMfa: validation.requiresMfa
  });
});

app.post(
  '/sessions/grant-privileged',
  requireSession(),
  requireReauth('session', 'grant_privileged'),
  async c => {
    const sessionManager = c.get('sessionManager');
    const sessionId = c.get('sessionId');
    const ipAddress = c.get('ipAddress');

    await sessionManager.grantPrivilegedAccess(sessionId, ipAddress);

    return c.json({
      success: true,
      message: 'Privileged access granted for 5 minutes'
    });
  }
);

export default app;
