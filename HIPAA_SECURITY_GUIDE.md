# HIPAA Security Implementation Guide

## Overview

This guide covers the comprehensive HIPAA security features implemented in your application:

1. **PHI Field Encryption** - Encrypt sensitive data at rest
2. **Immutable Audit Logging** - Tamper-evident audit trails
3. **RBAC** - Role-based access control with minimum necessary principle
4. **Session Hardening** - Automatic timeouts and re-authentication
5. **PHI Boundary Layer** - Centralized PHI access control

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Frontend                             │
│                    (React Components)                        │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    Worker Middleware                         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Session Validation → RBAC Check → Audit Logging      │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                     PHI Boundary Layer                       │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • Field-level access control                         │   │
│  │ • Automatic encryption/decryption                    │   │
│  │ • Audit trail generation                             │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    Cloudflare D1 Database                    │
│  • Encrypted PHI fields                                      │
│  • Immutable audit logs                                      │
│  • RBAC tables                                               │
└─────────────────────────────────────────────────────────────┘
```

## 1. PHI Field Encryption

### What Gets Encrypted

The following fields are automatically identified as PHI and encrypted:

- `ssn`
- `date_of_birth`
- `medical_record_number`
- `insurance_id`
- `diagnosis_codes`
- `treatment_notes`
- `prescription_info`
- `lab_results`
- `phone_number`
- `email`
- `address`
- `emergency_contact`

### Usage

```typescript
import { PHIEncryption } from './utils/phi-encryption';

const encryptionKey = env.ENCRYPTION_KEY;

const patientData = {
  name: 'John Doe',
  ssn: '123-45-6789',
  date_of_birth: '1980-01-01',
  medical_record_number: 'MRN-12345'
};

const encrypted = await PHIEncryption.encryptObject(
  patientData,
  encryptionKey
);

const decrypted = await PHIEncryption.decryptObject(encrypted, encryptionKey);
```

### Key Rotation

```typescript
const rotated = await PHIEncryption.rotateKey(
  encryptedData,
  oldKey,
  newKey,
  'key-v2'
);
```

## 2. Immutable Audit Logging

### Features

- **Immutability**: SQL triggers prevent updates/deletes
- **Tamper Detection**: Blockchain-style chain with cryptographic hashes
- **Comprehensive Tracking**: All PHI access is logged

### Usage

```typescript
import { createAuditLogger } from './utils/audit-logger';

const auditLogger = createAuditLogger(db);

const logId = await auditLogger.log({
  tenantId: 'tenant-123',
  userId: 'user-456',
  action: 'READ',
  resourceType: 'patient',
  resourceId: 'patient-789',
  phiAccessed: ['ssn', 'date_of_birth'],
  ipAddress: '192.168.1.1',
  userAgent: 'Mozilla/5.0...',
  success: true
});

const phiLogId = await auditLogger.logPHIAccess(
  'tenant-123',
  'user-456',
  'patient-789',
  ['ssn', 'date_of_birth'],
  'Clinical review for treatment plan',
  'supervisor-123',
  '192.168.1.1'
);
```

### Querying Logs

```typescript
const logs = await auditLogger.query({
  tenantId: 'tenant-123',
  userId: 'user-456',
  action: 'READ',
  resourceType: 'patient',
  startDate: Math.floor(Date.now() / 1000) - 86400,
  limit: 100
});
```

### Integrity Verification

```typescript
const integrity = await auditLogger.verifyIntegrity('tenant-123');

if (!integrity.valid) {
  console.error('Audit log tampering detected:', integrity.errors);
}
```

## 3. RBAC with Minimum Necessary

### Default Roles

- **Administrator**: Full system access
- **Clinician**: Patient care with PHI access
- **Billing Staff**: Financial data only, minimal PHI
- **Read-Only User**: View-only, no PHI access

### Usage

```typescript
import { createRBACManager } from './utils/rbac';

const rbac = createRBACManager(db);

const roles = await rbac.getUserRoles('user-123', 'tenant-456');

const decision = await rbac.checkAccess({
  userId: 'user-123',
  tenantId: 'tenant-456',
  resourceType: 'patient',
  action: 'read',
  resourceId: 'patient-789',
  requestedFields: ['ssn', 'date_of_birth']
});

if (!decision.allowed) {
  console.error('Access denied:', decision.reason);
}

const filtered = await rbac.filterPHIFields(
  patientData,
  'user-123',
  'tenant-456',
  'patient'
);
```

### Assigning Roles

```typescript
await rbac.assignRole(
  'user-123',
  'role_clinician',
  'tenant-456',
  'admin-user',
  Math.floor(Date.now() / 1000) + 86400 * 90
);

await rbac.revokeRole('user-123', 'role_clinician', 'tenant-456');
```

## 4. Session Hardening

### Features

- **Idle Timeout**: 15 minutes (configurable)
- **Absolute Timeout**: 8 hours (configurable)
- **Privileged Sessions**: 5 minutes for sensitive operations
- **Session Binding**: IP and user agent validation
- **MFA Requirements**: Configurable MFA verification

### Usage

```typescript
import { createSessionManager } from './utils/session-manager';

const sessionManager = createSessionManager(db, {
  idleTimeoutSeconds: 900,
  absoluteTimeoutSeconds: 28800,
  privilegedTimeoutSeconds: 300,
  requireMFA: true
});

const session = await sessionManager.createSession(
  'user-123',
  '192.168.1.1',
  'Mozilla/5.0...',
  true
);

const validation = await sessionManager.validateSession(
  session.id,
  '192.168.1.1',
  'Mozilla/5.0...'
);

if (!validation.valid) {
  console.error('Session invalid:', validation.reason);
}
```

### Re-Authentication

```typescript
const requiresReauth = await sessionManager.requiresReauthentication(
  'user-123',
  'patient',
  'delete'
);

if (requiresReauth) {
  return { error: 'Re-authentication required' };
}
```

### Privileged Access

```typescript
await sessionManager.grantPrivilegedAccess(session.id, '192.168.1.1');
```

### Cleanup

```typescript
const expired = await sessionManager.cleanupExpiredSessions();
console.log(`Cleaned up ${expired} expired sessions`);
```

## 5. PHI Boundary Layer

### Features

- **Unified API**: Single interface for all PHI operations
- **Automatic Encryption**: Transparent encryption/decryption
- **Access Control**: Integrated RBAC checks
- **Audit Trail**: Automatic logging of all operations

### Usage

```typescript
import { createPHIBoundary } from './utils/phi-boundary';

const phiBoundary = createPHIBoundary(db, encryptionKey);

const response = await phiBoundary.read({
  userId: 'user-123',
  tenantId: 'tenant-456',
  resourceType: 'patient',
  resourceId: 'patient-789',
  requestedFields: ['name', 'ssn', 'date_of_birth'],
  justification: 'Clinical review for treatment plan',
  ipAddress: '192.168.1.1',
  userAgent: 'Mozilla/5.0...'
});

if (response.success) {
  console.log('Data:', response.data);
  console.log('Denied fields:', response.deniedFields);
  console.log('Audit log ID:', response.auditLogId);
}
```

### Write Operations

```typescript
const writeResponse = await phiBoundary.write({
  userId: 'user-123',
  tenantId: 'tenant-456',
  resourceType: 'patient',
  resourceId: 'patient-789',
  data: {
    diagnosis_codes: ['E11.9', 'I10'],
    treatment_notes: 'Updated treatment plan'
  },
  justification: 'Treatment update',
  ipAddress: '192.168.1.1'
});
```

### Export Operations

```typescript
const exportResponse = await phiBoundary.export({
  userId: 'user-123',
  tenantId: 'tenant-456',
  resourceType: 'patient',
  resourceId: 'patient-789',
  requestedFields: ['ssn', 'medical_record_number'],
  justification: 'Required for insurance claim submission to ABC Insurance',
  ipAddress: '192.168.1.1'
});
```

## Worker Middleware Integration

### Setup

```typescript
import { Hono } from 'hono';
import {
  initializeHIPAASecurity,
  requireSession,
  requirePermission,
  requireReauth,
  auditRequest
} from './middleware/hipaa-security';

const app = new Hono();

app.use('*', initializeHIPAASecurity(env.ENCRYPTION_KEY));
```

### Protected Routes

```typescript
app.get(
  '/patients/:id',
  requireSession(),
  requirePermission('patient', 'read'),
  auditRequest('READ', 'patient'),
  async c => {
    const phiBoundary = c.get('phiBoundary');
    const userId = c.get('userId');
    const tenantId = c.get('tenantId');

    const response = await phiBoundary.read({
      userId,
      tenantId,
      resourceType: 'patient',
      resourceId: c.req.param('id'),
      requestedFields: ['name', 'ssn'],
      ipAddress: c.get('ipAddress'),
      userAgent: c.get('userAgent')
    });

    return c.json(response);
  }
);
```

## Database Migrations

### Apply Migrations

```bash
wrangler d1 execute roiblueprint --file=./migrations/immutable_audit_logging.sql
wrangler d1 execute roiblueprint --file=./migrations/rbac_system.sql
wrangler d1 execute roiblueprint --file=./migrations/session_hardening.sql
```

### Production

```bash
wrangler d1 execute roiblueprint --file=./migrations/immutable_audit_logging.sql --remote
wrangler d1 execute roiblueprint --file=./migrations/rbac_system.sql --remote
wrangler d1 execute roiblueprint --file=./migrations/session_hardening.sql --remote
```

## Environment Variables

Add to your `.env` and Cloudflare Worker secrets:

```bash
ENCRYPTION_KEY=your-256-bit-encryption-key-here
```

Generate a secure key:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Set as Cloudflare secret:

```bash
wrangler secret put ENCRYPTION_KEY
```

## Best Practices

### 1. Always Use the PHI Boundary

❌ **Don't do this:**
```typescript
const patient = await db.prepare('SELECT * FROM patients WHERE id = ?').bind(id).first();
```

✅ **Do this:**
```typescript
const response = await phiBoundary.read({
  userId,
  tenantId,
  resourceType: 'patient',
  resourceId: id,
  requestedFields: ['name', 'ssn'],
  justification: 'Clinical review'
});
```

### 2. Require Justification for PHI Access

```typescript
if (!justification || justification.length < 20) {
  return { error: 'Justification required (minimum 20 characters)' };
}
```

### 3. Monitor Audit Logs

```typescript
setInterval(async () => {
  const integrity = await auditLogger.verifyIntegrity(tenantId);
  if (!integrity.valid) {
    await alertSecurityTeam(integrity.errors);
  }
}, 3600000);
```

### 4. Implement Session Cleanup

```typescript
setInterval(async () => {
  await sessionManager.cleanupExpiredSessions();
}, 300000);
```

### 5. Use Privileged Sessions for Sensitive Operations

```typescript
if (action === 'delete' || action === 'export') {
  await sessionManager.grantPrivilegedAccess(sessionId);
}
```

## Testing

See `src/routes/secure-example.ts` for comprehensive examples of all security features in action.

## Compliance Checklist

- [x] PHI encrypted at rest (AES-256-GCM)
- [x] Immutable audit logging with tamper detection
- [x] Role-based access control
- [x] Minimum necessary access principle
- [x] Session timeout (idle and absolute)
- [x] Re-authentication for sensitive operations
- [x] Field-level PHI access control
- [x] Comprehensive audit trails
- [x] IP and user agent validation
- [x] MFA support framework

## Next Steps

1. Configure encryption key in Cloudflare secrets
2. Apply database migrations
3. Assign roles to users
4. Test audit log integrity verification
5. Configure session timeout values for your requirements
6. Implement MFA token generation (use libraries like `otpauth` or `speakeasy`)
