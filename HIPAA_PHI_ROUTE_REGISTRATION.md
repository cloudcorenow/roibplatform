# PHI Route Registration Guide

## Overview

The application enforces **default-deny** for routes that may contain Protected Health Information (PHI). Any route matching suspicious patterns must be explicitly registered or declared non-PHI.

## Why Default-Deny?

**Problem**: Developers add new endpoints without realizing they handle PHI, bypassing security controls.

**Solution**: Automatically detect suspicious routes and block them until properly classified.

## Suspicious Patterns (Auto-Detected)

The following URL patterns are automatically flagged as potentially PHI-bearing:

```typescript
/api/patient*      // Patient records
/api/health*       // Health information (except /api/health, /api/healthcheck)
/api/medical*      // Medical data
/api/diagnosis*    // Diagnosis information
/api/treatment*    // Treatment plans
/api/prescription* // Prescriptions
/api/insurance*    // Insurance information
/api/billing*      // Billing records
/api/claim*        // Insurance claims
/api/encounter*    // Patient encounters
/api/vital*        // Vital signs
/api/lab*          // Lab results
/api/record*       // Medical records
/api/chart*        // Patient charts
```

## Exempted Routes (Non-PHI by Default)

These routes are **automatically exempted** from PHI checks:

```typescript
/api/health          // Health check endpoint
/api/healthcheck     // Alternative health check
/api/status          // Status endpoint
/api/ping            // Ping endpoint
/api/auth/login      // Authentication
/api/auth/logout
/api/auth/register
/api/auth/refresh
/api/session/ping    // Session keep-alive
```

---

## Option 1: Register as PHI Route

**When**: Your route handles actual PHI data

**Steps:**

### 1. Add to PHI_BEARING_ROUTES

Edit `src/middleware/phi-route-guard.ts`:

```typescript
export const PHI_BEARING_ROUTES = {
  // ... existing routes ...

  patients: {  // Add your new route
    basePath: '/api/patients',
    operations: ['read', 'create', 'update', 'delete'],
    phiFields: ['name', 'ssn', 'dob', 'diagnosis', 'treatment'],
    requiresAuth: true,
    requiresAudit: true
  }
};
```

### 2. Register Route Handler

In your route file (e.g., `src/routes/patients.ts`):

```typescript
import { registerPHIRoute } from '../middleware/phi-route-guard';

// Register each specific route
registerPHIRoute({
  route: '/api/patients',
  method: 'GET',
  phiRoute: 'patients',
  requiresHIPAAMiddleware: true,
  requiresSession: true,
  requiresPermission: { resource: 'patients', action: 'read' },
  requiresAudit: true
});

registerPHIRoute({
  route: '/api/patients/:id',
  method: 'GET',
  phiRoute: 'patients',
  requiresHIPAAMiddleware: true,
  requiresSession: true,
  requiresPermission: { resource: 'patients', action: 'read' },
  requiresAudit: true
});

registerPHIRoute({
  route: '/api/patients',
  method: 'POST',
  phiRoute: 'patients',
  requiresHIPAAMiddleware: true,
  requiresSession: true,
  requiresPermission: { resource: 'patients', action: 'create' },
  requiresAudit: true
});
```

### 3. Use PHI Boundary for Encryption

In your handler:

```typescript
app.get('/api/patients/:id', async (c) => {
  const phiBoundary = c.get('phiBoundary');
  const patientId = c.req.param('id');

  // Fetch patient (encrypted fields)
  const patient = await db.prepare(
    'SELECT * FROM patients WHERE id = ?'
  ).bind(patientId).first();

  // Decrypt PHI fields
  const decrypted = await phiBoundary.decryptPHI(patient, [
    'name', 'ssn', 'dob', 'diagnosis'
  ]);

  return c.json({ patient: decrypted });
});

app.post('/api/patients', async (c) => {
  const phiBoundary = c.get('phiBoundary');
  const data = await c.req.json();

  // Encrypt PHI fields before storing
  const encrypted = await phiBoundary.encryptPHI(data, [
    'name', 'ssn', 'dob', 'diagnosis'
  ]);

  await db.prepare(
    'INSERT INTO patients (id, name, ssn, dob, diagnosis) VALUES (?, ?, ?, ?, ?)'
  ).bind(
    crypto.randomUUID(),
    encrypted.name,
    encrypted.ssn,
    encrypted.dob,
    encrypted.diagnosis
  ).run();

  return c.json({ success: true });
});
```

**What You Get:**
- ✅ Session validation (X-Session-ID required)
- ✅ RBAC permission checks
- ✅ Automatic audit logging
- ✅ PHI field encryption/decryption
- ✅ Session timeout enforcement
- ✅ IP address binding

---

## Option 2: Declare as Non-PHI Route

**When**: Your route matches a pattern but does NOT handle PHI

**Example**: `/api/health-metrics` (application health, not patient health)

### Method A: Add to NON_PHI_ROUTES

Edit `src/middleware/phi-route-guard.ts`:

```typescript
const NON_PHI_ROUTES = new Set([
  // ... existing routes ...
  '/api/health-metrics',  // Add your route
  '/api/healthz',
  '/api/patient-portal-status'  // Status check, no PHI
]);
```

### Method B: Declare Programmatically

In your route file:

```typescript
import { declareNonPHIRoute } from '../middleware/phi-route-guard';

// Declare this route does NOT contain PHI
declareNonPHIRoute('/api/health-metrics');
declareNonPHIRoute('/api/patient-count');  // Just a count, no actual PHI

app.get('/api/health-metrics', async (c) => {
  // No PHI here, just system metrics
  return c.json({
    activeUsers: 123,
    requestsPerMinute: 456
  });
});
```

**What You Get:**
- ✅ No session required
- ✅ No RBAC checks
- ✅ No audit logging
- ✅ Normal authentication flow (JWT only)

---

## Error Messages

### Error 1: Suspicious Unregistered Route

```json
{
  "error": "Security configuration error",
  "message": "This route matches PHI patterns but is not registered...",
  "route": "/api/patient-records",
  "patterns": ["/\\/api\\/patient/i", "/\\/api\\/record/i"],
  "action": "Contact security team to register this route properly"
}
```

**Fix**: Choose Option 1 or Option 2 above

### Error 2: PHI Route Without HIPAA Middleware

```json
{
  "error": "Security configuration error",
  "message": "This route requires HIPAA security middleware but it was not initialized",
  "route": "/api/assessments",
  "phiRoute": "assessments"
}
```

**Fix**: Ensure `initializeHIPAASecurity()` middleware runs before route handler

### Error 3: PHI Route Without Session

```json
{
  "error": "Session required",
  "message": "PHI routes require active session with X-Session-ID header",
  "route": "/api/assessments"
}
```

**Fix**: Send `X-Session-ID` header with PHI requests (see frontend integration below)

---

## Complete Example: Adding a New PHI Endpoint

### Scenario: Add `/api/lab-results` endpoint

#### Step 1: Add to PHI_BEARING_ROUTES

```typescript
// src/middleware/phi-route-guard.ts
export const PHI_BEARING_ROUTES = {
  // ... existing ...

  labResults: {
    basePath: '/api/lab-results',
    operations: ['read', 'create', 'update', 'delete'],
    phiFields: ['patient_id', 'test_type', 'results', 'notes'],
    requiresAuth: true,
    requiresAudit: true
  }
};
```

#### Step 2: Create Route File

```typescript
// src/routes/labResults.ts
import { Hono } from 'hono';
import { registerPHIRoute } from '../middleware/phi-route-guard';

const app = new Hono();

registerPHIRoute({
  route: '/api/lab-results',
  method: 'GET',
  phiRoute: 'labResults',
  requiresHIPAAMiddleware: true,
  requiresSession: true,
  requiresPermission: { resource: 'lab_results', action: 'read' },
  requiresAudit: true
});

registerPHIRoute({
  route: '/api/lab-results/:id',
  method: 'GET',
  phiRoute: 'labResults',
  requiresHIPAAMiddleware: true,
  requiresSession: true,
  requiresPermission: { resource: 'lab_results', action: 'read' },
  requiresAudit: true
});

app.get('/api/lab-results', async (c) => {
  const rbac = c.get('rbacManager');
  const userId = c.get('userId');
  const tenantId = c.get('tenantId');

  if (!await rbac.checkPermission(userId, tenantId, 'lab_results', 'read')) {
    return c.json({ error: 'Permission denied' }, 403);
  }

  const phiBoundary = c.get('phiBoundary');
  const db = c.get('DB');

  const results = await db.prepare(
    'SELECT * FROM lab_results WHERE tenant_id = ?'
  ).bind(tenantId).all();

  const decrypted = await Promise.all(
    results.results.map(result =>
      phiBoundary.decryptPHI(result, ['patient_id', 'test_type', 'results', 'notes'])
    )
  );

  return c.json({ results: decrypted });
});

app.get('/api/lab-results/:id', async (c) => {
  const rbac = c.get('rbacManager');
  const userId = c.get('userId');
  const tenantId = c.get('tenantId');
  const resultId = c.req.param('id');

  if (!await rbac.checkPermission(userId, tenantId, 'lab_results', 'read')) {
    return c.json({ error: 'Permission denied' }, 403);
  }

  const phiBoundary = c.get('phiBoundary');
  const db = c.get('DB');

  const result = await db.prepare(
    'SELECT * FROM lab_results WHERE id = ? AND tenant_id = ?'
  ).bind(resultId, tenantId).first();

  if (!result) {
    return c.json({ error: 'Not found' }, 404);
  }

  const decrypted = await phiBoundary.decryptPHI(result, [
    'patient_id', 'test_type', 'results', 'notes'
  ]);

  return c.json({ result: decrypted });
});

export default app;
```

#### Step 3: Wire Up in Worker

```typescript
// src/worker.ts
import labResults from './routes/labResults';

app.route('/', labResults);
```

#### Step 4: Create Migration

```sql
-- migrations/lab_results.sql
CREATE TABLE IF NOT EXISTS lab_results (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  patient_id TEXT NOT NULL,  -- Encrypted
  test_type TEXT NOT NULL,   -- Encrypted
  results TEXT NOT NULL,     -- Encrypted
  notes TEXT,                -- Encrypted
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  created_by TEXT NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

CREATE INDEX idx_lab_results_tenant ON lab_results(tenant_id);
CREATE INDEX idx_lab_results_created_at ON lab_results(created_at);

ALTER TABLE lab_results ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can read own tenant lab results"
  ON lab_results FOR SELECT
  TO authenticated
  USING (tenant_id = current_setting('app.tenant_id'));
```

#### Step 5: Add RBAC Permissions

```typescript
// In tenant setup or admin panel
await rbac.createRole(tenantId, {
  name: 'lab_technician',
  description: 'Can view and create lab results',
  permissions: [
    { resource: 'lab_results', action: 'read' },
    { resource: 'lab_results', action: 'create' }
  ]
});
```

---

## Frontend Integration

### Making PHI Requests

```typescript
// Store session ID after login
const loginResponse = await fetch('/api/auth/login', {
  method: 'POST',
  body: JSON.stringify({ email, password })
});

const { token, sessionId } = await loginResponse.json();
localStorage.setItem('jwt', token);
localStorage.setItem('sessionId', sessionId);

// All PHI requests must include both headers
const fetchPHIData = async (url: string, options: RequestInit = {}) => {
  return fetch(url, {
    ...options,
    headers: {
      'Authorization': `Bearer ${localStorage.getItem('jwt')}`,
      'X-Session-ID': localStorage.getItem('sessionId'),
      'Content-Type': 'application/json',
      ...options.headers
    }
  });
};

// Example: Fetch lab results
const response = await fetchPHIData('/api/lab-results');
const { results } = await response.json();
```

---

## Security Checklist

When adding a new endpoint:

- [ ] Does it handle patient data? → PHI
- [ ] Does it handle health information? → PHI
- [ ] Does it handle financial/insurance data? → PHI (ePHI under HIPAA)
- [ ] Does it handle user identifiers + health context? → PHI
- [ ] Does it match a suspicious pattern? → Must be registered or declared non-PHI

**When in doubt**: Register as PHI. False positives are safe, false negatives are breaches.

---

## Monitoring

### Check for Unregistered Routes

```sql
-- Query audit logs for blocked suspicious routes
SELECT
  metadata->>'path' as path,
  COUNT(*) as attempts,
  MIN(created_at) as first_attempt
FROM audit_logs
WHERE success = 0
  AND failure_reason LIKE '%Security configuration error%'
GROUP BY metadata->>'path'
ORDER BY attempts DESC;
```

### Alert on Security Violations

Set up monitoring for log pattern:

```
"CRITICAL SECURITY VIOLATION: Suspicious PHI route"
```

**Response**:
1. Identify the route
2. Determine if it contains PHI
3. Register appropriately
4. Review why it wasn't caught during code review

---

## FAQ

### Q: I added `/api/patient-count`, why is it blocked?

**A**: Matches pattern `/api/patient`. Use `declareNonPHIRoute('/api/patient-count')` if it only returns a count (no actual PHI).

### Q: Can I disable this check?

**A**: No. This is a critical security control for HIPAA compliance.

### Q: What if I need a temporary exception?

**A**: No temporary exceptions. Register the route properly or it stays blocked.

### Q: Can users access PHI without X-Session-ID?

**A**: No. Session validation is mandatory for all PHI routes.

### Q: What happens if I forget to register a route?

**A**: The route returns 500 error and blocks all access. Better to fail closed than leak PHI.

---

## Summary

**Default Stance**: Deny suspicious routes until proven safe

**Developer Action**: Explicitly classify every route that matches patterns

**Security Benefit**: Impossible to accidentally expose PHI through unprotected endpoints

**Compliance Impact**: Demonstrates "secure by default" architecture for auditors

This is **working as intended** and cannot be bypassed without modifying security-critical code.
