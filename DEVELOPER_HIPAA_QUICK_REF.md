# HIPAA Stack Quick Reference for Developers

**Last Updated**: January 2026
**Audience**: Engineers migrating routes to HIPAA-compliant stack

---

## ❌ OLD Stack (Do Not Use)

```typescript
// ❌ DEPRECATED - Do not import these
import { auditLogger } from '../utils/audit';
import { requirePermission, createSecurityContext } from '../utils/security';

// ❌ DEPRECATED - Old pattern
const securityContext = createSecurityContext(c);
requirePermission(securityContext, 'assessments:read');

await auditLogger(c.env, {
  action: 'read_assessment',
  user_id: userId
});

// ❌ Direct DB queries expose plaintext PHI
const result = await c.env.DB.prepare(`
  SELECT client_id, responses, results FROM assessments
`).all();
```

---

## ✅ NEW Stack (Use This)

```typescript
// ✅ No imports needed - use context
router.get('/', async (c) => {
  // Extract HIPAA components from context
  const auditLogger = c.get('auditLogger');      // Immutable audit logger
  const phiBoundary = c.get('phiBoundary');      // Encrypted PHI + field-level RBAC
  const rbacManager = c.get('rbacManager');      // Permission checks
  const sessionManager = c.get('sessionManager'); // Session validation (automatic)
  const userId = c.get('userId');                // From JWT
  const tenantId = c.get('tenantId');            // From JWT

  try {
    // 1. Check RBAC permission
    const access = await rbacManager.checkAccess(
      userId,
      'assessment',    // resource type
      'read',          // action
      tenantId
    );

    if (!access.allowed) {
      // Audit denial
      await auditLogger.log({
        action: 'ASSESSMENT_READ_DENIED',
        resource_type: 'assessment',
        resource_id: null,
        success: false,
        phi_accessed: false,
        failure_reason: 'Permission denied'
      });

      return c.json({ error: 'Access denied' }, 403);
    }

    // 2. Read data via PHI boundary (auto-encrypts/decrypts)
    const assessments = await phiBoundary.read({
      resource: 'assessment',
      query: { tenant_id: tenantId },
      requestedFields: ['id', 'client_id', 'responses', 'results', 'score'],
      userId
    });

    // 3. Audit success
    await auditLogger.log({
      action: 'ASSESSMENT_READ',
      resource_type: 'assessment',
      resource_id: null,
      success: true,
      phi_accessed: true,
      phi_fields: assessments.accessedFields,  // Which PHI fields were accessed
      record_count: assessments.data.length
    });

    return c.json(assessments.data);

  } catch (error) {
    // 4. Audit errors
    await auditLogger.log({
      action: 'ASSESSMENT_READ_ERROR',
      resource_type: 'assessment',
      success: false,
      phi_accessed: false,
      failure_reason: error.message
    });

    return c.json({ error: 'Internal server error' }, 500);
  }
});
```

---

## Common Patterns

### Pattern 1: List Resources (GET /api/resource)

```typescript
router.get('/', async (c) => {
  const auditLogger = c.get('auditLogger');
  const phiBoundary = c.get('phiBoundary');
  const rbacManager = c.get('rbacManager');
  const userId = c.get('userId');
  const tenantId = c.get('tenantId');

  // Check permission
  const access = await rbacManager.checkAccess(userId, 'resource', 'list', tenantId);
  if (!access.allowed) {
    await auditLogger.log({
      action: 'RESOURCE_LIST_DENIED',
      resource_type: 'resource',
      success: false,
      phi_accessed: false
    });
    return c.json({ error: 'Access denied' }, 403);
  }

  // Read via boundary
  const resources = await phiBoundary.read({
    resource: 'resource',
    query: { tenant_id: tenantId },
    requestedFields: ['id', 'name', 'status', 'phi_field'],  // Specify ALL fields
    userId
  });

  // Audit
  await auditLogger.log({
    action: 'RESOURCE_LIST',
    resource_type: 'resource',
    success: true,
    phi_accessed: true,
    phi_fields: resources.accessedFields,
    record_count: resources.data.length
  });

  return c.json(resources.data);
});
```

---

### Pattern 2: Get Single Resource (GET /api/resource/:id)

```typescript
router.get('/:id', async (c) => {
  const id = c.req.param('id');
  const auditLogger = c.get('auditLogger');
  const phiBoundary = c.get('phiBoundary');
  const rbacManager = c.get('rbacManager');
  const userId = c.get('userId');
  const tenantId = c.get('tenantId');

  // Check permission
  const access = await rbacManager.checkAccess(userId, 'resource', 'read', tenantId);
  if (!access.allowed) {
    await auditLogger.log({
      action: 'RESOURCE_READ_DENIED',
      resource_type: 'resource',
      resource_id: id,
      success: false,
      phi_accessed: false
    });
    return c.json({ error: 'Access denied' }, 403);
  }

  // Read single record
  const resource = await phiBoundary.read({
    resource: 'resource',
    query: { id, tenant_id: tenantId },
    requestedFields: ['id', 'name', 'phi_field_1', 'phi_field_2'],
    userId,
    expectSingle: true  // Returns single object, not array
  });

  if (!resource.data) {
    await auditLogger.log({
      action: 'RESOURCE_NOT_FOUND',
      resource_type: 'resource',
      resource_id: id,
      success: false,
      phi_accessed: false
    });
    return c.json({ error: 'Not found' }, 404);
  }

  // Audit
  await auditLogger.log({
    action: 'RESOURCE_READ',
    resource_type: 'resource',
    resource_id: id,
    success: true,
    phi_accessed: true,
    phi_fields: resource.accessedFields
  });

  return c.json(resource.data);
});
```

---

### Pattern 3: Create Resource (POST /api/resource)

```typescript
router.post('/', async (c) => {
  const auditLogger = c.get('auditLogger');
  const phiBoundary = c.get('phiBoundary');
  const rbacManager = c.get('rbacManager');
  const userId = c.get('userId');
  const tenantId = c.get('tenantId');

  // Check permission
  const access = await rbacManager.checkAccess(userId, 'resource', 'create', tenantId);
  if (!access.allowed) {
    await auditLogger.log({
      action: 'RESOURCE_CREATE_DENIED',
      resource_type: 'resource',
      success: false,
      phi_accessed: false
    });
    return c.json({ error: 'Access denied' }, 403);
  }

  // Get input
  const data = await c.req.json();

  // Validate input
  if (!data.name || !data.phi_field) {
    return c.json({ error: 'Missing required fields' }, 400);
  }

  // Write via boundary (auto-encrypts PHI fields)
  const created = await phiBoundary.write({
    resource: 'resource',
    data: {
      id: crypto.randomUUID(),
      tenant_id: tenantId,
      created_by: userId,
      created_at: Math.floor(Date.now() / 1000),
      ...data
    },
    userId
  });

  // Audit
  await auditLogger.log({
    action: 'RESOURCE_CREATE',
    resource_type: 'resource',
    resource_id: created.id,
    success: true,
    phi_accessed: true,
    phi_fields: ['name', 'phi_field']  // List which fields contain PHI
  });

  return c.json(created, 201);
});
```

---

### Pattern 4: Update Resource (PUT /api/resource/:id)

```typescript
router.put('/:id', async (c) => {
  const id = c.req.param('id');
  const auditLogger = c.get('auditLogger');
  const phiBoundary = c.get('phiBoundary');
  const rbacManager = c.get('rbacManager');
  const userId = c.get('userId');
  const tenantId = c.get('tenantId');

  // Check permission
  const access = await rbacManager.checkAccess(userId, 'resource', 'update', tenantId);
  if (!access.allowed) {
    await auditLogger.log({
      action: 'RESOURCE_UPDATE_DENIED',
      resource_type: 'resource',
      resource_id: id,
      success: false,
      phi_accessed: false
    });
    return c.json({ error: 'Access denied' }, 403);
  }

  // Get input
  const updates = await c.req.json();

  // Check resource exists
  const existing = await phiBoundary.read({
    resource: 'resource',
    query: { id, tenant_id: tenantId },
    requestedFields: ['id'],
    userId,
    expectSingle: true
  });

  if (!existing.data) {
    return c.json({ error: 'Not found' }, 404);
  }

  // Update via boundary
  const updated = await phiBoundary.write({
    resource: 'resource',
    data: {
      ...updates,
      updated_at: Math.floor(Date.now() / 1000),
      updated_by: userId
    },
    query: { id, tenant_id: tenantId },  // WHERE clause
    userId,
    operation: 'update'
  });

  // Audit
  await auditLogger.log({
    action: 'RESOURCE_UPDATE',
    resource_type: 'resource',
    resource_id: id,
    success: true,
    phi_accessed: true,
    phi_fields: Object.keys(updates),
    changes: updates  // Optional: log what changed
  });

  return c.json(updated);
});
```

---

### Pattern 5: Delete Resource (DELETE /api/resource/:id)

```typescript
router.delete('/:id', async (c) => {
  const id = c.req.param('id');
  const auditLogger = c.get('auditLogger');
  const phiBoundary = c.get('phiBoundary');
  const rbacManager = c.get('rbacManager');
  const userId = c.get('userId');
  const tenantId = c.get('tenantId');

  // Check permission
  const access = await rbacManager.checkAccess(userId, 'resource', 'delete', tenantId);
  if (!access.allowed) {
    await auditLogger.log({
      action: 'RESOURCE_DELETE_DENIED',
      resource_type: 'resource',
      resource_id: id,
      success: false,
      phi_accessed: false
    });
    return c.json({ error: 'Access denied' }, 403);
  }

  // Read first (for audit purposes - know what we're deleting)
  const existing = await phiBoundary.read({
    resource: 'resource',
    query: { id, tenant_id: tenantId },
    requestedFields: ['id', 'name'],
    userId,
    expectSingle: true
  });

  if (!existing.data) {
    return c.json({ error: 'Not found' }, 404);
  }

  // Delete (direct DB - no encryption needed for deletion)
  await c.env.DB.prepare(`
    DELETE FROM resources
    WHERE id = ? AND tenant_id = ?
  `).bind(id, tenantId).run();

  // Audit
  await auditLogger.log({
    action: 'RESOURCE_DELETE',
    resource_type: 'resource',
    resource_id: id,
    success: true,
    phi_accessed: true,
    phi_fields: ['name'],
    deleted_data: existing.data  // Optional: log what was deleted
  });

  return c.json({ success: true });
});
```

---

## PHI Field Identification

### Common PHI Fields by Route

#### Assessments (`/api/assessments`)
- `client_id` - Indirect patient identifier
- `responses` - Patient answers (symptoms, history)
- `results` - Assessment outcomes (diagnosis codes)
- `score` - Health assessment score
- `notes` - Clinician notes

#### Clients (`/api/clients`)
- `name` - Patient name (direct identifier)
- `email` - Contact info
- `phone` - Contact info
- `ssn` - Direct identifier
- `date_of_birth` - Indirect identifier
- `address` - Location PII
- `medical_record_number` - Direct identifier

#### Documents (`/api/documents`)
- `filename` - May contain patient names/SSN/DOB
- `description` - May contain diagnosis/treatment
- `tags` - May be PHI categories (e.g., "MRI-2024-01-15")
- `r2_key` - Derives from filename

#### Time Entries (`/api/timeEntries`)
- `client_id` - Indirect identifier
- `notes` - Service details, progress notes
- `service_type` - Treatment/therapy type
- `diagnosis_codes` - Diagnostic codes

---

## Checklist for Each Route

When migrating a route, ensure:

### 1. Remove Old Imports
```typescript
// ❌ Remove these
import { auditLogger } from '../utils/audit';
import { requirePermission, createSecurityContext } from '../utils/security';
```

### 2. Use Context Components
```typescript
// ✅ Add these
const auditLogger = c.get('auditLogger');
const phiBoundary = c.get('phiBoundary');
const rbacManager = c.get('rbacManager');
const userId = c.get('userId');
const tenantId = c.get('tenantId');
```

### 3. Check RBAC First
```typescript
const access = await rbacManager.checkAccess(userId, 'resource', 'action', tenantId);
if (!access.allowed) {
  await auditLogger.log({ action: 'DENIED', success: false, phi_accessed: false });
  return c.json({ error: 'Access denied' }, 403);
}
```

### 4. Use PHI Boundary for Data Access
```typescript
// ❌ Don't do this
const result = await c.env.DB.prepare('SELECT * FROM table').all();

// ✅ Do this
const result = await phiBoundary.read({
  resource: 'resource',
  query: { tenant_id: tenantId },
  requestedFields: ['field1', 'field2'],
  userId
});
```

### 5. Audit Every Operation
```typescript
await auditLogger.log({
  action: 'RESOURCE_ACTION',      // UPPERCASE_SNAKE_CASE
  resource_type: 'resource',       // lowercase
  resource_id: id || null,         // null for list operations
  success: true,                   // false for errors
  phi_accessed: true,              // false if no PHI read/written
  phi_fields: ['field1', 'field2'], // which PHI fields touched
  record_count: data.length        // for list operations
});
```

### 6. Register PHI Route
```typescript
// In src/middleware/phi-route-guard.ts
export const PHI_BEARING_ROUTES = {
  '/api/resource': {
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    phiFields: ['field1', 'field2'],
    requiresSession: true
  }
};
```

### 7. Write Tests
```typescript
describe('Resource Route (HIPAA)', () => {
  it('uses immutable audit logger', async () => {
    const auditSpy = vi.fn();
    c.set('auditLogger', { log: auditSpy });
    await handler(c);
    expect(auditSpy).toHaveBeenCalled();
  });

  it('uses PHI boundary', async () => {
    const boundarySpy = vi.fn();
    c.set('phiBoundary', { read: boundarySpy });
    await handler(c);
    expect(boundarySpy).toHaveBeenCalled();
  });

  it('checks RBAC', async () => {
    const rbacSpy = vi.fn().mockResolvedValue({ allowed: false });
    c.set('rbacManager', { checkAccess: rbacSpy });
    const response = await handler(c);
    expect(response.status).toBe(403);
  });
});
```

---

## Error Handling

### Pattern: Audit All Errors

```typescript
router.get('/:id', async (c) => {
  const auditLogger = c.get('auditLogger');
  const id = c.req.param('id');

  try {
    // ... normal logic
  } catch (error) {
    // Always audit errors
    await auditLogger.log({
      action: 'RESOURCE_READ_ERROR',
      resource_type: 'resource',
      resource_id: id,
      success: false,
      phi_accessed: false,
      failure_reason: error.message,
      error_stack: error.stack  // Optional: for debugging
    });

    console.error('Resource read error:', error);
    return c.json({ error: 'Internal server error' }, 500);
  }
});
```

---

## Performance Tips

### 1. Cache Decrypted PHI Within Request
```typescript
// ❌ Don't decrypt multiple times
const resource1 = await phiBoundary.read({ resource: 'r', query: { id: '1' } });
const resource2 = await phiBoundary.read({ resource: 'r', query: { id: '1' } });  // Decrypts again!

// ✅ Decrypt once, reuse
const resource = await phiBoundary.read({ resource: 'r', query: { id: '1' } });
c.set('cachedResource', resource);  // Store in context
// ... later in request
const cached = c.get('cachedResource');  // Reuse
```

### 2. Batch Read Operations
```typescript
// ❌ Don't read one-by-one
for (const id of ids) {
  const resource = await phiBoundary.read({ resource: 'r', query: { id } });
}

// ✅ Batch read
const resources = await phiBoundary.read({
  resource: 'r',
  query: { id: { $in: ids } },  // Use SQL IN clause
  requestedFields: ['id', 'name'],
  userId
});
```

### 3. Request Only Needed Fields
```typescript
// ❌ Don't request all fields
const resources = await phiBoundary.read({
  resource: 'r',
  query: { tenant_id: tenantId },
  requestedFields: ['*'],  // Decrypts everything!
  userId
});

// ✅ Request specific fields
const resources = await phiBoundary.read({
  resource: 'r',
  query: { tenant_id: tenantId },
  requestedFields: ['id', 'name', 'status'],  // Only what you need
  userId
});
```

---

## Common Mistakes

### ❌ Mistake 1: Forgetting to Audit Denials
```typescript
// ❌ Wrong
const access = await rbacManager.checkAccess(...);
if (!access.allowed) {
  return c.json({ error: 'Access denied' }, 403);  // No audit!
}

// ✅ Correct
const access = await rbacManager.checkAccess(...);
if (!access.allowed) {
  await auditLogger.log({
    action: 'ACCESS_DENIED',
    success: false,
    phi_accessed: false
  });
  return c.json({ error: 'Access denied' }, 403);
}
```

### ❌ Mistake 2: Direct DB Queries for PHI
```typescript
// ❌ Wrong
const client = await c.env.DB.prepare(`
  SELECT name, ssn, dob FROM clients WHERE id = ?
`).bind(id).first();  // Returns plaintext PHI!

// ✅ Correct
const client = await phiBoundary.read({
  resource: 'client',
  query: { id },
  requestedFields: ['name', 'ssn', 'dob'],
  userId
});  // Auto-decrypts, checks RBAC, audits
```

### ❌ Mistake 3: Not Listing PHI Fields
```typescript
// ❌ Wrong
await auditLogger.log({
  action: 'CLIENT_READ',
  success: true,
  phi_accessed: true
  // Missing: phi_fields
});

// ✅ Correct
await auditLogger.log({
  action: 'CLIENT_READ',
  success: true,
  phi_accessed: true,
  phi_fields: ['name', 'ssn', 'dob']  // List which PHI accessed
});
```

### ❌ Mistake 4: Mixing Old and New Stack
```typescript
// ❌ Wrong
import { auditLogger } from '../utils/audit';  // Old stack

router.get('/', async (c) => {
  const phiBoundary = c.get('phiBoundary');  // New stack
  // ...
  await auditLogger(c.env, { ... });  // Old audit logger!
});

// ✅ Correct
// Don't import anything
router.get('/', async (c) => {
  const auditLogger = c.get('auditLogger');  // New stack
  const phiBoundary = c.get('phiBoundary');  // New stack
  // ...
  await auditLogger.log({ ... });  // New audit logger!
});
```

---

## Questions?

**Migration issues?** See `ROUTE_MIGRATION_PLAN.md`

**Architecture questions?** See `HIPAA_ACCURATE_STATUS.md`

**Security review?** Contact security team

**PHI classification unclear?** When in doubt, treat as PHI and encrypt

---

**Last Updated**: January 2026
**Maintained By**: Security Team
**Next Review**: After Phase 1 migration complete
