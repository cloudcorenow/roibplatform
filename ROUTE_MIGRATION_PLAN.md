# Route Migration Plan: OLD → NEW HIPAA Stack

**Status**: 🔴 **CRITICAL GAP IDENTIFIED**
**Priority**: P0 (Blocking HIPAA compliance)

---

## Problem Statement

All business routes currently use the **OLD security stack** instead of the **NEW HIPAA-compliant stack**:

### OLD Stack (Currently Used)
- `auditLogger` from `src/utils/audit.ts` → audit_log table (KV, not immutable)
- `requirePermission` / `createSecurityContext` from `src/utils/security.ts` → Basic permission checks
- Direct DB queries → No PHI encryption, no field-level controls
- No tamper-evident audit chain

### NEW Stack (Built But Not Used)
- `c.get('auditLogger')` from `initializeHIPAASecurity()` → audit_logs + audit_chain (immutable)
- `c.get('rbacManager')` → HIPAA-aware RBAC with field-level controls
- `c.get('phiBoundary')` → Encrypted PHI storage + read/write controls
- `c.get('sessionManager')` → Session validation with timeouts

---

## Impact Analysis

### Current Risk Level: 🔴 HIGH

| Route | Uses OLD Stack | PHI Exposed | Audit Gap | Encryption Gap |
|-------|----------------|-------------|-----------|----------------|
| `/api/assessments` | ✅ | ✅ responses, results, client_id | ✅ No audit | ✅ Not encrypted |
| `/api/documents` | ✅ | ✅ filename, tags, r2_key | ✅ KV audit only | ✅ Metadata not encrypted |
| `/api/timeEntries` | ✅ | ⚠️ client_id, notes | ✅ No audit | ✅ Not encrypted |
| `/api/clients` | ✅ | ✅ name, email, phone | ✅ No audit | ✅ Not encrypted |
| `/api/users` | ✅ | ✅ email, name, role | ✅ KV audit only | ✅ Not encrypted |

**Verdict**: **PHI is being stored, transmitted, and audited without HIPAA controls.**

---

## Migration Strategy

### Phase 1: Core PHI Routes (P0)
**Deadline**: Before any PHI touches production

#### 1.1 `/api/assessments` (HIGHEST RISK)
**Current State**:
```typescript
// src/routes/assessments.ts
import { auditLogger } from '../utils/audit';  // ❌

router.get('/', async (c) => {
  const result = await c.env.DB.prepare(`
    SELECT responses, results, client_id FROM assessments
  `).all();  // ❌ Returns unencrypted PHI

  return c.json(result.results);  // ❌ No audit, no RBAC
});
```

**Required Changes**:
```typescript
// src/routes/assessments.ts
router.get('/', async (c) => {
  const auditLogger = c.get('auditLogger');      // ✅ Immutable audit
  const phiBoundary = c.get('phiBoundary');      // ✅ PHI encryption
  const rbacManager = c.get('rbacManager');      // ✅ Field-level RBAC
  const userId = c.get('userId');
  const tenantId = c.get('tenantId');

  // Check permission
  const hasAccess = await rbacManager.checkAccess(
    userId,
    'assessment',
    'read',
    tenantId
  );

  if (!hasAccess.allowed) {
    await auditLogger.log({
      action: 'ASSESSMENT_READ_DENIED',
      resource_type: 'assessment',
      success: false,
      phi_accessed: false
    });
    return c.json({ error: 'Access denied' }, 403);
  }

  // Read assessments via PHI boundary
  const assessments = await phiBoundary.read({
    resource: 'assessment',
    query: { tenant_id: tenantId },
    requestedFields: ['id', 'client_id', 'responses', 'results', 'score'],
    userId
  });

  // Audit successful access
  await auditLogger.log({
    action: 'ASSESSMENT_READ',
    resource_type: 'assessment',
    resource_id: null,
    success: true,
    phi_accessed: true,
    phi_fields: assessments.accessedFields
  });

  return c.json(assessments.data);
});
```

**Files to Modify**:
- `src/routes/assessments.ts` (all endpoints)

**PHI Fields**:
- `client_id` (indirect identifier)
- `responses` (may contain patient info)
- `results` (diagnostic/treatment data)
- `score` (health assessment)

---

#### 1.2 `/api/clients` (HIGH RISK)
**Current State**:
```typescript
// Likely direct DB queries returning name, email, phone, ssn
```

**Required Changes**:
- Use `phiBoundary.read()` for ALL client data
- Use `phiBoundary.write()` for client creation/updates
- Field-level encryption for: name, email, phone, ssn, address, dob
- Immutable audit for every access

**PHI Fields**:
- `name` (patient identifier)
- `email` (contact PII)
- `phone` (contact PII)
- `ssn` (direct identifier - if stored)
- `date_of_birth` (indirect identifier)
- `address` (location PII)

---

#### 1.3 `/api/documents` (MEDIUM-HIGH RISK)
**Current State**:
```typescript
import { auditLogger } from '../utils/audit';  // ❌
import { requirePermission, createSecurityContext } from '../utils/security';  // ❌

const securityContext = createSecurityContext(c);
requirePermission(securityContext, 'documents:create');  // ❌ Old RBAC
```

**Required Changes**:
```typescript
const auditLogger = c.get('auditLogger');
const phiBoundary = c.get('phiBoundary');
const rbacManager = c.get('rbacManager');

// Check access via new RBAC
const access = await rbacManager.checkAccess(
  userId,
  'document',
  'create',
  tenantId
);

// Encrypt document metadata
const encryptedMetadata = await phiBoundary.write({
  resource: 'document',
  data: {
    filename: file.name,  // May contain patient names
    description,
    tags,
    category
  },
  userId
});

// Audit with immutable chain
await auditLogger.log({
  action: 'DOCUMENT_UPLOAD',
  resource_type: 'document',
  resource_id: fileId,
  success: true,
  phi_accessed: true,
  phi_fields: ['filename', 'description', 'tags']
});
```

**PHI Fields**:
- `filename` (may contain patient names, SSN, DOB)
- `description` (may contain diagnosis, treatment info)
- `tags` (may be PHI categories)
- `r2_key` (derives from filename)

---

#### 1.4 `/api/timeEntries` (MEDIUM RISK)
**PHI Fields**:
- `client_id` (indirect identifier)
- `notes` (may contain service details, health info)
- `service_type` (treatment type)

**Required Changes**:
- Use `phiBoundary.read/write()` for all operations
- Encrypt `notes` field
- Audit all access to client-linked time entries

---

### Phase 2: User Routes (P1)
**Deadline**: Before multi-tenant production

#### 2.1 `/api/users`
**Current Risk**: Email, name, role exposed without HIPAA controls

**Required Changes**:
- Use immutable audit logger for user CRUD
- Consider PII encryption for email/name
- Use new RBAC for user management permissions

---

### Phase 3: Integration Routes (P2)
**Deadline**: Before enabling integrations

#### 3.1 `/api/centralreach`
- External API calls must be audited via immutable logger
- PHI transmitted externally requires special audit markers
- Validate PHI encryption before sending

#### 3.2 `/api/quickbooks`
- Financial data may contain client names (PHI)
- Use phiBoundary for invoice/expense descriptions
- Audit all external transmissions

---

## Implementation Checklist

### Step 1: Create PHI Boundary Wrappers
```typescript
// src/utils/phi-db-helpers.ts

export async function readAssessments(
  c: Context,
  filters: { tenant_id: string; user_id?: string }
) {
  const phiBoundary = c.get('phiBoundary');
  const userId = c.get('userId');

  return await phiBoundary.read({
    resource: 'assessment',
    query: filters,
    requestedFields: ['id', 'client_id', 'responses', 'results', 'score'],
    userId
  });
}

export async function writeAssessment(
  c: Context,
  data: AssessmentData
) {
  const phiBoundary = c.get('phiBoundary');
  const userId = c.get('userId');

  return await phiBoundary.write({
    resource: 'assessment',
    data,
    userId
  });
}
```

### Step 2: Update Route Imports
```diff
// src/routes/assessments.ts
- import { auditLogger } from '../utils/audit';
+ // No imports needed - use c.get('auditLogger')

// src/routes/documents.ts
- import { auditLogger } from '../utils/audit';
- import { requirePermission, createSecurityContext } from '../utils/security';
+ // No imports needed - use context
```

### Step 3: Update Route Handlers (Example)
```typescript
// BEFORE
router.get('/', async (c) => {
  const result = await c.env.DB.prepare('SELECT * FROM assessments').all();
  return c.json(result.results);
});

// AFTER
router.get('/', async (c) => {
  const auditLogger = c.get('auditLogger');
  const phiBoundary = c.get('phiBoundary');
  const rbacManager = c.get('rbacManager');
  const userId = c.get('userId');
  const tenantId = c.get('tenantId');

  // RBAC check
  const access = await rbacManager.checkAccess(userId, 'assessment', 'read', tenantId);
  if (!access.allowed) {
    await auditLogger.log({
      action: 'ASSESSMENT_READ_DENIED',
      resource_type: 'assessment',
      success: false,
      phi_accessed: false
    });
    return c.json({ error: 'Access denied' }, 403);
  }

  // Read via PHI boundary
  const assessments = await phiBoundary.read({
    resource: 'assessment',
    query: { tenant_id: tenantId },
    requestedFields: ['id', 'client_id', 'responses', 'results'],
    userId
  });

  // Audit success
  await auditLogger.log({
    action: 'ASSESSMENT_READ',
    resource_type: 'assessment',
    success: true,
    phi_accessed: true,
    phi_fields: assessments.accessedFields
  });

  return c.json(assessments.data);
});
```

### Step 4: Remove OLD Stack Files (After Migration)
**DO NOT DELETE YET** - Keep until all routes migrated
- `src/utils/audit.ts` (legacy audit_log)
- `src/utils/security.ts` (old requirePermission)

Mark as deprecated:
```typescript
// src/utils/audit.ts
/**
 * @deprecated Use c.get('auditLogger') from initializeHIPAASecurity() instead
 * This legacy audit system does not provide:
 * - Immutable audit chains
 * - Tamper-evident logging
 * - HIPAA-compliant audit trail
 */
export async function auditLogger(...) {
  console.error('DEPRECATED: Use c.get("auditLogger") from HIPAA context');
  // ...
}
```

---

## Testing Requirements

### Unit Tests Required
```typescript
// src/routes/__tests__/assessments.hipaa.test.ts

describe('Assessments Route (HIPAA Compliant)', () => {
  it('should use immutable audit logger', async () => {
    const auditSpy = vi.fn();
    c.set('auditLogger', { log: auditSpy });

    await router.fetch(request);

    expect(auditSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'ASSESSMENT_READ',
        phi_accessed: true
      })
    );
  });

  it('should use PHI boundary for reads', async () => {
    const boundaryReadSpy = vi.fn();
    c.set('phiBoundary', { read: boundaryReadSpy });

    await router.fetch(request);

    expect(boundaryReadSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        resource: 'assessment',
        requestedFields: expect.arrayContaining(['responses', 'results'])
      })
    );
  });

  it('should encrypt PHI fields before storage', async () => {
    const boundaryWriteSpy = vi.fn();
    c.set('phiBoundary', { write: boundaryWriteSpy });

    await router.fetch(createRequest);

    expect(boundaryWriteSpy).toHaveBeenCalled();
  });

  it('should fail without session', async () => {
    const response = await router.fetch(requestWithoutSession);
    expect(response.status).toBe(401);
  });
});
```

### Integration Tests Required
```typescript
// e2e/hipaa-compliance.test.ts

describe('End-to-End HIPAA Compliance', () => {
  it('should write to audit_chain for PHI access', async () => {
    await loginAndAccessAssessment();

    const auditChain = await db.prepare(
      'SELECT * FROM audit_chain ORDER BY created_at DESC LIMIT 1'
    ).first();

    expect(auditChain).toBeDefined();
    expect(auditChain.current_hash).toBeTruthy();
    expect(auditChain.previous_hash).toBeTruthy();
  });

  it('should store PHI fields encrypted', async () => {
    await createAssessment({ responses: { q1: 'patient data' } });

    const raw = await db.prepare(
      'SELECT responses FROM assessments WHERE id = ?'
    ).bind(assessmentId).first();

    // Should NOT be plaintext
    expect(raw.responses).not.toContain('patient data');
    expect(raw.responses).toMatch(/^encrypted:/);
  });

  it('should enforce field-level RBAC', async () => {
    const limitedUser = await loginAsLimitedUser();

    const response = await fetch('/api/assessments', {
      headers: { Authorization: `Bearer ${limitedUser.token}` }
    });

    const data = await response.json();

    // Should only return non-PHI fields
    expect(data[0]).not.toHaveProperty('responses');
    expect(data[0]).toHaveProperty('id');
    expect(data[0]).toHaveProperty('score');
  });
});
```

---

## Rollout Plan

### Week 1: Assessment Routes
- [ ] Day 1-2: Implement `readAssessments()` / `writeAssessment()` helpers
- [ ] Day 3-4: Migrate all 5 assessment endpoints
- [ ] Day 5: Write unit tests, integration tests
- [ ] Day 6-7: Code review, security audit

### Week 2: Client + Document Routes
- [ ] Day 1-3: Migrate `/api/clients` (highest PHI concentration)
- [ ] Day 4-5: Migrate `/api/documents`
- [ ] Day 6-7: Testing + audit

### Week 3: Time Entries + Users
- [ ] Day 1-3: Migrate `/api/timeEntries`
- [ ] Day 4-5: Migrate `/api/users`
- [ ] Day 6-7: Full regression testing

### Week 4: Integrations + Cleanup
- [ ] Day 1-2: Migrate `/api/centralreach`
- [ ] Day 3-4: Migrate `/api/quickbooks`
- [ ] Day 5: Deprecate old stack
- [ ] Day 6-7: Final security audit

---

## Risk Mitigation

### Backwards Compatibility
**Problem**: Existing encrypted data may use different keys/formats

**Solution**:
- Implement fallback decryption in phiBoundary
- Gradual migration with dual-read support
- Mark records with `encryption_version` column

### Performance Impact
**Problem**: PHI boundary adds encryption/decryption overhead

**Solution**:
- Cache decrypted results within request context
- Use batch operations for bulk reads
- Monitor query performance with alerts

### Audit Volume
**Problem**: Immutable audit chain grows quickly

**Solution**:
- Implement audit log rotation (90-day retention)
- Archive to cold storage after 90 days
- Monitor disk usage

---

## Success Criteria

### Before Migration (Current State)
- ❌ PHI stored in plaintext
- ❌ Audit logs use KV (mutable, losable)
- ❌ No field-level RBAC
- ❌ No tamper-evident chain
- ❌ Session validation bypassed
- **Compliance Score: 3/10**

### After Migration (Target State)
- ✅ All PHI encrypted at rest via phiBoundary
- ✅ Immutable audit_logs + audit_chain for ALL PHI access
- ✅ Field-level RBAC enforced on every request
- ✅ Tamper-evident hash chain validated
- ✅ Session validation enforced on PHI routes
- **Compliance Score: 9/10**

---

## Compliance Documentation

### For Auditors

**Question**: "How do you ensure PHI is protected?"

**Before**: "We have encryption helpers and permission checks." (Weak)

**After**: "All PHI routes use a centralized PHI boundary that:
1. Enforces field-level RBAC before any access
2. Encrypts all PHI fields using AES-256-GCM with envelope encryption
3. Logs every access to an immutable, tamper-evident audit chain
4. Validates sessions with idle/absolute timeouts
5. Fails closed if any security component is missing"

**Evidence**:
- `src/utils/phi-boundary.ts` (PHI access control)
- `src/utils/audit-logger.ts` (immutable audit)
- `src/middleware/hipaa-security.ts` (centralized initialization)
- `src/middleware/phi-route-guard.ts` (fail-closed enforcement)
- Test coverage showing routes use HIPAA stack

---

## Open Questions

1. **Encryption Key Rotation**: When should we rotate DEKs for existing encrypted PHI?
   - Recommendation: Every 90 days for active records

2. **Audit Retention**: How long to keep audit_chain records?
   - HIPAA minimum: 6 years
   - Recommendation: 7 years (to account for late audits)

3. **Performance SLA**: What's acceptable latency for PHI access?
   - Current: ~50ms average
   - Target: <100ms p95 after migration

4. **Backward Compatibility**: Support legacy encrypted data for how long?
   - Recommendation: 1 year transition period with dual-read

---

## Conclusion

**Current State**: Infrastructure exists but routes don't use it = **NOT HIPAA COMPLIANT**

**Target State**: All PHI routes use HIPAA stack = **PRODUCTION READY**

**Effort Estimate**: 4 weeks full-time for complete migration + testing

**Risk Level if Deployed Today**: 🔴 **CRITICAL** - PHI exposure without proper controls

---

**Document Version**: 1.0
**Author**: Security Audit
**Date**: January 2026
**Status**: Migration Plan Approved, Implementation Pending
