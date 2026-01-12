# HIPAA Key Rotation Procedures

## Overview

The application uses **envelope encryption** with automatic backward compatibility for rotated keys. When keys are rotated, old keys are retained (marked as `rotated`) to decrypt historical data while new data uses the new key.

## Key Architecture

```
Master Encryption Key (MEK)
  └─> Data Encryption Keys (DEKs) - One per tenant
      └─> PHI Data (encrypted with active DEK)

MEK: Environment variable (MASTER_ENCRYPTION_KEY)
DEKs: Stored encrypted in database (data_encryption_keys table)
```

### Key Lifecycle States

1. **active** - Current key for encrypting new data
2. **rotated** - Previous key retained for decrypting old data
3. **compromised** - Key suspected of breach, cannot be used

## Backward Decryption Support

**How it works:**

1. Every encrypted field stores `dekId` with the ciphertext
2. When decrypting, system looks up the DEK by ID
3. Works for any status: `active` OR `rotated`
4. Only `compromised` keys are blocked

**Example encrypted data:**
```json
{
  "ciphertext": "base64...",
  "iv": "base64...",
  "tag": "base64...",
  "dekId": "dek-123",
  "algorithm": "AES-GCM-256"
}
```

When rotating keys:
- New data encrypts with `dek-456` (active)
- Old data decrypts with `dek-123` (rotated)
- No re-encryption required immediately

## Rotation Procedures

### 1. Scheduled Rotation (Annual/Quarterly)

**Trigger**: Compliance policy (e.g., rotate every 90 days)

**Steps:**

```typescript
// Backend code (admin route)
const envelope = c.get('envelopeEncryption');

const result = await envelope.rotateDEK(
  tenantId,
  userId,
  'Scheduled annual rotation per HIPAA policy'
);

console.log(`Rotated to new DEK: ${result.newDekId}`);
```

**What happens:**
1. New DEK created with incremented version
2. Old DEK marked as `rotated` in database
3. Rotation logged in `key_rotation_logs`
4. New data uses new DEK immediately
5. Old data continues to decrypt with old DEK

**No downtime required** - keys rotate seamlessly

---

### 2. Emergency Rotation (Suspected Compromise)

**Trigger**: Security incident, leaked credentials, audit finding

**Steps:**

```typescript
// 1. Mark compromised key
await envelope.markDEKCompromised(
  compromisedDekId,
  'Suspected exposure in security incident #1234'
);

// 2. Rotate to new key
const result = await envelope.rotateDEK(
  tenantId,
  userId,
  'Emergency rotation due to security incident'
);

// 3. Re-encrypt all data with new key (critical)
await reencryptAllTenantData(tenantId, result.newDekId);
```

**What happens:**
1. Compromised DEK cannot decrypt anymore (throws error)
2. New DEK created
3. **MUST re-encrypt all data** to eliminate compromise risk
4. Logged in `key_compromise_logs`

**Requires immediate action** - data cannot be accessed until re-encrypted

---

### 3. Background Re-encryption (Optional Optimization)

**Purpose**: Clean up rotated keys, reduce key sprawl

**When**: After scheduled rotation, during low-traffic period

**Steps:**

```typescript
// Find all records encrypted with old DEK
const oldRecords = await db.prepare(
  `SELECT id, encrypted_field FROM my_table
   WHERE encrypted_field LIKE '%"dekId":"${oldDekId}"%'`
).all();

let reencrypted = 0;

for (const record of oldRecords.results) {
  const oldEncrypted = JSON.parse(record.encrypted_field);

  const newEncrypted = await envelope.reencryptWithNewDEK(oldEncrypted);

  await db.prepare(
    `UPDATE my_table SET encrypted_field = ? WHERE id = ?`
  ).bind(JSON.stringify(newEncrypted), record.id).run();

  reencrypted++;
}

// Update rotation log
await db.prepare(
  `UPDATE key_rotation_logs
   SET records_reencrypted = ?
   WHERE new_dek_id = ?`
).bind(reencrypted, newDekId).run();
```

**What happens:**
1. Each record decrypted with old DEK
2. Re-encrypted with new active DEK
3. Database updated with new ciphertext
4. Counter updated in rotation log

**Optional but recommended** for:
- Compliance requirements (some policies require re-encryption)
- Performance (fewer DEKs to manage)
- Security posture (minimize window of old key usage)

---

## Master Key Rotation

**More complex** - requires re-encrypting ALL DEKs

### Procedure

1. **Generate new master key:**
```bash
openssl rand -base64 32
```

2. **Store as `MASTER_ENCRYPTION_KEY_NEW`** in environment

3. **Run migration script:**
```typescript
const oldMEK = env.MASTER_ENCRYPTION_KEY;
const newMEK = env.MASTER_ENCRYPTION_KEY_NEW;

const allDEKs = await db.prepare(
  `SELECT id, encrypted_key FROM data_encryption_keys`
).all();

for (const dek of allDEKs.results) {
  // Decrypt with old MEK
  const plainDEK = await decryptWithMasterKey(dek.encrypted_key, oldMEK);

  // Re-encrypt with new MEK
  const newEncrypted = await encryptWithMasterKey(plainDEK, newMEK);

  // Update database
  await db.prepare(
    `UPDATE data_encryption_keys SET encrypted_key = ? WHERE id = ?`
  ).bind(newEncrypted, dek.id).run();
}

// Log master key rotation
await db.prepare(
  `INSERT INTO master_key_rotation_log (rotated_by, reason, deks_reencrypted, created_at)
   VALUES (?, ?, ?, ?)`
).bind(userId, 'Annual master key rotation', allDEKs.results.length, now()).run();
```

4. **Update environment to use new MEK:**
```bash
MASTER_ENCRYPTION_KEY=<new-key>
```

5. **Delete old MEK** from secure storage

**Requires maintenance window** - 5-15 minutes depending on DEK count

---

## Rotation Schedule (HIPAA Recommendations)

| Key Type | Rotation Frequency | Rationale |
|----------|-------------------|-----------|
| Master Encryption Key (MEK) | Annually | NIST SP 800-57 guidance for key-encrypting keys |
| Data Encryption Keys (DEK) | Quarterly or annually | Balance security and operational complexity |
| After suspected compromise | Immediately | Incident response requirement |
| After privileged user departure | Within 24 hours | Access control requirement |

---

## Monitoring & Alerting

### Key Metrics to Track

```sql
-- DEK age by tenant
SELECT
  tenant_id,
  status,
  MAX(created_at) as newest_key,
  MIN(created_at) as oldest_key,
  CAST((unixepoch() - MIN(created_at)) / 86400 AS INTEGER) as oldest_key_age_days
FROM data_encryption_keys
GROUP BY tenant_id, status;

-- Rotation history
SELECT
  COUNT(*) as rotations,
  MIN(created_at) as first_rotation,
  MAX(created_at) as last_rotation
FROM key_rotation_logs;

-- Compromised keys (should be 0)
SELECT COUNT(*)
FROM data_encryption_keys
WHERE status = 'compromised';
```

### Alerts to Configure

1. **DEK older than 90 days** → Schedule rotation
2. **Compromised DEK detected** → Emergency rotation + incident response
3. **Rotation failure** → Investigate immediately
4. **Master key access spike** → Potential breach investigation

---

## Access Control

### Who Can Rotate Keys?

**Required role**: `platform_admin` (highest privilege)

**Audit requirements**:
- All key operations logged in `master_key_access_log`
- Multi-person approval for master key rotation
- Separation of duties (different person validates rotation)

**Implementation:**

```typescript
app.post('/api/admin/rotate-dek', async (c) => {
  const rbac = c.get('rbacManager');
  const userId = c.get('userId');
  const tenantId = c.get('tenantId');

  // Check platform_admin role
  if (!await rbac.hasRole(userId, tenantId, 'platform_admin')) {
    return c.json({ error: 'Unauthorized' }, 403);
  }

  const { reason, approvedBy } = await c.req.json();

  // Require approval from different admin
  if (approvedBy === userId) {
    return c.json({
      error: 'Separation of duties violation',
      message: 'Key rotation must be approved by a different admin'
    }, 403);
  }

  const envelope = c.get('envelopeEncryption');
  const result = await envelope.rotateDEK(tenantId, userId, reason);

  await auditLogger.log({
    tenantId,
    userId,
    action: 'KEY_ROTATION',
    resourceType: 'encryption_key',
    resourceId: result.newDekId,
    metadata: { oldDekId: result.oldDekId, approvedBy, reason }
  });

  return c.json(result);
});
```

---

## Testing Key Rotation

### Test 1: Verify Backward Decryption

```typescript
// 1. Encrypt with current key
const encrypted1 = await envelope.encrypt('sensitive data', 'tenant-1');
console.log('DEK v1:', encrypted1.dekId);

// 2. Rotate key
await envelope.rotateDEK('tenant-1', 'admin-1', 'Test rotation');

// 3. Encrypt new data with new key
const encrypted2 = await envelope.encrypt('new sensitive data', 'tenant-1');
console.log('DEK v2:', encrypted2.dekId);

// 4. Verify both can decrypt
const decrypted1 = await envelope.decrypt(encrypted1);
console.log('Old data:', decrypted1); // Should work ✅

const decrypted2 = await envelope.decrypt(encrypted2);
console.log('New data:', decrypted2); // Should work ✅

// 5. Verify rotation logged
const history = await envelope.getKeyRotationHistory('tenant-1');
console.log('Rotations:', history); // Should show 1 rotation ✅
```

### Test 2: Verify Compromised Key Blocks Access

```typescript
// 1. Mark key as compromised
await envelope.markDEKCompromised(encrypted1.dekId, 'Test compromise');

// 2. Attempt decrypt
try {
  await envelope.decrypt(encrypted1);
  console.log('ERROR: Compromised key allowed decrypt ❌');
} catch (e) {
  console.log('Correctly blocked compromised key ✅');
}
```

---

## Disaster Recovery

### Lost Master Key

**Impact**: All DEKs cannot be decrypted → all PHI data inaccessible

**Prevention**:
- Store MEK in multiple secure locations
- Hardware Security Module (HSM) for production
- Encrypted backups with separate key
- Document custodians with access

**Recovery**:
1. Restore MEK from secure backup
2. Validate with test decryption
3. Update environment configuration
4. Run integrity checks on all DEKs

### Compromised Master Key

**Impact**: All DEKs potentially exposed → emergency rotation required

**Response**:
1. Generate new master key immediately
2. Re-encrypt all DEKs (see Master Key Rotation above)
3. Rotate all DEKs for all tenants
4. Consider re-encrypting all PHI data
5. Incident report to compliance team
6. Notify affected parties if required by breach policy

---

## Compliance Checklist

- [ ] Master key stored in secure location (not in code repository)
- [ ] Master key access logged and monitored
- [ ] DEK rotation performed quarterly (or per policy)
- [ ] Rotation logs retained for audit (minimum 7 years for HIPAA)
- [ ] Emergency rotation procedure documented and tested
- [ ] Separation of duties enforced for key operations
- [ ] Key compromise detection and response plan active
- [ ] Backward compatibility tested after each rotation
- [ ] Disaster recovery procedures validated annually

---

## Summary

**Key Rotation Status**: ✅ Fully Implemented

**Backward Decryption**: ✅ Automatic (dekId-based lookup)

**Emergency Rotation**: ✅ Supported (markDEKCompromised + rotateDEK)

**Re-encryption**: ✅ Implemented (reencryptWithNewDEK)

**Audit Trail**: ✅ Complete (key_rotation_logs, key_compromise_logs, master_key_access_log)

**Production Ready**: ✅ Yes (after establishing rotation schedule)

---

## Next Steps

1. **Establish rotation schedule** (recommend quarterly for DEKs, annual for MEK)
2. **Create admin UI** for key rotation operations
3. **Set up monitoring** for key age and rotation compliance
4. **Document master key custodians** and access procedures
5. **Test disaster recovery** procedures in staging environment
6. **Create runbook** for on-call engineers
