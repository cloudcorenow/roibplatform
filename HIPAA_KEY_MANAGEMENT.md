# HIPAA Key Management & Deployment Guide

## Overview

This guide covers the complete key management strategy for HIPAA-compliant encryption at rest. The system uses **envelope encryption** with a two-tier key hierarchy:

1. **Master Key (MEK)** - Stored in Cloudflare Secrets, never in database
2. **Data Encryption Keys (DEK)** - Encrypted by MEK, stored in database

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Cloudflare Worker Secret                  │
│                   MASTER_ENCRYPTION_KEY                      │
│                    (256-bit AES key)                         │
└──────────────────────┬──────────────────────────────────────┘
                       │ Encrypts/Decrypts
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                 Data Encryption Keys (DEKs)                  │
│                  (Stored in D1 Database)                     │
│  • One active DEK per tenant                                 │
│  • Keys are encrypted at rest with MEK                       │
│  • Automatic rotation with audit trail                       │
└──────────────────────┬──────────────────────────────────────┘
                       │ Encrypts/Decrypts
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                       PHI Data                               │
│                  (Stored in D1 Database)                     │
│  • Each field encrypted with tenant's active DEK             │
│  • Includes DEK ID for decryption                            │
└─────────────────────────────────────────────────────────────┘
```

## Initial Setup

### Step 1: Generate Master Encryption Key

**CRITICAL**: The master key must be:
- 256 bits (32 bytes) of cryptographically secure random data
- Generated in a secure environment
- Never stored in code, config files, or database
- Only stored in Cloudflare Secrets

#### Generate Key (Option A: Command Line)

```bash
# Using Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Using OpenSSL
openssl rand -hex 32

# Using Python
python3 -c "import secrets; print(secrets.token_hex(32))"
```

#### Generate Key (Option B: Production KMS)

For production environments, use a proper KMS:

```bash
# AWS KMS
aws kms generate-data-key --key-id alias/my-master-key --key-spec AES_256

# Google Cloud KMS
gcloud kms keys create hipaa-master-key \
  --location=us-central1 \
  --keyring=hipaa-keyring \
  --purpose=encryption

# Cloudflare for Teams (if available)
# Follow: https://developers.cloudflare.com/cloudflare-one/
```

### Step 2: Store Master Key in Cloudflare Secrets

```bash
# Set for production
wrangler secret put MASTER_ENCRYPTION_KEY
# Paste your generated key when prompted

# Verify it's set
wrangler secret list
```

**IMPORTANT**:
- Never commit the key to git
- Never log the key
- Never send the key over unencrypted channels
- Store backup in secure vault (1Password, AWS Secrets Manager, etc.)

### Step 3: Apply Database Migrations

```bash
# Local development
wrangler d1 execute roiblueprint --file=./migrations/immutable_audit_logging.sql
wrangler d1 execute roiblueprint --file=./migrations/rbac_system.sql
wrangler d1 execute roiblueprint --file=./migrations/session_hardening.sql

# Production
wrangler d1 execute roiblueprint --file=./migrations/immutable_audit_logging.sql --remote
wrangler d1 execute roiblueprint --file=./migrations/rbac_system.sql --remote
wrangler d1 execute roiblueprint --file=./migrations/session_hardening.sql --remote
```

### Step 4: Initialize Envelope Encryption

The system will automatically create DEKs on first use, but you can pre-initialize:

```typescript
// In your worker initialization
import { createEnvelopeEncryption } from './utils/envelope-encryption';

const envelopeEncryption = createEnvelopeEncryption(
  env.MASTER_ENCRYPTION_KEY,
  env.DB
);

await envelopeEncryption.initialize();
```

## Key Rotation

### When to Rotate Keys

Rotate DEKs:
- **Every 90 days** (recommended)
- **Immediately** if compromised
- After employee departure (if they had key access)
- After security incident
- Before major compliance audits

### How to Rotate DEKs

```typescript
import { createEnvelopeEncryption } from './utils/envelope-encryption';

const envelopeEncryption = createEnvelopeEncryption(
  env.MASTER_ENCRYPTION_KEY,
  env.DB
);

const result = await envelopeEncryption.rotateDEK(
  tenantId,
  userId,
  'Scheduled 90-day rotation'
);

console.log(`New DEK: ${result.newDekId}`);
```

### Automated Rotation Schedule

Create a Cloudflare Cron Trigger:

```toml
# wrangler.toml
[triggers]
crons = ["0 0 1 */3 * *"]  # Every 3 months on the 1st at midnight
```

```typescript
// In your worker
export default {
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    const envelopeEncryption = createEnvelopeEncryption(
      env.MASTER_ENCRYPTION_KEY,
      env.DB
    );

    const tenants = await env.DB.prepare('SELECT id FROM tenants WHERE active = 1').all();

    for (const tenant of tenants.results || []) {
      try {
        await envelopeEncryption.rotateDEK(
          tenant.id as string,
          'system',
          'Automated quarterly rotation'
        );
        console.log(`Rotated DEK for tenant: ${tenant.id}`);
      } catch (error) {
        console.error(`Failed to rotate DEK for tenant ${tenant.id}:`, error);
      }
    }
  }
};
```

### Master Key Rotation

⚠️ **CRITICAL OPERATION** - Requires re-encrypting ALL DEKs

```bash
# 1. Generate new master key
NEW_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")

# 2. Store as temporary secret
wrangler secret put MASTER_ENCRYPTION_KEY_NEW
# Paste $NEW_KEY

# 3. Deploy rotation script
# 4. After successful rotation, replace old key
wrangler secret put MASTER_ENCRYPTION_KEY
# Paste $NEW_KEY

# 5. Delete temporary secret
wrangler secret delete MASTER_ENCRYPTION_KEY_NEW
```

## Key Security Best Practices

### Access Control

1. **Principle of Least Privilege**
   - Only 2-3 people should have access to master key
   - Use separate keys for dev/staging/production
   - Log all key access

2. **Separation of Duties**
   - Key rotation should require two people
   - One generates, one verifies
   - Both operations must be logged

3. **Audit Trail**
   - All key operations are logged in `master_key_access_log`
   - Review logs monthly
   - Alert on unusual patterns

### Storage Security

```bash
# ❌ NEVER DO THIS
MASTER_ENCRYPTION_KEY=abc123...  # In .env file
const key = "abc123..."           # Hardcoded in code
localStorage.setItem("key", ...)  # In browser storage

# ✅ ALWAYS DO THIS
wrangler secret put MASTER_ENCRYPTION_KEY  # Cloudflare Secret
env.MASTER_ENCRYPTION_KEY                   # Access via env only
```

### Key Backup

Store encrypted backup in multiple locations:

1. **Primary**: Cloudflare Secrets (production)
2. **Backup 1**: Corporate password manager (1Password, LastPass)
3. **Backup 2**: Hardware security module (Yubikey, etc.)
4. **Backup 3**: Secure offline storage (safe deposit box)

Create backup procedure:

```typescript
// backup-keys.ts
import { createEnvelopeEncryption } from './utils/envelope-encryption';

async function backupKeys(masterKey: string, db: D1Database) {
  const envelope = createEnvelopeEncryption(masterKey, db);

  const deks = await db.prepare(
    `SELECT id, tenant_id, version, encrypted_key, created_at
     FROM data_encryption_keys
     WHERE status = 'active'
     ORDER BY tenant_id, version DESC`
  ).all();

  const backup = {
    timestamp: new Date().toISOString(),
    masterKeyHash: await hashKey(masterKey),
    deks: deks.results
  };

  return JSON.stringify(backup, null, 2);
}

async function hashKey(key: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(key);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
```

## Monitoring & Alerts

### Key Metrics to Monitor

1. **Key Age**
   - Alert if DEK > 90 days old
   - Alert if master key > 1 year old

2. **Failed Decryption Attempts**
   - Alert on 3+ failures in 1 hour
   - Could indicate compromised key

3. **Key Access Patterns**
   - Alert on access outside business hours
   - Alert on access from unusual IPs

### Setup Monitoring

```typescript
// monitoring.ts
export async function checkKeyHealth(db: D1Database) {
  const now = Math.floor(Date.now() / 1000);
  const ninetyDaysAgo = now - (90 * 24 * 60 * 60);

  const oldKeys = await db.prepare(
    `SELECT id, tenant_id, created_at
     FROM data_encryption_keys
     WHERE status = 'active' AND created_at < ?`
  ).bind(ninetyDaysAgo).all();

  if (oldKeys.results && oldKeys.results.length > 0) {
    await sendAlert({
      severity: 'warning',
      message: `${oldKeys.results.length} DEKs are older than 90 days`,
      action: 'Rotate keys immediately'
    });
  }

  const failedDecryptions = await db.prepare(
    `SELECT COUNT(*) as count
     FROM master_key_access_log
     WHERE operation = 'decrypt'
       AND success = 0
       AND created_at > ?`
  ).bind(now - 3600).first();

  if (failedDecryptions && failedDecryptions.count > 3) {
    await sendAlert({
      severity: 'critical',
      message: `${failedDecryptions.count} failed decryptions in last hour`,
      action: 'Investigate immediately - possible compromised key'
    });
  }
}
```

## Disaster Recovery

### Scenario 1: Master Key Compromised

1. **Immediate Response**
   ```bash
   # Generate new master key
   NEW_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")

   # Store in secrets
   wrangler secret put MASTER_ENCRYPTION_KEY_EMERGENCY
   ```

2. **Mark All DEKs Compromised**
   ```typescript
   await db.exec(`
     UPDATE data_encryption_keys
     SET status = 'compromised'
     WHERE status = 'active'
   `);
   ```

3. **Create New DEKs & Re-encrypt**
   ```typescript
   // Re-encrypt all PHI data with new keys
   // This is a heavy operation - plan for downtime
   ```

### Scenario 2: Lost Master Key

⚠️ **WITHOUT BACKUP = PERMANENT DATA LOSS**

1. Restore from backup (see Key Backup section)
2. Verify restoration:
   ```typescript
   const valid = await envelopeEncryption.validateMasterKey();
   if (!valid) {
     console.error('KEY RESTORATION FAILED');
   }
   ```

### Scenario 3: Tenant DEK Compromised

```typescript
await envelopeEncryption.markDEKCompromised(
  dekId,
  'Security incident #12345'
);

await envelopeEncryption.rotateDEK(
  tenantId,
  userId,
  'Emergency rotation due to compromise'
);
```

## Compliance Documentation

### HIPAA Requirements Met

- ✅ **164.312(a)(2)(iv)** - Encryption at rest (AES-256-GCM)
- ✅ **164.312(e)(2)(ii)** - Encryption in transit (TLS 1.3)
- ✅ **164.308(a)(1)(ii)(D)** - Information access management (RBAC)
- ✅ **164.312(b)** - Audit controls (immutable logs)
- ✅ **164.308(a)(3)(i)** - Workforce authorization (session management)

### Audit Evidence

Generate compliance report:

```typescript
async function generateComplianceReport(db: D1Database, tenantId: string) {
  const report = {
    timestamp: new Date().toISOString(),
    tenant_id: tenantId,

    encryption: {
      algorithm: 'AES-256-GCM',
      keyManagement: 'Envelope encryption with DEK rotation',
      activeDEK: await getActiveDEK(tenantId)
    },

    keyRotation: await getKeyRotationHistory(tenantId),

    auditLogs: await db.prepare(
      `SELECT COUNT(*) as count FROM audit_logs WHERE tenant_id = ?`
    ).bind(tenantId).first(),

    accessControl: {
      roles: await getRoleCount(tenantId),
      users: await getUserCount(tenantId)
    }
  };

  return report;
}
```

## Testing

### Verify Encryption

```typescript
// test-encryption.ts
import { createEnvelopeEncryption } from './utils/envelope-encryption';

async function testEncryption(masterKey: string, db: D1Database) {
  const envelope = createEnvelopeEncryption(masterKey, db);
  await envelope.initialize();

  const testData = 'SENSITIVE PHI DATA: SSN 123-45-6789';

  const encrypted = await envelope.encrypt(testData, 'test-tenant');
  console.log('Encrypted:', encrypted);

  const decrypted = await envelope.decrypt(encrypted);
  console.log('Decrypted:', decrypted);

  if (decrypted === testData) {
    console.log('✓ Encryption test passed');
  } else {
    console.error('✗ Encryption test failed');
  }
}
```

### Verify Key Rotation

```typescript
async function testKeyRotation(envelope: EnvelopeEncryption) {
  const tenantId = 'test-tenant';

  const oldDEK = await envelope.getActiveDEK(tenantId);
  const encrypted1 = await envelope.encrypt('Test data', tenantId);

  await envelope.rotateDEK(tenantId, 'test-user', 'Test rotation');

  const newDEK = await envelope.getActiveDEK(tenantId);
  const encrypted2 = await envelope.encrypt('Test data', tenantId);

  const decrypted1 = await envelope.decrypt(encrypted1);
  const decrypted2 = await envelope.decrypt(encrypted2);

  console.log('Old DEK:', oldDEK?.id);
  console.log('New DEK:', newDEK?.id);
  console.log('Both decrypt correctly:', decrypted1 === 'Test data' && decrypted2 === 'Test data');
}
```

## Environment-Specific Configuration

### Development

```bash
# .env.development
MASTER_ENCRYPTION_KEY=dev-key-DO-NOT-USE-IN-PRODUCTION-32bytes
```

### Staging

```bash
wrangler secret put MASTER_ENCRYPTION_KEY --env staging
```

### Production

```bash
wrangler secret put MASTER_ENCRYPTION_KEY --env production
```

## Checklist for Production Deployment

- [ ] Master key generated with cryptographically secure random
- [ ] Master key stored in Cloudflare Secrets (never in code)
- [ ] Master key backed up in 3+ secure locations
- [ ] All database migrations applied
- [ ] Envelope encryption initialized for all tenants
- [ ] Key rotation schedule configured (90 days)
- [ ] Monitoring alerts configured
- [ ] Audit logging verified working
- [ ] Disaster recovery procedure documented
- [ ] Team trained on key management procedures
- [ ] Compliance report generated and reviewed

## Support & Troubleshooting

### Common Issues

**Issue**: "DEK not found"
- **Cause**: Missing DEK for tenant
- **Fix**: Run `await envelope.initialize()` for tenant

**Issue**: "Failed to decrypt"
- **Cause**: Wrong master key or corrupted DEK
- **Fix**: Verify master key, check key rotation logs

**Issue**: "Key too old" warning
- **Cause**: DEK older than 90 days
- **Fix**: Run key rotation procedure

### Emergency Contacts

Document emergency procedures:
1. Security team contact
2. Database backup location
3. Key backup location
4. Compliance officer contact

## Next Steps

1. Review this guide with security team
2. Set up master key with proper backup procedures
3. Configure monitoring and alerts
4. Schedule quarterly key rotation
5. Document in company security procedures
6. Train team on key management
