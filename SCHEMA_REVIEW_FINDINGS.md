# Database Schema Review - Findings & Recommendations

## Executive Summary

The database schema has **5 critical mismatches** between what the application code expects and what exists in the database. These will cause runtime errors when the application tries to query or insert data.

## Critical Issues Found

### ❌ Issue #1: time_entries Table - Missing 8 Columns

**Severity:** CRITICAL
**Impact:** Time tracking features will completely fail

**What the code expects:**
- `client` (TEXT)
- `project` (TEXT)
- `service` (TEXT)
- `duration_min` (INTEGER)
- `is_rnd` (INTEGER)
- `employee_id` (TEXT)
- `employee_name` (TEXT)
- `created_by` (TEXT)

**What exists in database:**
- `user_id`, `client_id`, `project_id`, `task`, `description`, `hours`, `billable`, `date`

**Location:** `src/utils/d1-queries.ts:55-60`

---

### ❌ Issue #2: clients Table - Missing 2 Columns

**Severity:** HIGH
**Impact:** Client data queries will fail when trying to access industry or contact person

**Missing columns:**
- `industry` (TEXT)
- `contact_person` (TEXT)

**Location:** `src/utils/d1-queries.ts:302-305`

---

### ❌ Issue #3: projects Table - Missing 1 Column

**Severity:** HIGH
**Impact:** Cannot track R&D status of projects

**Missing column:**
- `is_rnd` (INTEGER/BOOLEAN)

**Location:** `src/utils/d1-queries.ts:335`

---

### ❌ Issue #4: documents Table - Column Name Mismatches

**Severity:** CRITICAL
**Impact:** Document uploads and queries will fail

**Code expects → Database has:**
- `file_name` → `filename`
- `file_size` → `size_bytes`
- `file_type` → `mime_type`
- `uploaded_by` → `user_id`
- Missing: `description` column

**Location:** `src/routes/documents.ts:270, 392`

---

### ❌ Issue #5: document_versions Table - Incorrect Schema

**Severity:** HIGH
**Impact:** Document versioning will fail

**Problem:** The existing `document_versions` table has a simplified schema that doesn't match what the code expects.

**Code expects:**
- `document_id`, `tenant_id`, `version`, `filename`, `mime_type`, `size_bytes`,
- `r2_key`, `checksum`, `uploaded_by`, `verified`, `change_description`, `created_at`

**What exists:**
- Only: `id`, `document_id`, `version`, `checksum`, `changed_by`, `changed_at`

**Location:** `src/routes/documents.ts:152-168`

---

## Additional Findings

### ✅ Tables Created Successfully (19 tables)
- clients ✓
- projects ✓
- security_officers ✓
- training_modules ✓
- user_training_completions ✓
- user_terminations ✓
- roles ✓
- permissions ✓
- role_permissions ✓
- user_roles ✓
- session_activities ✓
- reauth_requirements ✓
- audit_logs ✓
- audit_chain ✓
- phi_access_log ✓
- data_encryption_keys ✓
- key_rotation_logs ✓
- key_compromise_logs ✓
- master_key_access_log ✓

### ✅ Immutability Triggers Working
- audit_logs (immutable) ✓
- audit_chain (immutable) ✓
- phi_access_log (immutable) ✓

### ✅ Default Data Inserted
- Permissions (19 entries) ✓
- Roles (4 entries) ✓
- Role-permission mappings ✓
- Training modules (5 entries) ✓

---

## Recommended Actions

### Immediate Actions (Required)

1. **Run schema_fixes.sql** to add missing columns:
   ```bash
   wrangler d1 execute roiblueprint --file=./schema_fixes.sql
   ```

2. **OR Update Application Code** to match existing schema (not recommended - more work)

3. **Data Migration** - If you have existing data in time_entries:
   ```sql
   -- Map old columns to new columns
   UPDATE time_entries SET
     client = (SELECT name FROM clients WHERE id = client_id),
     project = (SELECT name FROM projects WHERE id = project_id),
     service = task,
     duration_min = CAST(hours * 60 AS INTEGER),
     created_by = user_id
   WHERE client IS NULL;
   ```

### Future Recommendations

1. **Use TypeScript types** to generate schema (e.g., Drizzle ORM, Prisma)
2. **Add schema validation tests** to catch mismatches early
3. **Document the source of truth** - Is it the schema.sql or the TypeScript code?
4. **Use database migrations** with version control

---

## Testing Checklist

After applying fixes, test these features:

- [ ] Create a new time entry
- [ ] List time entries with pagination
- [ ] Query clients with industry/contact_person
- [ ] Query projects with is_rnd flag
- [ ] Upload a document
- [ ] List documents
- [ ] Download a document
- [ ] Check document versioning

---

## Files Reviewed

- ✓ schema.sql
- ✓ missing_tables.sql
- ✓ src/utils/d1-queries.ts
- ✓ src/utils/d1-helpers.ts
- ✓ src/routes/auth.ts
- ✓ src/routes/assessments.ts
- ✓ src/routes/documents.ts
- ✓ src/types/index.ts

---

**Generated:** 2026-01-11
**Status:** CRITICAL FIXES REQUIRED
