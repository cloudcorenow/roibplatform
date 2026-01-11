/*
  # Immutable Audit Logging System

  Comprehensive audit trail for HIPAA compliance with tamper-evident logging.

  ## New Tables

  ### `audit_logs`
  Immutable audit trail for all PHI access and modifications
  - `id` (TEXT, primary key) - Unique log entry ID
  - `tenant_id` (TEXT, not null) - Tenant isolation
  - `user_id` (TEXT, not null) - User who performed action
  - `action` (TEXT, not null) - Action type (CREATE, READ, UPDATE, DELETE, ACCESS)
  - `resource_type` (TEXT, not null) - Type of resource (patient, document, assessment)
  - `resource_id` (TEXT) - ID of affected resource
  - `phi_accessed` (TEXT) - JSON array of PHI fields accessed
  - `ip_address` (TEXT) - Client IP address
  - `user_agent` (TEXT) - Client user agent
  - `request_id` (TEXT) - Request correlation ID
  - `success` (INTEGER) - Whether action succeeded (1) or failed (0)
  - `failure_reason` (TEXT) - Reason for failure if applicable
  - `metadata` (TEXT) - Additional JSON metadata
  - `checksum` (TEXT, not null) - SHA-256 hash for tamper detection
  - `created_at` (INTEGER, not null) - Unix timestamp

  ### `audit_chain`
  Blockchain-style chain for detecting tampering
  - `id` (TEXT, primary key) - Chain entry ID
  - `tenant_id` (TEXT, not null) - Tenant isolation
  - `audit_log_id` (TEXT, not null) - Reference to audit log
  - `previous_hash` (TEXT) - Hash of previous chain entry
  - `current_hash` (TEXT, not null) - Hash of current entry
  - `created_at` (INTEGER, not null) - Unix timestamp

  ## Security Features

  1. **Immutability**: No UPDATE or DELETE operations allowed on audit tables
  2. **Tamper Detection**: Cryptographic checksums and chain hashing
  3. **Comprehensive Tracking**: All PHI access is logged with context
  4. **Tenant Isolation**: All logs are tenant-scoped
*/

-- Immutable audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('CREATE', 'READ', 'UPDATE', 'DELETE', 'ACCESS', 'LOGIN', 'LOGOUT', 'EXPORT', 'PRINT')),
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  phi_accessed TEXT,
  ip_address TEXT,
  user_agent TEXT,
  request_id TEXT,
  success INTEGER NOT NULL DEFAULT 1 CHECK (success IN (0, 1)),
  failure_reason TEXT,
  metadata TEXT,
  checksum TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_id ON audit_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_type ON audit_logs(resource_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_id ON audit_logs(resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id ON audit_logs(request_id);

-- Blockchain-style audit chain for tamper detection
CREATE TABLE IF NOT EXISTS audit_chain (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  tenant_id TEXT NOT NULL,
  audit_log_id TEXT NOT NULL UNIQUE,
  previous_hash TEXT,
  current_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT,
  FOREIGN KEY (audit_log_id) REFERENCES audit_logs(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_audit_chain_tenant_id ON audit_chain(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_chain_audit_log_id ON audit_chain(audit_log_id);
CREATE INDEX IF NOT EXISTS idx_audit_chain_created_at ON audit_chain(created_at);

-- Trigger to prevent updates to audit_logs (immutability)
CREATE TRIGGER IF NOT EXISTS prevent_audit_logs_update
BEFORE UPDATE ON audit_logs
BEGIN
  SELECT RAISE(ABORT, 'Audit logs are immutable and cannot be updated');
END;

-- Trigger to prevent deletes from audit_logs (immutability)
CREATE TRIGGER IF NOT EXISTS prevent_audit_logs_delete
BEFORE DELETE ON audit_logs
BEGIN
  SELECT RAISE(ABORT, 'Audit logs are immutable and cannot be deleted');
END;

-- Trigger to prevent updates to audit_chain (immutability)
CREATE TRIGGER IF NOT EXISTS prevent_audit_chain_update
BEFORE UPDATE ON audit_chain
BEGIN
  SELECT RAISE(ABORT, 'Audit chain is immutable and cannot be updated');
END;

-- Trigger to prevent deletes from audit_chain (immutability)
CREATE TRIGGER IF NOT EXISTS prevent_audit_chain_delete
BEFORE DELETE ON audit_chain
BEGIN
  SELECT RAISE(ABORT, 'Audit chain is immutable and cannot be deleted');
END;

-- PHI access tracking table (for minimum necessary principle)
CREATE TABLE IF NOT EXISTS phi_access_log (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  patient_id TEXT,
  fields_accessed TEXT NOT NULL,
  justification TEXT,
  approved_by TEXT,
  ip_address TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_phi_access_log_tenant_id ON phi_access_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_phi_access_log_user_id ON phi_access_log(user_id);
CREATE INDEX IF NOT EXISTS idx_phi_access_log_patient_id ON phi_access_log(patient_id);
CREATE INDEX IF NOT EXISTS idx_phi_access_log_created_at ON phi_access_log(created_at);

-- Trigger to prevent updates to phi_access_log
CREATE TRIGGER IF NOT EXISTS prevent_phi_access_log_update
BEFORE UPDATE ON phi_access_log
BEGIN
  SELECT RAISE(ABORT, 'PHI access logs are immutable and cannot be updated');
END;

-- Trigger to prevent deletes from phi_access_log
CREATE TRIGGER IF NOT EXISTS prevent_phi_access_log_delete
BEFORE DELETE ON phi_access_log
BEGIN
  SELECT RAISE(ABORT, 'PHI access logs are immutable and cannot be deleted');
END;
