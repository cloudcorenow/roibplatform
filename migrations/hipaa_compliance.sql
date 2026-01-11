/*
  # HIPAA Compliance Migration

  This migration implements comprehensive HIPAA compliance features including:

  ## 1. Access Controls
    - Password complexity enforcement (tracked via password_last_changed)
    - Account lockout mechanism (failed_login_attempts, account_locked_until)
    - Multi-factor authentication (MFA) support
    - Automatic session timeout (15-minute sessions)
    - Password expiration tracking (force_password_change)

  ## 2. Administrative Safeguards
    - Security Officers designation and management
    - Workforce training program tracking
    - Security incident response system
    - User termination procedures and audit trail

  ## 3. Data Integrity
    - Document checksum verification
    - Document versioning system
    - Tampering detection via checksums

  ## New Tables Created
    - `security_officers` - Designated HIPAA Security Officers per tenant
    - `training_modules` - HIPAA training courses and materials
    - `user_training_completions` - Track user training completion
    - `security_incidents` - Log and track security incidents
    - `user_terminations` - Audit trail for user access termination
    - `document_versions` - Complete document version history
    - `password_history` - Prevent password reuse

  ## Modified Tables
    - `users` - Added MFA, password policy, and login security columns
    - `documents` - Added checksum and current_version fields
    - `sessions` - Added last_activity for 15-minute timeout tracking
*/

-- =====================================================
-- USERS TABLE ENHANCEMENTS
-- =====================================================

-- Add password security columns to users table
ALTER TABLE users ADD COLUMN password_last_changed INTEGER DEFAULT (unixepoch());
ALTER TABLE users ADD COLUMN password_expires_at INTEGER;
ALTER TABLE users ADD COLUMN force_password_change INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN account_locked_until INTEGER;
ALTER TABLE users ADD COLUMN last_login_at INTEGER;
ALTER TABLE users ADD COLUMN last_login_ip TEXT;

-- Add MFA columns to users table
ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN mfa_secret TEXT;
ALTER TABLE users ADD COLUMN mfa_backup_codes TEXT;
ALTER TABLE users ADD COLUMN mfa_enabled_at INTEGER;

-- Add user status and termination tracking
ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active';
ALTER TABLE users ADD COLUMN deactivated_at INTEGER;
ALTER TABLE users ADD COLUMN deactivated_by TEXT;
ALTER TABLE users ADD COLUMN deactivation_reason TEXT;

-- Create indexes for new columns
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_account_locked_until ON users(account_locked_until);
CREATE INDEX IF NOT EXISTS idx_users_mfa_enabled ON users(mfa_enabled);

-- =====================================================
-- SESSIONS TABLE ENHANCEMENTS
-- =====================================================

-- Add session activity tracking for 15-minute timeout
ALTER TABLE sessions ADD COLUMN last_activity INTEGER DEFAULT (unixepoch());
ALTER TABLE sessions ADD COLUMN ip_address TEXT;
ALTER TABLE sessions ADD COLUMN user_agent TEXT;

CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON sessions(last_activity);

-- =====================================================
-- DOCUMENTS TABLE ENHANCEMENTS
-- =====================================================

-- Add document integrity columns
ALTER TABLE documents ADD COLUMN checksum TEXT;
ALTER TABLE documents ADD COLUMN current_version INTEGER DEFAULT 1;
ALTER TABLE documents ADD COLUMN verified_at INTEGER;

CREATE INDEX IF NOT EXISTS idx_documents_checksum ON documents(checksum);

-- =====================================================
-- PASSWORD HISTORY TABLE
-- =====================================================

CREATE TABLE IF NOT EXISTS password_history (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_password_history_user_id ON password_history(user_id);
CREATE INDEX IF NOT EXISTS idx_password_history_created_at ON password_history(created_at);

-- =====================================================
-- SECURITY OFFICERS TABLE
-- =====================================================

CREATE TABLE IF NOT EXISTS security_officers (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  designation TEXT NOT NULL,
  responsibilities TEXT,
  appointed_at INTEGER DEFAULT (unixepoch()),
  appointed_by TEXT,
  status TEXT DEFAULT 'active',
  deactivated_at INTEGER,
  created_at INTEGER DEFAULT (unixepoch()),
  updated_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (appointed_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_security_officers_tenant_id ON security_officers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_security_officers_user_id ON security_officers(user_id);
CREATE INDEX IF NOT EXISTS idx_security_officers_status ON security_officers(status);

-- =====================================================
-- TRAINING MODULES TABLE
-- =====================================================

CREATE TABLE IF NOT EXISTS training_modules (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  tenant_id TEXT,
  title TEXT NOT NULL,
  description TEXT,
  content TEXT,
  category TEXT NOT NULL,
  duration_minutes INTEGER,
  required INTEGER DEFAULT 1,
  frequency_days INTEGER,
  passing_score INTEGER DEFAULT 80,
  version INTEGER DEFAULT 1,
  active INTEGER DEFAULT 1,
  created_by TEXT,
  created_at INTEGER DEFAULT (unixepoch()),
  updated_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_training_modules_tenant_id ON training_modules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_training_modules_category ON training_modules(category);
CREATE INDEX IF NOT EXISTS idx_training_modules_required ON training_modules(required);
CREATE INDEX IF NOT EXISTS idx_training_modules_active ON training_modules(active);

-- =====================================================
-- USER TRAINING COMPLETIONS TABLE
-- =====================================================

CREATE TABLE IF NOT EXISTS user_training_completions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  module_id TEXT NOT NULL,
  status TEXT DEFAULT 'in_progress',
  score INTEGER,
  attempts INTEGER DEFAULT 1,
  started_at INTEGER DEFAULT (unixepoch()),
  completed_at INTEGER,
  expires_at INTEGER,
  certificate_issued INTEGER DEFAULT 0,
  created_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (module_id) REFERENCES training_modules(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_training_tenant_id ON user_training_completions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_user_training_user_id ON user_training_completions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_training_module_id ON user_training_completions(module_id);
CREATE INDEX IF NOT EXISTS idx_user_training_status ON user_training_completions(status);
CREATE INDEX IF NOT EXISTS idx_user_training_expires_at ON user_training_completions(expires_at);

-- =====================================================
-- SECURITY INCIDENTS TABLE
-- =====================================================

CREATE TABLE IF NOT EXISTS security_incidents (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  tenant_id TEXT NOT NULL,
  incident_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  affected_systems TEXT,
  affected_users TEXT,
  reported_by TEXT NOT NULL,
  assigned_to TEXT,
  status TEXT DEFAULT 'open',
  resolution TEXT,
  resolved_at INTEGER,
  ip_address TEXT,
  user_agent TEXT,
  metadata TEXT,
  created_at INTEGER DEFAULT (unixepoch()),
  updated_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (reported_by) REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_security_incidents_tenant_id ON security_incidents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_security_incidents_type ON security_incidents(incident_type);
CREATE INDEX IF NOT EXISTS idx_security_incidents_severity ON security_incidents(severity);
CREATE INDEX IF NOT EXISTS idx_security_incidents_status ON security_incidents(status);
CREATE INDEX IF NOT EXISTS idx_security_incidents_reported_by ON security_incidents(reported_by);
CREATE INDEX IF NOT EXISTS idx_security_incidents_created_at ON security_incidents(created_at);

-- =====================================================
-- USER TERMINATIONS TABLE
-- =====================================================

CREATE TABLE IF NOT EXISTS user_terminations (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  terminated_by TEXT NOT NULL,
  termination_type TEXT NOT NULL,
  reason TEXT NOT NULL,
  access_revoked_at INTEGER DEFAULT (unixepoch()),
  data_archived INTEGER DEFAULT 0,
  data_archive_location TEXT,
  devices_returned INTEGER DEFAULT 0,
  exit_interview_completed INTEGER DEFAULT 0,
  checklist_completed TEXT,
  notes TEXT,
  created_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY (terminated_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_user_terminations_tenant_id ON user_terminations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_user_terminations_user_id ON user_terminations(user_id);
CREATE INDEX IF NOT EXISTS idx_user_terminations_terminated_by ON user_terminations(terminated_by);
CREATE INDEX IF NOT EXISTS idx_user_terminations_created_at ON user_terminations(created_at);

-- =====================================================
-- DOCUMENT VERSIONS TABLE
-- =====================================================

CREATE TABLE IF NOT EXISTS document_versions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  tenant_id TEXT NOT NULL,
  document_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  filename TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  r2_key TEXT NOT NULL,
  checksum TEXT NOT NULL,
  uploaded_by TEXT NOT NULL,
  change_description TEXT,
  previous_checksum TEXT,
  verified INTEGER DEFAULT 0,
  created_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
  FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_document_versions_tenant_id ON document_versions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_document_versions_document_id ON document_versions(document_id);
CREATE INDEX IF NOT EXISTS idx_document_versions_version ON document_versions(document_id, version);
CREATE INDEX IF NOT EXISTS idx_document_versions_checksum ON document_versions(checksum);
CREATE INDEX IF NOT EXISTS idx_document_versions_created_at ON document_versions(created_at);

-- =====================================================
-- INSERT DEFAULT TRAINING MODULES
-- =====================================================

INSERT OR IGNORE INTO training_modules (id, tenant_id, title, description, category, duration_minutes, required, frequency_days, version)
VALUES
  ('hipaa-basics', NULL, 'HIPAA Basics Training', 'Introduction to HIPAA Privacy and Security Rules', 'compliance', 60, 1, 365, 1),
  ('phi-handling', NULL, 'Protected Health Information Handling', 'Best practices for handling PHI data', 'compliance', 45, 1, 365, 1),
  ('security-awareness', NULL, 'Security Awareness Training', 'Recognizing and preventing security threats', 'security', 30, 1, 180, 1),
  ('breach-notification', NULL, 'Breach Notification Procedures', 'Steps to take when a breach occurs', 'incident-response', 30, 1, 365, 1),
  ('access-controls', NULL, 'Access Control Best Practices', 'Proper use of passwords, MFA, and access controls', 'security', 20, 1, 180, 1);
