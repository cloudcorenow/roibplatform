-- HIPAA Compliance Migration
-- Adds technical safeguards for HIPAA compliance

-- ============================================
-- 1. SESSION TIMEOUT TRACKING
-- ============================================
-- Add last_activity to track session inactivity
ALTER TABLE sessions ADD COLUMN last_activity INTEGER DEFAULT (unixepoch());
ALTER TABLE sessions ADD COLUMN ip_address TEXT;
ALTER TABLE sessions ADD COLUMN user_agent TEXT;

CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON sessions(last_activity);

-- ============================================
-- 2. PASSWORD POLICIES
-- ============================================
-- Add password management columns to users table
ALTER TABLE users ADD COLUMN password_changed_at INTEGER DEFAULT (unixepoch());
ALTER TABLE users ADD COLUMN password_expires_at INTEGER DEFAULT (unixepoch() + (90 * 24 * 60 * 60)); -- 90 days
ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until INTEGER;
ALTER TABLE users ADD COLUMN authorized_by TEXT;
ALTER TABLE users ADD COLUMN authorization_date INTEGER;
ALTER TABLE users ADD COLUMN last_access_review INTEGER;

CREATE INDEX IF NOT EXISTS idx_users_locked_until ON users(locked_until);
CREATE INDEX IF NOT EXISTS idx_users_password_expires_at ON users(password_expires_at);

-- Password history to prevent reuse
CREATE TABLE IF NOT EXISTS password_history (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_password_history_user_id ON password_history(user_id);
CREATE INDEX IF NOT EXISTS idx_password_history_created_at ON password_history(created_at);

-- ============================================
-- 3. MULTI-FACTOR AUTHENTICATION
-- ============================================
CREATE TABLE IF NOT EXISTS mfa_tokens (
  user_id TEXT PRIMARY KEY,
  secret TEXT NOT NULL,
  backup_codes TEXT,
  enabled INTEGER DEFAULT 0,
  created_at INTEGER DEFAULT (unixepoch()),
  last_used INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mfa_tokens_enabled ON mfa_tokens(enabled);

-- ============================================
-- 4. DOCUMENT INTEGRITY (CHECKSUMS)
-- ============================================
ALTER TABLE documents ADD COLUMN checksum TEXT;
ALTER TABLE documents ADD COLUMN encryption_key_id TEXT;
ALTER TABLE documents ADD COLUMN verified_at INTEGER;

CREATE INDEX IF NOT EXISTS idx_documents_checksum ON documents(checksum);

-- Document versions for integrity tracking
CREATE TABLE IF NOT EXISTS document_versions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  document_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  checksum TEXT NOT NULL,
  changed_by TEXT NOT NULL,
  changed_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
  FOREIGN KEY (changed_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_document_versions_document_id ON document_versions(document_id);
CREATE INDEX IF NOT EXISTS idx_document_versions_changed_at ON document_versions(changed_at);

-- ============================================
-- 5. SECURITY INCIDENTS
-- ============================================
CREATE TABLE IF NOT EXISTS security_incidents (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  tenant_id TEXT NOT NULL,
  incident_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  detected_at INTEGER DEFAULT (unixepoch()),
  detected_by TEXT,
  status TEXT DEFAULT 'open',
  affected_users TEXT,
  affected_records INTEGER,
  description TEXT,
  resolution TEXT,
  resolved_at INTEGER,
  reported_to_hhs INTEGER,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (detected_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_security_incidents_tenant_id ON security_incidents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_security_incidents_status ON security_incidents(status);
CREATE INDEX IF NOT EXISTS idx_security_incidents_severity ON security_incidents(severity);
CREATE INDEX IF NOT EXISTS idx_security_incidents_detected_at ON security_incidents(detected_at);

-- ============================================
-- 6. ACCESS REVIEWS
-- ============================================
CREATE TABLE IF NOT EXISTS access_reviews (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL,
  reviewer_id TEXT NOT NULL,
  review_date INTEGER DEFAULT (unixepoch()),
  access_approved INTEGER NOT NULL,
  notes TEXT,
  next_review_date INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (reviewer_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_access_reviews_user_id ON access_reviews(user_id);
CREATE INDEX IF NOT EXISTS idx_access_reviews_next_review_date ON access_reviews(next_review_date);

-- ============================================
-- 7. TRAINING RECORDS
-- ============================================
CREATE TABLE IF NOT EXISTS training_records (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL,
  training_type TEXT NOT NULL,
  completed_at INTEGER NOT NULL,
  expires_at INTEGER,
  certificate_url TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_training_records_user_id ON training_records(user_id);
CREATE INDEX IF NOT EXISTS idx_training_records_expires_at ON training_records(expires_at);

-- ============================================
-- 8. BACKUP LOG
-- ============================================
CREATE TABLE IF NOT EXISTS backup_log (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  backup_date INTEGER DEFAULT (unixepoch()),
  backup_type TEXT NOT NULL,
  backup_size INTEGER,
  backup_location TEXT,
  status TEXT NOT NULL,
  verified_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_backup_log_backup_date ON backup_log(backup_date);
CREATE INDEX IF NOT EXISTS idx_backup_log_status ON backup_log(status);
