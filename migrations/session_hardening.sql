/*
  # Session Hardening for HIPAA Compliance

  Enhanced session management with automatic timeouts and re-authentication.

  ## Schema Changes

  ### Updated `sessions` table
  Add columns for session hardening:
  - `last_activity` (INTEGER) - Last activity timestamp for idle timeout
  - `ip_address` (TEXT) - Client IP for anomaly detection
  - `user_agent` (TEXT) - Client user agent for session binding
  - `requires_mfa` (INTEGER) - Whether session requires MFA
  - `mfa_verified_at` (INTEGER) - When MFA was last verified
  - `privileged` (INTEGER) - Whether this is a privileged session
  - `privileged_expires_at` (INTEGER) - When privileged access expires

  ### New `session_activities` table
  Track all session activities for security monitoring
  - `id` (TEXT, primary key) - Activity ID
  - `session_id` (TEXT, not null) - Session reference
  - `activity_type` (TEXT, not null) - Type of activity
  - `ip_address` (TEXT) - Client IP
  - `created_at` (INTEGER) - Unix timestamp

  ## Security Features

  1. **Idle Timeout**: Sessions expire after 15 minutes of inactivity
  2. **Absolute Timeout**: Sessions expire after 8 hours regardless of activity
  3. **Privileged Sessions**: Sensitive operations require re-authentication
  4. **Session Binding**: Sessions are bound to IP and user agent
  5. **Activity Tracking**: All session activities are logged
*/

-- Add new columns to sessions table
ALTER TABLE sessions ADD COLUMN last_activity INTEGER DEFAULT (unixepoch());
ALTER TABLE sessions ADD COLUMN ip_address TEXT;
ALTER TABLE sessions ADD COLUMN user_agent TEXT;
ALTER TABLE sessions ADD COLUMN requires_mfa INTEGER DEFAULT 0 CHECK (requires_mfa IN (0, 1));
ALTER TABLE sessions ADD COLUMN mfa_verified_at INTEGER;
ALTER TABLE sessions ADD COLUMN privileged INTEGER DEFAULT 0 CHECK (privileged IN (0, 1));
ALTER TABLE sessions ADD COLUMN privileged_expires_at INTEGER;

-- Create index for last_activity
CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON sessions(last_activity);

-- Session activities tracking
CREATE TABLE IF NOT EXISTS session_activities (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  session_id TEXT NOT NULL,
  activity_type TEXT NOT NULL CHECK (activity_type IN ('login', 'logout', 'access', 'timeout', 'mfa_verify', 'privilege_grant', 'privilege_expire')),
  ip_address TEXT,
  metadata TEXT,
  created_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_session_activities_session_id ON session_activities(session_id);
CREATE INDEX IF NOT EXISTS idx_session_activities_activity_type ON session_activities(activity_type);
CREATE INDEX IF NOT EXISTS idx_session_activities_created_at ON session_activities(created_at);

-- MFA tokens table
CREATE TABLE IF NOT EXISTS mfa_tokens (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL,
  secret TEXT NOT NULL,
  backup_codes TEXT,
  enabled INTEGER DEFAULT 0 CHECK (enabled IN (0, 1)),
  verified_at INTEGER,
  created_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(user_id)
);

CREATE INDEX IF NOT EXISTS idx_mfa_tokens_user_id ON mfa_tokens(user_id);

-- Re-authentication requirements table
CREATE TABLE IF NOT EXISTS reauth_requirements (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  resource_type TEXT NOT NULL,
  action TEXT NOT NULL,
  max_age_seconds INTEGER NOT NULL DEFAULT 300,
  requires_mfa INTEGER DEFAULT 1 CHECK (requires_mfa IN (0, 1)),
  description TEXT,
  UNIQUE(resource_type, action)
);

-- Insert default re-authentication requirements
INSERT OR IGNORE INTO reauth_requirements (resource_type, action, max_age_seconds, requires_mfa, description)
VALUES
  ('patient', 'delete', 300, 1, 'Deleting patient records requires recent re-authentication'),
  ('patient', 'export', 300, 1, 'Exporting patient data requires recent re-authentication'),
  ('document', 'share', 300, 1, 'Sharing documents requires recent re-authentication'),
  ('user', 'update', 300, 1, 'Updating user permissions requires recent re-authentication'),
  ('settings', 'update', 300, 1, 'Updating security settings requires recent re-authentication');
