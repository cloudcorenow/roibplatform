-- =====================================================
-- MISSING TABLES FOR D1 DATABASE
-- Run this to create the 19 missing tables
-- =====================================================

-- 1. CLIENTS TABLE
CREATE TABLE IF NOT EXISTS clients (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  company TEXT,
  status TEXT DEFAULT 'active',
  created_at INTEGER DEFAULT (unixepoch()),
  updated_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_clients_tenant_id ON clients(tenant_id);
CREATE INDEX IF NOT EXISTS idx_clients_status ON clients(status);
CREATE INDEX IF NOT EXISTS idx_clients_name ON clients(name);

-- 2. PROJECTS TABLE
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  tenant_id TEXT NOT NULL,
  client_id TEXT,
  name TEXT NOT NULL,
  description TEXT,
  status TEXT DEFAULT 'active',
  start_date TEXT,
  end_date TEXT,
  created_at INTEGER DEFAULT (unixepoch()),
  updated_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_projects_tenant_id ON projects(tenant_id);
CREATE INDEX IF NOT EXISTS idx_projects_client_id ON projects(client_id);
CREATE INDEX IF NOT EXISTS idx_projects_status ON projects(status);

-- 3. SECURITY OFFICERS TABLE
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

-- 4. TRAINING MODULES TABLE
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

-- 5. USER TRAINING COMPLETIONS TABLE
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

-- 6. USER TERMINATIONS TABLE
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

-- 7. ROLES TABLE
CREATE TABLE IF NOT EXISTS roles (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  is_system_role INTEGER DEFAULT 0 CHECK (is_system_role IN (0, 1)),
  created_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  UNIQUE(tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_roles_tenant_id ON roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);

-- 8. PERMISSIONS TABLE
CREATE TABLE IF NOT EXISTS permissions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  resource_type TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('create', 'read', 'update', 'delete', 'export', 'print', 'share')),
  field_level INTEGER DEFAULT 0 CHECK (field_level IN (0, 1)),
  allowed_fields TEXT,
  description TEXT,
  UNIQUE(resource_type, action, field_level)
);

CREATE INDEX IF NOT EXISTS idx_permissions_resource_type ON permissions(resource_type);
CREATE INDEX IF NOT EXISTS idx_permissions_action ON permissions(action);

-- 9. ROLE PERMISSIONS MAPPING
CREATE TABLE IF NOT EXISTS role_permissions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  role_id TEXT NOT NULL,
  permission_id TEXT NOT NULL,
  constraints TEXT,
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
  FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
  UNIQUE(role_id, permission_id)
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);

-- 10. USER ROLES ASSIGNMENT
CREATE TABLE IF NOT EXISTS user_roles (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL,
  role_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  granted_by TEXT,
  granted_at INTEGER DEFAULT (unixepoch()),
  expires_at INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (granted_by) REFERENCES users(id) ON DELETE SET NULL,
  UNIQUE(user_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_tenant_id ON user_roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_expires_at ON user_roles(expires_at);

-- 11. SESSION ACTIVITIES TRACKING
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

-- 12. RE-AUTHENTICATION REQUIREMENTS TABLE
CREATE TABLE IF NOT EXISTS reauth_requirements (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  resource_type TEXT NOT NULL,
  action TEXT NOT NULL,
  max_age_seconds INTEGER NOT NULL DEFAULT 300,
  requires_mfa INTEGER DEFAULT 1 CHECK (requires_mfa IN (0, 1)),
  description TEXT,
  UNIQUE(resource_type, action)
);

-- 13. IMMUTABLE AUDIT LOGS TABLE (comprehensive tracking)
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

-- 14. BLOCKCHAIN-STYLE AUDIT CHAIN
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

-- 15. PHI ACCESS LOG
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

-- 16. DATA ENCRYPTION KEYS TABLE
CREATE TABLE IF NOT EXISTS data_encryption_keys (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  tenant_id TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  encrypted_key TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  algorithm TEXT NOT NULL DEFAULT 'AES-256-GCM',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'rotated', 'compromised')),
  created_at INTEGER DEFAULT (unixepoch()),
  rotated_at INTEGER,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_data_encryption_keys_tenant_id ON data_encryption_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_data_encryption_keys_status ON data_encryption_keys(status);
CREATE INDEX IF NOT EXISTS idx_data_encryption_keys_key_hash ON data_encryption_keys(key_hash);

-- 17. KEY ROTATION LOGS
CREATE TABLE IF NOT EXISTS key_rotation_logs (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  old_dek_id TEXT NOT NULL,
  new_dek_id TEXT NOT NULL,
  rotated_by TEXT NOT NULL,
  reason TEXT,
  records_reencrypted INTEGER DEFAULT 0,
  created_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (old_dek_id) REFERENCES data_encryption_keys(id) ON DELETE RESTRICT,
  FOREIGN KEY (new_dek_id) REFERENCES data_encryption_keys(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_key_rotation_logs_old_dek_id ON key_rotation_logs(old_dek_id);
CREATE INDEX IF NOT EXISTS idx_key_rotation_logs_new_dek_id ON key_rotation_logs(new_dek_id);
CREATE INDEX IF NOT EXISTS idx_key_rotation_logs_created_at ON key_rotation_logs(created_at);

-- 18. KEY COMPROMISE LOGS
CREATE TABLE IF NOT EXISTS key_compromise_logs (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  dek_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (dek_id) REFERENCES data_encryption_keys(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_key_compromise_logs_dek_id ON key_compromise_logs(dek_id);
CREATE INDEX IF NOT EXISTS idx_key_compromise_logs_created_at ON key_compromise_logs(created_at);

-- 19. MASTER KEY ACCESS LOG
CREATE TABLE IF NOT EXISTS master_key_access_log (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  operation TEXT NOT NULL,
  success INTEGER NOT NULL CHECK (success IN (0, 1)),
  error TEXT,
  created_at INTEGER DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_master_key_access_log_created_at ON master_key_access_log(created_at);
CREATE INDEX IF NOT EXISTS idx_master_key_access_log_operation ON master_key_access_log(operation);

-- =====================================================
-- TRIGGERS FOR IMMUTABILITY
-- =====================================================

-- Trigger to prevent updates to audit_logs
CREATE TRIGGER IF NOT EXISTS prevent_audit_logs_update
BEFORE UPDATE ON audit_logs
BEGIN
  SELECT RAISE(ABORT, 'Audit logs are immutable and cannot be updated');
END;

-- Trigger to prevent deletes from audit_logs
CREATE TRIGGER IF NOT EXISTS prevent_audit_logs_delete
BEFORE DELETE ON audit_logs
BEGIN
  SELECT RAISE(ABORT, 'Audit logs are immutable and cannot be deleted');
END;

-- Trigger to prevent updates to audit_chain
CREATE TRIGGER IF NOT EXISTS prevent_audit_chain_update
BEFORE UPDATE ON audit_chain
BEGIN
  SELECT RAISE(ABORT, 'Audit chain is immutable and cannot be updated');
END;

-- Trigger to prevent deletes from audit_chain
CREATE TRIGGER IF NOT EXISTS prevent_audit_chain_delete
BEFORE DELETE ON audit_chain
BEGIN
  SELECT RAISE(ABORT, 'Audit chain is immutable and cannot be deleted');
END;

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

-- =====================================================
-- DEFAULT DATA INSERTS
-- =====================================================

-- Insert default permissions
INSERT OR IGNORE INTO permissions (id, resource_type, action, field_level, description) VALUES
  ('perm_patient_read', 'patient', 'read', 0, 'Read patient records'),
  ('perm_patient_read_phi', 'patient', 'read', 1, 'Read specific PHI fields'),
  ('perm_patient_create', 'patient', 'create', 0, 'Create patient records'),
  ('perm_patient_update', 'patient', 'update', 0, 'Update patient records'),
  ('perm_patient_delete', 'patient', 'delete', 0, 'Delete patient records'),
  ('perm_patient_export', 'patient', 'export', 0, 'Export patient data'),
  ('perm_document_read', 'document', 'read', 0, 'Read documents'),
  ('perm_document_create', 'document', 'create', 0, 'Upload documents'),
  ('perm_document_update', 'document', 'update', 0, 'Update document metadata'),
  ('perm_document_delete', 'document', 'delete', 0, 'Delete documents'),
  ('perm_document_share', 'document', 'share', 0, 'Share documents'),
  ('perm_assessment_read', 'assessment', 'read', 0, 'Read assessments'),
  ('perm_assessment_create', 'assessment', 'create', 0, 'Create assessments'),
  ('perm_assessment_update', 'assessment', 'update', 0, 'Update assessments'),
  ('perm_assessment_delete', 'assessment', 'delete', 0, 'Delete assessments'),
  ('perm_time_read', 'time_entry', 'read', 0, 'Read time entries'),
  ('perm_time_create', 'time_entry', 'create', 0, 'Create time entries'),
  ('perm_time_update', 'time_entry', 'update', 0, 'Update time entries'),
  ('perm_time_delete', 'time_entry', 'delete', 0, 'Delete time entries');

-- Insert default roles for the default tenant
INSERT OR IGNORE INTO roles (id, tenant_id, name, description, is_system_role) VALUES
  ('role_admin', 'default', 'Administrator', 'Full system access', 1),
  ('role_clinician', 'default', 'Clinician', 'Clinical staff with patient access', 1),
  ('role_billing', 'default', 'Billing Staff', 'Billing and financial access only', 1),
  ('role_readonly', 'default', 'Read-Only User', 'View-only access to non-PHI data', 1);

-- Assign permissions to admin role (full access)
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT 'role_admin', id FROM permissions;

-- Assign permissions to clinician role (patient care focused)
INSERT OR IGNORE INTO role_permissions (role_id, permission_id, constraints)
VALUES
  ('role_clinician', 'perm_patient_read', '{"own_records_only": false}'),
  ('role_clinician', 'perm_patient_read_phi', '{"allowed_fields": ["ssn", "date_of_birth", "medical_record_number", "diagnosis_codes", "treatment_notes"]}'),
  ('role_clinician', 'perm_patient_create', NULL),
  ('role_clinician', 'perm_patient_update', '{"own_records_only": true}'),
  ('role_clinician', 'perm_document_read', NULL),
  ('role_clinician', 'perm_document_create', NULL),
  ('role_clinician', 'perm_assessment_read', NULL),
  ('role_clinician', 'perm_assessment_create', NULL),
  ('role_clinician', 'perm_assessment_update', '{"own_records_only": true}'),
  ('role_clinician', 'perm_time_read', '{"own_records_only": true}'),
  ('role_clinician', 'perm_time_create', NULL),
  ('role_clinician', 'perm_time_update', '{"own_records_only": true}');

-- Assign permissions to billing role (financial data only, minimal PHI)
INSERT OR IGNORE INTO role_permissions (role_id, permission_id, constraints)
VALUES
  ('role_billing', 'perm_patient_read_phi', '{"allowed_fields": ["insurance_id"]}'),
  ('role_billing', 'perm_time_read', NULL),
  ('role_billing', 'perm_assessment_read', '{"financial_only": true}');

-- Assign permissions to read-only role (no PHI access)
INSERT OR IGNORE INTO role_permissions (role_id, permission_id, constraints)
VALUES
  ('role_readonly', 'perm_time_read', '{"own_records_only": true}'),
  ('role_readonly', 'perm_document_read', '{"non_phi_only": true}');

-- Insert default re-authentication requirements
INSERT OR IGNORE INTO reauth_requirements (resource_type, action, max_age_seconds, requires_mfa, description)
VALUES
  ('patient', 'delete', 300, 1, 'Deleting patient records requires recent re-authentication'),
  ('patient', 'export', 300, 1, 'Exporting patient data requires recent re-authentication'),
  ('document', 'share', 300, 1, 'Sharing documents requires recent re-authentication'),
  ('user', 'update', 300, 1, 'Updating user permissions requires recent re-authentication'),
  ('settings', 'update', 300, 1, 'Updating security settings requires recent re-authentication');

-- INSERT DEFAULT TRAINING MODULES
INSERT OR IGNORE INTO training_modules (id, tenant_id, title, description, category, duration_minutes, required, frequency_days, version)
VALUES
  ('hipaa-basics', NULL, 'HIPAA Basics Training', 'Introduction to HIPAA Privacy and Security Rules', 'compliance', 60, 1, 365, 1),
  ('phi-handling', NULL, 'Protected Health Information Handling', 'Best practices for handling PHI data', 'compliance', 45, 1, 365, 1),
  ('security-awareness', NULL, 'Security Awareness Training', 'Recognizing and preventing security threats', 'security', 30, 1, 180, 1),
  ('breach-notification', NULL, 'Breach Notification Procedures', 'Steps to take when a breach occurs', 'incident-response', 30, 1, 365, 1),
  ('access-controls', NULL, 'Access Control Best Practices', 'Proper use of passwords, MFA, and access controls', 'security', 20, 1, 180, 1);
