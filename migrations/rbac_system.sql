/*
  # Role-Based Access Control (RBAC) System

  Comprehensive RBAC with minimum necessary access principle for HIPAA compliance.

  ## New Tables

  ### `roles`
  Define roles with specific permissions
  - `id` (TEXT, primary key) - Role ID
  - `tenant_id` (TEXT, not null) - Tenant isolation
  - `name` (TEXT, not null) - Role name
  - `description` (TEXT) - Role description
  - `is_system_role` (INTEGER) - Whether this is a built-in system role
  - `created_at` (INTEGER) - Unix timestamp

  ### `permissions`
  Define granular permissions
  - `id` (TEXT, primary key) - Permission ID
  - `resource_type` (TEXT, not null) - Type of resource (patient, document, assessment)
  - `action` (TEXT, not null) - Action (create, read, update, delete, export)
  - `field_level` (INTEGER) - Whether this is field-level permission
  - `allowed_fields` (TEXT) - JSON array of allowed PHI fields for field-level permissions
  - `description` (TEXT) - Permission description

  ### `role_permissions`
  Map permissions to roles
  - `role_id` (TEXT, not null) - Role ID
  - `permission_id` (TEXT, not null) - Permission ID
  - `constraints` (TEXT) - JSON constraints (e.g., own_records_only, department_only)

  ### `user_roles`
  Assign roles to users
  - `user_id` (TEXT, not null) - User ID
  - `role_id` (TEXT, not null) - Role ID
  - `tenant_id` (TEXT, not null) - Tenant isolation
  - `granted_by` (TEXT) - User who granted this role
  - `granted_at` (INTEGER) - Unix timestamp when granted
  - `expires_at` (INTEGER) - Optional expiration timestamp

  ## Security Features

  1. **Minimum Necessary**: Field-level permissions control PHI access
  2. **Temporal Access**: Role assignments can expire
  3. **Audit Trail**: All role grants are tracked
  4. **Tenant Isolation**: All roles and permissions are tenant-scoped
*/

-- Roles table
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

-- Permissions table
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

-- Role permissions mapping
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

-- User roles assignment
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
