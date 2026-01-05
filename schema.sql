-- Tenants table
CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  name TEXT NOT NULL,
  domain TEXT UNIQUE,
  settings TEXT,
  active INTEGER DEFAULT 1,
  created_at INTEGER DEFAULT (unixepoch()),
  updated_at INTEGER DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_tenants_domain ON tenants(domain);
CREATE INDEX IF NOT EXISTS idx_tenants_active ON tenants(active);

-- Insert default tenant if not exists
INSERT OR IGNORE INTO tenants (id, name, domain) VALUES ('default', 'Default Tenant', NULL);

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT,
  role TEXT NOT NULL DEFAULT 'user',
  user_type TEXT NOT NULL DEFAULT 'tenant',
  tenant_id TEXT,
  created_at INTEGER DEFAULT (unixepoch()),
  updated_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_user_type ON users(user_type);

-- Sessions table (for refresh tokens)
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL,
  refresh_token TEXT UNIQUE NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token ON sessions(refresh_token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- Time entries table
-- IMPORTANT: tenant_id is NOT NULL with NO DEFAULT to enforce explicit tenant assignment
CREATE TABLE IF NOT EXISTS time_entries (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  client_id TEXT,
  project_id TEXT,
  task TEXT NOT NULL,
  description TEXT,
  hours REAL NOT NULL,
  billable INTEGER DEFAULT 1,
  date TEXT NOT NULL,
  created_at INTEGER DEFAULT (unixepoch()),
  updated_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_time_entries_tenant_id ON time_entries(tenant_id);
CREATE INDEX IF NOT EXISTS idx_time_entries_user_id ON time_entries(user_id);
CREATE INDEX IF NOT EXISTS idx_time_entries_date ON time_entries(date);
CREATE INDEX IF NOT EXISTS idx_time_entries_client_id ON time_entries(client_id);

-- Documents table
-- IMPORTANT: tenant_id is NOT NULL with NO DEFAULT to enforce explicit tenant assignment
CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  filename TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  r2_key TEXT NOT NULL,
  category TEXT,
  tags TEXT,
  created_at INTEGER DEFAULT (unixepoch()),
  updated_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_documents_tenant_id ON documents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_documents_user_id ON documents(user_id);
CREATE INDEX IF NOT EXISTS idx_documents_category ON documents(category);

-- Assessments table
-- IMPORTANT: tenant_id is NOT NULL with NO DEFAULT to enforce explicit tenant assignment
-- results is NULLABLE to support draft → completed workflow
CREATE TABLE IF NOT EXISTS assessments (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  tenant_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft',
  responses TEXT NOT NULL,
  results TEXT,
  score REAL DEFAULT 0,
  completed_at INTEGER,
  created_by TEXT,
  created_at INTEGER DEFAULT (unixepoch()),
  updated_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_assessments_tenant_id ON assessments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_assessments_client_id ON assessments(client_id);
CREATE INDEX IF NOT EXISTS idx_assessments_status ON assessments(status);
CREATE INDEX IF NOT EXISTS idx_assessments_created_by ON assessments(created_by);

-- Tenant switches audit log (for platform admins)
-- IMPORTANT: Uses platform_user_id (clearer than admin_id long-term)
-- IMPORTANT: Tenant FKs use ON DELETE SET NULL to preserve audit history
CREATE TABLE IF NOT EXISTS tenant_switches (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  platform_user_id TEXT NOT NULL,
  from_tenant_id TEXT,
  to_tenant_id TEXT NOT NULL,
  reason TEXT,
  ip_address TEXT,
  user_agent TEXT,
  switched_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (platform_user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (from_tenant_id) REFERENCES tenants(id) ON DELETE SET NULL,
  FOREIGN KEY (to_tenant_id) REFERENCES tenants(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_tenant_switches_platform_user_id ON tenant_switches(platform_user_id);
CREATE INDEX IF NOT EXISTS idx_tenant_switches_to_tenant_id ON tenant_switches(to_tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_switches_switched_at ON tenant_switches(switched_at);
CREATE INDEX IF NOT EXISTS idx_tenant_switches_platform_user_id_switched_at ON tenant_switches(platform_user_id, switched_at);

-- Emergency access requests (for compliance)
-- IMPORTANT: Uses platform_user_id (consistent naming)
-- IMPORTANT: Tenant FK uses ON DELETE SET NULL to preserve audit history
CREATE TABLE IF NOT EXISTS emergency_access_requests (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  platform_user_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  approved_by TEXT,
  approved_at INTEGER,
  expires_at INTEGER NOT NULL,
  created_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (platform_user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL,
  FOREIGN KEY (approved_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_emergency_access_platform_user_id ON emergency_access_requests(platform_user_id);
CREATE INDEX IF NOT EXISTS idx_emergency_access_tenant_id ON emergency_access_requests(tenant_id);
CREATE INDEX IF NOT EXISTS idx_emergency_access_status ON emergency_access_requests(status);
CREATE INDEX IF NOT EXISTS idx_emergency_access_expires_at ON emergency_access_requests(expires_at);
CREATE INDEX IF NOT EXISTS idx_emergency_access_platform_user_id_created_at ON emergency_access_requests(platform_user_id, created_at);

-- Audit log (unified compliance trail)
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  ip_address TEXT,
  user_agent TEXT,
  details TEXT,
  created_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_id ON audit_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_resource_type ON audit_log(resource_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_id_created_at ON audit_log(tenant_id, created_at);
