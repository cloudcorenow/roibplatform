-- =====================================================
-- SCHEMA FIXES - Align Database with Application Code
-- =====================================================

-- FIX 1: time_entries table - Add missing columns
ALTER TABLE time_entries ADD COLUMN client TEXT;
ALTER TABLE time_entries ADD COLUMN project TEXT;
ALTER TABLE time_entries ADD COLUMN service TEXT;
ALTER TABLE time_entries ADD COLUMN duration_min INTEGER;
ALTER TABLE time_entries ADD COLUMN is_rnd INTEGER DEFAULT 0;
ALTER TABLE time_entries ADD COLUMN employee_id TEXT;
ALTER TABLE time_entries ADD COLUMN employee_name TEXT;
ALTER TABLE time_entries ADD COLUMN created_by TEXT;

CREATE INDEX IF NOT EXISTS idx_time_entries_is_rnd ON time_entries(is_rnd);
CREATE INDEX IF NOT EXISTS idx_time_entries_employee_id ON time_entries(employee_id);
CREATE INDEX IF NOT EXISTS idx_time_entries_created_by ON time_entries(created_by);

-- FIX 2: clients table - Add missing columns
ALTER TABLE clients ADD COLUMN industry TEXT;
ALTER TABLE clients ADD COLUMN contact_person TEXT;

CREATE INDEX IF NOT EXISTS idx_clients_industry ON clients(industry);

-- FIX 3: projects table - Add missing column
ALTER TABLE projects ADD COLUMN is_rnd INTEGER DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_projects_is_rnd ON projects(is_rnd);

-- FIX 4: documents table - Add missing columns
ALTER TABLE documents ADD COLUMN file_name TEXT;
ALTER TABLE documents ADD COLUMN file_size INTEGER;
ALTER TABLE documents ADD COLUMN file_type TEXT;
ALTER TABLE documents ADD COLUMN description TEXT;
ALTER TABLE documents ADD COLUMN uploaded_by TEXT;

-- Create indexes for new document columns
CREATE INDEX IF NOT EXISTS idx_documents_file_name ON documents(file_name);
CREATE INDEX IF NOT EXISTS idx_documents_uploaded_by ON documents(uploaded_by);

-- FIX 5: document_versions table - Recreate properly
DROP TABLE IF EXISTS document_versions;

CREATE TABLE document_versions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  document_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  filename TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  r2_key TEXT NOT NULL,
  checksum TEXT NOT NULL,
  uploaded_by TEXT NOT NULL,
  verified INTEGER DEFAULT 0,
  change_description TEXT,
  created_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_document_versions_document_id ON document_versions(document_id);
CREATE INDEX IF NOT EXISTS idx_document_versions_tenant_id ON document_versions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_document_versions_version ON document_versions(document_id, version);
CREATE INDEX IF NOT EXISTS idx_document_versions_checksum ON document_versions(checksum);
CREATE INDEX IF NOT EXISTS idx_document_versions_uploaded_by ON document_versions(uploaded_by);
CREATE INDEX IF NOT EXISTS idx_document_versions_created_at ON document_versions(created_at);
