export interface SecurityOfficer {
  id: string;
  tenant_id: string;
  user_id: string;
  designation: string;
  responsibilities?: string;
  appointed_at: number;
  appointed_by?: string;
  status: 'active' | 'inactive';
  deactivated_at?: number;
  created_at: number;
  updated_at: number;
}

export interface TrainingModule {
  id: string;
  tenant_id?: string;
  title: string;
  description?: string;
  content?: string;
  category: 'compliance' | 'security' | 'incident-response' | 'privacy';
  duration_minutes?: number;
  required: boolean;
  frequency_days?: number;
  passing_score: number;
  version: number;
  active: boolean;
  created_by?: string;
  created_at: number;
  updated_at: number;
}

export interface UserTrainingCompletion {
  id: string;
  tenant_id: string;
  user_id: string;
  module_id: string;
  status: 'not_started' | 'in_progress' | 'completed' | 'failed' | 'expired';
  score?: number;
  attempts: number;
  started_at: number;
  completed_at?: number;
  expires_at?: number;
  certificate_issued: boolean;
  created_at: number;
}

export interface SecurityIncident {
  id: string;
  tenant_id: string;
  incident_type: 'breach' | 'unauthorized_access' | 'data_loss' | 'malware' | 'phishing' | 'other';
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  affected_systems?: string;
  affected_users?: string;
  reported_by: string;
  assigned_to?: string;
  status: 'open' | 'investigating' | 'contained' | 'resolved' | 'closed';
  resolution?: string;
  resolved_at?: number;
  ip_address?: string;
  user_agent?: string;
  metadata?: string;
  created_at: number;
  updated_at: number;
}

export interface UserTermination {
  id: string;
  tenant_id: string;
  user_id: string;
  terminated_by: string;
  termination_type: 'voluntary' | 'involuntary' | 'contract_end' | 'other';
  reason: string;
  access_revoked_at: number;
  data_archived: boolean;
  data_archive_location?: string;
  devices_returned: boolean;
  exit_interview_completed: boolean;
  checklist_completed?: string;
  notes?: string;
  created_at: number;
}

export interface DocumentVersion {
  id: string;
  tenant_id: string;
  document_id: string;
  version: number;
  filename: string;
  mime_type: string;
  size_bytes: number;
  r2_key: string;
  checksum: string;
  uploaded_by: string;
  change_description?: string;
  previous_checksum?: string;
  verified: boolean;
  created_at: number;
}

export interface PasswordHistory {
  id: string;
  user_id: string;
  password_hash: string;
  created_at: number;
}

export interface MFASetupResponse {
  success: boolean;
  secret: string;
  otpauthUrl: string;
  backupCodes: string[];
}

export interface MFAVerifyRequest {
  token: string;
}

export interface MFALoginRequest {
  userId: string;
  token: string;
}

export interface UserSecurityProfile {
  password_last_changed: number;
  password_expires_at?: number;
  force_password_change: boolean;
  failed_login_attempts: number;
  account_locked_until?: number;
  last_login_at?: number;
  last_login_ip?: string;
  mfa_enabled: boolean;
  mfa_secret?: string;
  mfa_backup_codes?: string;
  mfa_enabled_at?: number;
  status: 'active' | 'inactive' | 'locked' | 'suspended';
  deactivated_at?: number;
  deactivated_by?: string;
  deactivation_reason?: string;
}

export interface SessionInfo {
  id: string;
  user_id: string;
  refresh_token: string;
  expires_at: number;
  last_activity: number;
  ip_address?: string;
  user_agent?: string;
  created_at: number;
}

export interface AuditLogEntry {
  id: string;
  tenant_id: string;
  user_id: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  ip_address?: string;
  user_agent?: string;
  details?: string;
  created_at: number;
}

export interface ComplianceReport {
  period_start: number;
  period_end: number;
  total_users: number;
  active_users: number;
  mfa_enabled_users: number;
  mfa_percentage: number;
  training_compliance_rate: number;
  password_compliance_rate: number;
  open_incidents: number;
  resolved_incidents: number;
  failed_login_attempts: number;
  locked_accounts: number;
  document_uploads: number;
  audit_log_entries: number;
}

export interface TrainingComplianceStatus {
  user_id: string;
  user_name: string;
  user_email: string;
  completed_modules: number;
  required_modules: number;
  compliance_percentage: number;
  expired_trainings: number;
  upcoming_expirations: number;
  last_training_completed?: number;
}

export interface PasswordPolicyCompliance {
  user_id: string;
  user_email: string;
  password_age_days: number;
  needs_change: boolean;
  mfa_enabled: boolean;
  last_login_days_ago: number;
  risk_score: 'low' | 'medium' | 'high';
}

export type HIPAAComplianceArea =
  | 'access_controls'
  | 'audit_controls'
  | 'integrity_controls'
  | 'transmission_security'
  | 'authentication'
  | 'encryption'
  | 'workforce_training'
  | 'incident_response'
  | 'business_associate'
  | 'risk_assessment';

export interface ComplianceChecklist {
  area: HIPAAComplianceArea;
  requirement: string;
  status: 'compliant' | 'partial' | 'non_compliant' | 'not_applicable';
  evidence?: string;
  notes?: string;
  last_reviewed: number;
  reviewed_by: string;
}
