export const PHI_FIELDS = [
  'ssn',
  'date_of_birth',
  'medical_record_number',
  'insurance_id',
  'diagnosis_codes',
  'treatment_notes',
  'prescription_info',
  'lab_results',
  'phone_number',
  'email',
  'address',
  'emergency_contact',
  'client_name',
  'full_name',
  'first_name',
  'last_name',
  'results',
  'responses',
  'qualified_expenses',
  'notes',
  'description',
  'client',
  'project',
  'filename',
  'file_name',
  'file_content',
  'category'
] as const;

export type PHIField = typeof PHI_FIELDS[number];

export const isPHIField = (field: string): field is PHIField => {
  return PHI_FIELDS.includes(field as PHIField);
};

export const PHI_BEARING_TABLES = [
  'assessments',
  'documents',
  'time_entries',
  'users',
  'clients',
  'sessions',
  'audit_logs',
  'phi_access_log'
] as const;

export type PHITable = typeof PHI_BEARING_TABLES[number];

export const isPHITable = (table: string): table is PHITable => {
  return PHI_BEARING_TABLES.includes(table as PHITable);
};

export const PHI_ROUTES = [
  '/api/assessments',
  '/api/time-entries',
  '/api/documents',
  '/api/clients'
] as const;

export type PHIRoute = typeof PHI_ROUTES[number];

export const isPHIRoute = (path: string): path is PHIRoute => {
  return PHI_ROUTES.some(route => path.startsWith(route));
};

export const TABLE_PHI_FIELDS: Record<string, PHIField[]> = {
  assessments: ['client_name', 'results', 'responses', 'qualified_expenses', 'description'],
  time_entries: ['notes', 'description', 'client', 'project'],
  documents: ['filename', 'file_name', 'file_content', 'category', 'description'],
  users: ['email', 'phone_number', 'full_name', 'first_name', 'last_name', 'address'],
  clients: ['full_name', 'first_name', 'last_name', 'email', 'phone_number', 'address', 'ssn', 'date_of_birth'],
  sessions: ['ssn', 'medical_record_number', 'insurance_id', 'diagnosis_codes', 'treatment_notes', 'prescription_info', 'lab_results']
};

export const getTablePHIFields = (table: string): PHIField[] => {
  return TABLE_PHI_FIELDS[table] || [];
};

export const isJSONBlobField = (field: string): boolean => {
  return ['responses', 'results', 'qualified_expenses'].includes(field);
};
