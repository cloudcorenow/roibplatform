export interface CentralReachConfig {
  apiKey: string;
  baseUrl: string;
  organizationId: string;
}

export interface CentralReachClient {
  id: string;
  firstName: string;
  lastName: string;
  email?: string;
  phone?: string;
  dateOfBirth?: string;
  status: 'active' | 'inactive';
  createdDate: string;
  modifiedDate: string;
}

export interface CentralReachStaff {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  role: string;
  department?: string;
  isActive: boolean;
  hireDate?: string;
}

export interface CentralReachService {
  id: string;
  name: string;
  code: string;
  description?: string;
  category: string;
  isActive: boolean;
}

export interface CentralReachTimeEntry {
  id: string;
  clientId: string;
  staffId: string;
  serviceId: string;
  date: string;
  startTime: string;
  endTime: string;
  duration: number; // in minutes
  notes?: string;
  status: 'draft' | 'submitted' | 'approved' | 'billed';
  billable: boolean;
}

export interface CentralReachSyncResult {
  success: boolean;
  message: string;
  syncedRecords: number;
  errors: string[];
}