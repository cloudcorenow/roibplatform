export interface TimeEntry {
  tenantId: string;
  id: string;
  date: string; // ISO YYYY-MM-DD format
  client: string;
  project: string;
  service: string;
  durationMin: number;
  notes?: string;
  isRnD: boolean;
  employeeId?: string;
  employeeName?: string;
  projectId?: string;
  projectName?: string;
  status?: 'active' | 'completed' | 'paused';
  createdAt?: string;
  updatedAt?: string;
  createdBy?: string;
}

export interface TimeEntryCreateRequest {
  date: string;
  client: string;
  project: string;
  service: string;
  durationMin: number;
  notes?: string;
  isRnD?: boolean;
}

export interface TimeEntryListResponse {
  items: TimeEntry[];
  paging: {
    limit: number;
    offset: number;
    nextOffset: number | null;
    prevOffset: number | null;
    from?: string;
    to?: string;
  };
  total: number;
}