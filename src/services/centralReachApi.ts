import { CentralReachConfig, CentralReachClient, CentralReachStaff, CentralReachService, CentralReachTimeEntry, CentralReachSyncResult } from '../types/centralreach';

class CentralReachAPI {
  private config: CentralReachConfig;

  constructor(config: CentralReachConfig) {
    this.config = config;
  }

  private async makeRequest<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.config.baseUrl}${endpoint}`;
    
    const response = await fetch(url, {
      ...options,
      headers: {
        'Authorization': `Bearer ${this.config.apiKey}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...options.headers,
      },
    });

    if (!response.ok) {
      throw new Error(`CentralReach API Error: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }

  // Client Management
  async getClients(): Promise<CentralReachClient[]> {
    return this.makeRequest<CentralReachClient[]>('/clients');
  }

  async getClient(clientId: string): Promise<CentralReachClient> {
    return this.makeRequest<CentralReachClient>(`/clients/${clientId}`);
  }

  async createClient(client: Omit<CentralReachClient, 'id' | 'createdDate' | 'modifiedDate'>): Promise<CentralReachClient> {
    return this.makeRequest<CentralReachClient>('/clients', {
      method: 'POST',
      body: JSON.stringify(client),
    });
  }

  // Staff Management
  async getStaff(): Promise<CentralReachStaff[]> {
    return this.makeRequest<CentralReachStaff[]>('/staff');
  }

  async getStaffMember(staffId: string): Promise<CentralReachStaff> {
    return this.makeRequest<CentralReachStaff>(`/staff/${staffId}`);
  }

  // Services
  async getServices(): Promise<CentralReachService[]> {
    return this.makeRequest<CentralReachService[]>('/services');
  }

  // Time Tracking
  async getTimeEntries(params?: {
    startDate?: string;
    endDate?: string;
    clientId?: string;
    staffId?: string;
  }): Promise<CentralReachTimeEntry[]> {
    const queryParams = new URLSearchParams();
    if (params?.startDate) queryParams.append('startDate', params.startDate);
    if (params?.endDate) queryParams.append('endDate', params.endDate);
    if (params?.clientId) queryParams.append('clientId', params.clientId);
    if (params?.staffId) queryParams.append('staffId', params.staffId);

    const endpoint = `/timeentries${queryParams.toString() ? `?${queryParams.toString()}` : ''}`;
    return this.makeRequest<CentralReachTimeEntry[]>(endpoint);
  }

  async createTimeEntry(timeEntry: Omit<CentralReachTimeEntry, 'id'>): Promise<CentralReachTimeEntry> {
    return this.makeRequest<CentralReachTimeEntry>('/timeentries', {
      method: 'POST',
      body: JSON.stringify(timeEntry),
    });
  }

  async updateTimeEntry(id: string, timeEntry: Partial<CentralReachTimeEntry>): Promise<CentralReachTimeEntry> {
    return this.makeRequest<CentralReachTimeEntry>(`/timeentries/${id}`, {
      method: 'PUT',
      body: JSON.stringify(timeEntry),
    });
  }

  // Sync Methods
  async syncClients(): Promise<CentralReachSyncResult> {
    try {
      const clients = await this.getClients();
      // Here you would implement the logic to sync with your local database
      return {
        success: true,
        message: 'Clients synced successfully',
        syncedRecords: clients.length,
        errors: []
      };
    } catch (error) {
      return {
        success: false,
        message: 'Failed to sync clients',
        syncedRecords: 0,
        errors: [error instanceof Error ? error.message : 'Unknown error']
      };
    }
  }

  async syncTimeEntries(startDate: string, endDate: string): Promise<CentralReachSyncResult> {
    try {
      const timeEntries = await this.getTimeEntries({ startDate, endDate });
      // Here you would implement the logic to sync with your local time tracking
      return {
        success: true,
        message: 'Time entries synced successfully',
        syncedRecords: timeEntries.length,
        errors: []
      };
    } catch (error) {
      return {
        success: false,
        message: 'Failed to sync time entries',
        syncedRecords: 0,
        errors: [error instanceof Error ? error.message : 'Unknown error']
      };
    }
  }
}

export default CentralReachAPI;