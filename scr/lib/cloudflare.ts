// Cloudflare Workers API client
export interface CloudflareConfig {
  apiUrl: string;
  tenantId: string;
  userId: string;
}

export class CloudflareAPI {
  private config: CloudflareConfig;

  constructor(config: CloudflareConfig) {
    this.config = config;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const token = btoa(JSON.stringify({
      tenant_id: this.config.tenantId,
      user_id: this.config.userId,
      exp: Date.now() + 3600000
    }));

    const response = await fetch(`${this.config.apiUrl}${endpoint}`, {
      ...options,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || `HTTP ${response.status}`);
    }

    return response.json();
  }

  // Time Entries
  async getTimeEntries(params: {
    limit?: number;
    offset?: number;
  } = {}) {
    const queryParams = new URLSearchParams();
    if (params.limit) queryParams.append('limit', params.limit.toString());
    if (params.offset) queryParams.append('offset', params.offset.toString());

    const endpoint = `/time-entries${queryParams.toString() ? `?${queryParams.toString()}` : ''}`;
    return this.request(endpoint);
  }

  async createTimeEntry(entry: {
    date: string;
    client: string;
    project: string;
    service: string;
    duration_min: number;
    notes?: string;
    is_rnd?: boolean;
  }) {
    return this.request('/time-entries', {
      method: 'POST',
      body: JSON.stringify(entry),
    });
  }

  async deleteTimeEntry(id: string) {
    return this.request(`/time-entries/${id}`, {
      method: 'DELETE',
    });
  }

  // CentralReach Integration
  async getCentralReachClients() {
    return this.request('/centralreach/clients');
  }

  async getCentralReachStaff() {
    return this.request('/centralreach/staff');
  }

  async syncCentralReach(syncType: 'clients' | 'timeentries' | 'all') {
    return this.request('/centralreach/sync', {
      method: 'POST',
      body: JSON.stringify({ syncType }),
    });
  }

  // QuickBooks Integration
  async getQuickBooksCustomers() {
    return this.request('/quickbooks/customers');
  }

  async getQuickBooksEmployees() {
    return this.request('/quickbooks/employees');
  }

  async saveQuickBooksConfig(config: any) {
    return this.request('/quickbooks/config', {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }
}

// Default instance
export const cloudflareApi = new CloudflareAPI({
  apiUrl: import.meta.env.VITE_API_URL || 'http://localhost:8787/api',
  tenantId: 'demo-tenant',
  userId: 'demo-user'
});