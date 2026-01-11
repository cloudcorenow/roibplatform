// Secure API wrapper for server-side integrations
// This prevents exposing API keys in the client

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export class SecureApiClient {
  private baseUrl: string;

  constructor(baseUrl: string = '/api') {
    this.baseUrl = baseUrl;
  }

  private async request<T>(
    endpoint: string, 
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    try {
      const response = await fetch(`${this.baseUrl}${endpoint}`, {
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
        ...options,
      });

      const data = await response.json();

      if (!response.ok) {
        return {
          success: false,
          error: data.error || `HTTP ${response.status}`,
          message: data.message
        };
      }

      return {
        success: true,
        data: data.data || data
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  // CentralReach endpoints (server-side proxy)
  async getCentralReachClients() {
    return this.request('/centralreach/clients');
  }

  async getCentralReachStaff() {
    return this.request('/centralreach/staff');
  }

  async getCentralReachTimeEntries(params?: {
    startDate?: string;
    endDate?: string;
    clientId?: string;
  }) {
    const queryParams = new URLSearchParams();
    if (params?.startDate) queryParams.append('startDate', params.startDate);
    if (params?.endDate) queryParams.append('endDate', params.endDate);
    if (params?.clientId) queryParams.append('clientId', params.clientId);

    const endpoint = `/centralreach/timeentries${queryParams.toString() ? `?${queryParams.toString()}` : ''}`;
    return this.request(endpoint);
  }

  // QuickBooks endpoints (server-side proxy)
  async getQuickBooksCustomers() {
    return this.request('/quickbooks/customers');
  }

  async getQuickBooksEmployees() {
    return this.request('/quickbooks/employees');
  }

  async getQuickBooksTimeActivities(params?: {
    startDate?: string;
    endDate?: string;
    employeeId?: string;
  }) {
    const queryParams = new URLSearchParams();
    if (params?.startDate) queryParams.append('startDate', params.startDate);
    if (params?.endDate) queryParams.append('endDate', params.endDate);
    if (params?.employeeId) queryParams.append('employeeId', params.employeeId);

    const endpoint = `/quickbooks/timeactivities${queryParams.toString() ? `?${queryParams.toString()}` : ''}`;
    return this.request(endpoint);
  }

  async getQuickBooksExpenses(params?: {
    startDate?: string;
    endDate?: string;
  }) {
    const queryParams = new URLSearchParams();
    if (params?.startDate) queryParams.append('startDate', params.startDate);
    if (params?.endDate) queryParams.append('endDate', params.endDate);

    const endpoint = `/quickbooks/expenses${queryParams.toString() ? `?${queryParams.toString()}` : ''}`;
    return this.request(endpoint);
  }
}

export const secureApi = new SecureApiClient();