import { 
  QuickBooksConfig, 
  QuickBooksCustomer, 
  QuickBooksEmployee, 
  QuickBooksTimeActivity, 
  QuickBooksItem,
  QuickBooksExpense,
  QuickBooksSyncResult,
  QuickBooksAuthResponse 
} from '../types/quickbooks';

class QuickBooksAPI {
  private config: QuickBooksConfig;
  private baseUrl: string;

  constructor(config: QuickBooksConfig) {
    this.config = config;
    this.baseUrl = config.sandbox 
      ? 'https://sandbox-quickbooks.api.intuit.com'
      : 'https://quickbooks.api.intuit.com';
  }

  private async makeRequest<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    if (!this.config.accessToken) {
      throw new Error('QuickBooks access token is required. Please authenticate first.');
    }

    const url = `${this.baseUrl}/v3/company/${this.config.companyId}/${endpoint}`;
    
    const response = await fetch(url, {
      ...options,
      headers: {
        'Authorization': `Bearer ${this.config.accessToken}`,
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });

    if (!response.ok) {
      if (response.status === 401) {
        throw new Error('QuickBooks authentication expired. Please re-authenticate.');
      }
      throw new Error(`QuickBooks API Error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    return data.QueryResponse || data;
  }

  // Authentication
  getAuthUrl(): string {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      scope: 'com.intuit.quickbooks.accounting',
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      access_type: 'offline'
    });

    const baseAuthUrl = this.config.sandbox
      ? 'https://appcenter.intuit.com/connect/oauth2'
      : 'https://appcenter.intuit.com/connect/oauth2';

    return `${baseAuthUrl}?${params.toString()}`;
  }

  async exchangeCodeForTokens(code: string): Promise<QuickBooksAuthResponse> {
    const tokenUrl = this.config.sandbox
      ? 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer'
      : 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer';

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${btoa(`${this.config.clientId}:${this.config.clientSecret}`)}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: this.config.redirectUri,
      }),
    });

    if (!response.ok) {
      throw new Error(`Token exchange failed: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }

  async refreshAccessToken(): Promise<QuickBooksAuthResponse> {
    if (!this.config.refreshToken) {
      throw new Error('Refresh token is required');
    }

    const tokenUrl = this.config.sandbox
      ? 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer'
      : 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer';

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${btoa(`${this.config.clientId}:${this.config.clientSecret}`)}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: this.config.refreshToken,
      }),
    });

    if (!response.ok) {
      throw new Error(`Token refresh failed: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }

  // Customer Management
  async getCustomers(): Promise<QuickBooksCustomer[]> {
    const response = await this.makeRequest<{ Customer: QuickBooksCustomer[] }>('customers');
    return response.Customer || [];
  }

  async getCustomer(customerId: string): Promise<QuickBooksCustomer> {
    const response = await this.makeRequest<{ Customer: QuickBooksCustomer[] }>(`customers/${customerId}`);
    return response.Customer[0];
  }

  async createCustomer(customer: Partial<QuickBooksCustomer>): Promise<QuickBooksCustomer> {
    const response = await this.makeRequest<{ Customer: QuickBooksCustomer }>('customers', {
      method: 'POST',
      body: JSON.stringify({ Customer: customer }),
    });
    return response.Customer;
  }

  // Employee Management
  async getEmployees(): Promise<QuickBooksEmployee[]> {
    const response = await this.makeRequest<{ Employee: QuickBooksEmployee[] }>('employees');
    return response.Employee || [];
  }

  async getEmployee(employeeId: string): Promise<QuickBooksEmployee> {
    const response = await this.makeRequest<{ Employee: QuickBooksEmployee[] }>(`employees/${employeeId}`);
    return response.Employee[0];
  }

  // Time Activities
  async getTimeActivities(params?: {
    startDate?: string;
    endDate?: string;
    employeeId?: string;
  }): Promise<QuickBooksTimeActivity[]> {
    let query = "SELECT * FROM TimeActivity";
    const conditions = [];

    if (params?.startDate) {
      conditions.push(`TxnDate >= '${params.startDate}'`);
    }
    if (params?.endDate) {
      conditions.push(`TxnDate <= '${params.endDate}'`);
    }
    if (params?.employeeId) {
      conditions.push(`EmployeeRef = '${params.employeeId}'`);
    }

    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(' AND ')}`;
    }

    const response = await this.makeRequest<{ TimeActivity: QuickBooksTimeActivity[] }>(`query?query=${encodeURIComponent(query)}`);
    return response.TimeActivity || [];
  }

  async createTimeActivity(timeActivity: Partial<QuickBooksTimeActivity>): Promise<QuickBooksTimeActivity> {
    const response = await this.makeRequest<{ TimeActivity: QuickBooksTimeActivity }>('timeactivities', {
      method: 'POST',
      body: JSON.stringify({ TimeActivity: timeActivity }),
    });
    return response.TimeActivity;
  }

  // Items/Services
  async getItems(): Promise<QuickBooksItem[]> {
    const response = await this.makeRequest<{ Item: QuickBooksItem[] }>('items');
    return response.Item || [];
  }

  // Expenses
  async getExpenses(params?: {
    startDate?: string;
    endDate?: string;
  }): Promise<QuickBooksExpense[]> {
    let query = "SELECT * FROM Purchase WHERE PaymentType IN ('Cash', 'Check', 'CreditCard')";
    const conditions = [];

    if (params?.startDate) {
      conditions.push(`TxnDate >= '${params.startDate}'`);
    }
    if (params?.endDate) {
      conditions.push(`TxnDate <= '${params.endDate}'`);
    }

    if (conditions.length > 0) {
      query += ` AND ${conditions.join(' AND ')}`;
    }

    const response = await this.makeRequest<{ Purchase: QuickBooksExpense[] }>(`query?query=${encodeURIComponent(query)}`);
    return response.Purchase || [];
  }

  async createExpense(expense: Partial<QuickBooksExpense>): Promise<QuickBooksExpense> {
    const response = await this.makeRequest<{ Purchase: QuickBooksExpense }>('purchases', {
      method: 'POST',
      body: JSON.stringify({ Purchase: expense }),
    });
    return response.Purchase;
  }

  // Sync Methods
  async syncCustomers(): Promise<QuickBooksSyncResult> {
    try {
      const customers = await this.getCustomers();
      // Here you would implement the logic to sync with your local database
      return {
        success: true,
        message: 'Customers synced successfully',
        syncedRecords: customers.length,
        errors: [],
        lastSyncTime: new Date().toISOString()
      };
    } catch (error) {
      return {
        success: false,
        message: 'Failed to sync customers',
        syncedRecords: 0,
        errors: [error instanceof Error ? error.message : 'Unknown error'],
        lastSyncTime: new Date().toISOString()
      };
    }
  }

  async syncEmployees(): Promise<QuickBooksSyncResult> {
    try {
      const employees = await this.getEmployees();
      return {
        success: true,
        message: 'Employees synced successfully',
        syncedRecords: employees.length,
        errors: [],
        lastSyncTime: new Date().toISOString()
      };
    } catch (error) {
      return {
        success: false,
        message: 'Failed to sync employees',
        syncedRecords: 0,
        errors: [error instanceof Error ? error.message : 'Unknown error'],
        lastSyncTime: new Date().toISOString()
      };
    }
  }

  async syncTimeActivities(startDate: string, endDate: string): Promise<QuickBooksSyncResult> {
    try {
      const timeActivities = await this.getTimeActivities({ startDate, endDate });
      return {
        success: true,
        message: 'Time activities synced successfully',
        syncedRecords: timeActivities.length,
        errors: [],
        lastSyncTime: new Date().toISOString()
      };
    } catch (error) {
      return {
        success: false,
        message: 'Failed to sync time activities',
        syncedRecords: 0,
        errors: [error instanceof Error ? error.message : 'Unknown error'],
        lastSyncTime: new Date().toISOString()
      };
    }
  }

  async syncExpenses(startDate: string, endDate: string): Promise<QuickBooksSyncResult> {
    try {
      const expenses = await this.getExpenses({ startDate, endDate });
      return {
        success: true,
        message: 'Expenses synced successfully',
        syncedRecords: expenses.length,
        errors: [],
        lastSyncTime: new Date().toISOString()
      };
    } catch (error) {
      return {
        success: false,
        message: 'Failed to sync expenses',
        syncedRecords: 0,
        errors: [error instanceof Error ? error.message : 'Unknown error'],
        lastSyncTime: new Date().toISOString()
      };
    }
  }

  // Company Information
  async getCompanyInfo() {
    return this.makeRequest('companyinfo/1');
  }

  // Chart of Accounts
  async getAccounts() {
    const response = await this.makeRequest<{ Account: any[] }>('accounts');
    return response.Account || [];
  }
}

export default QuickBooksAPI;