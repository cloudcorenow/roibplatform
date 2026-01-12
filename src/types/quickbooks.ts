export interface QuickBooksConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  sandbox: boolean;
  companyId: string;
  accessToken?: string;
  refreshToken?: string;
}

export interface QuickBooksCustomer {
  id: string;
  name: string;
  companyName?: string;
  email?: string;
  phone?: string;
  address?: {
    line1?: string;
    city?: string;
    state?: string;
    postalCode?: string;
    country?: string;
  };
  active: boolean;
  createdTime: string;
  lastUpdatedTime: string;
}

export interface QuickBooksEmployee {
  id: string;
  givenName: string;
  familyName: string;
  displayName: string;
  email?: string;
  phone?: string;
  active: boolean;
  hiredDate?: string;
  releasedDate?: string;
}

export interface QuickBooksTimeActivity {
  id: string;
  employeeRef: string;
  customerRef?: string;
  itemRef?: string;
  date: string;
  startTime?: string;
  endTime?: string;
  hours: number;
  minutes: number;
  description?: string;
  billableStatus: 'billable' | 'not-billable' | 'has-been-billed';
  hourlyRate?: number;
  createdTime: string;
  lastUpdatedTime: string;
}

export interface QuickBooksItem {
  id: string;
  name: string;
  description?: string;
  type: 'service' | 'inventory' | 'non-inventory';
  unitPrice?: number;
  active: boolean;
}

export interface QuickBooksExpense {
  id: string;
  paymentType: 'cash' | 'check' | 'credit-card';
  accountRef: string;
  totalAmt: number;
  txnDate: string;
  privateNote?: string;
  line: {
    amount: number;
    description?: string;
    accountRef?: string;
    customerRef?: string;
    itemRef?: string;
  }[];
}

export interface QuickBooksSyncResult {
  success: boolean;
  message: string;
  syncedRecords: number;
  errors: string[];
  lastSyncTime: string;
}

export interface QuickBooksAuthResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  x_refresh_token_expires_in: number;
  realmId: string;
}