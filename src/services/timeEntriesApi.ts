import { TimeEntry, TimeEntryCreateRequest, TimeEntryListResponse } from '../types/time';
import { TimeEntryListResponseSchema, ApiErrorSchema } from '../utils/validation';

export interface ListTimeEntriesParams {
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
}

class TimeEntriesAPI {
  private baseUrl: string;

  constructor() {
    this.baseUrl = `${import.meta.env.VITE_API_URL || 'http://localhost:8787'}/api`;
  }

  private async getAuthHeaders() {
    const token = localStorage.getItem('auth_token');
    if (!token) {
      throw new Error('Please log in to continue');
    }

    return {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    };
  }

  private async handleResponse<T>(response: Response, schema?: any): Promise<T> {
    if (!response.ok) {
      let errorData;
      try {
        errorData = await response.json();
        // Validate error response format
        const validatedError = ApiErrorSchema.safeParse(errorData);
        if (validatedError.success) {
          throw new Error(validatedError.data.error);
        }
      } catch (parseError) {
        // Fallback for non-JSON errors
      }
      
      throw new Error(errorData?.error || `HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    
    // Validate response if schema provided
    if (schema) {
      const result = schema.safeParse(data);
      if (!result.success) {
        console.error('API response validation failed:', result.error);
        throw new Error('Invalid response format from server');
      }
      return result.data;
    }
    
    return data;
  }

  async listTimeEntries(params: ListTimeEntriesParams = {}): Promise<TimeEntryListResponse> {
    const { from, to, limit = 50, offset = 0 } = params;
    const headers = await this.getAuthHeaders();
    
    const url = new URL(`${this.baseUrl}/time-entries`);
    if (from) url.searchParams.set('from', from);
    if (to) url.searchParams.set('to', to);
    url.searchParams.set('limit', Math.min(limit, 200).toString()); // Client-side cap
    url.searchParams.set('offset', offset.toString());

    const response = await fetch(url.toString(), { 
      headers,
      signal: AbortSignal.timeout(10000)
    });

    return this.handleResponse<TimeEntryListResponse>(response, TimeEntryListResponseSchema);
  }

  async createTimeEntry(entry: TimeEntryCreateRequest): Promise<TimeEntry> {
    const headers = await this.getAuthHeaders();

    const response = await fetch(`${this.baseUrl}/time-entries`, {
      method: 'POST',
      headers,
      signal: AbortSignal.timeout(10000),
      body: JSON.stringify({
        date: entry.date,
        client: entry.client,
        project: entry.project,
        service: entry.service,
        durationMin: entry.durationMin,
        notes: entry.notes,
        isRnD: entry.isRnD ?? true
      })
    });

    const result = await this.handleResponse<{ data: TimeEntry }>(response);
    return result.data;
  }

  async deleteTimeEntry(id: string): Promise<void> {
    const headers = await this.getAuthHeaders();

    const response = await fetch(`${this.baseUrl}/time-entries/${id}`, {
      method: 'DELETE',
      headers,
      signal: AbortSignal.timeout(10000)
    });

    await this.handleResponse<{ success: boolean }>(response);
  }

  async getTimeEntry(id: string): Promise<TimeEntry> {
    const headers = await this.getAuthHeaders();

    const response = await fetch(`${this.baseUrl}/time-entries/${id}`, {
      headers,
      signal: AbortSignal.timeout(10000)
    });

    const result = await this.handleResponse<{ data: TimeEntry }>(response);
    return result.data;
  }

  async batchCreateTimeEntries(entries: TimeEntryCreateRequest[]): Promise<{ success: boolean; count: number; ids: string[] }> {
    const headers = await this.getAuthHeaders();

    const response = await fetch(`${this.baseUrl}/time-entries/batch`, {
      method: 'POST',
      headers,
      signal: AbortSignal.timeout(30000),
      body: JSON.stringify({
        entries: entries.map(entry => ({
          date: entry.date,
          client: entry.client,
          project: entry.project,
          service: entry.service,
          durationMin: entry.durationMin,
          notes: entry.notes,
          isRnD: entry.isRnD ?? true
        }))
      })
    });

    return this.handleResponse<{ success: boolean; count: number; ids: string[] }>(response);
  }
}

export const timeEntriesApi = new TimeEntriesAPI();

export const listTimeEntries = (params: ListTimeEntriesParams) => timeEntriesApi.listTimeEntries(params);
export const createTimeEntry = (entry: TimeEntryCreateRequest) => timeEntriesApi.createTimeEntry(entry);
export const deleteTimeEntry = (id: string) => timeEntriesApi.deleteTimeEntry(id);
export const getTimeEntry = (id: string) => timeEntriesApi.getTimeEntry(id);
export const batchCreateTimeEntries = (entries: TimeEntryCreateRequest[]) => timeEntriesApi.batchCreateTimeEntries(entries);