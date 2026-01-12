import { Assessment, AssessmentFormData, CalculationResults } from '../types/assessment';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8787';

function getAuthHeaders(): HeadersInit {
  const token = localStorage.getItem('auth_token');
  return {
    'Content-Type': 'application/json',
    'Authorization': token ? `Bearer ${token}` : '',
  };
}

export const assessmentsApi = {
  async list(tenantId: string): Promise<Assessment[]> {
    const response = await fetch(
      `${API_URL}/api/assessments?tenant_id=${tenantId}`,
      { headers: getAuthHeaders() }
    );

    if (!response.ok) {
      throw new Error('Failed to fetch assessments');
    }

    return response.json();
  },

  async getByClient(tenantId: string, clientId: string): Promise<Assessment[]> {
    const response = await fetch(
      `${API_URL}/api/assessments/client/${clientId}?tenant_id=${tenantId}`,
      { headers: getAuthHeaders() }
    );

    if (!response.ok) {
      throw new Error('Failed to fetch client assessments');
    }

    return response.json();
  },

  async getById(id: string): Promise<Assessment | null> {
    const response = await fetch(
      `${API_URL}/api/assessments/${id}`,
      { headers: getAuthHeaders() }
    );

    if (!response.ok) {
      if (response.status === 404) {
        return null;
      }
      throw new Error('Failed to fetch assessment');
    }

    return response.json();
  },

  async create(
    tenantId: string,
    clientId: string,
    responses: Partial<AssessmentFormData>,
    results: CalculationResults,
    createdBy?: string
  ): Promise<Assessment> {
    const body = {
      tenant_id: tenantId,
      client_id: clientId,
      responses,
      results,
    };

    const response = await fetch(`${API_URL}/api/assessments`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      throw new Error('Failed to create assessment');
    }

    return response.json();
  },

  async update(
    id: string,
    updates: {
      responses?: Partial<AssessmentFormData>;
      results?: CalculationResults;
      status?: 'draft' | 'completed' | 'archived';
    }
  ): Promise<Assessment> {
    const response = await fetch(`${API_URL}/api/assessments/${id}`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify(updates),
    });

    if (!response.ok) {
      throw new Error('Failed to update assessment');
    }

    return response.json();
  },

  async complete(
    id: string,
    responses: Partial<AssessmentFormData>,
    results: CalculationResults
  ): Promise<Assessment> {
    const body = {
      responses,
      results,
      status: 'completed',
    };

    const response = await fetch(`${API_URL}/api/assessments/${id}`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      throw new Error('Failed to complete assessment');
    }

    return response.json();
  },

  async delete(id: string): Promise<void> {
    const response = await fetch(`${API_URL}/api/assessments/${id}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to delete assessment');
    }
  },
};
