import {
  Document,
  DocumentCategory,
  DocumentListResponse,
  DocumentUploadResponse
} from '../types/documents';

export interface ListDocumentsParams {
  category?: DocumentCategory;
  limit?: number;
  offset?: number;
}

class DocumentsAPI {
  private baseUrl: string;

  constructor() {
    this.baseUrl = `${import.meta.env.VITE_API_URL || 'http://localhost:8787'}/api`;
  }

  private async getAuthHeaders(includeContentType = true) {
    const token = localStorage.getItem('auth_token');
    if (!token) {
      throw new Error('Please log in to continue');
    }

    const headers: Record<string, string> = {
      'Authorization': `Bearer ${token}`,
    };

    if (includeContentType) {
      headers['Content-Type'] = 'application/json';
    }

    return headers;
  }

  private async handleResponse<T>(response: Response): Promise<T> {
    if (!response.ok) {
      let errorData;
      try {
        errorData = await response.json();
      } catch (parseError) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      throw new Error(errorData?.error || `HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    return data;
  }

  async uploadDocument(
    file: File,
    category: DocumentCategory = 'general',
    description?: string
  ): Promise<DocumentUploadResponse> {
    const headers = await this.getAuthHeaders(false);
    delete headers['Content-Type'];

    const formData = new FormData();
    formData.append('file', file);
    formData.append('category', category);
    if (description) {
      formData.append('description', description);
    }

    const response = await fetch(`${this.baseUrl}/documents/upload`, {
      method: 'POST',
      headers,
      body: formData,
      signal: AbortSignal.timeout(60000)
    });

    return this.handleResponse<DocumentUploadResponse>(response);
  }

  async listDocuments(params: ListDocumentsParams = {}): Promise<DocumentListResponse> {
    const { category, limit = 50, offset = 0 } = params;
    const headers = await this.getAuthHeaders();

    const url = new URL(`${this.baseUrl}/documents`);
    if (category) url.searchParams.set('category', category);
    url.searchParams.set('limit', Math.min(limit, 200).toString());
    url.searchParams.set('offset', offset.toString());

    const response = await fetch(url.toString(), {
      headers,
      signal: AbortSignal.timeout(10000)
    });

    return this.handleResponse<DocumentListResponse>(response);
  }

  async getDocumentMetadata(id: string): Promise<Document> {
    const headers = await this.getAuthHeaders();

    const response = await fetch(`${this.baseUrl}/documents/${id}/metadata`, {
      headers,
      signal: AbortSignal.timeout(10000)
    });

    const result = await this.handleResponse<{ data: Document }>(response);
    return result.data;
  }

  async downloadDocument(id: string, fileName?: string): Promise<void> {
    const headers = await this.getAuthHeaders();

    const response = await fetch(`${this.baseUrl}/documents/${id}`, {
      headers,
      signal: AbortSignal.timeout(30000)
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData?.error || `Failed to download document`);
    }

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName || 'document';
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  }

  async deleteDocument(id: string): Promise<void> {
    const headers = await this.getAuthHeaders();

    const response = await fetch(`${this.baseUrl}/documents/${id}`, {
      method: 'DELETE',
      headers,
      signal: AbortSignal.timeout(10000)
    });

    await this.handleResponse<{ success: boolean }>(response);
  }

  getDocumentUrl(id: string): string {
    const token = localStorage.getItem('auth_token');
    return `${this.baseUrl}/documents/${id}?token=${token}`;
  }
}

export const documentsApi = new DocumentsAPI();

export const uploadDocument = (
  file: File,
  category?: DocumentCategory,
  description?: string
) => documentsApi.uploadDocument(file, category, description);

export const listDocuments = (params: ListDocumentsParams) =>
  documentsApi.listDocuments(params);

export const getDocumentMetadata = (id: string) =>
  documentsApi.getDocumentMetadata(id);

export const downloadDocument = (id: string, fileName?: string) =>
  documentsApi.downloadDocument(id, fileName);

export const deleteDocument = (id: string) =>
  documentsApi.deleteDocument(id);

export const getDocumentUrl = (id: string) =>
  documentsApi.getDocumentUrl(id);
