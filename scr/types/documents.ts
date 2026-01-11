export interface Document {
  id: string;
  fileName: string;
  fileSize: number;
  fileType: string;
  description?: string;
  category: DocumentCategory;
  uploadedBy: string;
  createdAt: string;
}

export type DocumentCategory =
  | 'general'
  | 'invoice'
  | 'contract'
  | 'report'
  | 'receipt'
  | 'tax_document'
  | 'financial_statement'
  | 'rnd_documentation';

export interface DocumentUploadRequest {
  file: File;
  category?: DocumentCategory;
  description?: string;
}

export interface DocumentListResponse {
  items: Document[];
  paging: {
    limit: number;
    offset: number;
    total: number;
    hasMore: boolean;
  };
}

export interface DocumentUploadResponse {
  id: string;
  fileName: string;
  fileSize: number;
  fileType: string;
  category: DocumentCategory;
  uploadDuration: number;
}
