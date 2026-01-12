import React, { useState } from 'react';
import { Upload, File, FileText, Image, Download, Trash2, Eye, Plus, Search, Filter, Calendar, User, Tag } from 'lucide-react';
import { Document, Project } from '../types';
import { formatDate, formatFileSize } from '../utils/formatters';

interface DocumentManagerProps {
  documents: Document[];
  projects: Project[];
  onAddDocument: (document: Omit<Document, 'id' | 'uploadedAt'>) => void;
  onDeleteDocument: (id: string) => void;
  onUpdateDocument: (id: string, updates: Partial<Document>) => void;
}

export const DocumentManager: React.FC<DocumentManagerProps> = ({
  documents,
  projects,
  onAddDocument,
  onDeleteDocument,
  onUpdateDocument
}) => {
  const [showUploadForm, setShowUploadForm] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [filterProject, setFilterProject] = useState<string>('all');
  const [dragActive, setDragActive] = useState(false);
  const [newDocument, setNewDocument] = useState({
    name: '',
    description: '',
    category: 'technical-documentation' as const,
    projectId: '',
    isRnDRelated: true,
    tags: [] as string[],
    confidentialityLevel: 'internal' as const
  });

  const categories = [
    'technical-documentation',
    'financial-records',
    'contracts',
    'research-reports',
    'compliance-documents',
    'receipts-invoices',
    'employee-records',
    'other'
  ];

  const filteredDocuments = documents.filter(doc => {
    const matchesSearch = doc.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         doc.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         doc.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesCategory = filterCategory === 'all' || doc.category === filterCategory;
    const matchesProject = filterProject === 'all' || doc.projectId === filterProject;
    return matchesSearch && matchesCategory && matchesProject;
  });

  const handleFileUpload = (files: FileList | null) => {
    if (!files) return;

    Array.from(files).forEach(file => {
      // In a real app, you would upload to a server/cloud storage
      // For demo purposes, we'll create a mock document entry
      const mockDocument = {
        ...newDocument,
        name: newDocument.name || file.name,
        fileName: file.name,
        fileSize: file.size,
        fileType: file.type,
        fileUrl: URL.createObjectURL(file), // Mock URL for demo
        uploadedBy: 'Current User'
      };

      const project = projects.find(p => p.id === mockDocument.projectId);
      if (project) {
        mockDocument.projectName = project.name;
      }

      onAddDocument(mockDocument);
    });

    // Reset form
    setNewDocument({
      name: '',
      description: '',
      category: 'technical-documentation' as const,
      projectId: '',
      isRnDRelated: true,
      tags: [],
      confidentialityLevel: 'internal' as const
    });
    setShowUploadForm(false);
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files);
    }
  };

  const getFileIcon = (fileType: string) => {
    if (fileType.startsWith('image/')) return <Image className="h-5 w-5" />;
    if (fileType.includes('pdf')) return <FileText className="h-5 w-5" />;
    return <File className="h-5 w-5" />;
  };

  const getCategoryColor = (category: string) => {
    const colors = {
      'technical-documentation': 'bg-blue-100 text-blue-800',
      'financial-records': 'bg-green-100 text-green-800',
      'contracts': 'bg-purple-100 text-purple-800',
      'research-reports': 'bg-indigo-100 text-indigo-800',
      'compliance-documents': 'bg-yellow-100 text-yellow-800',
      'receipts-invoices': 'bg-orange-100 text-orange-800',
      'employee-records': 'bg-pink-100 text-pink-800',
      'other': 'bg-gray-100 text-gray-800'
    };
    return colors[category as keyof typeof colors] || 'bg-gray-100 text-gray-800';
  };

  const handleTagInput = (value: string) => {
    const tags = value.split(',').map(tag => tag.trim()).filter(tag => tag.length > 0);
    setNewDocument({ ...newDocument, tags });
  };

  const documentStats = {
    total: documents.length,
    rndRelated: documents.filter(doc => doc.isRnDRelated).length,
    byCategory: categories.reduce((acc, category) => {
      acc[category] = documents.filter(doc => doc.category === category).length;
      return acc;
    }, {} as Record<string, number>)
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-4xl font-bold text-slate-800">
            Document Management
          </h1>
          <p className="text-slate-600 mt-2">Upload, organize, and manage all R&D-related documents</p>
        </div>
        <button
          onClick={() => setShowUploadForm(true)}
          className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2 shadow-sm"
        >
          <Plus className="h-4 w-4" />
          <span>Upload Document</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-6">
        <div className="bg-blue-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-blue-900 mb-2 flex items-center">
            <File className="h-4 w-4 mr-1" />
            Total Documents
          </h4>
          <p className="text-2xl font-bold text-blue-600">{documentStats.total}</p>
        </div>
        <div className="bg-green-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-green-900 mb-2 flex items-center">
            <FileText className="h-4 w-4 mr-1" />
            R&D Related
          </h4>
          <p className="text-2xl font-bold text-green-600">{documentStats.rndRelated}</p>
        </div>
        <div className="bg-purple-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-purple-900 mb-2">Technical Docs</h4>
          <p className="text-2xl font-bold text-purple-600">{documentStats.byCategory['technical-documentation']}</p>
        </div>
        <div className="bg-orange-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-orange-900 mb-2">Financial Records</h4>
          <p className="text-2xl font-bold text-orange-600">{documentStats.byCategory['financial-records']}</p>
        </div>
      </div>

      {showUploadForm && (
        <div className="bg-white p-6 rounded-lg shadow-lg border border-gray-200">
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
              <Upload className="h-5 w-5 text-white" />
            </div>
            <h3 className="text-xl font-semibold text-slate-800">Upload New Document</h3>
          </div>

          <div
            className={`border-2 border-dashed rounded-lg p-8 text-center mb-6 transition-colors ${
              dragActive ? 'border-blue-400 bg-blue-50' : 'border-gray-300'
            }`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            <Upload className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <p className="text-lg font-medium text-gray-900 mb-2">
              Drag and drop files here, or click to select
            </p>
            <p className="text-sm text-gray-600 mb-4">
              Supports PDF, DOC, DOCX, XLS, XLSX, images, and more
            </p>
            <input
              type="file"
              multiple
              onChange={(e) => handleFileUpload(e.target.files)}
              className="hidden"
              id="file-upload"
            />
            <label
              htmlFor="file-upload"
              className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors cursor-pointer inline-block"
            >
              Select Files
            </label>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">Document Name (Optional)</label>
              <input
                type="text"
                value={newDocument.name}
                onChange={(e) => setNewDocument({ ...newDocument, name: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Leave blank to use filename"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">Category</label>
              <select
                value={newDocument.category}
                onChange={(e) => setNewDocument({ ...newDocument, category: e.target.value as any })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="technical-documentation">Technical Documentation</option>
                <option value="financial-records">Financial Records</option>
                <option value="contracts">Contracts</option>
                <option value="research-reports">Research Reports</option>
                <option value="compliance-documents">Compliance Documents</option>
                <option value="receipts-invoices">Receipts & Invoices</option>
                <option value="employee-records">Employee Records</option>
                <option value="other">Other</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">Project (Optional)</label>
              <select
                value={newDocument.projectId}
                onChange={(e) => setNewDocument({ ...newDocument, projectId: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="">No specific project</option>
                {projects.map(project => (
                  <option key={project.id} value={project.id}>{project.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">Confidentiality Level</label>
              <select
                value={newDocument.confidentialityLevel}
                onChange={(e) => setNewDocument({ ...newDocument, confidentialityLevel: e.target.value as any })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="public">Public</option>
                <option value="internal">Internal</option>
                <option value="confidential">Confidential</option>
                <option value="restricted">Restricted</option>
              </select>
            </div>
            <div className="md:col-span-2">
              <label className="block text-sm font-medium text-slate-700 mb-2">Description</label>
              <textarea
                value={newDocument.description}
                onChange={(e) => setNewDocument({ ...newDocument, description: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                rows={3}
                placeholder="Brief description of the document..."
              />
            </div>
            <div className="md:col-span-2">
              <label className="block text-sm font-medium text-slate-700 mb-2">Tags (comma-separated)</label>
              <input
                type="text"
                value={newDocument.tags.join(', ')}
                onChange={(e) => handleTagInput(e.target.value)}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="research, algorithm, compliance..."
              />
            </div>
            <div className="md:col-span-2 flex items-center">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={newDocument.isRnDRelated}
                  onChange={(e) => setNewDocument({ ...newDocument, isRnDRelated: e.target.checked })}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-slate-700 font-medium">R&D Related Document</span>
              </label>
            </div>
          </div>

          <div className="flex justify-end space-x-3 mt-6">
            <button
              onClick={() => setShowUploadForm(false)}
              className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      <div className="bg-white p-6 rounded-lg shadow-md border border-gray-200">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-slate-800">Document Library</h3>
          <div className="flex space-x-3">
            <div className="relative">
              <Search className="h-4 w-4 absolute left-3 top-3 text-gray-400" />
              <input
                type="text"
                placeholder="Search documents..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-9 pr-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <select
              value={filterCategory}
              onChange={(e) => setFilterCategory(e.target.value)}
              className="border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Categories</option>
              {categories.map(category => (
                <option key={category} value={category}>
                  {category.replace('-', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                </option>
              ))}
            </select>
            <select
              value={filterProject}
              onChange={(e) => setFilterProject(e.target.value)}
              className="border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Projects</option>
              {projects.map(project => (
                <option key={project.id} value={project.id}>{project.name}</option>
              ))}
            </select>
          </div>
        </div>

        <div className="space-y-4">
          {filteredDocuments.map((document) => (
            <div key={document.id} className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-all duration-200">
              <div className="flex items-start justify-between">
                <div className="flex items-start space-x-3 flex-1">
                  <div className="text-gray-500 mt-1">
                    {getFileIcon(document.fileType)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-3 mb-2">
                      <h4 className="font-semibold text-slate-800 truncate">{document.name}</h4>
                      <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getCategoryColor(document.category)}`}>
                        {document.category.replace('-', ' ')}
                      </span>
                      {document.isRnDRelated && (
                        <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                          R&D
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-gray-600 mb-2">{document.description}</p>
                    <div className="flex items-center space-x-4 text-xs text-gray-500">
                      <span className="flex items-center">
                        <User className="h-3 w-3 mr-1" />
                        {document.uploadedBy}
                      </span>
                      <span className="flex items-center">
                        <Calendar className="h-3 w-3 mr-1" />
                        {formatDate(document.uploadedAt)}
                      </span>
                      <span>{formatFileSize(document.fileSize)}</span>
                      {document.projectName && (
                        <span>Project: {document.projectName}</span>
                      )}
                    </div>
                    {document.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-2">
                        {document.tags.map((tag, index) => (
                          <span key={index} className="inline-flex items-center px-1.5 py-0.5 rounded text-xs bg-gray-100 text-gray-600">
                            <Tag className="h-2 w-2 mr-1" />
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
                <div className="flex items-center space-x-2 ml-4">
                  <button
                    onClick={() => window.open(document.fileUrl, '_blank')}
                    className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                    title="View Document"
                  >
                    <Eye className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => {
                      const link = document.createElement('a');
                      link.href = document.fileUrl;
                      link.download = document.fileName;
                      link.click();
                    }}
                    className="p-2 text-green-600 hover:bg-green-50 rounded-lg transition-colors"
                    title="Download"
                  >
                    <Download className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => onDeleteDocument(document.id)}
                    className="p-2 text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                    title="Delete"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
          {filteredDocuments.length === 0 && (
            <div className="text-center py-12 text-gray-500">
              <div className="w-16 h-16 bg-blue-100 rounded-lg flex items-center justify-center mx-auto mb-4">
                <File className="h-8 w-8 text-blue-500" />
              </div>
              <p className="text-lg font-medium">No documents found</p>
              <p className="text-sm mt-1">Upload your first document to get started</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};