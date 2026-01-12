import React, { useState } from 'react';
import { BookOpen, Plus, Search, Tag, User, Clock, Lightbulb, AlertTriangle, Code, Award } from 'lucide-react';
import { KnowledgeBaseEntry, Project } from '../types';
import { formatDateTime } from '../utils/formatters';

interface KnowledgeBaseProps {
  entries: KnowledgeBaseEntry[];
  projects: Project[];
  onAddEntry: (entry: Omit<KnowledgeBaseEntry, 'id' | 'createdAt' | 'updatedAt'>) => void;
  onUpdateEntry: (id: string, updates: Partial<KnowledgeBaseEntry>) => void;
}

export const KnowledgeBase: React.FC<KnowledgeBaseProps> = ({
  entries,
  projects,
  onAddEntry,
  onUpdateEntry
}) => {
  const [selectedEntry, setSelectedEntry] = useState<KnowledgeBaseEntry | null>(entries[0] || null);
  const [showNewEntryForm, setShowNewEntryForm] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [newEntry, setNewEntry] = useState({
    title: '',
    content: '',
    category: 'lessons-learned' as const,
    projectId: '',
    author: 'Current User',
    tags: [] as string[],
    isPublic: true,
    relatedSprint: ''
  });

  const filteredEntries = entries.filter(entry => {
    const matchesSearch = entry.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         entry.content.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         entry.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesCategory = filterCategory === 'all' || entry.category === filterCategory;
    return matchesSearch && matchesCategory;
  });

  const handleAddEntry = () => {
    if (!newEntry.title || !newEntry.content) return;
    
    const project = projects.find(p => p.id === newEntry.projectId);
    
    onAddEntry({
      ...newEntry,
      projectName: project?.name
    });

    setNewEntry({
      title: '',
      content: '',
      category: 'lessons-learned' as const,
      projectId: '',
      author: 'Current User',
      tags: [],
      isPublic: true,
      relatedSprint: ''
    });
    setShowNewEntryForm(false);
  };

  const handleTagInput = (value: string) => {
    const tags = value.split(',').map(tag => tag.trim()).filter(tag => tag.length > 0);
    setNewEntry({ ...newEntry, tags });
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'lessons-learned': return <Lightbulb className="h-4 w-4" />;
      case 'failed-experiments': return <AlertTriangle className="h-4 w-4" />;
      case 'code-snippets': return <Code className="h-4 w-4" />;
      case 'best-practices': return <Award className="h-4 w-4" />;
      default: return <BookOpen className="h-4 w-4" />;
    }
  };

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'lessons-learned': return 'bg-blue-100 text-blue-800';
      case 'failed-experiments': return 'bg-red-100 text-red-800';
      case 'code-snippets': return 'bg-green-100 text-green-800';
      case 'best-practices': return 'bg-purple-100 text-purple-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const categoryStats = {
    'lessons-learned': entries.filter(e => e.category === 'lessons-learned').length,
    'failed-experiments': entries.filter(e => e.category === 'failed-experiments').length,
    'code-snippets': entries.filter(e => e.category === 'code-snippets').length,
    'best-practices': entries.filter(e => e.category === 'best-practices').length
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Knowledge Base</h1>
        <button
          onClick={() => setShowNewEntryForm(true)}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2"
        >
          <Plus className="h-4 w-4" />
          <span>Add Entry</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-6">
        <div className="bg-blue-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-blue-900 mb-2 flex items-center">
            <Lightbulb className="h-4 w-4 mr-1" />
            Lessons Learned
          </h4>
          <p className="text-2xl font-bold text-blue-600">{categoryStats['lessons-learned']}</p>
        </div>
        <div className="bg-red-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-red-900 mb-2 flex items-center">
            <AlertTriangle className="h-4 w-4 mr-1" />
            Failed Experiments
          </h4>
          <p className="text-2xl font-bold text-red-600">{categoryStats['failed-experiments']}</p>
        </div>
        <div className="bg-green-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-green-900 mb-2 flex items-center">
            <Code className="h-4 w-4 mr-1" />
            Code Snippets
          </h4>
          <p className="text-2xl font-bold text-green-600">{categoryStats['code-snippets']}</p>
        </div>
        <div className="bg-purple-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-purple-900 mb-2 flex items-center">
            <Award className="h-4 w-4 mr-1" />
            Best Practices
          </h4>
          <p className="text-2xl font-bold text-purple-600">{categoryStats['best-practices']}</p>
        </div>
      </div>

      {showNewEntryForm && (
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Create Knowledge Base Entry</h3>
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Title</label>
                <input
                  type="text"
                  value={newEntry.title}
                  onChange={(e) => setNewEntry({ ...newEntry, title: e.target.value })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="Entry title..."
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Category</label>
                <select
                  value={newEntry.category}
                  onChange={(e) => setNewEntry({ ...newEntry, category: e.target.value as any })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="lessons-learned">Lessons Learned</option>
                  <option value="failed-experiments">Failed Experiments</option>
                  <option value="code-snippets">Code Snippets</option>
                  <option value="best-practices">Best Practices</option>
                </select>
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Project (Optional)</label>
                <select
                  value={newEntry.projectId}
                  onChange={(e) => setNewEntry({ ...newEntry, projectId: e.target.value })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="">No specific project</option>
                  {projects.map(project => (
                    <option key={project.id} value={project.id}>{project.name}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Related Sprint (Optional)</label>
                <input
                  type="text"
                  value={newEntry.relatedSprint}
                  onChange={(e) => setNewEntry({ ...newEntry, relatedSprint: e.target.value })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="Sprint 2024-12, etc."
                />
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Tags (comma-separated)</label>
              <input
                type="text"
                value={newEntry.tags.join(', ')}
                onChange={(e) => handleTagInput(e.target.value)}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="machine-learning, optimization, debugging..."
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Content</label>
              <textarea
                value={newEntry.content}
                onChange={(e) => setNewEntry({ ...newEntry, content: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                rows={8}
                placeholder="Share your knowledge, lessons learned, code snippets, or best practices..."
              />
            </div>
            <div className="flex items-center">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={newEntry.isPublic}
                  onChange={(e) => setNewEntry({ ...newEntry, isPublic: e.target.checked })}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700">Make this entry visible to all team members</span>
              </label>
            </div>
          </div>
          <div className="flex justify-end space-x-3 mt-6">
            <button
              onClick={() => setShowNewEntryForm(false)}
              className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              onClick={handleAddEntry}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              Create Entry
            </button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-1">
          <div className="bg-white p-4 rounded-xl shadow-sm border border-gray-200">
            <div className="space-y-4">
              <div className="relative">
                <Search className="h-4 w-4 absolute left-3 top-3 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search knowledge base..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-9 pr-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Filter by Category</label>
                <select
                  value={filterCategory}
                  onChange={(e) => setFilterCategory(e.target.value)}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="all">All Categories</option>
                  <option value="lessons-learned">Lessons Learned</option>
                  <option value="failed-experiments">Failed Experiments</option>
                  <option value="code-snippets">Code Snippets</option>
                  <option value="best-practices">Best Practices</option>
                </select>
              </div>
            </div>

            <div className="mt-6 space-y-2">
              {filteredEntries.map((entry) => (
                <div
                  key={entry.id}
                  onClick={() => setSelectedEntry(entry)}
                  className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                    selectedEntry?.id === entry.id
                      ? 'border-blue-200 bg-blue-50'
                      : 'border-gray-200 hover:bg-gray-50'
                  }`}
                >
                  <div className="flex items-start justify-between mb-2">
                    <h4 className="text-sm font-medium text-gray-900 line-clamp-2">{entry.title}</h4>
                    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium ${getCategoryColor(entry.category)}`}>
                      {getCategoryIcon(entry.category)}
                    </span>
                  </div>
                  {entry.projectName && (
                    <p className="text-xs text-gray-600 mb-1">{entry.projectName}</p>
                  )}
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-gray-500">{formatDateTime(entry.updatedAt)}</p>
                    {!entry.isPublic && (
                      <span className="text-xs text-orange-600">Private</span>
                    )}
                  </div>
                  {entry.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {entry.tags.slice(0, 2).map((tag, index) => (
                        <span key={index} className="inline-flex items-center px-1.5 py-0.5 rounded text-xs bg-gray-100 text-gray-600">
                          <Tag className="h-2 w-2 mr-1" />
                          {tag}
                        </span>
                      ))}
                      {entry.tags.length > 2 && (
                        <span className="text-xs text-gray-500">+{entry.tags.length - 2}</span>
                      )}
                    </div>
                  )}
                </div>
              ))}
              {filteredEntries.length === 0 && (
                <div className="text-center py-8 text-gray-500">
                  <BookOpen className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                  <p className="text-sm">No entries found</p>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="lg:col-span-3">
          {selectedEntry ? (
            <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
              <div className="flex items-start justify-between mb-6">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <h3 className="text-lg font-semibold text-gray-900">{selectedEntry.title}</h3>
                    <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getCategoryColor(selectedEntry.category)}`}>
                      {getCategoryIcon(selectedEntry.category)}
                      <span className="ml-1 capitalize">{selectedEntry.category.replace('-', ' ')}</span>
                    </span>
                  </div>
                  <div className="flex items-center space-x-4 text-sm text-gray-600">
                    <span className="flex items-center">
                      <User className="h-4 w-4 mr-1" />
                      {selectedEntry.author}
                    </span>
                    <span className="flex items-center">
                      <Clock className="h-4 w-4 mr-1" />
                      {formatDateTime(selectedEntry.updatedAt)}
                    </span>
                    {selectedEntry.projectName && (
                      <span>{selectedEntry.projectName}</span>
                    )}
                    {selectedEntry.relatedSprint && (
                      <span>Sprint: {selectedEntry.relatedSprint}</span>
                    )}
                  </div>
                </div>
              </div>

              {selectedEntry.tags.length > 0 && (
                <div className="flex flex-wrap gap-2 mb-6">
                  {selectedEntry.tags.map((tag, index) => (
                    <span key={index} className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-gray-100 text-gray-600">
                      <Tag className="h-3 w-3 mr-1" />
                      {tag}
                    </span>
                  ))}
                </div>
              )}

              <div className="prose max-w-none">
                <div className="whitespace-pre-wrap text-gray-700 leading-relaxed">
                  {selectedEntry.content}
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-white p-8 rounded-xl shadow-sm border border-gray-200 text-center">
              <BookOpen className="h-16 w-16 mx-auto mb-4 text-gray-300" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">No Entry Selected</h3>
              <p className="text-gray-600">Select an entry from the sidebar to view its content</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};