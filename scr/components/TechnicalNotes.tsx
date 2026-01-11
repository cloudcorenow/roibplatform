import React, { useState } from 'react';
import { Plus, Search, Edit3, Save, X, FileText, Tag, BookOpen, Lightbulb } from 'lucide-react';
import { TechnicalNote, Project } from '../types';
import { formatDateTime } from '../utils/formatters';

interface TechnicalNotesProps {
  notes: TechnicalNote[];
  projects: Project[];
  onAddNote: (note: Omit<TechnicalNote, 'id' | 'createdAt' | 'updatedAt'>) => void;
  onUpdateNote: (id: string, updates: Partial<TechnicalNote>) => void;
}

export const TechnicalNotes: React.FC<TechnicalNotesProps> = ({
  notes,
  projects,
  onAddNote,
  onUpdateNote
}) => {
  const [selectedNote, setSelectedNote] = useState<TechnicalNote | null>(notes[0] || null);
  const [isEditing, setIsEditing] = useState(false);
  const [showNewNoteForm, setShowNewNoteForm] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [editContent, setEditContent] = useState('');
  const [newNote, setNewNote] = useState({
    title: '',
    content: '',
    projectId: '',
    author: 'Current User',
    tags: [] as string[],
    isRnDQualified: true
  });

  const filteredNotes = notes.filter(note =>
    note.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
    note.content.toLowerCase().includes(searchTerm.toLowerCase()) ||
    note.projectName.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleEditNote = () => {
    if (!selectedNote) return;
    setEditContent(selectedNote.content);
    setIsEditing(true);
  };

  const handleSaveNote = () => {
    if (!selectedNote) return;
    onUpdateNote(selectedNote.id, { 
      content: editContent,
      updatedAt: new Date().toISOString()
    });
    setIsEditing(false);
  };

  const handleAddNote = () => {
    if (!newNote.title || !newNote.content || !newNote.projectId) return;
    
    const project = projects.find(p => p.id === newNote.projectId);
    if (!project) return;

    onAddNote({
      ...newNote,
      projectName: project.name
    });

    setNewNote({
      title: '',
      content: '',
      projectId: '',
      author: 'Current User',
      tags: [],
      isRnDQualified: true
    });
    setShowNewNoteForm(false);
  };

  const handleTagInput = (value: string) => {
    const tags = value.split(',').map(tag => tag.trim()).filter(tag => tag.length > 0);
    setNewNote({ ...newNote, tags });
  };

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-4xl font-bold text-slate-800">
            Technical Documentation
          </h1>
          <p className="text-slate-600 mt-2">Document your R&D processes, experiments, and technical insights</p>
        </div>
        <button
          onClick={() => setShowNewNoteForm(true)}
          className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2 shadow-sm"
        >
          <Plus className="h-4 w-4" />
          <span>New Note</span>
        </button>
      </div>

      {showNewNoteForm && (
        <div className="bg-white p-6 rounded-lg shadow-lg border border-gray-200">
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
              <FileText className="h-5 w-5 text-white" />
            </div>
            <h3 className="text-lg font-semibold text-slate-800">Create New Technical Note</h3>
          </div>
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-2">Title</label>
                <input
                  type="text"
                  value={newNote.title}
                  onChange={(e) => setNewNote({ ...newNote, title: e.target.value })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="Note title..."
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-2">Project</label>
                <select
                  value={newNote.projectId}
                  onChange={(e) => setNewNote({ ...newNote, projectId: e.target.value })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="">Select a project</option>
                  {projects.map(project => (
                    <option key={project.id} value={project.id}>{project.name}</option>
                  ))}
                </select>
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">Tags (comma-separated)</label>
              <input
                type="text"
                value={newNote.tags.join(', ')}
                onChange={(e) => handleTagInput(e.target.value)}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="research, algorithm, optimization..."
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">Content</label>
              <textarea
                value={newNote.content}
                onChange={(e) => setNewNote({ ...newNote, content: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                rows={10}
                placeholder="Write your technical documentation here..."
              />
            </div>
            <div className="flex items-center">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={newNote.isRnDQualified}
                  onChange={(e) => setNewNote({ ...newNote, isRnDQualified: e.target.checked })}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-slate-700 font-medium">R&D Qualified Activity</span>
              </label>
            </div>
          </div>
          <div className="flex justify-end space-x-3 mt-6">
            <button
              onClick={() => setShowNewNoteForm(false)}
              className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              onClick={handleAddNote}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              Create Note
            </button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-1">
          <div className="bg-white p-4 rounded-lg shadow-md border border-gray-200">
            <div className="relative mb-4">
              <Search className="h-4 w-4 absolute left-3 top-3 text-slate-400" />
              <input
                type="text"
                placeholder="Search notes..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-9 pr-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div className="space-y-2">
              {filteredNotes.map((note) => (
                <div
                  key={note.id}
                  onClick={() => setSelectedNote(note)}
                  className={`p-3 rounded-lg border cursor-pointer transition-all duration-200 hover:shadow-md ${
                    selectedNote?.id === note.id
                      ? 'border-blue-300 bg-blue-50'
                      : 'border-gray-200 hover:bg-gray-50'
                  }`}
                >
                  <h4 className="text-sm font-semibold text-slate-800 line-clamp-2">{note.title}</h4>
                  <p className="text-xs text-slate-600 mt-1 font-medium">{note.projectName}</p>
                  <div className="flex items-center justify-between mt-2">
                    <p className="text-xs text-slate-500">{formatDateTime(note.updatedAt)}</p>
                    {note.isRnDQualified && (
                      <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800">
                        R&D
                      </span>
                    )}
                  </div>
                  {note.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {note.tags.slice(0, 2).map((tag, index) => (
                        <span key={index} className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-slate-100 text-slate-600">
                          <Tag className="h-2 w-2 mr-1" />
                          {tag}
                        </span>
                      ))}
                      {note.tags.length > 2 && (
                        <span className="text-xs text-slate-500">+{note.tags.length - 2}</span>
                      )}
                    </div>
                  )}
                </div>
              ))}
              {filteredNotes.length === 0 && (
                <div className="text-center py-12 text-slate-500">
                  <div className="w-16 h-16 bg-blue-100 rounded-lg flex items-center justify-center mx-auto mb-4">
                    <FileText className="h-8 w-8 text-cyan-500" />
                  </div>
                  <p className="text-sm font-medium">No notes found</p>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="lg:col-span-3">
          {selectedNote ? (
            <div className="bg-white p-6 rounded-lg shadow-md border border-gray-200">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h3 className="text-lg font-semibold text-slate-800">{selectedNote.title}</h3>
                  <p className="text-sm text-slate-600 mt-1">
                    {selectedNote.projectName} • Last updated {formatDateTime(selectedNote.updatedAt)}
                  </p>
                  <p className="text-sm text-slate-500 mt-1">By {selectedNote.author}</p>
                </div>
                <div className="flex items-center space-x-2">
                  {selectedNote.isRnDQualified && (
                    <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800">
                      R&D Qualified
                    </span>
                  )}
                  {isEditing ? (
                    <div className="flex space-x-2">
                      <button
                        onClick={handleSaveNote}
                        className="p-2 text-emerald-600 hover:text-emerald-700 hover:bg-emerald-50 rounded-lg transition-colors"
                      >
                        <Save className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => setIsEditing(false)}
                        className="p-2 text-slate-400 hover:text-slate-600 hover:bg-slate-50 rounded-lg transition-colors"
                      >
                        <X className="h-4 w-4" />
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={handleEditNote}
                      className="p-2 text-slate-400 hover:text-slate-600 hover:bg-slate-50 rounded-lg transition-colors"
                    >
                      <Edit3 className="h-4 w-4" />
                    </button>
                  )}
                </div>
              </div>

              {selectedNote.tags.length > 0 && (
                <div className="flex flex-wrap gap-2 mb-6">
                  {selectedNote.tags.map((tag, index) => (
                    <span key={index} className="inline-flex items-center px-3 py-1 rounded-full text-xs bg-slate-100 text-slate-600 font-medium">
                      <Tag className="h-3 w-3 mr-1" />
                      {tag}
                    </span>
                  ))}
                </div>
              )}

              <div className="prose max-w-none">
                {isEditing ? (
                  <textarea
                    value={editContent}
                    onChange={(e) => setEditContent(e.target.value)}
                    className="w-full h-96 border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
                  />
                ) : (
                  <div className="whitespace-pre-wrap text-slate-700 leading-relaxed bg-gray-50 p-4 rounded-lg">
                    {selectedNote.content}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="bg-white p-8 rounded-lg shadow-md border border-gray-200 text-center">
              <div className="w-16 h-16 bg-blue-100 rounded-lg flex items-center justify-center mx-auto mb-4">
                <BookOpen className="h-10 w-10 text-cyan-500" />
              </div>
              <h3 className="text-lg font-semibold text-slate-800 mb-2">No Note Selected</h3>
              <p className="text-slate-600">Select a note from the sidebar to view its content</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};