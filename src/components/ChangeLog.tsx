import React, { useState } from 'react';
import { History, Clock, User, Edit3, Plus, FileText } from 'lucide-react';
import { ChangeLogEntry, TechnicalNote } from '../types';
import { formatDateTime } from '../utils/formatters';

interface ChangeLogProps {
  note: TechnicalNote;
  onAddChangeLog: (noteId: string, entry: Omit<ChangeLogEntry, 'id' | 'timestamp'>) => void;
}

export const ChangeLog: React.FC<ChangeLogProps> = ({ note, onAddChangeLog }) => {
  const [showAddEntry, setShowAddEntry] = useState(false);
  const [newEntry, setNewEntry] = useState({
    author: 'Current User',
    action: 'updated' as const,
    changes: '',
    previousVersion: ''
  });

  const handleAddEntry = () => {
    if (!newEntry.changes.trim()) return;
    
    onAddChangeLog(note.id, newEntry);
    setNewEntry({
      author: 'Current User',
      action: 'updated' as const,
      changes: '',
      previousVersion: ''
    });
    setShowAddEntry(false);
  };

  const getActionColor = (action: string) => {
    switch (action) {
      case 'created': return 'text-green-600 bg-green-100';
      case 'updated': return 'text-blue-600 bg-blue-100';
      case 'deleted': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getActionIcon = (action: string) => {
    switch (action) {
      case 'created': return <Plus className="h-3 w-3" />;
      case 'updated': return <Edit3 className="h-3 w-3" />;
      case 'deleted': return <FileText className="h-3 w-3" />;
      default: return <History className="h-3 w-3" />;
    }
  };

  return (
    <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900 flex items-center">
          <History className="h-5 w-5 mr-2" />
          Version History
        </h3>
        <div className="flex items-center space-x-2">
          <span className="text-sm text-gray-500">v{note.version}</span>
          <button
            onClick={() => setShowAddEntry(true)}
            className="text-blue-600 hover:text-blue-700 text-sm font-medium"
          >
            Add Entry
          </button>
        </div>
      </div>

      {showAddEntry && (
        <div className="mb-4 p-4 bg-gray-50 rounded-lg">
          <h4 className="text-sm font-medium text-gray-900 mb-3">Add Change Log Entry</h4>
          <div className="space-y-3">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Action Type</label>
              <select
                value={newEntry.action}
                onChange={(e) => setNewEntry({ ...newEntry, action: e.target.value as any })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="updated">Updated</option>
                <option value="created">Created</option>
                <option value="deleted">Deleted</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Changes Description</label>
              <textarea
                value={newEntry.changes}
                onChange={(e) => setNewEntry({ ...newEntry, changes: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                rows={3}
                placeholder="Describe what was changed..."
              />
            </div>
          </div>
          <div className="flex justify-end space-x-2 mt-3">
            <button
              onClick={() => setShowAddEntry(false)}
              className="px-3 py-1 text-sm text-gray-600 border border-gray-300 rounded hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              onClick={handleAddEntry}
              className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
            >
              Add Entry
            </button>
          </div>
        </div>
      )}

      <div className="space-y-3">
        {note.changeLog.map((entry) => (
          <div key={entry.id} className="flex items-start space-x-3 p-3 bg-gray-50 rounded-lg">
            <div className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getActionColor(entry.action)}`}>
              {getActionIcon(entry.action)}
              <span className="ml-1 capitalize">{entry.action}</span>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm text-gray-900">{entry.changes}</p>
              <div className="flex items-center space-x-4 mt-1 text-xs text-gray-500">
                <span className="flex items-center">
                  <User className="h-3 w-3 mr-1" />
                  {entry.author}
                </span>
                <span className="flex items-center">
                  <Clock className="h-3 w-3 mr-1" />
                  {formatDateTime(entry.timestamp)}
                </span>
              </div>
            </div>
          </div>
        ))}
        {note.changeLog.length === 0 && (
          <div className="text-center py-4 text-gray-500">
            <History className="h-8 w-8 mx-auto mb-2 text-gray-300" />
            <p className="text-sm">No change history available</p>
          </div>
        )}
      </div>
    </div>
  );
};