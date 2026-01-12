import React, { useState } from 'react';
import { Clock } from 'lucide-react';
import { TimeEntry, Project } from '../../types';

interface TimeEntryFormProps {
  projects: Project[];
  onSubmit: (entry: Omit<TimeEntry, 'id'>) => void;
  onCancel: () => void;
  initialData?: Partial<TimeEntry>;
}

export const TimeEntryForm: React.FC<TimeEntryFormProps> = ({
  projects,
  onSubmit,
  onCancel,
  initialData = {}
}) => {
  const [formData, setFormData] = useState({
    projectId: initialData.projectId || '',
    task: initialData.task || '',
    duration: initialData.duration || 0,
    date: initialData.date || new Date().toISOString().split('T')[0],
    isRnD: initialData.isRnD ?? true,
    notes: initialData.notes || '',
    employeeId: initialData.employeeId || '1',
    employeeName: initialData.employeeName || 'Current User'
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!formData.projectId || !formData.task) return;
    
    const project = projects.find(p => p.id === formData.projectId);
    if (!project) return;

    onSubmit({
      ...formData,
      projectName: project.name,
      status: 'completed'
    });
  };

  const handleChange = (field: keyof typeof formData, value: any) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  return (
    <div className="bg-white p-8 rounded-lg shadow-lg border border-gray-200">
      <div className="flex items-center space-x-3 mb-6">
        <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
          <Clock className="h-5 w-5 text-white" />
        </div>
        <h3 className="text-xl font-semibold text-slate-800">New Time Entry</h3>
      </div>

      <form onSubmit={handleSubmit}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-2">Project</label>
            <select
              value={formData.projectId}
              onChange={(e) => handleChange('projectId', e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              required
            >
              <option value="">Select a project</option>
              {projects.map(project => (
                <option key={project.id} value={project.id}>{project.name}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-2">Task Description</label>
            <input
              type="text"
              value={formData.task}
              onChange={(e) => handleChange('task', e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="What did you work on?"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-2">Duration (minutes)</label>
            <input
              type="number"
              value={formData.duration}
              onChange={(e) => handleChange('duration', parseInt(e.target.value) || 0)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              min="0"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-2">Date</label>
            <input
              type="date"
              value={formData.date}
              onChange={(e) => handleChange('date', e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              required
            />
          </div>

          <div className="flex items-center space-x-4">
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={formData.isRnD}
                onChange={(e) => handleChange('isRnD', e.target.checked)}
                className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
              />
              <span className="ml-2 text-sm text-slate-700">R&D Activity</span>
            </label>
          </div>

          <div className="md:col-span-2">
            <label className="block text-sm font-medium text-slate-700 mb-2">Notes (optional)</label>
            <textarea
              value={formData.notes}
              onChange={(e) => handleChange('notes', e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              rows={2}
              placeholder="Additional details..."
            />
          </div>
        </div>

        <div className="flex justify-end space-x-4 mt-6">
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
          >
            Cancel
          </button>
          <button
            type="submit"
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            Add Entry
          </button>
        </div>
      </form>
    </div>
  );
};