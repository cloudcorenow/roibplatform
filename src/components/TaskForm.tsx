import React, { useState } from 'react';
import { X, Plus, Calendar, Clock, Users, Target, Tag, FileText, CheckCircle, User } from 'lucide-react';
import { Task } from '../types/tasks';
import { Project, Employee } from '../types';
import { generateId } from '../utils/formatters';

interface TaskFormProps {
  projects: Project[];
  employees: Employee[];
  onSubmit: (task: Omit<Task, 'id' | 'createdAt' | 'updatedAt'>) => void;
  onCancel: () => void;
  initialData?: Partial<Task>;
}

export const TaskForm: React.FC<TaskFormProps> = ({
  projects,
  employees,
  onSubmit,
  onCancel,
  initialData = {}
}) => {
  const [formData, setFormData] = useState({
    title: initialData.title || '',
    description: initialData.description || '',
    status: initialData.status || 'todo' as const,
    priority: initialData.priority || 'medium' as const,
    category: initialData.category || 'development' as const,
    projectId: initialData.projectId || '',
    parentTaskId: initialData.parentTaskId || '',
    dependsOn: initialData.dependsOn || [],
    assignedTo: initialData.assignedTo || [],
    isRnD: initialData.isRnD ?? true,
    technicalUncertainty: initialData.technicalUncertainty || '',
    experimentationRequired: initialData.experimentationRequired ?? false,
    rndJustification: initialData.rndJustification || '',
    estimatedHours: initialData.estimatedHours || 8,
    startDate: initialData.startDate || '',
    dueDate: initialData.dueDate || '',
    tags: initialData.tags || [],
    progress: initialData.progress || 0
  });

  const [tagInput, setTagInput] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!formData.title.trim() || !formData.description.trim()) return;

    const project = projects.find(p => p.id === formData.projectId);
    const assignedEmployees = employees.filter(emp => formData.assignedTo.includes(emp.id));

    const taskData: Omit<Task, 'id' | 'createdAt' | 'updatedAt'> = {
      tenantId: 'demo-tenant',
      ...formData,
      projectName: project?.name,
      assignedNames: assignedEmployees.map(emp => emp.name),
      createdBy: '1', // Current user
      createdByName: 'Current User',
      actualHours: 0,
      subtasks: [],
      attachments: [],
      comments: [],
      templateId: undefined,
      isTemplate: false
    };

    onSubmit(taskData);
  };

  const handleChange = (field: keyof typeof formData, value: any) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const handleEmployeeToggle = (employeeId: string) => {
    const isSelected = formData.assignedTo.includes(employeeId);
    const newAssignedTo = isSelected
      ? formData.assignedTo.filter(id => id !== employeeId)
      : [...formData.assignedTo, employeeId];
    
    handleChange('assignedTo', newAssignedTo);
  };

  const handleAddTag = () => {
    if (tagInput.trim() && !formData.tags.includes(tagInput.trim())) {
      handleChange('tags', [...formData.tags, tagInput.trim()]);
      setTagInput('');
    }
  };

  const handleRemoveTag = (tagToRemove: string) => {
    handleChange('tags', formData.tags.filter(tag => tag !== tagToRemove));
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleAddTag();
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto mx-4">
        <div className="flex items-center justify-between p-6 border-b border-gray-200">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
              <Target className="h-5 w-5 text-white" />
            </div>
            <h2 className="text-lg sm:text-xl font-semibold text-gray-900">Create New Task</h2>
          </div>
          <button
            onClick={onCancel}
            className="text-gray-400 hover:text-gray-600 p-2 rounded-lg hover:bg-gray-100 min-h-[44px] min-w-[44px]"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-4 sm:p-6">
          <div className="space-y-6">
            {/* Basic Information */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="sm:col-span-2">
                <label className="block text-sm font-medium text-gray-700 mb-2">Task Title *</label>
                <input
                  type="text"
                  value={formData.title}
                  onChange={(e) => handleChange('title', e.target.value)}
                  className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
                  placeholder="Enter task title..."
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Project</label>
                <select
                  value={formData.projectId}
                  onChange={(e) => handleChange('projectId', e.target.value)}
                  className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
                >
                  <option value="">No specific project</option>
                  {projects.map(project => (
                    <option key={project.id} value={project.id}>{project.name}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Category</label>
                <select
                  value={formData.category}
                  onChange={(e) => handleChange('category', e.target.value as Task['category'])}
                  className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
                >
                  <option value="research">Research</option>
                  <option value="development">Development</option>
                  <option value="testing">Testing</option>
                  <option value="documentation">Documentation</option>
                  <option value="analysis">Analysis</option>
                  <option value="experiment">Experiment</option>
                  <option value="other">Other</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Priority</label>
                <select
                  value={formData.priority}
                  onChange={(e) => handleChange('priority', e.target.value as Task['priority'])}
                  className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="urgent">Urgent</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Estimated Hours</label>
                <input
                  type="number"
                  value={formData.estimatedHours}
                  onChange={(e) => handleChange('estimatedHours', parseInt(e.target.value) || 0)}
                  className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
                  min="0"
                  step="0.5"
                  inputMode="decimal"
                />
              </div>
            </div>

            {/* Description */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Description *</label>
              <textarea
                value={formData.description}
                onChange={(e) => handleChange('description', e.target.value)}
                className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[88px]"
                rows={4}
                placeholder="Describe the task in detail..."
                required
              />
            </div>

            {/* Dates */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Start Date</label>
                <input
                  type="date"
                  value={formData.startDate}
                  onChange={(e) => handleChange('startDate', e.target.value)}
                  className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Due Date</label>
                <input
                  type="date"
                  value={formData.dueDate}
                  onChange={(e) => handleChange('dueDate', e.target.value)}
                  className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
                />
              </div>
            </div>

            {/* Assignment */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Assign To ({formData.assignedTo.length} selected)
              </label>
              <div className="border border-gray-300 rounded-lg p-3 max-h-40 sm:max-h-32 overflow-y-auto">
                {employees.length === 0 ? (
                  <p className="text-sm text-gray-500">No employees available</p>
                ) : (
                  <div className="space-y-2">
                    {employees.map(employee => {
                      const isSelected = formData.assignedTo.includes(employee.id);
                      return (
                        <label
                          key={employee.id}
                          className={`flex items-center p-3 rounded-lg cursor-pointer transition-all duration-200 min-h-[44px] ${
                            isSelected ? 'bg-blue-50 border border-blue-200' : 'hover:bg-gray-50'
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => handleEmployeeToggle(employee.id)}
                            className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                          />
                          <div className="ml-2 flex-1">
                            <p className="text-sm font-medium text-gray-900">{employee.name}</p>
                            <p className="text-xs text-gray-600">{employee.role} • {employee.rndPercentage}% R&D</p>
                          </div>
                          {isSelected && (
                            <div className="ml-2 text-blue-600">
                              <CheckCircle className="h-4 w-4" />
                            </div>
                          )}
                        </label>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>

            {/* R&D Classification */}
            <div className="space-y-4">
              <div className="flex items-center">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={formData.isRnD}
                    onChange={(e) => handleChange('isRnD', e.target.checked)}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="ml-2 text-sm font-medium text-gray-700">R&D Qualified Activity</span>
                </label>
              </div>

              {formData.isRnD && (
                <div className="space-y-4 pl-6 border-l-2 border-blue-200">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Technical Uncertainty</label>
                    <textarea
                      value={formData.technicalUncertainty}
                      onChange={(e) => handleChange('technicalUncertainty', e.target.value)}
                      className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[88px]"
                      rows={3}
                      placeholder="Describe the technical uncertainty this task addresses..."
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">R&D Justification</label>
                    <textarea
                      value={formData.rndJustification}
                      onChange={(e) => handleChange('rndJustification', e.target.value)}
                      className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[66px]"
                      rows={2}
                      placeholder="Explain why this qualifies as R&D under IRC Section 41..."
                    />
                  </div>

                  <div className="flex items-center">
                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        checked={formData.experimentationRequired}
                        onChange={(e) => handleChange('experimentationRequired', e.target.checked)}
                        className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                      />
                      <span className="ml-2 text-sm text-gray-700">Requires Systematic Experimentation</span>
                    </label>
                  </div>
                </div>
              )}
            </div>

            {/* Tags */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Tags</label>
              <div className="space-y-2">
                <div className="flex space-x-2">
                  <input
                    type="text"
                    value={tagInput}
                    onChange={(e) => setTagInput(e.target.value)}
                    onKeyPress={handleKeyPress}
                    className="flex-1 border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
                    placeholder="Add a tag..."
                  />
                  <button
                    type="button"
                    onClick={handleAddTag}
                    className="px-3 py-3 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 min-h-[44px] min-w-[44px]"
                  >
                    <Plus className="h-4 w-4" />
                  </button>
                </div>
                {formData.tags.length > 0 && (
                  <div className="flex flex-wrap gap-2">
                    {formData.tags.map((tag, index) => (
                      <span
                        key={index}
                        className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-blue-100 text-blue-800"
                      >
                        <Tag className="h-3 w-3 mr-1" />
                        {tag}
                        <button
                          type="button"
                          onClick={() => handleRemoveTag(tag)}
                          className="ml-1 text-blue-600 hover:text-blue-800 p-1 min-h-[24px] min-w-[24px]"
                        >
                          <X className="h-3 w-3" />
                        </button>
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row justify-end space-y-2 sm:space-y-0 sm:space-x-3 mt-8 pt-6 border-t border-gray-200">
            <button
              type="button"
              onClick={onCancel}
              className="w-full sm:w-auto px-6 py-3 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors min-h-[44px]"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="w-full sm:w-auto px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors min-h-[44px]"
            >
              Create Task
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};