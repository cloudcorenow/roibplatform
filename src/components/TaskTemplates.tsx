import React, { useState } from 'react';
import { BookTemplate as Template, Plus, Clock, CheckCircle, Users, Target, FileText } from 'lucide-react';
import { TaskTemplate } from '../types/tasks';
import { Project, Employee } from '../types';
import { formatDuration } from '../utils/formatters';

interface TaskTemplatesProps {
  templates: TaskTemplate[];
  projects: Project[];
  employees: Employee[];
  onCreateFromTemplate: (templateId: string, projectId: string, assignedTo: string[]) => void;
}

export const TaskTemplates: React.FC<TaskTemplatesProps> = ({
  templates,
  projects,
  employees,
  onCreateFromTemplate
}) => {
  const [selectedTemplate, setSelectedTemplate] = useState<TaskTemplate | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [createData, setCreateData] = useState({
    projectId: '',
    assignedTo: [] as string[]
  });

  const handleCreateFromTemplate = () => {
    if (!selectedTemplate || !createData.projectId) return;
    
    onCreateFromTemplate(selectedTemplate.id, createData.projectId, createData.assignedTo);
    setShowCreateForm(false);
    setSelectedTemplate(null);
    setCreateData({ projectId: '', assignedTo: [] });
  };

  const handleEmployeeToggle = (employeeId: string) => {
    const isSelected = createData.assignedTo.includes(employeeId);
    const newAssignedTo = isSelected
      ? createData.assignedTo.filter(id => id !== employeeId)
      : [...createData.assignedTo, employeeId];
    
    setCreateData({ ...createData, assignedTo: newAssignedTo });
  };

  const getCategoryColor = (category: TaskTemplate['category']) => {
    switch (category) {
      case 'research': return 'bg-blue-100 text-blue-800';
      case 'development': return 'bg-green-100 text-green-800';
      case 'testing': return 'bg-yellow-100 text-yellow-800';
      case 'documentation': return 'bg-purple-100 text-purple-800';
      case 'analysis': return 'bg-orange-100 text-orange-800';
      case 'experiment': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {templates.map(template => (
          <div key={template.id} className="bg-white p-6 rounded-lg border border-gray-200 hover:shadow-md transition-all duration-200">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                  <Template className="h-5 w-5 text-blue-600" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-gray-900">{template.name}</h3>
                  <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getCategoryColor(template.category)}`}>
                    {template.category}
                  </span>
                </div>
              </div>
            </div>

            <p className="text-sm text-gray-600 mb-4">{template.description}</p>

            <div className="space-y-3 mb-4">
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-600 flex items-center">
                  <Clock className="h-4 w-4 mr-1" />
                  Estimated Time
                </span>
                <span className="font-medium">{formatDuration(template.estimatedHours)}</span>
              </div>
              
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-600 flex items-center">
                  <Target className="h-4 w-4 mr-1" />
                  Subtasks
                </span>
                <span className="font-medium">{template.subtaskTemplates.length}</span>
              </div>

              {template.isRnD && (
                <div className="flex items-center text-sm">
                  <CheckCircle className="h-4 w-4 mr-1 text-green-600" />
                  <span className="text-green-600 font-medium">R&D Qualified</span>
                </div>
              )}
            </div>

            {template.tags.length > 0 && (
              <div className="flex flex-wrap gap-1 mb-4">
                {template.tags.map((tag, index) => (
                  <span key={index} className="inline-flex items-center px-2 py-1 rounded text-xs bg-gray-100 text-gray-600">
                    {tag}
                  </span>
                ))}
              </div>
            )}

            <div className="flex space-x-2">
              <button
                onClick={() => setSelectedTemplate(template)}
                className="flex-1 text-blue-600 border border-blue-600 px-3 py-2 rounded-lg hover:bg-blue-50 text-sm font-medium"
              >
                View Details
              </button>
              <button
                onClick={() => {
                  setSelectedTemplate(template);
                  setShowCreateForm(true);
                }}
                className="flex-1 bg-blue-600 text-white px-3 py-2 rounded-lg hover:bg-blue-700 text-sm font-medium"
              >
                Use Template
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Template Details Modal */}
      {selectedTemplate && !showCreateForm && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-xl max-w-2xl w-full max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between p-6 border-b border-gray-200">
              <h2 className="text-xl font-semibold text-gray-900">{selectedTemplate.name}</h2>
              <button
                onClick={() => setSelectedTemplate(null)}
                className="text-gray-400 hover:text-gray-600"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="p-6">
              <p className="text-gray-700 mb-6">{selectedTemplate.description}</p>

              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-3">Subtasks</h3>
                  <div className="space-y-2">
                    {selectedTemplate.subtaskTemplates.map((subtask, index) => (
                      <div key={index} className="flex items-start space-x-3 p-3 bg-gray-50 rounded-lg">
                        <div className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                          <span className="text-xs font-medium text-blue-600">{subtask.order}</span>
                        </div>
                        <div className="flex-1">
                          <h4 className="text-sm font-medium text-gray-900">{subtask.title}</h4>
                          <p className="text-xs text-gray-600 mt-1">{subtask.description}</p>
                          <p className="text-xs text-gray-500 mt-1">{formatDuration(subtask.estimatedHours)}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-3">Checklist</h3>
                  <div className="space-y-2">
                    {selectedTemplate.checklist.map((item, index) => (
                      <div key={index} className="flex items-center space-x-2">
                        <CheckCircle className={`h-4 w-4 ${item.required ? 'text-red-500' : 'text-gray-400'}`} />
                        <span className="text-sm text-gray-700">{item.item}</span>
                        {item.required && (
                          <span className="text-xs text-red-600 font-medium">Required</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="flex justify-end space-x-3 mt-6 pt-6 border-t border-gray-200">
                <button
                  onClick={() => setSelectedTemplate(null)}
                  className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
                >
                  Close
                </button>
                <button
                  onClick={() => setShowCreateForm(true)}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  Use This Template
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Create from Template Modal */}
      {showCreateForm && selectedTemplate && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-xl max-w-md w-full">
            <div className="flex items-center justify-between p-6 border-b border-gray-200">
              <h2 className="text-xl font-semibold text-gray-900">Create from Template</h2>
              <button
                onClick={() => setShowCreateForm(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="p-6">
              <div className="space-y-4">
                <div>
                  <h3 className="text-sm font-medium text-gray-900 mb-2">Template: {selectedTemplate.name}</h3>
                  <p className="text-xs text-gray-600">{selectedTemplate.description}</p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Project *</label>
                  <select
                    value={createData.projectId}
                    onChange={(e) => setCreateData({ ...createData, projectId: e.target.value })}
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
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Assign To ({createData.assignedTo.length} selected)
                  </label>
                  <div className="border border-gray-300 rounded-lg p-3 max-h-32 overflow-y-auto">
                    {employees.map(employee => {
                      const isSelected = createData.assignedTo.includes(employee.id);
                      return (
                        <label
                          key={employee.id}
                          className={`flex items-center p-2 rounded cursor-pointer transition-colors ${
                            isSelected ? 'bg-blue-50 border border-blue-200' : 'hover:bg-gray-50'
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => handleEmployeeToggle(employee.id)}
                            className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                          />
                          <div className="ml-2">
                            <p className="text-sm font-medium text-gray-900">{employee.name}</p>
                            <p className="text-xs text-gray-600">{employee.role}</p>
                          </div>
                        </label>
                      );
                    })}
                  </div>
                </div>
              </div>

              <div className="flex justify-end space-x-3 mt-6">
                <button
                  onClick={() => setShowCreateForm(false)}
                  className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  onClick={handleCreateFromTemplate}
                  disabled={!createData.projectId}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                >
                  Create Tasks
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};