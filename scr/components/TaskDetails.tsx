import React, { useState } from 'react';
import { X, Edit3, Trash2, MessageSquare, Clock, Users, Calendar, Target, Tag, CheckCircle, AlertTriangle, Play } from 'lucide-react';
import { Task, TaskComment } from '../types/tasks';
import { Project, Employee } from '../types';
import { formatDate, formatDuration, formatDateTime } from '../utils/formatters';

interface TaskDetailsProps {
  task: Task;
  projects: Project[];
  employees: Employee[];
  onUpdate: (id: string, updates: Partial<Task>) => void;
  onDelete: (id: string) => void;
  onAddComment: (taskId: string, comment: string) => void;
  onClose: () => void;
}

export const TaskDetails: React.FC<TaskDetailsProps> = ({
  task,
  projects,
  employees,
  onUpdate,
  onDelete,
  onAddComment,
  onClose
}) => {
  const [isEditing, setIsEditing] = useState(false);
  const [newComment, setNewComment] = useState('');
  const [editData, setEditData] = useState({
    title: task.title,
    description: task.description,
    status: task.status,
    priority: task.priority,
    progress: task.progress,
    estimatedHours: task.estimatedHours,
    dueDate: task.dueDate || '',
    technicalUncertainty: task.technicalUncertainty || '',
    rndJustification: task.rndJustification || ''
  });

  const handleSave = () => {
    const updates: Partial<Task> = {
      ...editData,
      updatedAt: new Date().toISOString()
    };

    if (editData.status === 'completed' && task.status !== 'completed') {
      updates.completedDate = new Date().toISOString();
      updates.progress = 100;
    }

    onUpdate(task.id, updates);
    setIsEditing(false);
  };

  const handleAddComment = () => {
    if (!newComment.trim()) return;
    onAddComment(task.id, newComment.trim());
    setNewComment('');
  };

  const handleStatusChange = (newStatus: Task['status']) => {
    const updates: Partial<Task> = { 
      status: newStatus,
      updatedAt: new Date().toISOString()
    };
    
    if (newStatus === 'completed' && task.status !== 'completed') {
      updates.completedDate = new Date().toISOString();
      updates.progress = 100;
    }
    
    onUpdate(task.id, updates);
  };

  const getPriorityColor = (priority: Task['priority']) => {
    switch (priority) {
      case 'urgent': return 'bg-red-100 text-red-800';
      case 'high': return 'bg-orange-100 text-orange-800';
      case 'medium': return 'bg-yellow-100 text-yellow-800';
      case 'low': return 'bg-gray-100 text-gray-800';
    }
  };

  const getStatusColor = (status: Task['status']) => {
    switch (status) {
      case 'completed': return 'bg-green-100 text-green-800';
      case 'in-progress': return 'bg-blue-100 text-blue-800';
      case 'review': return 'bg-purple-100 text-purple-800';
      case 'cancelled': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getStatusIcon = (status: Task['status']) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-4 w-4" />;
      case 'in-progress': return <Play className="h-4 w-4" />;
      case 'review': return <AlertTriangle className="h-4 w-4" />;
      default: return <Target className="h-4 w-4" />;
    }
  };

  const isOverdue = task.dueDate && new Date(task.dueDate) < new Date() && task.status !== 'completed';
  const project = projects.find(p => p.id === task.projectId);

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-6 border-b border-gray-200">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
              <Target className="h-5 w-5 text-white" />
            </div>
            <div>
              <h2 className="text-xl font-semibold text-gray-900">{task.title}</h2>
              <p className="text-sm text-gray-600">{project?.name}</p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setIsEditing(!isEditing)}
              className="text-blue-600 hover:text-blue-700 p-2 rounded-lg hover:bg-blue-50"
            >
              <Edit3 className="h-4 w-4" />
            </button>
            <button
              onClick={() => onDelete(task.id)}
              className="text-red-600 hover:text-red-700 p-2 rounded-lg hover:bg-red-50"
            >
              <Trash2 className="h-4 w-4" />
            </button>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600 p-2 rounded-lg hover:bg-gray-100"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        <div className="p-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Main Content */}
            <div className="lg:col-span-2 space-y-6">
              {/* Status and Priority */}
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-2">
                  <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(task.status)}`}>
                    {getStatusIcon(task.status)}
                    <span className="ml-1 capitalize">{task.status.replace('-', ' ')}</span>
                  </span>
                  <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getPriorityColor(task.priority)}`}>
                    {task.priority} priority
                  </span>
                  {task.isRnD && (
                    <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-green-100 text-green-800">
                      R&D Qualified
                    </span>
                  )}
                  {isOverdue && (
                    <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-red-100 text-red-800">
                      <AlertTriangle className="h-3 w-3 mr-1" />
                      Overdue
                    </span>
                  )}
                </div>
              </div>

              {/* Quick Status Actions */}
              {!isEditing && (
                <div className="flex space-x-2">
                  {task.status === 'todo' && (
                    <button
                      onClick={() => handleStatusChange('in-progress')}
                      className="bg-blue-600 text-white px-3 py-1 rounded text-sm hover:bg-blue-700"
                    >
                      Start Task
                    </button>
                  )}
                  {task.status === 'in-progress' && (
                    <button
                      onClick={() => handleStatusChange('review')}
                      className="bg-purple-600 text-white px-3 py-1 rounded text-sm hover:bg-purple-700"
                    >
                      Submit for Review
                    </button>
                  )}
                  {task.status === 'review' && (
                    <button
                      onClick={() => handleStatusChange('completed')}
                      className="bg-green-600 text-white px-3 py-1 rounded text-sm hover:bg-green-700"
                    >
                      Mark Complete
                    </button>
                  )}
                </div>
              )}

              {/* Description */}
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-3">Description</h3>
                {isEditing ? (
                  <textarea
                    value={editData.description}
                    onChange={(e) => setEditData({ ...editData, description: e.target.value })}
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    rows={4}
                  />
                ) : (
                  <p className="text-gray-700 whitespace-pre-wrap">{task.description}</p>
                )}
              </div>

              {/* R&D Information */}
              {task.isRnD && (
                <div className="bg-green-50 p-4 rounded-lg">
                  <h3 className="text-lg font-semibold text-green-900 mb-3">R&D Qualification Details</h3>
                  
                  {task.technicalUncertainty && (
                    <div className="mb-3">
                      <h4 className="text-sm font-medium text-green-800 mb-1">Technical Uncertainty</h4>
                      {isEditing ? (
                        <textarea
                          value={editData.technicalUncertainty}
                          onChange={(e) => setEditData({ ...editData, technicalUncertainty: e.target.value })}
                          className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                          rows={2}
                        />
                      ) : (
                        <p className="text-green-700 text-sm">{task.technicalUncertainty}</p>
                      )}
                    </div>
                  )}

                  {task.rndJustification && (
                    <div className="mb-3">
                      <h4 className="text-sm font-medium text-green-800 mb-1">R&D Justification</h4>
                      {isEditing ? (
                        <textarea
                          value={editData.rndJustification}
                          onChange={(e) => setEditData({ ...editData, rndJustification: e.target.value })}
                          className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                          rows={2}
                        />
                      ) : (
                        <p className="text-green-700 text-sm">{task.rndJustification}</p>
                      )}
                    </div>
                  )}

                  {task.experimentationRequired && (
                    <div className="flex items-center text-sm text-green-800">
                      <CheckCircle className="h-4 w-4 mr-2" />
                      <span>Requires systematic experimentation</span>
                    </div>
                  )}
                </div>
              )}

              {/* Comments */}
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-3">Comments</h3>
                <div className="space-y-3">
                  {task.comments.map(comment => (
                    <div key={comment.id} className="bg-gray-50 p-3 rounded-lg">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm font-medium text-gray-900">{comment.authorName}</span>
                        <span className="text-xs text-gray-500">{formatDateTime(comment.timestamp)}</span>
                      </div>
                      <p className="text-sm text-gray-700">{comment.content}</p>
                    </div>
                  ))}
                  
                  <div className="flex space-x-2">
                    <input
                      type="text"
                      value={newComment}
                      onChange={(e) => setNewComment(e.target.value)}
                      className="flex-1 border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      placeholder="Add a comment..."
                      onKeyPress={(e) => e.key === 'Enter' && handleAddComment()}
                    />
                    <button
                      onClick={handleAddComment}
                      className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
                    >
                      <MessageSquare className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Sidebar */}
            <div className="space-y-6">
              {/* Progress */}
              <div className="bg-white p-4 rounded-lg border border-gray-200">
                <h4 className="text-sm font-medium text-gray-900 mb-3">Progress</h4>
                {isEditing ? (
                  <div className="space-y-2">
                    <input
                      type="range"
                      min="0"
                      max="100"
                      value={editData.progress}
                      onChange={(e) => setEditData({ ...editData, progress: parseInt(e.target.value) })}
                      className="w-full"
                    />
                    <div className="text-center text-sm text-gray-600">{editData.progress}%</div>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <div className="w-full bg-gray-200 rounded-full h-3">
                      <div
                        className={`h-3 rounded-full ${
                          task.progress === 100 ? 'bg-green-500' :
                          task.progress >= 75 ? 'bg-blue-500' :
                          task.progress >= 50 ? 'bg-yellow-500' :
                          'bg-gray-400'
                        }`}
                        style={{ width: `${task.progress}%` }}
                      />
                    </div>
                    <div className="text-center text-sm text-gray-600">{task.progress}%</div>
                  </div>
                )}
              </div>

              {/* Time Tracking */}
              <div className="bg-white p-4 rounded-lg border border-gray-200">
                <h4 className="text-sm font-medium text-gray-900 mb-3">Time Tracking</h4>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600">Estimated:</span>
                    <span className="font-medium">{formatDuration(task.estimatedHours)}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600">Actual:</span>
                    <span className="font-medium">{formatDuration(task.actualHours)}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600">Remaining:</span>
                    <span className={`font-medium ${
                      task.actualHours > task.estimatedHours ? 'text-red-600' : 'text-green-600'
                    }`}>
                      {formatDuration(Math.max(0, task.estimatedHours - task.actualHours))}
                    </span>
                  </div>
                </div>
              </div>

              {/* Assignment */}
              <div className="bg-white p-4 rounded-lg border border-gray-200">
                <h4 className="text-sm font-medium text-gray-900 mb-3">Assignment</h4>
                <div className="space-y-2">
                  {task.assignedNames.map((name, index) => (
                    <div key={index} className="flex items-center space-x-2">
                      <div className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center">
                        <span className="text-xs font-medium text-blue-600">
                          {name.split(' ').map(n => n[0]).join('')}
                        </span>
                      </div>
                      <span className="text-sm text-gray-900">{name}</span>
                    </div>
                  ))}
                  {task.assignedNames.length === 0 && (
                    <p className="text-sm text-gray-500">Unassigned</p>
                  )}
                </div>
              </div>

              {/* Dates */}
              <div className="bg-white p-4 rounded-lg border border-gray-200">
                <h4 className="text-sm font-medium text-gray-900 mb-3">Timeline</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-600">Created:</span>
                    <span>{formatDate(task.createdAt)}</span>
                  </div>
                  {task.startDate && (
                    <div className="flex justify-between">
                      <span className="text-gray-600">Start:</span>
                      <span>{formatDate(task.startDate)}</span>
                    </div>
                  )}
                  {task.dueDate && (
                    <div className="flex justify-between">
                      <span className="text-gray-600">Due:</span>
                      <span className={isOverdue ? 'text-red-600 font-medium' : ''}>
                        {formatDate(task.dueDate)}
                      </span>
                    </div>
                  )}
                  {task.completedDate && (
                    <div className="flex justify-between">
                      <span className="text-gray-600">Completed:</span>
                      <span className="text-green-600">{formatDate(task.completedDate)}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Tags */}
              {task.tags.length > 0 && (
                <div className="bg-white p-4 rounded-lg border border-gray-200">
                  <h4 className="text-sm font-medium text-gray-900 mb-3">Tags</h4>
                  <div className="flex flex-wrap gap-2">
                    {task.tags.map((tag, index) => (
                      <span key={index} className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-gray-100 text-gray-600">
                        <Tag className="h-3 w-3 mr-1" />
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {isEditing && (
                <div className="flex justify-end space-x-3 pt-4 border-t border-gray-200">
                  <button
                    onClick={() => setIsEditing(false)}
                    className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleSave}
                    className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                  >
                    Save Changes
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};