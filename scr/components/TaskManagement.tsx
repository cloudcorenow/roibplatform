import React, { useState } from 'react';
import { Plus, Search, Filter, Calendar, Clock, Users, Target, CheckCircle, AlertTriangle, Play, Pause, Square } from 'lucide-react';
import { Task, TaskTemplate, TaskFilter, TaskStats } from '../types/tasks';
import { Project, Employee } from '../types';
import { formatDuration, formatDate, generateId } from '../utils/formatters';
import { TaskBoard } from './TaskBoard';
import { TaskForm } from './TaskForm';
import { TaskDetails } from './TaskDetails';
import { TaskTemplates } from './TaskTemplates';

interface TaskManagementProps {
  tasks: Task[];
  projects: Project[];
  employees: Employee[];
  templates: TaskTemplate[];
  onAddTask: (task: Omit<Task, 'id' | 'createdAt' | 'updatedAt'>) => void;
  onUpdateTask: (id: string, updates: Partial<Task>) => void;
  onDeleteTask: (id: string) => void;
  onAddComment: (taskId: string, comment: string) => void;
  onCreateFromTemplate: (templateId: string, projectId: string, assignedTo: string[]) => void;
}

export const TaskManagement: React.FC<TaskManagementProps> = ({
  tasks,
  projects,
  employees,
  templates,
  onAddTask,
  onUpdateTask,
  onDeleteTask,
  onAddComment,
  onCreateFromTemplate
}) => {
  const [activeView, setActiveView] = useState<'board' | 'list' | 'templates'>('board');
  const [selectedTask, setSelectedTask] = useState<Task | null>(null);
  const [showTaskForm, setShowTaskForm] = useState(false);
  const [showFilters, setShowFilters] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filters, setFilters] = useState<TaskFilter>({});

  // Calculate task statistics
  const taskStats: TaskStats = React.useMemo(() => {
    const now = new Date();
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    
    return {
      total: tasks.length,
      byStatus: {
        'todo': tasks.filter(t => t.status === 'todo').length,
        'in-progress': tasks.filter(t => t.status === 'in-progress').length,
        'review': tasks.filter(t => t.status === 'review').length,
        'completed': tasks.filter(t => t.status === 'completed').length,
        'cancelled': tasks.filter(t => t.status === 'cancelled').length
      },
      byPriority: {
        'low': tasks.filter(t => t.priority === 'low').length,
        'medium': tasks.filter(t => t.priority === 'medium').length,
        'high': tasks.filter(t => t.priority === 'high').length,
        'urgent': tasks.filter(t => t.priority === 'urgent').length
      },
      overdue: tasks.filter(t => t.dueDate && new Date(t.dueDate) < now && t.status !== 'completed').length,
      completedThisWeek: tasks.filter(t => 
        t.status === 'completed' && 
        t.completedDate && 
        new Date(t.completedDate) >= weekAgo
      ).length,
      totalEstimatedHours: tasks.reduce((sum, t) => sum + t.estimatedHours, 0),
      totalActualHours: tasks.reduce((sum, t) => sum + t.actualHours, 0),
      rndTasks: tasks.filter(t => t.isRnD).length
    };
  }, [tasks]);

  // Filter tasks based on search and filters
  const filteredTasks = React.useMemo(() => {
    return tasks.filter(task => {
      // Search filter
      if (searchTerm) {
        const searchLower = searchTerm.toLowerCase();
        const matchesSearch = 
          task.title.toLowerCase().includes(searchLower) ||
          task.description.toLowerCase().includes(searchLower) ||
          task.tags.some(tag => tag.toLowerCase().includes(searchLower)) ||
          task.assignedNames.some(name => name.toLowerCase().includes(searchLower));
        if (!matchesSearch) return false;
      }

      // Status filter
      if (filters.status && filters.status.length > 0) {
        if (!filters.status.includes(task.status)) return false;
      }

      // Priority filter
      if (filters.priority && filters.priority.length > 0) {
        if (!filters.priority.includes(task.priority)) return false;
      }

      // Category filter
      if (filters.category && filters.category.length > 0) {
        if (!filters.category.includes(task.category)) return false;
      }

      // Assigned to filter
      if (filters.assignedTo && filters.assignedTo.length > 0) {
        const hasAssignedUser = filters.assignedTo.some(userId => 
          task.assignedTo.includes(userId)
        );
        if (!hasAssignedUser) return false;
      }

      // Project filter
      if (filters.projectId) {
        if (task.projectId !== filters.projectId) return false;
      }

      // R&D filter
      if (filters.isRnD !== undefined) {
        if (task.isRnD !== filters.isRnD) return false;
      }

      // Due date range filter
      if (filters.dueDateRange) {
        if (!task.dueDate) return false;
        const taskDueDate = new Date(task.dueDate);
        const startDate = new Date(filters.dueDateRange.start);
        const endDate = new Date(filters.dueDateRange.end);
        if (taskDueDate < startDate || taskDueDate > endDate) return false;
      }

      // Tags filter
      if (filters.tags && filters.tags.length > 0) {
        const hasMatchingTag = filters.tags.some(tag => task.tags.includes(tag));
        if (!hasMatchingTag) return false;
      }

      return true;
    });
  }, [tasks, searchTerm, filters]);

  const handleCreateTask = (taskData: Omit<Task, 'id' | 'createdAt' | 'updatedAt'>) => {
    onAddTask(taskData);
    setShowTaskForm(false);
  };

  const handleUpdateFilter = (key: keyof TaskFilter, value: any) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  };

  const clearFilters = () => {
    setFilters({});
    setSearchTerm('');
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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex-1 min-w-0">
          <h1 className="text-3xl font-bold text-gray-900">Task Management</h1>
          <p className="text-gray-600 mt-2 text-sm sm:text-base">Organize and track your R&D tasks and activities</p>
        </div>
        <div className="flex flex-col sm:flex-row items-end sm:items-center space-y-2 sm:space-y-0 sm:space-x-3">
          <div className="flex bg-gray-100 rounded-lg p-1 w-full sm:w-auto">
            <button
              onClick={() => setActiveView('board')}
              className={`flex-1 sm:flex-none px-3 py-2 rounded text-sm font-medium transition-colors ${
                activeView === 'board' ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600'
              }`}
            >
              Board
            </button>
            <button
              onClick={() => setActiveView('list')}
              className={`flex-1 sm:flex-none px-3 py-2 rounded text-sm font-medium transition-colors ${
                activeView === 'list' ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600'
              }`}
            >
              List
            </button>
            <button
              onClick={() => setActiveView('templates')}
              className={`flex-1 sm:flex-none px-3 py-2 rounded text-sm font-medium transition-colors ${
                activeView === 'templates' ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600'
              }`}
            >
              Templates
            </button>
          </div>
          <button
            onClick={() => setShowTaskForm(true)}
            className="w-full sm:w-auto bg-blue-600 text-white px-4 py-3 rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center space-x-2 min-h-[44px]"
          >
            <Plus className="h-4 w-4" />
            <span>New Task</span>
          </button>
        </div>
      </div>

      {/* Task Statistics */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
        <div className="bg-blue-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-blue-900 mb-2 flex items-center">
            <Target className="h-4 w-4 mr-1" />
            Total Tasks
          </h4>
          <p className="text-xl sm:text-2xl font-bold text-blue-600">{taskStats.total}</p>
        </div>
        <div className="bg-yellow-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-yellow-900 mb-2 flex items-center">
            <Play className="h-4 w-4 mr-1" />
            In Progress
          </h4>
          <p className="text-xl sm:text-2xl font-bold text-yellow-600">{taskStats.byStatus['in-progress']}</p>
        </div>
        <div className="bg-green-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-green-900 mb-2 flex items-center">
            <CheckCircle className="h-4 w-4 mr-1" />
            Completed
          </h4>
          <p className="text-xl sm:text-2xl font-bold text-green-600">{taskStats.byStatus.completed}</p>
        </div>
        <div className="bg-red-50 p-4 rounded-lg col-span-2 sm:col-span-1">
          <h4 className="text-sm font-medium text-red-900 mb-2 flex items-center">
            <AlertTriangle className="h-4 w-4 mr-1" />
            Overdue
          </h4>
          <p className="text-xl sm:text-2xl font-bold text-red-600">{taskStats.overdue}</p>
        </div>
        <div className="bg-purple-50 p-4 rounded-lg col-span-2 sm:col-span-3 lg:col-span-1">
          <h4 className="text-sm font-medium text-purple-900 mb-2 flex items-center">
            <Clock className="h-4 w-4 mr-1" />
            R&D Tasks
          </h4>
          <p className="text-xl sm:text-2xl font-bold text-purple-600">{taskStats.rndTasks}</p>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="bg-white p-4 rounded-lg border border-gray-200">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between mb-4 space-y-3 sm:space-y-0">
          <div className="flex flex-col sm:flex-row items-start sm:items-center space-y-3 sm:space-y-0 sm:space-x-4 flex-1 w-full sm:w-auto">
            <div className="relative flex-1 max-w-md">
              <Search className="h-4 w-4 absolute left-3 top-3 text-gray-400" />
              <input
                type="text"
                placeholder="Search tasks..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-9 pr-3 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
              />
            </div>
            <button
              onClick={() => setShowFilters(!showFilters)}
              className="w-full sm:w-auto flex items-center justify-center space-x-2 px-3 py-3 border border-gray-300 rounded-lg hover:bg-gray-50 min-h-[44px]"
            >
              <Filter className="h-4 w-4" />
              <span>Filters</span>
            </button>
            {(Object.keys(filters).length > 0 || searchTerm) && (
              <button
                onClick={clearFilters}
                className="text-sm text-gray-500 hover:text-gray-700 px-2 py-1"
              >
                Clear All
              </button>
            )}
          </div>
          <div className="text-sm text-gray-600 w-full sm:w-auto text-center sm:text-right">
            {filteredTasks.length} of {tasks.length} tasks
          </div>
        </div>

        {showFilters && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-4 border-t border-gray-200">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Status</label>
              <select
                multiple
                value={filters.status || []}
                onChange={(e) => handleUpdateFilter('status', Array.from(e.target.selectedOptions, option => option.value) as Task['status'][])}
                className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
              >
                <option value="todo">To Do</option>
                <option value="in-progress">In Progress</option>
                <option value="review">Review</option>
                <option value="completed">Completed</option>
                <option value="cancelled">Cancelled</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Priority</label>
              <select
                multiple
                value={filters.priority || []}
                onChange={(e) => handleUpdateFilter('priority', Array.from(e.target.selectedOptions, option => option.value) as Task['priority'][])}
                className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="urgent">Urgent</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Project</label>
              <select
                value={filters.projectId || ''}
                onChange={(e) => handleUpdateFilter('projectId', e.target.value || undefined)}
                className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
              >
                <option value="">All Projects</option>
                {projects.map(project => (
                  <option key={project.id} value={project.id}>{project.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">R&D Classification</label>
              <select
                value={filters.isRnD === undefined ? '' : filters.isRnD.toString()}
                onChange={(e) => {
                  const value = e.target.value;
                  handleUpdateFilter('isRnD', value === '' ? undefined : value === 'true');
                }}
                className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
              >
                <option value="">All Tasks</option>
                <option value="true">R&D Only</option>
                <option value="false">Non-R&D Only</option>
              </select>
            </div>
          </div>
        )}
      </div>

      {/* Task Form Modal */}
      {showTaskForm && (
        <TaskForm
          projects={projects}
          employees={employees}
          onSubmit={handleCreateTask}
          onCancel={() => setShowTaskForm(false)}
        />
      )}

      {/* Task Details Modal */}
      {selectedTask && (
        <TaskDetails
          task={selectedTask}
          projects={projects}
          employees={employees}
          onUpdate={onUpdateTask}
          onDelete={onDeleteTask}
          onAddComment={onAddComment}
          onClose={() => setSelectedTask(null)}
        />
      )}

      {/* Main Content */}
      {activeView === 'board' && (
        <TaskBoard
          tasks={filteredTasks}
          onTaskClick={setSelectedTask}
          onUpdateTask={onUpdateTask}
          getPriorityColor={getPriorityColor}
          getStatusColor={getStatusColor}
        />
      )}

      {activeView === 'list' && (
        <div className="bg-white rounded-lg border border-gray-200">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Task</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Priority</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Assigned</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Due Date</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Progress</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredTasks.map(task => (
                  <tr 
                    key={task.id} 
                    className="hover:bg-gray-50 cursor-pointer"
                    onClick={() => setSelectedTask(task)}
                  >
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="flex-1">
                          <div className="text-sm font-medium text-gray-900">{task.title}</div>
                          <div className="text-sm text-gray-500">{task.projectName}</div>
                        </div>
                        {task.isRnD && (
                          <span className="ml-2 inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                            R&D
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(task.status)}`}>
                        {task.status.replace('-', ' ')}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getPriorityColor(task.priority)}`}>
                        {task.priority}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {task.assignedNames.join(', ')}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {task.dueDate ? formatDate(task.dueDate) : '-'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="w-16 bg-gray-200 rounded-full h-2 mr-2">
                          <div
                            className="bg-blue-600 h-2 rounded-full"
                            style={{ width: `${task.progress}%` }}
                          />
                        </div>
                        <span className="text-sm text-gray-600">{task.progress}%</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {filteredTasks.length === 0 && (
            <div className="text-center py-8 text-gray-500">
              <Target className="h-12 w-12 mx-auto mb-4 text-gray-300" />
              <p>No tasks found matching your criteria</p>
            </div>
          )}
        </div>
      )}

      {activeView === 'templates' && (
        <TaskTemplates
          templates={templates}
          projects={projects}
          employees={employees}
          onCreateFromTemplate={onCreateFromTemplate}
        />
      )}
    </div>
  );
};