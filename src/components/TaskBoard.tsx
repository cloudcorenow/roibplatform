import React from 'react';
import { Clock, Users, Calendar, AlertTriangle, CheckCircle, Play, Pause } from 'lucide-react';
import { Task } from '../types/tasks';
import { formatDate, formatDuration } from '../utils/formatters';

interface TaskBoardProps {
  tasks: Task[];
  onTaskClick: (task: Task) => void;
  onUpdateTask: (id: string, updates: Partial<Task>) => void;
  getPriorityColor: (priority: Task['priority']) => string;
  getStatusColor: (status: Task['status']) => string;
}

export const TaskBoard: React.FC<TaskBoardProps> = ({
  tasks,
  onTaskClick,
  onUpdateTask,
  getPriorityColor,
  getStatusColor
}) => {
  const columns = [
    { id: 'todo', title: 'To Do', status: 'todo' as const },
    { id: 'in-progress', title: 'In Progress', status: 'in-progress' as const },
    { id: 'review', title: 'Review', status: 'review' as const },
    { id: 'completed', title: 'Completed', status: 'completed' as const }
  ];

  const handleDragStart = (e: React.DragEvent, task: Task) => {
    e.dataTransfer.setData('text/plain', task.id);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const handleDrop = (e: React.DragEvent, newStatus: Task['status']) => {
    e.preventDefault();
    const taskId = e.dataTransfer.getData('text/plain');
    const task = tasks.find(t => t.id === taskId);
    
    if (task && task.status !== newStatus) {
      const updates: Partial<Task> = { 
        status: newStatus,
        updatedAt: new Date().toISOString()
      };
      
      if (newStatus === 'completed' && !task.completedDate) {
        updates.completedDate = new Date().toISOString();
        updates.progress = 100;
      }
      
      onUpdateTask(taskId, updates);
    }
  };

  const getTasksByStatus = (status: Task['status']) => {
    return tasks.filter(task => task.status === status);
  };

  const isOverdue = (task: Task) => {
    return task.dueDate && new Date(task.dueDate) < new Date() && task.status !== 'completed';
  };

  const TaskCard: React.FC<{ task: Task }> = ({ task }) => (
    <div
      draggable
      onDragStart={(e) => handleDragStart(e, task)}
      onClick={() => onTaskClick(task)}
      className={`bg-white p-3 sm:p-4 rounded-lg border border-gray-200 shadow-sm hover:shadow-md transition-all duration-200 cursor-pointer touch-manipulation ${
        isOverdue(task) ? 'border-red-300 bg-red-50' : ''
      }`}
    >
      <div className="flex flex-col sm:flex-row sm:items-start justify-between mb-3 space-y-2 sm:space-y-0">
        <h4 className="text-sm font-medium text-gray-900 line-clamp-2 flex-1">{task.title}</h4>
        <div className="flex items-center space-x-1 sm:ml-2">
          <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium ${getPriorityColor(task.priority)}`}>
            {task.priority}
          </span>
          {task.isRnD && (
            <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
              R&D
            </span>
          )}
        </div>
      </div>

      {task.projectName && (
        <p className="text-xs text-gray-600 mb-2 truncate">{task.projectName}</p>
      )}

      <div className="space-y-2">
        {task.assignedNames.length > 0 && (
          <div className="flex items-center text-xs text-gray-600">
            <Users className="h-3 w-3 mr-1" />
            <span className="truncate">{task.assignedNames.join(', ')}</span>
          </div>
        )}

        {task.dueDate && (
          <div className={`flex items-center text-xs ${isOverdue(task) ? 'text-red-600' : 'text-gray-600'}`}>
            <Calendar className="h-3 w-3 mr-1 flex-shrink-0" />
            <span>{formatDate(task.dueDate)}</span>
            {isOverdue(task) && <AlertTriangle className="h-3 w-3 ml-1" />}
          </div>
        )}

        <div className="flex items-center justify-between">
          <div className="flex items-center text-xs text-gray-600">
            <Clock className="h-3 w-3 mr-1 flex-shrink-0" />
            <span>{formatDuration(task.actualHours)} / {formatDuration(task.estimatedHours)}</span>
          </div>
          <div className="text-xs text-gray-600">{task.progress}%</div>
        </div>

        <div className="w-full bg-gray-200 rounded-full h-1.5">
          <div
            className={`h-1.5 rounded-full ${
              task.progress === 100 ? 'bg-green-500' :
              task.progress >= 75 ? 'bg-blue-500' :
              task.progress >= 50 ? 'bg-yellow-500' :
              'bg-gray-400'
            }`}
            style={{ width: `${task.progress}%` }}
          />
        </div>

        {task.tags.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2 max-h-8 overflow-hidden">
            {task.tags.slice(0, 3).map((tag, index) => (
              <span key={index} className="inline-flex items-center px-1.5 py-0.5 rounded text-xs bg-gray-100 text-gray-600">
                {tag}
              </span>
            ))}
            {task.tags.length > 3 && (
              <span className="text-xs text-gray-500">+{task.tags.length - 3}</span>
            )}
          </div>
        )}
      </div>
    </div>
  );

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 lg:gap-6">
      {columns.map(column => {
        const columnTasks = getTasksByStatus(column.status);
        
        return (
          <div key={column.id} className="bg-gray-50 rounded-lg p-3 sm:p-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-medium text-gray-900">{column.title}</h3>
              <span className="bg-gray-200 text-gray-700 text-xs font-medium px-2 py-1 rounded-full">
                {columnTasks.length}
              </span>
            </div>
            
            <div
              className="space-y-3 min-h-[150px] sm:min-h-[200px]"
              onDragOver={handleDragOver}
              onDrop={(e) => handleDrop(e, column.status)}
            >
              {columnTasks.map(task => (
                <TaskCard key={task.id} task={task} />
              ))}
              
              {columnTasks.length === 0 && (
                <div className="text-center py-6 sm:py-8 text-gray-400">
                  <div className="w-12 h-12 bg-gray-200 rounded-lg flex items-center justify-center mx-auto mb-2">
                    {column.status === 'todo' && <Play className="h-6 w-6" />}
                    {column.status === 'in-progress' && <Pause className="h-6 w-6" />}
                    {column.status === 'review' && <AlertTriangle className="h-6 w-6" />}
                    {column.status === 'completed' && <CheckCircle className="h-6 w-6" />}
                  </div>
                  <p className="text-sm">No {column.title.toLowerCase()} tasks</p>
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
};