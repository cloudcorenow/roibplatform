import React, { useState } from 'react';
import { Calendar as CalendarIcon, Clock, Target, AlertCircle, CheckCircle, Plus } from 'lucide-react';
import { Milestone, TimeEntry, Project } from '../types';
import { formatDate, formatDuration } from '../utils/formatters';

interface CalendarProps {
  milestones: Milestone[];
  timeEntries: TimeEntry[];
  projects: Project[];
  onAddMilestone: (milestone: Omit<Milestone, 'id'>) => void;
  onUpdateMilestone: (id: string, updates: Partial<Milestone>) => void;
}

export const Calendar: React.FC<CalendarProps> = ({
  milestones,
  timeEntries,
  projects,
  onAddMilestone,
  onUpdateMilestone
}) => {
  const [currentDate, setCurrentDate] = useState(new Date());
  const [viewMode, setViewMode] = useState<'month' | 'timeline'>('month');
  const [showNewMilestoneForm, setShowNewMilestoneForm] = useState(false);
  const [newMilestone, setNewMilestone] = useState({
    projectId: '',
    title: '',
    description: '',
    dueDate: new Date().toISOString().split('T')[0],
    status: 'pending' as const,
    type: 'project' as const,
    isRnDRelated: true,
    assignedTo: [] as string[]
  });

  const handleAddMilestone = () => {
    if (!newMilestone.title || !newMilestone.projectId) return;
    
    onAddMilestone(newMilestone);
    setNewMilestone({
      projectId: '',
      title: '',
      description: '',
      dueDate: new Date().toISOString().split('T')[0],
      status: 'pending' as const,
      type: 'project' as const,
      isRnDRelated: true,
      assignedTo: []
    });
    setShowNewMilestoneForm(false);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'bg-green-100 text-green-800';
      case 'in-progress': return 'bg-blue-100 text-blue-800';
      case 'overdue': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-4 w-4" />;
      case 'in-progress': return <Clock className="h-4 w-4" />;
      case 'overdue': return <AlertCircle className="h-4 w-4" />;
      default: return <Target className="h-4 w-4" />;
    }
  };

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'tax-deadline': return 'bg-red-50 border-red-200';
      case 'sprint': return 'bg-blue-50 border-blue-200';
      case 'compliance': return 'bg-yellow-50 border-yellow-200';
      default: return 'bg-gray-50 border-gray-200';
    }
  };

  // Get time entries for the current week
  const getWeekTimeEntries = () => {
    const startOfWeek = new Date(currentDate);
    startOfWeek.setDate(currentDate.getDate() - currentDate.getDay());
    const endOfWeek = new Date(startOfWeek);
    endOfWeek.setDate(startOfWeek.getDate() + 6);

    return timeEntries.filter(entry => {
      const entryDate = new Date(entry.date);
      return entryDate >= startOfWeek && entryDate <= endOfWeek;
    });
  };

  const weekTimeEntries = getWeekTimeEntries();
  const weeklyHours = weekTimeEntries.reduce((total, entry) => total + entry.duration, 0);
  const rndHours = weekTimeEntries.filter(entry => entry.isRnD).reduce((total, entry) => total + entry.duration, 0);

  const upcomingMilestones = milestones
    .filter(milestone => new Date(milestone.dueDate) >= new Date())
    .sort((a, b) => new Date(a.dueDate).getTime() - new Date(b.dueDate).getTime())
    .slice(0, 5);

  const overdueMilestones = milestones.filter(milestone => 
    new Date(milestone.dueDate) < new Date() && milestone.status !== 'completed'
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Calendar & Timeline</h1>
        <div className="flex items-center space-x-3">
          <div className="flex bg-gray-100 rounded-lg p-1">
            <button
              onClick={() => setViewMode('month')}
              className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
                viewMode === 'month' ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600'
              }`}
            >
              Month
            </button>
            <button
              onClick={() => setViewMode('timeline')}
              className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
                viewMode === 'timeline' ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600'
              }`}
            >
              Timeline
            </button>
          </div>
          <button
            onClick={() => setShowNewMilestoneForm(true)}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2"
          >
            <Plus className="h-4 w-4" />
            <span>Add Milestone</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-6">
        <div className="bg-blue-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-blue-900 mb-2">This Week Hours</h4>
          <p className="text-2xl font-bold text-blue-600">{formatDuration(weeklyHours)}</p>
        </div>
        <div className="bg-green-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-green-900 mb-2">R&D Hours</h4>
          <p className="text-2xl font-bold text-green-600">{formatDuration(rndHours)}</p>
        </div>
        <div className="bg-yellow-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-yellow-900 mb-2">Upcoming Milestones</h4>
          <p className="text-2xl font-bold text-yellow-600">{upcomingMilestones.length}</p>
        </div>
        <div className="bg-red-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-red-900 mb-2">Overdue Items</h4>
          <p className="text-2xl font-bold text-red-600">{overdueMilestones.length}</p>
        </div>
      </div>

      {showNewMilestoneForm && (
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Add New Milestone</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Title</label>
              <input
                type="text"
                value={newMilestone.title}
                onChange={(e) => setNewMilestone({ ...newMilestone, title: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Milestone title..."
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Project</label>
              <select
                value={newMilestone.projectId}
                onChange={(e) => setNewMilestone({ ...newMilestone, projectId: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="">Select a project</option>
                {projects.map(project => (
                  <option key={project.id} value={project.id}>{project.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Due Date</label>
              <input
                type="date"
                value={newMilestone.dueDate}
                onChange={(e) => setNewMilestone({ ...newMilestone, dueDate: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Type</label>
              <select
                value={newMilestone.type}
                onChange={(e) => setNewMilestone({ ...newMilestone, type: e.target.value as any })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="project">Project Milestone</option>
                <option value="tax-deadline">Tax Deadline</option>
                <option value="sprint">Sprint Goal</option>
                <option value="compliance">Compliance Check</option>
              </select>
            </div>
            <div className="md:col-span-2">
              <label className="block text-sm font-medium text-gray-700 mb-2">Description</label>
              <textarea
                value={newMilestone.description}
                onChange={(e) => setNewMilestone({ ...newMilestone, description: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                rows={3}
                placeholder="Milestone description..."
              />
            </div>
            <div className="md:col-span-2 flex items-center">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={newMilestone.isRnDRelated}
                  onChange={(e) => setNewMilestone({ ...newMilestone, isRnDRelated: e.target.checked })}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700">R&D Related</span>
              </label>
            </div>
          </div>
          <div className="flex justify-end space-x-3 mt-6">
            <button
              onClick={() => setShowNewMilestoneForm(false)}
              className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              onClick={handleAddMilestone}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              Add Milestone
            </button>
          </div>
        </div>
      )}

      {viewMode === 'month' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 bg-white p-6 rounded-xl shadow-sm border border-gray-200">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-semibold text-gray-900 flex items-center">
                <CalendarIcon className="h-5 w-5 mr-2" />
                {currentDate.toLocaleDateString('en-US', { month: 'long', year: 'numeric' })}
              </h3>
              <div className="flex space-x-2">
                <button
                  onClick={() => setCurrentDate(new Date(currentDate.getFullYear(), currentDate.getMonth() - 1))}
                  className="p-2 text-gray-400 hover:text-gray-600"
                >
                  ←
                </button>
                <button
                  onClick={() => setCurrentDate(new Date())}
                  className="px-3 py-1 text-sm bg-blue-100 text-blue-600 rounded"
                >
                  Today
                </button>
                <button
                  onClick={() => setCurrentDate(new Date(currentDate.getFullYear(), currentDate.getMonth() + 1))}
                  className="p-2 text-gray-400 hover:text-gray-600"
                >
                  →
                </button>
              </div>
            </div>

            <div className="grid grid-cols-7 gap-1 mb-4">
              {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map(day => (
                <div key={day} className="p-2 text-center text-sm font-medium text-gray-500">
                  {day}
                </div>
              ))}
            </div>

            <div className="grid grid-cols-7 gap-1">
              {Array.from({ length: 35 }, (_, i) => {
                const date = new Date(currentDate.getFullYear(), currentDate.getMonth(), i - 6);
                const isCurrentMonth = date.getMonth() === currentDate.getMonth();
                const isToday = date.toDateString() === new Date().toDateString();
                const dayMilestones = milestones.filter(m => 
                  new Date(m.dueDate).toDateString() === date.toDateString()
                );
                const dayTimeEntries = timeEntries.filter(e => 
                  new Date(e.date).toDateString() === date.toDateString()
                );

                return (
                  <div
                    key={i}
                    className={`min-h-[80px] p-1 border border-gray-100 ${
                      isCurrentMonth ? 'bg-white' : 'bg-gray-50'
                    } ${isToday ? 'bg-blue-50 border-blue-200' : ''}`}
                  >
                    <div className={`text-sm ${isCurrentMonth ? 'text-gray-900' : 'text-gray-400'} ${isToday ? 'font-bold text-blue-600' : ''}`}>
                      {date.getDate()}
                    </div>
                    <div className="space-y-1">
                      {dayMilestones.slice(0, 2).map(milestone => (
                        <div
                          key={milestone.id}
                          className={`text-xs p-1 rounded ${getTypeColor(milestone.type)} truncate`}
                        >
                          {milestone.title}
                        </div>
                      ))}
                      {dayTimeEntries.length > 0 && (
                        <div className="text-xs text-green-600 font-medium">
                          {formatDuration(dayTimeEntries.reduce((total, entry) => total + entry.duration, 0))}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="space-y-6">
            <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Upcoming Milestones</h3>
              <div className="space-y-3">
                {upcomingMilestones.map(milestone => (
                  <div key={milestone.id} className="flex items-start space-x-3 p-3 bg-gray-50 rounded-lg">
                    <div className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(milestone.status)}`}>
                      {getStatusIcon(milestone.status)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <h4 className="text-sm font-medium text-gray-900">{milestone.title}</h4>
                      <p className="text-xs text-gray-600">{milestone.description}</p>
                      <div className="flex items-center space-x-2 mt-1">
                        <span className="text-xs text-gray-500">{formatDate(milestone.dueDate)}</span>
                        {milestone.isRnDRelated && (
                          <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
                            R&D
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
                {upcomingMilestones.length === 0 && (
                  <p className="text-sm text-gray-500 text-center py-4">No upcoming milestones</p>
                )}
              </div>
            </div>

            {overdueMilestones.length > 0 && (
              <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
                <h3 className="text-lg font-semibold text-red-900 mb-4">Overdue Items</h3>
                <div className="space-y-3">
                  {overdueMilestones.map(milestone => (
                    <div key={milestone.id} className="flex items-start space-x-3 p-3 bg-red-50 rounded-lg">
                      <AlertCircle className="h-4 w-4 text-red-500 mt-0.5" />
                      <div className="flex-1 min-w-0">
                        <h4 className="text-sm font-medium text-gray-900">{milestone.title}</h4>
                        <p className="text-xs text-red-600">Due: {formatDate(milestone.dueDate)}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {viewMode === 'timeline' && (
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900 mb-6">Project Timeline</h3>
          <div className="space-y-6">
            {projects.map(project => {
              const projectMilestones = milestones.filter(m => m.projectId === project.id);
              const projectTimeEntries = timeEntries.filter(e => e.projectId === project.id);
              const totalHours = projectTimeEntries.reduce((total, entry) => total + entry.duration, 0);

              return (
                <div key={project.id} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <h4 className="font-medium text-gray-900">{project.name}</h4>
                      <p className="text-sm text-gray-600">{formatDuration(totalHours)} logged</p>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className="w-32 bg-gray-200 rounded-full h-2">
                        <div
                          className="bg-blue-600 h-2 rounded-full"
                          style={{ width: `${project.progress}%` }}
                        />
                      </div>
                      <span className="text-sm text-gray-600">{project.progress}%</span>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {projectMilestones.map(milestone => (
                      <div
                        key={milestone.id}
                        className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(milestone.status)}`}
                      >
                        {getStatusIcon(milestone.status)}
                        <span className="ml-1">{milestone.title}</span>
                        <span className="ml-2 text-gray-500">({formatDate(milestone.dueDate)})</span>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};