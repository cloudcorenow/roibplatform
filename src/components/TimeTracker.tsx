import React, { useState } from 'react';
import { Play, Pause, Square, Plus, Clock, Timer, Activity, CheckCircle, Zap, TrendingUp } from 'lucide-react';
import { TimeEntry, Project, Employee, Task } from '../types';
import { formatDuration } from '../utils/formatters';

interface TimeTrackerProps {
  timeEntries: TimeEntry[];
  projects: Project[];
  employees: Employee[];
  tasks: Task[];
  onAddTimeEntry: (entry: Omit<TimeEntry, 'id'>) => void;
  onUpdateTimeEntry: (id: string, updates: Partial<TimeEntry>) => void;
}

export const TimeTracker: React.FC<TimeTrackerProps> = ({
  timeEntries,
  projects,
  employees,
  tasks,
  onAddTimeEntry,
  onUpdateTimeEntry
}) => {
  const [activeTimer, setActiveTimer] = useState<string | null>(null);
  const [showNewEntryForm, setShowNewEntryForm] = useState(false);
  const [newEntry, setNewEntry] = useState({
    projectId: '',
    task: '',
    duration: 0,
    isRnD: true,
    notes: '',
    employeeIds: [] as string[],
    employeeNames: [] as string[]
  });

  const handleStartTimer = (entryId: string) => {
    if (activeTimer && activeTimer !== entryId) {
      onUpdateTimeEntry(activeTimer, { status: 'paused' });
    }
    setActiveTimer(entryId);
    onUpdateTimeEntry(entryId, { status: 'active' });
  };

  const handleStopTimer = (entryId: string) => {
    setActiveTimer(null);
    onUpdateTimeEntry(entryId, { status: 'completed' });
  };

  const handleAddEntry = () => {
    if (!newEntry.projectId || !newEntry.task) return;
    
    const project = projects.find(p => p.id === newEntry.projectId);
    if (!project) return;

    onAddTimeEntry({
      ...newEntry,
      clientId: project.clientId,
      projectName: project.name,
      date: new Date().toISOString().split('T')[0],
      status: 'completed'
    });

    setNewEntry({
      projectId: '',
      task: '',
      duration: 0,
      isRnD: true,
      notes: '',
      employeeIds: [],
      employeeNames: []
    });
    setShowNewEntryForm(false);
  };

  const handleEmployeeToggle = (employeeId: string, employeeName: string) => {
    const isSelected = newEntry.employeeIds.includes(employeeId);
    
    if (isSelected) {
      // Remove employee
      setNewEntry({
        ...newEntry,
        employeeIds: newEntry.employeeIds.filter(id => id !== employeeId),
        employeeNames: newEntry.employeeNames.filter(name => name !== employeeName)
      });
    } else {
      // Add employee
      setNewEntry({
        ...newEntry,
        employeeIds: [...newEntry.employeeIds, employeeId],
        employeeNames: [...newEntry.employeeNames, employeeName]
      });
    }
  };

  const todaysEntries = (timeEntries || []).filter(entry => 
    entry.date === new Date().toISOString().split('T')[0]
  );

  const weeklyHours = (timeEntries || [])
    .filter(entry => {
      const entryDate = new Date(entry.date);
      const weekAgo = new Date();
      weekAgo.setDate(weekAgo.getDate() - 7);
      return entryDate >= weekAgo;
    })
    .reduce((total, entry) => total + entry.duration, 0);

  const rndHours = (timeEntries || [])
    .filter(entry => entry.isRnD)
    .reduce((total, entry) => total + entry.duration, 0);

  const totalHours = (timeEntries || []).reduce((total, entry) => total + entry.duration, 0);
  const rndPercentage = totalHours > 0 ? Math.round((rndHours / totalHours) * 100) : 0;

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div className="flex-1 min-w-0">
          <h1 className="text-4xl font-bold text-slate-800">
            Time Tracking
          </h1>
          <p className="text-slate-600 mt-2 text-sm sm:text-base">Track and manage your R&D activities with precision</p>
        </div>
        <button
          onClick={() => setShowNewEntryForm(true)}
          className="bg-blue-600 text-white px-4 sm:px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2 shadow-sm min-h-[44px]"
        >
          <Plus className="h-4 w-4 sm:mr-2" />
          <span className="hidden sm:inline">Add Entry</span>
        </button>
      </div>

      {showNewEntryForm && (
        <div className="bg-white p-4 sm:p-6 lg:p-8 rounded-lg shadow-lg border border-gray-200">
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
              <Clock className="h-5 w-5 text-white" />
            </div>
            <h3 className="text-xl font-semibold text-slate-800">New Time Entry</h3>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">Project</label>
              <select
                value={newEntry.projectId}
                onChange={(e) => setNewEntry({ ...newEntry, projectId: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
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
                value={newEntry.task}
                onChange={(e) => setNewEntry({ ...newEntry, task: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
                placeholder="What did you work on?"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">
                Employees Involved ({newEntry.employeeIds.length} selected)
              </label>
              <div className="border border-gray-300 rounded-lg p-3 max-h-32 overflow-y-auto">
                {employees.length === 0 ? (
                  <p className="text-sm text-gray-500">No employees available</p>
                ) : (
                  <div className="space-y-2">
                    {employees.map(employee => {
                      const isSelected = newEntry.employeeIds.includes(employee.id);
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
                            onChange={() => handleEmployeeToggle(employee.id, employee.name)}
                            className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                          />
                          <div className="ml-2 flex-1">
                            <p className="text-sm font-medium text-slate-900">{employee.name}</p>
                            <p className="text-xs text-slate-600">{employee.role} • {employee.rndPercentage}% R&D</p>
                          </div>
                        </label>
                      );
                    })}
                  </div>
                )}
              </div>
              {newEntry.employeeIds.length > 0 && (
                <div className="mt-2">
                  <p className="text-xs text-slate-600">Selected:</p>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {newEntry.employeeNames.map((name, index) => (
                      <span key={index} className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-blue-100 text-blue-600">
                        {name}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">Duration (minutes)</label>
              <input
                type="number"
                value={newEntry.duration}
                onChange={(e) => setNewEntry({ ...newEntry, duration: parseInt(e.target.value) || 0 })}
                className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
                min="0"
                placeholder="e.g., 120 for 2 hours"
                inputMode="numeric"
              />
            </div>
            <div className="flex items-center space-x-4">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={newEntry.isRnD}
                  onChange={(e) => setNewEntry({ ...newEntry, isRnD: e.target.checked })}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-slate-700">R&D Activity</span>
              </label>
            </div>
            <div className="sm:col-span-2">
              <label className="block text-sm font-medium text-slate-700 mb-2">Notes (optional)</label>
              <textarea
                value={newEntry.notes}
                onChange={(e) => setNewEntry({ ...newEntry, notes: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[88px]"
                rows={2}
                placeholder="Additional details..."
              />
            </div>
          </div>
          <div className="flex flex-col sm:flex-row justify-end space-y-2 sm:space-y-0 sm:space-x-4 mt-6">
            <button
              onClick={() => setShowNewEntryForm(false)}
              className="w-full sm:w-auto px-4 py-3 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50 min-h-[44px]"
            >
              Cancel
            </button>
            <button
              onClick={handleAddEntry}
              className="w-full sm:w-auto px-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 min-h-[44px]"
            >
              Add Entry
            </button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-2 bg-white p-4 sm:p-6 rounded-lg shadow-md border border-gray-200">
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
              <Activity className="h-4 w-4 text-white" />
            </div>
            <h3 className="text-lg font-semibold text-slate-800">Today's Activities</h3>
          </div>
          <div className="space-y-4">
            {todaysEntries.map((entry) => (
              <div key={entry.id} className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-all duration-200">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between space-y-3 sm:space-y-0">
                  <div className="flex-1">
                    <h4 className="font-semibold text-slate-800">{entry.projectName}</h4>
                    <p className="text-sm text-slate-600 mt-1">{entry.task}</p>
                    {entry.notes && (
                      <p className="text-xs text-slate-500 mt-2 italic">{entry.notes}</p>
                    )}
                  </div>
                  <div className="flex items-center justify-between sm:flex-col sm:text-right">
                    <p className="font-semibold text-slate-800">{formatDuration(entry.duration)}</p>
                    <div className="flex items-center space-x-2 mt-1">
                      {entry.status === 'active' ? (
                        <>
                          <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-bold bg-green-100 text-green-800">
                            <Activity className="h-3 w-3 mr-1" />
                            Active
                          </span>
                          <button
                            onClick={() => handleStopTimer(entry.id)}
                            className="p-2 text-red-500 hover:bg-red-50 rounded-lg transition-colors min-h-[44px] min-w-[44px]"
                            title="Stop Timer"
                          >
                            <Square className="h-4 w-4" />
                          </button>
                        </>
                      ) : (
                        <>
                          <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-bold bg-slate-100 text-slate-800">
                            <CheckCircle className="h-3 w-3 mr-1" />
                            Completed
                          </span>
                          <button
                            onClick={() => handleStartTimer(entry.id)}
                            className="p-2 text-green-600 hover:bg-green-50 rounded-lg transition-colors min-h-[44px] min-w-[44px]"
                            title="Start Timer"
                          >
                            <Play className="h-4 w-4" />
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                  {entry.employeeNames && entry.employeeNames.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2 sm:mt-0">
                      {entry.employeeNames.map((name, index) => (
                        <span key={index} className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-blue-100 text-blue-600">
                          {name}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))}
            {todaysEntries.length === 0 && (
              <div className="text-center py-12 text-slate-500">
                <div className="w-16 h-16 bg-blue-100 rounded-lg flex items-center justify-center mx-auto mb-4">
                  <Clock className="h-8 w-8 text-indigo-500" />
                </div>
                <p className="text-lg font-medium">No time entries for today</p>
                <p className="text-sm mt-1">Click "Add Entry" above to start tracking your R&D work!</p>
              </div>
            )}
          </div>
        </div>

        <div className="bg-white p-4 sm:p-6 rounded-lg shadow-md border border-gray-200">
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
              <Zap className="h-4 w-4 text-white" />
            </div>
            <h3 className="text-lg font-semibold text-slate-800">Quick Start</h3>
          </div>
          <div className="space-y-3">
            {projects.filter(p => p.status === 'active').map((project) => (
              <button
                key={project.id}
                className="w-full text-left p-3 rounded-lg border border-gray-200 hover:bg-gray-50 transition-colors min-h-[44px]"
                onClick={() => {
                  setNewEntry({
                    ...newEntry,
                    projectId: project.id,
                    task: '',
                    isRnD: project.isRnD
                  });
                  setShowNewEntryForm(true);
                }}
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-slate-800">{project.name}</span>
                  <Timer className="h-4 w-4 text-indigo-500" />
                </div>
              </button>
            ))}
            
            {/* Quick Task Actions */}
            {tasks.filter(t => t.status === 'in-progress').slice(0, 3).map(task => (
              <button
                key={task.id}
                className="w-full text-left p-3 rounded-lg border border-blue-200 bg-blue-50 hover:bg-blue-100 transition-colors min-h-[44px]"
                onClick={() => {
                  setNewEntry({
                    ...newEntry,
                    projectId: task.projectId || '',
                    task: task.title,
                    isRnD: task.isRnD
                  });
                  setShowNewEntryForm(true);
                }}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-sm font-medium text-blue-800">{task.title}</span>
                    <p className="text-xs text-blue-600">{task.projectName}</p>
                  </div>
                  <Clock className="h-4 w-4 text-blue-500" />
                </div>
              </button>
            ))}
          </div>

          <div className="mt-6 pt-4 border-t border-gray-200">
            <div className="flex items-center space-x-2 mb-4">
              <TrendingUp className="h-4 w-4 text-indigo-500" />
              <h4 className="text-sm font-medium text-slate-800">Weekly Summary</h4>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-slate-600">This week</span>
                <span className="font-medium text-slate-800">{formatDuration(weeklyHours)}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-slate-600">R&D Hours</span>
                <span className="font-medium text-green-600">{rndPercentage}%</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-slate-600">Total Entries</span>
                <span className="font-medium text-slate-800">{(timeEntries || []).length}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};