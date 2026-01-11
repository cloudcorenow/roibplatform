import React from 'react';
import { BarChart3, TrendingUp, Clock, DollarSign, Users, Target, Calendar, Award, Zap, Activity } from 'lucide-react';
import { TimeEntry, Project, Expense, Employee } from '../types';
import { formatDuration, formatCurrency } from '../utils/formatters';
import { useMemoizedStats } from '../hooks/useMemoizedData';

interface AnalyticsDashboardProps {
  timeEntries: TimeEntry[];
  projects: Project[];
  expenses: Expense[];
  employees: Employee[];
}

export const AnalyticsDashboard: React.FC<AnalyticsDashboardProps> = ({
  timeEntries,
  projects,
  expenses,
  employees
}) => {
  const stats = useMemoizedStats(timeEntries, projects);

  // Calculate additional metrics
  const totalExpenses = expenses.reduce((total, expense) => total + expense.amount, 0);
  const rndExpenses = expenses.filter(expense => expense.isRnD).reduce((total, expense) => total + expense.amount, 0);
  const avgProjectProgress = projects.length > 0 ? 
    Math.round(projects.reduce((sum, project) => sum + project.progress, 0) / projects.length) : 0;

  // Weekly trend data
  const weeklyData = React.useMemo(() => {
    const weeks = [];
    const now = new Date();
    
    for (let i = 6; i >= 0; i--) {
      const weekStart = new Date(now);
      weekStart.setDate(now.getDate() - (i * 7));
      weekStart.setHours(0, 0, 0, 0);
      
      const weekEnd = new Date(weekStart);
      weekEnd.setDate(weekStart.getDate() + 6);
      weekEnd.setHours(23, 59, 59, 999);
      
      const weekEntries = timeEntries.filter(entry => {
        const entryDate = new Date(entry.date);
        return entryDate >= weekStart && entryDate <= weekEnd;
      });
      
      const weekHours = weekEntries.reduce((total, entry) => total + entry.duration, 0);
      const weekRndHours = weekEntries.filter(entry => entry.isRnD).reduce((total, entry) => total + entry.duration, 0);
      
      weeks.push({
        week: `Week ${7 - i}`,
        totalHours: weekHours,
        rndHours: weekRndHours,
        date: weekStart.toLocaleDateString()
      });
    }
    
    return weeks;
  }, [timeEntries]);

  // Project efficiency metrics
  const projectEfficiency = React.useMemo(() => {
    return projects.map(project => {
      const projectEntries = timeEntries.filter(entry => entry.projectId === project.id);
      const actualHours = projectEntries.reduce((total, entry) => total + entry.duration, 0);
      const efficiency = project.totalHours > 0 ? (actualHours / project.totalHours) * 100 : 0;
      
      return {
        name: project.name,
        progress: project.progress,
        efficiency: Math.round(efficiency),
        status: project.status
      };
    });
  }, [projects, timeEntries]);

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-4xl font-bold text-slate-800">
            Analytics Dashboard
          </h1>
          <p className="text-slate-600 mt-2">Comprehensive insights into your R&D activities and performance</p>
        </div>
        <div className="text-sm text-slate-500 bg-white/50 backdrop-blur-sm px-4 py-2 rounded-xl border border-cyan-200/50">
          Last updated: {new Date().toLocaleDateString()}
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-blue-50 p-4 rounded-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-blue-900 text-sm font-medium">Total R&D Hours</p>
              <p className="text-2xl font-bold text-blue-600">{formatDuration(stats.rndHours)}</p>
              <p className="text-blue-700 text-xs mt-1">{stats.rndPercentage}% of total time</p>
            </div>
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
              <Clock className="h-5 w-5 text-white" />
            </div>
          </div>
        </div>

        <div className="bg-green-50 p-4 rounded-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-green-900 text-sm font-medium">R&D Expenses</p>
              <p className="text-2xl font-bold text-green-600">{formatCurrency(rndExpenses)}</p>
              <p className="text-green-700 text-xs mt-1">{Math.round((rndExpenses / totalExpenses) * 100)}% of total</p>
            </div>
            <div className="w-10 h-10 bg-green-600 rounded-lg flex items-center justify-center">
              <DollarSign className="h-5 w-5 text-white" />
            </div>
          </div>
        </div>

        <div className="bg-gray-50 p-4 rounded-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-700 text-sm font-medium">Active Projects</p>
              <p className="text-2xl font-bold text-gray-900">{stats.activeProjects}</p>
              <p className="text-gray-600 text-xs mt-1">{stats.rndProjects} R&D qualified</p>
            </div>
            <div className="w-10 h-10 bg-gray-600 rounded-lg flex items-center justify-center">
              <Target className="h-5 w-5 text-white" />
            </div>
          </div>
        </div>

        <div className="bg-yellow-50 p-4 rounded-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-yellow-900 text-sm font-medium">Avg Progress</p>
              <p className="text-2xl font-bold text-yellow-600">{avgProjectProgress}%</p>
              <p className="text-yellow-700 text-xs mt-1">Across all projects</p>
            </div>
            <div className="w-10 h-10 bg-yellow-600 rounded-lg flex items-center justify-center">
              <TrendingUp className="h-5 w-5 text-white" />
            </div>
          </div>
        </div>
      </div>

      {/* Charts and Trends */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Weekly Trend */}
        <div className="bg-white p-6 rounded-lg shadow-md border border-gray-200">
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
              <Calendar className="h-4 w-4 text-white" />
            </div>
            <h3 className="text-lg font-semibold text-slate-800">
            Weekly R&D Hours Trend
            </h3>
          </div>
          <div className="space-y-3">
            {weeklyData.map((week, index) => {
              const maxHours = Math.max(...weeklyData.map(w => w.totalHours));
              const totalWidth = maxHours > 0 ? (week.totalHours / maxHours) * 100 : 0;
              const rndWidth = maxHours > 0 ? (week.rndHours / maxHours) * 100 : 0;
              
              return (
                <div key={index} className="space-y-1">
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-600">{week.week}</span>
                    <span className="text-slate-800 font-medium">{formatDuration(week.totalHours)}</span>
                  </div>
                  <div className="relative h-3 bg-gray-200 rounded-full overflow-hidden">
                    <div 
                      className="absolute top-0 left-0 h-full bg-blue-200 rounded-full"
                      style={{ width: `${totalWidth}%` }}
                    />
                    <div 
                      className="absolute top-0 left-0 h-full bg-blue-500 rounded-full"
                      style={{ width: `${rndWidth}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-xs text-slate-500">
                    <span>R&D: {formatDuration(week.rndHours)}</span>
                    <span>{week.date}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Project Efficiency */}
        <div className="bg-white p-6 rounded-lg shadow-md border border-gray-200">
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
              <Award className="h-4 w-4 text-white" />
            </div>
            <h3 className="text-lg font-semibold text-slate-800">
            Project Efficiency
            </h3>
          </div>
          <div className="space-y-4">
            {projectEfficiency.slice(0, 5).map((project, index) => (
              <div key={index} className="space-y-2">
                <div className="flex justify-between items-center">
                  <span className="text-sm font-medium text-slate-800 truncate">{project.name}</span>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs text-slate-500">{project.efficiency}% efficient</span>
                    <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-bold ${
                      project.status === 'active' ? 'bg-emerald-100 text-emerald-800' :
                      project.status === 'completed' ? 'bg-cyan-100 text-cyan-800' :
                      'bg-slate-100 text-slate-800'
                    }`}>
                      {project.status}
                    </span>
                  </div>
                </div>
                <div className="flex space-x-2">
                  <div className="flex-1">
                    <div className="text-xs text-slate-500 mb-1">Progress</div>
                    <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-blue-500 rounded-full"
                        style={{ width: `${project.progress}%` }}
                      />
                    </div>
                  </div>
                  <div className="flex-1">
                    <div className="text-xs text-slate-500 mb-1">Efficiency</div>
                    <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                      <div 
                        className={`h-full rounded-full ${
                          project.efficiency > 100 ? 'bg-red-500' :
                          project.efficiency > 80 ? 'bg-emerald-500' :
                          project.efficiency > 60 ? 'bg-amber-500' :
                          'bg-red-500'
                        }`}
                        style={{ width: `${Math.min(project.efficiency, 100)}%` }}
                      />
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Team Performance */}
      <div className="bg-white p-6 rounded-lg shadow-md border border-gray-200">
        <div className="flex items-center space-x-3 mb-6">
          <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
            <Users className="h-4 w-4 text-white" />
          </div>
          <h3 className="text-lg font-semibold text-slate-800">
          Team R&D Performance
          </h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {employees.map(employee => {
            const employeeEntries = timeEntries.filter(entry => (entry.employeeIds || []).includes(employee.id));
            const employeeHours = employeeEntries.reduce((total, entry) => total + entry.duration, 0);
            const employeeRndHours = employeeEntries.filter(entry => entry.isRnD).reduce((total, entry) => total + entry.duration, 0);
            const rndPercentage = employeeHours > 0 ? Math.round((employeeRndHours / employeeHours) * 100) : 0;
            
            return (
              <div key={employee.id} className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-all duration-200">
                <div className="flex items-center justify-between mb-3">
                  <h4 className="font-semibold text-slate-800">{employee.name}</h4>
                  <span className="text-sm text-slate-500">{employee.role}</span>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-600">Total Hours</span>
                    <span className="font-medium text-slate-800">{formatDuration(employeeHours)}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-600">R&D Hours</span>
                    <span className="font-medium text-green-600">{formatDuration(employeeRndHours)}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-600">R&D %</span>
                    <span className="font-medium text-slate-800">{rndPercentage}%</span>
                  </div>
                  <div className="mt-2">
                    <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-green-500 rounded-full"
                        style={{ width: `${rndPercentage}%` }}
                      />
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};