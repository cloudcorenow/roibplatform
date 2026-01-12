import React, { useState } from 'react';
import { Download, FileText, BarChart3, Calendar, Users, DollarSign, Clock, Shield } from 'lucide-react';
import { Client, Project, TimeEntry, TechnicalNote, Expense } from '../types';
import { formatCurrency, formatDuration, formatDate } from '../utils/formatters';

interface CPAPortalProps {
  clients: Client[];
  projects: Project[];
  timeEntries: TimeEntry[];
  technicalNotes: TechnicalNote[];
  expenses: Expense[];
  selectedClientId: string | null;
}

export const CPAPortal: React.FC<CPAPortalProps> = ({
  clients,
  projects,
  timeEntries,
  technicalNotes,
  expenses,
  selectedClientId
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'reports' | 'documentation' | 'export'>('overview');

  const selectedClient = clients.find(c => c.id === selectedClientId);
  const clientProjects = projects.filter(p => p.clientId === selectedClientId);
  const clientTimeEntries = timeEntries.filter(e => e.clientId === selectedClientId);
  const clientNotes = technicalNotes.filter(n => n.clientId === selectedClientId);
  const clientExpenses = expenses.filter(e => e.clientId === selectedClientId);

  const totalRnDHours = clientTimeEntries.filter(e => e.isRnD).reduce((total, entry) => total + entry.duration, 0);
  const totalRnDExpenses = clientExpenses.filter(e => e.isRnD).reduce((total, expense) => total + expense.amount, 0);
  const rndProjects = clientProjects.filter(p => p.isRnD);

  const generateReport = (type: string) => {
    // In a real application, this would generate and download actual reports
    console.log(`Generating ${type} report for client ${selectedClient?.name}`);
    alert(`${type} report would be generated and downloaded here.`);
  };

  if (!selectedClientId || !selectedClient) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold text-gray-900">CPA Portal</h1>
        <div className="bg-white p-8 rounded-xl shadow-sm border border-gray-200 text-center">
          <Shield className="h-16 w-16 mx-auto mb-4 text-gray-300" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">Select a Client</h3>
          <p className="text-gray-600">Choose a client from the sidebar to view their R&D documentation and reports.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">CPA Portal</h1>
          <p className="text-gray-600">Read-only access for {selectedClient.name}</p>
        </div>
        <div className="flex items-center space-x-2">
          <Shield className="h-5 w-5 text-green-600" />
          <span className="text-sm text-green-600 font-medium">Secure Access</span>
        </div>
      </div>

      <div className="bg-white rounded-xl shadow-sm border border-gray-200">
        <div className="border-b border-gray-200">
          <nav className="flex space-x-8 px-6">
            <button
              onClick={() => setActiveTab('overview')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'overview'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              Overview
            </button>
            <button
              onClick={() => setActiveTab('reports')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'reports'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              Reports
            </button>
            <button
              onClick={() => setActiveTab('documentation')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'documentation'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              Documentation
            </button>
            <button
              onClick={() => setActiveTab('export')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'export'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              Export
            </button>
          </nav>
        </div>

        <div className="p-6">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
                <div className="bg-blue-50 p-4 rounded-lg">
                  <h4 className="text-sm font-medium text-blue-900 mb-2 flex items-center">
                    <BarChart3 className="h-4 w-4 mr-1" />
                    R&D Projects
                  </h4>
                  <p className="text-2xl font-bold text-blue-600">{rndProjects.length}</p>
                </div>
                <div className="bg-green-50 p-4 rounded-lg">
                  <h4 className="text-sm font-medium text-green-900 mb-2 flex items-center">
                    <Clock className="h-4 w-4 mr-1" />
                    R&D Hours
                  </h4>
                  <p className="text-2xl font-bold text-green-600">{formatDuration(totalRnDHours)}</p>
                </div>
                <div className="bg-purple-50 p-4 rounded-lg">
                  <h4 className="text-sm font-medium text-purple-900 mb-2 flex items-center">
                    <DollarSign className="h-4 w-4 mr-1" />
                    R&D Expenses
                  </h4>
                  <p className="text-2xl font-bold text-purple-600">{formatCurrency(totalRnDExpenses)}</p>
                </div>
                <div className="bg-orange-50 p-4 rounded-lg">
                  <h4 className="text-sm font-medium text-orange-900 mb-2 flex items-center">
                    <FileText className="h-4 w-4 mr-1" />
                    Documentation
                  </h4>
                  <p className="text-2xl font-bold text-orange-600">{clientNotes.length}</p>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">R&D Projects</h3>
                  <div className="space-y-3">
                    {rndProjects.map(project => (
                      <div key={project.id} className="border border-gray-200 rounded-lg p-4">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-medium text-gray-900">{project.name}</h4>
                          <span className="text-sm text-gray-500">{project.progress}%</span>
                        </div>
                        <div className="w-full bg-gray-200 rounded-full h-2 mb-2">
                          <div
                            className="bg-blue-600 h-2 rounded-full"
                            style={{ width: `${project.progress}%` }}
                          />
                        </div>
                        <p className="text-sm text-gray-600">{formatDuration(project.totalHours)} • {formatCurrency(project.budget)}</p>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Activity</h3>
                  <div className="space-y-3">
                    {clientTimeEntries.slice(0, 5).map(entry => (
                      <div key={entry.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                        <div>
                          <p className="text-sm font-medium text-gray-900">{entry.task}</p>
                          <p className="text-xs text-gray-600">{entry.projectName} • {entry.employeeName}</p>
                        </div>
                        <div className="text-right">
                          <p className="text-sm font-medium text-gray-900">{formatDuration(entry.duration)}</p>
                          <p className="text-xs text-gray-500">{formatDate(entry.date)}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'reports' && (
            <div className="space-y-6">
              <h3 className="text-lg font-semibold text-gray-900">Available Reports</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                <div className="border border-gray-200 rounded-lg p-6">
                  <div className="flex items-center space-x-3 mb-4">
                    <div className="bg-blue-100 p-2 rounded-lg">
                      <BarChart3 className="h-6 w-6 text-blue-600" />
                    </div>
                    <h4 className="font-medium text-gray-900">R&D Summary Report</h4>
                  </div>
                  <p className="text-sm text-gray-600 mb-4">Comprehensive overview of all R&D activities, hours, and expenses.</p>
                  <button
                    onClick={() => generateReport('R&D Summary')}
                    className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
                  >
                    Generate Report
                  </button>
                </div>

                <div className="border border-gray-200 rounded-lg p-6">
                  <div className="flex items-center space-x-3 mb-4">
                    <div className="bg-green-100 p-2 rounded-lg">
                      <Clock className="h-6 w-6 text-green-600" />
                    </div>
                    <h4 className="font-medium text-gray-900">Time Tracking Report</h4>
                  </div>
                  <p className="text-sm text-gray-600 mb-4">Detailed breakdown of time entries by project and employee.</p>
                  <button
                    onClick={() => generateReport('Time Tracking')}
                    className="w-full bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700 transition-colors"
                  >
                    Generate Report
                  </button>
                </div>

                <div className="border border-gray-200 rounded-lg p-6">
                  <div className="flex items-center space-x-3 mb-4">
                    <div className="bg-purple-100 p-2 rounded-lg">
                      <DollarSign className="h-6 w-6 text-purple-600" />
                    </div>
                    <h4 className="font-medium text-gray-900">Expense Report</h4>
                  </div>
                  <p className="text-sm text-gray-600 mb-4">Complete listing of R&D-qualified expenses with supporting documentation.</p>
                  <button
                    onClick={() => generateReport('Expense')}
                    className="w-full bg-purple-600 text-white px-4 py-2 rounded-lg hover:bg-purple-700 transition-colors"
                  >
                    Generate Report
                  </button>
                </div>

                <div className="border border-gray-200 rounded-lg p-6">
                  <div className="flex items-center space-x-3 mb-4">
                    <div className="bg-orange-100 p-2 rounded-lg">
                      <FileText className="h-6 w-6 text-orange-600" />
                    </div>
                    <h4 className="font-medium text-gray-900">Technical Documentation</h4>
                  </div>
                  <p className="text-sm text-gray-600 mb-4">All technical notes and R&D qualification documentation.</p>
                  <button
                    onClick={() => generateReport('Technical Documentation')}
                    className="w-full bg-orange-600 text-white px-4 py-2 rounded-lg hover:bg-orange-700 transition-colors"
                  >
                    Generate Report
                  </button>
                </div>

                <div className="border border-gray-200 rounded-lg p-6">
                  <div className="flex items-center space-x-3 mb-4">
                    <div className="bg-red-100 p-2 rounded-lg">
                      <Users className="h-6 w-6 text-red-600" />
                    </div>
                    <h4 className="font-medium text-gray-900">Employee Report</h4>
                  </div>
                  <p className="text-sm text-gray-600 mb-4">Employee qualifications and R&D activity percentages.</p>
                  <button
                    onClick={() => generateReport('Employee')}
                    className="w-full bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors"
                  >
                    Generate Report
                  </button>
                </div>

                <div className="border border-gray-200 rounded-lg p-6">
                  <div className="flex items-center space-x-3 mb-4">
                    <div className="bg-gray-100 p-2 rounded-lg">
                      <Calendar className="h-6 w-6 text-gray-600" />
                    </div>
                    <h4 className="font-medium text-gray-900">Audit Package</h4>
                  </div>
                  <p className="text-sm text-gray-600 mb-4">Complete audit-ready documentation package.</p>
                  <button
                    onClick={() => generateReport('Audit Package')}
                    className="w-full bg-gray-600 text-white px-4 py-2 rounded-lg hover:bg-gray-700 transition-colors"
                  >
                    Generate Package
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'documentation' && (
            <div className="space-y-6">
              <h3 className="text-lg font-semibold text-gray-900">Technical Documentation</h3>
              <div className="space-y-4">
                {clientNotes.map(note => (
                  <div key={note.id} className="border border-gray-200 rounded-lg p-4">
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <h4 className="font-medium text-gray-900">{note.title}</h4>
                        <p className="text-sm text-gray-600">{note.projectName} • {note.author}</p>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className="text-xs text-gray-500">v{note.version}</span>
                        {note.isRnDQualified && (
                          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                            R&D Qualified
                          </span>
                        )}
                      </div>
                    </div>
                    <p className="text-sm text-gray-700 mb-3">{note.content.substring(0, 200)}...</p>
                    <div className="flex items-center justify-between">
                      <div className="flex flex-wrap gap-1">
                        {note.tags.slice(0, 3).map((tag, index) => (
                          <span key={index} className="inline-flex items-center px-1.5 py-0.5 rounded text-xs bg-gray-100 text-gray-600">
                            {tag}
                          </span>
                        ))}
                      </div>
                      <span className="text-xs text-gray-500">{formatDate(note.updatedAt)}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'export' && (
            <div className="space-y-6">
              <h3 className="text-lg font-semibold text-gray-900">Export Data</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="border border-gray-200 rounded-lg p-6">
                  <h4 className="font-medium text-gray-900 mb-4">Bulk Data Export</h4>
                  <p className="text-sm text-gray-600 mb-4">Export all client data in various formats for external analysis.</p>
                  <div className="space-y-3">
                    <button
                      onClick={() => generateReport('CSV Export')}
                      className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center space-x-2"
                    >
                      <Download className="h-4 w-4" />
                      <span>Export as CSV</span>
                    </button>
                    <button
                      onClick={() => generateReport('Excel Export')}
                      className="w-full bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700 transition-colors flex items-center justify-center space-x-2"
                    >
                      <Download className="h-4 w-4" />
                      <span>Export as Excel</span>
                    </button>
                    <button
                      onClick={() => generateReport('PDF Export')}
                      className="w-full bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors flex items-center justify-center space-x-2"
                    >
                      <Download className="h-4 w-4" />
                      <span>Export as PDF</span>
                    </button>
                  </div>
                </div>

                <div className="border border-gray-200 rounded-lg p-6">
                  <h4 className="font-medium text-gray-900 mb-4">Custom Reports</h4>
                  <p className="text-sm text-gray-600 mb-4">Generate custom reports with specific date ranges and filters.</p>
                  <div className="space-y-3">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Date Range</label>
                      <div className="grid grid-cols-2 gap-2">
                        <input
                          type="date"
                          className="border border-gray-300 rounded px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                        <input
                          type="date"
                          className="border border-gray-300 rounded px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Include</label>
                      <div className="space-y-1">
                        <label className="flex items-center text-sm">
                          <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" defaultChecked />
                          <span className="ml-2">Time entries</span>
                        </label>
                        <label className="flex items-center text-sm">
                          <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" defaultChecked />
                          <span className="ml-2">Expenses</span>
                        </label>
                        <label className="flex items-center text-sm">
                          <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" defaultChecked />
                          <span className="ml-2">Technical notes</span>
                        </label>
                      </div>
                    </div>
                    <button
                      onClick={() => generateReport('Custom Report')}
                      className="w-full bg-purple-600 text-white px-4 py-2 rounded-lg hover:bg-purple-700 transition-colors"
                    >
                      Generate Custom Report
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};