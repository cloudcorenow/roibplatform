import React, { useState } from 'react';
import { GitBranch, Clock, Code, Zap, Settings, CheckCircle, AlertCircle, Activity, Calendar } from 'lucide-react';
import { AutoTimeEntry, Project } from '../types';
import { formatDuration, formatDateTime } from '../utils/formatters';

interface AutoTimeIntegrationProps {
  autoTimeEntries: AutoTimeEntry[];
  projects: Project[];
  onApproveEntry: (entryId: string) => void;
  onRejectEntry: (entryId: string) => void;
  onUpdateEntry: (entryId: string, updates: Partial<AutoTimeEntry>) => void;
}

export const AutoTimeIntegration: React.FC<AutoTimeIntegrationProps> = ({
  autoTimeEntries,
  projects,
  onApproveEntry,
  onRejectEntry,
  onUpdateEntry
}) => {
  const [activeTab, setActiveTab] = useState<'pending' | 'approved' | 'settings'>('pending');
  const [selectedSource, setSelectedSource] = useState<string>('all');

  const pendingEntries = autoTimeEntries.filter(entry => !entry.metadata.approved && !entry.metadata.rejected);
  const approvedEntries = autoTimeEntries.filter(entry => entry.metadata.approved);

  const getSourceIcon = (source: string) => {
    switch (source) {
      case 'github': return <GitBranch className="h-4 w-4" />;
      case 'gitlab': return <GitBranch className="h-4 w-4" />;
      case 'jira': return <Activity className="h-4 w-4" />;
      case 'vscode': return <Code className="h-4 w-4" />;
      default: return <Clock className="h-4 w-4" />;
    }
  };

  const getSourceColor = (source: string) => {
    switch (source) {
      case 'github': return 'bg-gray-100 text-gray-800';
      case 'gitlab': return 'bg-orange-100 text-orange-800';
      case 'jira': return 'bg-blue-100 text-blue-800';
      case 'vscode': return 'bg-purple-100 text-purple-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.8) return 'text-green-600';
    if (confidence >= 0.6) return 'text-yellow-600';
    return 'text-red-600';
  };

  const filteredEntries = (entries: AutoTimeEntry[]) => {
    if (selectedSource === 'all') return entries;
    return entries.filter(entry => entry.source === selectedSource);
  };

  const totalAutoHours = autoTimeEntries.reduce((total, entry) => total + entry.duration, 0);
  const rndAutoHours = autoTimeEntries.filter(entry => entry.isRnD).reduce((total, entry) => total + entry.duration, 0);
  const avgConfidence = autoTimeEntries.reduce((sum, entry) => sum + entry.confidence, 0) / autoTimeEntries.length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Auto Time Integration</h1>
        <div className="flex items-center space-x-2">
          <Zap className="h-5 w-5 text-blue-600" />
          <span className="text-sm text-gray-600">Automated time tracking from developer tools</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-6">
        <div className="bg-blue-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-blue-900 mb-2 flex items-center">
            <Clock className="h-4 w-4 mr-1" />
            Auto-Tracked Hours
          </h4>
          <p className="text-2xl font-bold text-blue-600">{formatDuration(totalAutoHours)}</p>
        </div>
        <div className="bg-green-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-green-900 mb-2 flex items-center">
            <Zap className="h-4 w-4 mr-1" />
            R&D Hours
          </h4>
          <p className="text-2xl font-bold text-green-600">{formatDuration(rndAutoHours)}</p>
        </div>
        <div className="bg-purple-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-purple-900 mb-2 flex items-center">
            <Activity className="h-4 w-4 mr-1" />
            Pending Review
          </h4>
          <p className="text-2xl font-bold text-purple-600">{pendingEntries.length}</p>
        </div>
        <div className="bg-orange-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-orange-900 mb-2 flex items-center">
            <CheckCircle className="h-4 w-4 mr-1" />
            Avg Confidence
          </h4>
          <p className="text-2xl font-bold text-orange-600">{Math.round(avgConfidence * 100)}%</p>
        </div>
      </div>

      <div className="bg-white rounded-xl shadow-sm border border-gray-200">
        <div className="border-b border-gray-200">
          <nav className="flex space-x-8 px-6">
            <button
              onClick={() => setActiveTab('pending')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'pending'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              Pending Review ({pendingEntries.length})
            </button>
            <button
              onClick={() => setActiveTab('approved')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'approved'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              Approved ({approvedEntries.length})
            </button>
            <button
              onClick={() => setActiveTab('settings')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'settings'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              Integration Settings
            </button>
          </nav>
        </div>

        <div className="p-6">
          {(activeTab === 'pending' || activeTab === 'approved') && (
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">Filter by Source</label>
              <select
                value={selectedSource}
                onChange={(e) => setSelectedSource(e.target.value)}
                className="border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="all">All Sources</option>
                <option value="github">GitHub</option>
                <option value="gitlab">GitLab</option>
                <option value="jira">Jira</option>
                <option value="vscode">VS Code</option>
              </select>
            </div>
          )}

          {activeTab === 'pending' && (
            <div className="space-y-4">
              {filteredEntries(pendingEntries).map((entry) => {
                const project = projects.find(p => p.id === entry.projectId);
                
                return (
                  <div key={entry.id} className="border border-gray-200 rounded-lg p-4">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-2">
                          <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getSourceColor(entry.source)}`}>
                            {getSourceIcon(entry.source)}
                            <span className="ml-1 capitalize">{entry.source}</span>
                          </span>
                          <span className={`text-sm font-medium ${getConfidenceColor(entry.confidence)}`}>
                            {Math.round(entry.confidence * 100)}% confidence
                          </span>
                          {entry.isRnD && (
                            <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                              R&D
                            </span>
                          )}
                        </div>
                        <h4 className="font-medium text-gray-900 mb-1">{entry.activity}</h4>
                        <p className="text-sm text-gray-600 mb-2">{project?.name}</p>
                        <div className="flex items-center space-x-4 text-xs text-gray-500">
                          <span className="flex items-center">
                            <Calendar className="h-3 w-3 mr-1" />
                            {formatDateTime(entry.timestamp)}
                          </span>
                          <span>{formatDuration(entry.duration)}</span>
                          {entry.metadata.repository && (
                            <span>Repo: {entry.metadata.repository}</span>
                          )}
                          {entry.metadata.branch && (
                            <span>Branch: {entry.metadata.branch}</span>
                          )}
                        </div>
                        {entry.metadata.commits && entry.metadata.commits.length > 0 && (
                          <div className="mt-2">
                            <p className="text-xs text-gray-500 mb-1">Recent commits:</p>
                            <ul className="text-xs text-gray-600 space-y-1">
                              {entry.metadata.commits.slice(0, 3).map((commit, index) => (
                                <li key={index} className="truncate">• {commit}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                      <div className="flex items-center space-x-2 ml-4">
                        <button
                          onClick={() => onRejectEntry(entry.id)}
                          className="p-2 text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                          title="Reject"
                        >
                          <AlertCircle className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => onApproveEntry(entry.id)}
                          className="p-2 text-green-600 hover:bg-green-50 rounded-lg transition-colors"
                          title="Approve"
                        >
                          <CheckCircle className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
              {filteredEntries(pendingEntries).length === 0 && (
                <div className="text-center py-8 text-gray-500">
                  <Clock className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                  <p>No pending time entries to review</p>
                </div>
              )}
            </div>
          )}

          {activeTab === 'approved' && (
            <div className="space-y-4">
              {filteredEntries(approvedEntries).map((entry) => {
                const project = projects.find(p => p.id === entry.projectId);
                
                return (
                  <div key={entry.id} className="border border-gray-200 rounded-lg p-4 bg-green-50">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-2">
                          <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getSourceColor(entry.source)}`}>
                            {getSourceIcon(entry.source)}
                            <span className="ml-1 capitalize">{entry.source}</span>
                          </span>
                          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                            <CheckCircle className="h-3 w-3 mr-1" />
                            Approved
                          </span>
                          {entry.isRnD && (
                            <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                              R&D
                            </span>
                          )}
                        </div>
                        <h4 className="font-medium text-gray-900 mb-1">{entry.activity}</h4>
                        <p className="text-sm text-gray-600 mb-2">{project?.name}</p>
                        <div className="flex items-center space-x-4 text-xs text-gray-500">
                          <span>{formatDateTime(entry.timestamp)}</span>
                          <span>{formatDuration(entry.duration)}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
              {filteredEntries(approvedEntries).length === 0 && (
                <div className="text-center py-8 text-gray-500">
                  <CheckCircle className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                  <p>No approved time entries yet</p>
                </div>
              )}
            </div>
          )}

          {activeTab === 'settings' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Integration Configuration</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="border border-gray-200 rounded-lg p-4">
                    <div className="flex items-center space-x-3 mb-3">
                      <GitBranch className="h-6 w-6 text-gray-600" />
                      <h4 className="font-medium text-gray-900">GitHub Integration</h4>
                    </div>
                    <p className="text-sm text-gray-600 mb-3">
                      Automatically track time based on commit activity and branch work.
                    </p>
                    <div className="space-y-2">
                      <label className="flex items-center text-sm">
                        <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" defaultChecked />
                        <span className="ml-2">Track commit activity</span>
                      </label>
                      <label className="flex items-center text-sm">
                        <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" defaultChecked />
                        <span className="ml-2">Auto-detect R&D branches</span>
                      </label>
                      <label className="flex items-center text-sm">
                        <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" />
                        <span className="ml-2">Include pull request reviews</span>
                      </label>
                    </div>
                  </div>

                  <div className="border border-gray-200 rounded-lg p-4">
                    <div className="flex items-center space-x-3 mb-3">
                      <Activity className="h-6 w-6 text-blue-600" />
                      <h4 className="font-medium text-gray-900">Jira Integration</h4>
                    </div>
                    <p className="text-sm text-gray-600 mb-3">
                      Import time logged on R&D tickets and development tasks.
                    </p>
                    <div className="space-y-2">
                      <label className="flex items-center text-sm">
                        <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" defaultChecked />
                        <span className="ml-2">Sync time logs</span>
                      </label>
                      <label className="flex items-center text-sm">
                        <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" defaultChecked />
                        <span className="ml-2">Auto-tag R&D tickets</span>
                      </label>
                      <label className="flex items-center text-sm">
                        <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" />
                        <span className="ml-2">Include story points</span>
                      </label>
                    </div>
                  </div>

                  <div className="border border-gray-200 rounded-lg p-4">
                    <div className="flex items-center space-x-3 mb-3">
                      <Code className="h-6 w-6 text-purple-600" />
                      <h4 className="font-medium text-gray-900">VS Code Extension</h4>
                    </div>
                    <p className="text-sm text-gray-600 mb-3">
                      Track active development time on tagged R&D projects.
                    </p>
                    <div className="space-y-2">
                      <label className="flex items-center text-sm">
                        <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" defaultChecked />
                        <span className="ml-2">Track active coding time</span>
                      </label>
                      <label className="flex items-center text-sm">
                        <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" />
                        <span className="ml-2">Include debugging sessions</span>
                      </label>
                      <label className="flex items-center text-sm">
                        <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" />
                        <span className="ml-2">Track file types</span>
                      </label>
                    </div>
                  </div>

                  <div className="border border-gray-200 rounded-lg p-4">
                    <div className="flex items-center space-x-3 mb-3">
                      <Settings className="h-6 w-6 text-gray-600" />
                      <h4 className="font-medium text-gray-900">General Settings</h4>
                    </div>
                    <div className="space-y-3">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Minimum confidence threshold</label>
                        <select className="w-full border border-gray-300 rounded px-3 py-2 text-sm">
                          <option value="0.6">60%</option>
                          <option value="0.7">70%</option>
                          <option value="0.8" selected>80%</option>
                          <option value="0.9">90%</option>
                        </select>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Auto-approve threshold</label>
                        <select className="w-full border border-gray-300 rounded px-3 py-2 text-sm">
                          <option value="0.9">90%</option>
                          <option value="0.95" selected>95%</option>
                          <option value="1.0">100% (manual review)</option>
                        </select>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-blue-50 p-4 rounded-lg">
                <h4 className="font-medium text-blue-900 mb-2">Setup Instructions</h4>
                <ol className="text-sm text-blue-800 space-y-1 list-decimal list-inside">
                  <li>Install the Firm Flowz browser extension or IDE plugin</li>
                  <li>Connect your GitHub, GitLab, or Jira accounts</li>
                  <li>Configure project mappings and R&D tagging rules</li>
                  <li>Review and approve automatically detected time entries</li>
                </ol>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};