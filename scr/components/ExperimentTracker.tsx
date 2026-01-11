import React, { useState } from 'react';
import { Plus, Search, FlaskRound as Flask, CheckCircle, XCircle, Clock, AlertTriangle, Users, Calendar, Tag, FileText, Lightbulb } from 'lucide-react';
import { Experiment, Project } from '../types';
import { formatDate } from '../utils/formatters';

interface ExperimentTrackerProps {
  experiments: Experiment[];
  projects: Project[];
  onAddExperiment: (experiment: Omit<Experiment, 'id' | 'createdAt' | 'updatedAt'>) => void;
  onUpdateExperiment: (id: string, updates: Partial<Experiment>) => void;
}

export const ExperimentTracker: React.FC<ExperimentTrackerProps> = ({
  experiments,
  projects,
  onAddExperiment,
  onUpdateExperiment
}) => {
  const [selectedExperiment, setSelectedExperiment] = useState<Experiment | null>(experiments[0] || null);
  const [showNewExperimentForm, setShowNewExperimentForm] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [newExperiment, setNewExperiment] = useState({
    projectId: '',
    title: '',
    hypothesis: '',
    technicalUncertainty: '',
    technologies: [] as string[],
    methodology: '',
    expectedOutcome: '',
    actualResults: '',
    status: 'planned' as const,
    startDate: new Date().toISOString().split('T')[0],
    endDate: '',
    author: 'Current User',
    collaborators: [] as string[],
    isRnDQualified: true,
    passFailStatus: 'inconclusive' as const,
    issuesFound: [] as string[],
    lessonsLearned: '',
    nextSteps: '',
    relatedExperiments: [] as string[],
    attachments: [] as string[]
  });

  const filteredExperiments = experiments.filter(experiment => {
    const matchesSearch = experiment.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         experiment.hypothesis.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         experiment.technologies.some(tech => tech.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesStatus = filterStatus === 'all' || experiment.status === filterStatus;
    return matchesSearch && matchesStatus;
  });

  const handleAddExperiment = () => {
    if (!newExperiment.title || !newExperiment.projectId || !newExperiment.hypothesis) return;
    
    const project = projects.find(p => p.id === newExperiment.projectId);
    if (!project) return;

    onAddExperiment({
      ...newExperiment,
      projectName: project.name
    });

    setNewExperiment({
      projectId: '',
      title: '',
      hypothesis: '',
      technicalUncertainty: '',
      technologies: [],
      methodology: '',
      expectedOutcome: '',
      actualResults: '',
      status: 'planned' as const,
      startDate: new Date().toISOString().split('T')[0],
      endDate: '',
      author: 'Current User',
      collaborators: [],
      isRnDQualified: true,
      passFailStatus: 'inconclusive' as const,
      issuesFound: [],
      lessonsLearned: '',
      nextSteps: '',
      relatedExperiments: [],
      attachments: []
    });
    setShowNewExperimentForm(false);
  };

  const handleTechnologiesInput = (value: string) => {
    const technologies = value.split(',').map(tech => tech.trim()).filter(tech => tech.length > 0);
    setNewExperiment({ ...newExperiment, technologies });
  };

  const handleIssuesInput = (value: string) => {
    const issues = value.split(',').map(issue => issue.trim()).filter(issue => issue.length > 0);
    setNewExperiment({ ...newExperiment, issuesFound: issues });
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'bg-green-100 text-green-800';
      case 'in-progress': return 'bg-blue-100 text-blue-800';
      case 'failed': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-4 w-4" />;
      case 'in-progress': return <Clock className="h-4 w-4" />;
      case 'failed': return <XCircle className="h-4 w-4" />;
      default: return <AlertTriangle className="h-4 w-4" />;
    }
  };

  const getPassFailColor = (status: string) => {
    switch (status) {
      case 'pass': return 'bg-green-100 text-green-800';
      case 'fail': return 'bg-red-100 text-red-800';
      case 'partial': return 'bg-yellow-100 text-yellow-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const experimentStats = {
    total: experiments.length,
    completed: experiments.filter(e => e.status === 'completed').length,
    inProgress: experiments.filter(e => e.status === 'in-progress').length,
    rndQualified: experiments.filter(e => e.isRnDQualified).length
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Experiment Tracking</h1>
        <button
          onClick={() => setShowNewExperimentForm(true)}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2"
        >
          <Plus className="h-4 w-4" />
          <span>New Experiment</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-6">
        <div className="bg-blue-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-blue-900 mb-2 flex items-center">
            <Flask className="h-4 w-4 mr-1" />
            Total Experiments
          </h4>
          <p className="text-2xl font-bold text-blue-600">{experimentStats.total}</p>
        </div>
        <div className="bg-green-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-green-900 mb-2 flex items-center">
            <CheckCircle className="h-4 w-4 mr-1" />
            Completed
          </h4>
          <p className="text-2xl font-bold text-green-600">{experimentStats.completed}</p>
        </div>
        <div className="bg-yellow-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-yellow-900 mb-2 flex items-center">
            <Clock className="h-4 w-4 mr-1" />
            In Progress
          </h4>
          <p className="text-2xl font-bold text-yellow-600">{experimentStats.inProgress}</p>
        </div>
        <div className="bg-purple-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-purple-900 mb-2 flex items-center">
            <Lightbulb className="h-4 w-4 mr-1" />
            R&D Qualified
          </h4>
          <p className="text-2xl font-bold text-purple-600">{experimentStats.rndQualified}</p>
        </div>
      </div>

      {showNewExperimentForm && (
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Create New Experiment</h3>
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Experiment Title</label>
                <input
                  type="text"
                  value={newExperiment.title}
                  onChange={(e) => setNewExperiment({ ...newExperiment, title: e.target.value })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="Descriptive experiment title..."
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Project</label>
                <select
                  value={newExperiment.projectId}
                  onChange={(e) => setNewExperiment({ ...newExperiment, projectId: e.target.value })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="">Select a project</option>
                  {projects.map(project => (
                    <option key={project.id} value={project.id}>{project.name}</option>
                  ))}
                </select>
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Hypothesis</label>
              <textarea
                value={newExperiment.hypothesis}
                onChange={(e) => setNewExperiment({ ...newExperiment, hypothesis: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                rows={3}
                placeholder="What do you expect to happen and why?"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Technical Uncertainty</label>
              <textarea
                value={newExperiment.technicalUncertainty}
                onChange={(e) => setNewExperiment({ ...newExperiment, technicalUncertainty: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                rows={3}
                placeholder="What technical challenges or unknowns are you trying to resolve?"
              />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Technologies Used (comma-separated)</label>
                <input
                  type="text"
                  value={newExperiment.technologies.join(', ')}
                  onChange={(e) => handleTechnologiesInput(e.target.value)}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="ML, NLP, blockchain, React, Python..."
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Status</label>
                <select
                  value={newExperiment.status}
                  onChange={(e) => setNewExperiment({ ...newExperiment, status: e.target.value as any })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="planned">Planned</option>
                  <option value="in-progress">In Progress</option>
                  <option value="completed">Completed</option>
                  <option value="failed">Failed</option>
                </select>
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Methodology</label>
              <textarea
                value={newExperiment.methodology}
                onChange={(e) => setNewExperiment({ ...newExperiment, methodology: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                rows={3}
                placeholder="Describe your systematic approach to testing the hypothesis..."
              />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Start Date</label>
                <input
                  type="date"
                  value={newExperiment.startDate}
                  onChange={(e) => setNewExperiment({ ...newExperiment, startDate: e.target.value })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">End Date (Optional)</label>
                <input
                  type="date"
                  value={newExperiment.endDate}
                  onChange={(e) => setNewExperiment({ ...newExperiment, endDate: e.target.value })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
            </div>
            <div className="flex items-center">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={newExperiment.isRnDQualified}
                  onChange={(e) => setNewExperiment({ ...newExperiment, isRnDQualified: e.target.checked })}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700">R&D Qualified Activity</span>
              </label>
            </div>
          </div>
          <div className="flex justify-end space-x-3 mt-6">
            <button
              onClick={() => setShowNewExperimentForm(false)}
              className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              onClick={handleAddExperiment}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              Create Experiment
            </button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-1">
          <div className="bg-white p-4 rounded-xl shadow-sm border border-gray-200">
            <div className="space-y-4">
              <div className="relative">
                <Search className="h-4 w-4 absolute left-3 top-3 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search experiments..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-9 pr-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Filter by Status</label>
                <select
                  value={filterStatus}
                  onChange={(e) => setFilterStatus(e.target.value)}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="all">All Status</option>
                  <option value="planned">Planned</option>
                  <option value="in-progress">In Progress</option>
                  <option value="completed">Completed</option>
                  <option value="failed">Failed</option>
                </select>
              </div>
            </div>

            <div className="mt-6 space-y-2">
              {filteredExperiments.map((experiment) => (
                <div
                  key={experiment.id}
                  onClick={() => setSelectedExperiment(experiment)}
                  className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                    selectedExperiment?.id === experiment.id
                      ? 'border-blue-200 bg-blue-50'
                      : 'border-gray-200 hover:bg-gray-50'
                  }`}
                >
                  <div className="flex items-start justify-between mb-2">
                    <h4 className="text-sm font-medium text-gray-900 line-clamp-2">{experiment.title}</h4>
                    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium ${getStatusColor(experiment.status)}`}>
                      {getStatusIcon(experiment.status)}
                    </span>
                  </div>
                  <p className="text-xs text-gray-600 mb-2">{experiment.projectName}</p>
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-gray-500">{formatDate(experiment.startDate)}</p>
                    {experiment.isRnDQualified && (
                      <span className="text-xs text-green-600">R&D</span>
                    )}
                  </div>
                  {experiment.technologies.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {experiment.technologies.slice(0, 2).map((tech, index) => (
                        <span key={index} className="inline-flex items-center px-1.5 py-0.5 rounded text-xs bg-gray-100 text-gray-600">
                          {tech}
                        </span>
                      ))}
                      {experiment.technologies.length > 2 && (
                        <span className="text-xs text-gray-500">+{experiment.technologies.length - 2}</span>
                      )}
                    </div>
                  )}
                </div>
              ))}
              {filteredExperiments.length === 0 && (
                <div className="text-center py-8 text-gray-500">
                  <Flask className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                  <p className="text-sm">No experiments found</p>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="lg:col-span-3">
          {selectedExperiment ? (
            <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
              <div className="flex items-start justify-between mb-6">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <h3 className="text-lg font-semibold text-gray-900">{selectedExperiment.title}</h3>
                    <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(selectedExperiment.status)}`}>
                      {getStatusIcon(selectedExperiment.status)}
                      <span className="ml-1 capitalize">{selectedExperiment.status.replace('-', ' ')}</span>
                    </span>
                    {selectedExperiment.isRnDQualified && (
                      <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                        R&D Qualified
                      </span>
                    )}
                  </div>
                  <div className="flex items-center space-x-4 text-sm text-gray-600">
                    <span className="flex items-center">
                      <Users className="h-4 w-4 mr-1" />
                      {selectedExperiment.author}
                    </span>
                    <span className="flex items-center">
                      <Calendar className="h-4 w-4 mr-1" />
                      {formatDate(selectedExperiment.startDate)}
                      {selectedExperiment.endDate && ` - ${formatDate(selectedExperiment.endDate)}`}
                    </span>
                    <span>{selectedExperiment.projectName}</span>
                  </div>
                </div>
              </div>

              {selectedExperiment.technologies.length > 0 && (
                <div className="mb-6">
                  <h4 className="text-sm font-medium text-gray-900 mb-2">Technologies Used</h4>
                  <div className="flex flex-wrap gap-2">
                    {selectedExperiment.technologies.map((tech, index) => (
                      <span key={index} className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-blue-100 text-blue-600">
                        <Tag className="h-3 w-3 mr-1" />
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div className="space-y-6">
                <div>
                  <h4 className="text-sm font-medium text-gray-900 mb-2">Hypothesis</h4>
                  <p className="text-gray-700 bg-blue-50 p-3 rounded-lg">{selectedExperiment.hypothesis}</p>
                </div>

                <div>
                  <h4 className="text-sm font-medium text-gray-900 mb-2">Technical Uncertainty</h4>
                  <p className="text-gray-700 bg-yellow-50 p-3 rounded-lg">{selectedExperiment.technicalUncertainty}</p>
                </div>

                {selectedExperiment.methodology && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 mb-2">Methodology</h4>
                    <p className="text-gray-700 whitespace-pre-wrap">{selectedExperiment.methodology}</p>
                  </div>
                )}

                {selectedExperiment.expectedOutcome && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 mb-2">Expected Outcome</h4>
                    <p className="text-gray-700">{selectedExperiment.expectedOutcome}</p>
                  </div>
                )}

                {selectedExperiment.actualResults && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 mb-2">Actual Results</h4>
                    <div className="flex items-start space-x-3">
                      <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getPassFailColor(selectedExperiment.passFailStatus)}`}>
                        {selectedExperiment.passFailStatus.toUpperCase()}
                      </span>
                      <p className="text-gray-700 flex-1">{selectedExperiment.actualResults}</p>
                    </div>
                  </div>
                )}

                {selectedExperiment.issuesFound.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 mb-2">Issues Found</h4>
                    <ul className="list-disc list-inside space-y-1 text-gray-700">
                      {selectedExperiment.issuesFound.map((issue, index) => (
                        <li key={index}>{issue}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {selectedExperiment.lessonsLearned && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 mb-2">Lessons Learned</h4>
                    <p className="text-gray-700 bg-green-50 p-3 rounded-lg">{selectedExperiment.lessonsLearned}</p>
                  </div>
                )}

                {selectedExperiment.nextSteps && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 mb-2">Next Steps</h4>
                    <p className="text-gray-700">{selectedExperiment.nextSteps}</p>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="bg-white p-8 rounded-xl shadow-sm border border-gray-200 text-center">
              <Flask className="h-16 w-16 mx-auto mb-4 text-gray-300" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">No Experiment Selected</h3>
              <p className="text-gray-600">Select an experiment from the sidebar to view its details</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};