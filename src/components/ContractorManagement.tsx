import React, { useState } from 'react';
import { Users, Plus, Search, Clock, DollarSign, CheckCircle, XCircle, Building, Mail, Phone } from 'lucide-react';
import { Contractor, ContractorTimeEntry, Project } from '../types';
import { formatCurrency, formatDuration, formatDate } from '../utils/formatters';

interface ContractorManagementProps {
  contractors: Contractor[];
  contractorTimeEntries: ContractorTimeEntry[];
  projects: Project[];
  onAddContractor: (contractor: Omit<Contractor, 'id'>) => void;
  onUpdateContractor: (id: string, updates: Partial<Contractor>) => void;
  onAddContractorTime: (entry: Omit<ContractorTimeEntry, 'id'>) => void;
}

export const ContractorManagement: React.FC<ContractorManagementProps> = ({
  contractors,
  contractorTimeEntries,
  projects,
  onAddContractor,
  onUpdateContractor,
  onAddContractorTime
}) => {
  const [activeTab, setActiveTab] = useState<'contractors' | 'timesheet'>('contractors');
  const [showNewContractorForm, setShowNewContractorForm] = useState(false);
  const [showNewTimeForm, setShowNewTimeForm] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [newContractor, setNewContractor] = useState({
    name: '',
    company: '',
    email: '',
    phone: '',
    specialization: '',
    hourlyRate: 0,
    isActive: true,
    rndQualified: true,
    contractStartDate: new Date().toISOString().split('T')[0],
    contractEndDate: ''
  });
  const [newTimeEntry, setNewTimeEntry] = useState({
    contractorId: '',
    projectId: '',
    task: '',
    duration: 0,
    date: new Date().toISOString().split('T')[0],
    hourlyRate: 0,
    isRnD: true,
    invoiceNumber: '',
    notes: ''
  });

  const filteredContractors = contractors.filter(contractor =>
    contractor.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    contractor.company.toLowerCase().includes(searchTerm.toLowerCase()) ||
    contractor.specialization.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleAddContractor = () => {
    if (!newContractor.name || !newContractor.company) return;
    
    onAddContractor(newContractor);
    setNewContractor({
      name: '',
      company: '',
      email: '',
      phone: '',
      specialization: '',
      hourlyRate: 0,
      isActive: true,
      rndQualified: true,
      contractStartDate: new Date().toISOString().split('T')[0],
      contractEndDate: ''
    });
    setShowNewContractorForm(false);
  };

  const handleAddTimeEntry = () => {
    if (!newTimeEntry.contractorId || !newTimeEntry.projectId || !newTimeEntry.task) return;
    
    const contractor = contractors.find(c => c.id === newTimeEntry.contractorId);
    const project = projects.find(p => p.id === newTimeEntry.projectId);
    if (!contractor || !project) return;

    onAddContractorTime({
      ...newTimeEntry,
      contractorName: contractor.name,
      projectName: project.name,
      hourlyRate: newTimeEntry.hourlyRate || contractor.hourlyRate
    });

    setNewTimeEntry({
      contractorId: '',
      projectId: '',
      task: '',
      duration: 0,
      date: new Date().toISOString().split('T')[0],
      hourlyRate: 0,
      isRnD: true,
      invoiceNumber: '',
      notes: ''
    });
    setShowNewTimeForm(false);
  };

  const totalContractorCosts = contractorTimeEntries.reduce((total, entry) => 
    total + (entry.duration / 60) * entry.hourlyRate, 0
  );

  const rndContractorCosts = contractorTimeEntries
    .filter(entry => entry.isRnD)
    .reduce((total, entry) => total + (entry.duration / 60) * entry.hourlyRate, 0);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Contractor & Vendor Management</h1>
        <div className="flex space-x-3">
          <button
            onClick={() => setShowNewTimeForm(true)}
            className="bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700 transition-colors flex items-center space-x-2"
          >
            <Clock className="h-4 w-4" />
            <span>Log Time</span>
          </button>
          <button
            onClick={() => setShowNewContractorForm(true)}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2"
          >
            <Plus className="h-4 w-4" />
            <span>Add Contractor</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        <div className="bg-blue-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-blue-900 mb-2">Active Contractors</h4>
          <p className="text-2xl font-bold text-blue-600">{contractors.filter(c => c.isActive).length}</p>
        </div>
        <div className="bg-green-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-green-900 mb-2">R&D Contractor Costs</h4>
          <p className="text-2xl font-bold text-green-600">{formatCurrency(rndContractorCosts)}</p>
        </div>
        <div className="bg-purple-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-purple-900 mb-2">Total Contractor Costs</h4>
          <p className="text-2xl font-bold text-purple-600">{formatCurrency(totalContractorCosts)}</p>
        </div>
      </div>

      {showNewContractorForm && (
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Add New Contractor</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Name</label>
              <input
                type="text"
                value={newContractor.name}
                onChange={(e) => setNewContractor({ ...newContractor, name: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Company</label>
              <input
                type="text"
                value={newContractor.company}
                onChange={(e) => setNewContractor({ ...newContractor, company: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Email</label>
              <input
                type="email"
                value={newContractor.email}
                onChange={(e) => setNewContractor({ ...newContractor, email: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Phone</label>
              <input
                type="tel"
                value={newContractor.phone}
                onChange={(e) => setNewContractor({ ...newContractor, phone: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Specialization</label>
              <input
                type="text"
                value={newContractor.specialization}
                onChange={(e) => setNewContractor({ ...newContractor, specialization: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="e.g., Machine Learning, Frontend Development"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Hourly Rate</label>
              <input
                type="number"
                value={newContractor.hourlyRate}
                onChange={(e) => setNewContractor({ ...newContractor, hourlyRate: parseFloat(e.target.value) || 0 })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Contract Start Date</label>
              <input
                type="date"
                value={newContractor.contractStartDate}
                onChange={(e) => setNewContractor({ ...newContractor, contractStartDate: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Contract End Date (Optional)</label>
              <input
                type="date"
                value={newContractor.contractEndDate}
                onChange={(e) => setNewContractor({ ...newContractor, contractEndDate: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div className="md:col-span-2 flex items-center space-x-4">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={newContractor.rndQualified}
                  onChange={(e) => setNewContractor({ ...newContractor, rndQualified: e.target.checked })}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700">R&D Qualified</span>
              </label>
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={newContractor.isActive}
                  onChange={(e) => setNewContractor({ ...newContractor, isActive: e.target.checked })}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700">Active</span>
              </label>
            </div>
          </div>
          <div className="flex justify-end space-x-3 mt-6">
            <button
              onClick={() => setShowNewContractorForm(false)}
              className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              onClick={handleAddContractor}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              Add Contractor
            </button>
          </div>
        </div>
      )}

      {showNewTimeForm && (
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Log Contractor Time</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Contractor</label>
              <select
                value={newTimeEntry.contractorId}
                onChange={(e) => setNewTimeEntry({ ...newTimeEntry, contractorId: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="">Select contractor</option>
                {contractors.filter(c => c.isActive).map(contractor => (
                  <option key={contractor.id} value={contractor.id}>{contractor.name} - {contractor.company}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Project</label>
              <select
                value={newTimeEntry.projectId}
                onChange={(e) => setNewTimeEntry({ ...newTimeEntry, projectId: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="">Select project</option>
                {projects.map(project => (
                  <option key={project.id} value={project.id}>{project.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Task Description</label>
              <input
                type="text"
                value={newTimeEntry.task}
                onChange={(e) => setNewTimeEntry({ ...newTimeEntry, task: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Duration (minutes)</label>
              <input
                type="number"
                value={newTimeEntry.duration}
                onChange={(e) => setNewTimeEntry({ ...newTimeEntry, duration: parseInt(e.target.value) || 0 })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Date</label>
              <input
                type="date"
                value={newTimeEntry.date}
                onChange={(e) => setNewTimeEntry({ ...newTimeEntry, date: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Hourly Rate (optional)</label>
              <input
                type="number"
                value={newTimeEntry.hourlyRate}
                onChange={(e) => setNewTimeEntry({ ...newTimeEntry, hourlyRate: parseFloat(e.target.value) || 0 })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Leave blank to use contractor's default rate"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Invoice Number (optional)</label>
              <input
                type="text"
                value={newTimeEntry.invoiceNumber}
                onChange={(e) => setNewTimeEntry({ ...newTimeEntry, invoiceNumber: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div className="flex items-center">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={newTimeEntry.isRnD}
                  onChange={(e) => setNewTimeEntry({ ...newTimeEntry, isRnD: e.target.checked })}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700">R&D Activity</span>
              </label>
            </div>
            <div className="md:col-span-2">
              <label className="block text-sm font-medium text-gray-700 mb-2">Notes</label>
              <textarea
                value={newTimeEntry.notes}
                onChange={(e) => setNewTimeEntry({ ...newTimeEntry, notes: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                rows={2}
              />
            </div>
          </div>
          <div className="flex justify-end space-x-3 mt-6">
            <button
              onClick={() => setShowNewTimeForm(false)}
              className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              onClick={handleAddTimeEntry}
              className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
            >
              Log Time
            </button>
          </div>
        </div>
      )}

      <div className="bg-white rounded-xl shadow-sm border border-gray-200">
        <div className="border-b border-gray-200">
          <nav className="flex space-x-8 px-6">
            <button
              onClick={() => setActiveTab('contractors')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'contractors'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              Contractors
            </button>
            <button
              onClick={() => setActiveTab('timesheet')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'timesheet'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              Time Entries
            </button>
          </nav>
        </div>

        <div className="p-6">
          {activeTab === 'contractors' && (
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="relative">
                  <Search className="h-4 w-4 absolute left-3 top-3 text-gray-400" />
                  <input
                    type="text"
                    placeholder="Search contractors..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-9 pr-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredContractors.map((contractor) => (
                  <div key={contractor.id} className="border border-gray-200 rounded-lg p-4">
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <h4 className="font-medium text-gray-900">{contractor.name}</h4>
                        <p className="text-sm text-gray-600 flex items-center">
                          <Building className="h-3 w-3 mr-1" />
                          {contractor.company}
                        </p>
                      </div>
                      <div className="flex items-center space-x-1">
                        {contractor.isActive ? (
                          <CheckCircle className="h-4 w-4 text-green-500" />
                        ) : (
                          <XCircle className="h-4 w-4 text-red-500" />
                        )}
                        {contractor.rndQualified && (
                          <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
                            R&D
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="space-y-2 text-sm">
                      <p className="text-gray-600">{contractor.specialization}</p>
                      <p className="font-medium text-green-600">{formatCurrency(contractor.hourlyRate)}/hr</p>
                      <div className="flex items-center space-x-3 text-xs text-gray-500">
                        <span className="flex items-center">
                          <Mail className="h-3 w-3 mr-1" />
                          {contractor.email}
                        </span>
                        <span className="flex items-center">
                          <Phone className="h-3 w-3 mr-1" />
                          {contractor.phone}
                        </span>
                      </div>
                      <p className="text-xs text-gray-500">
                        Contract: {formatDate(contractor.contractStartDate)} - {contractor.contractEndDate ? formatDate(contractor.contractEndDate) : 'Ongoing'}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'timesheet' && (
            <div className="space-y-4">
              {contractorTimeEntries.map((entry) => (
                <div key={entry.id} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <h4 className="font-medium text-gray-900">{entry.contractorName}</h4>
                      <p className="text-sm text-gray-600">{entry.projectName} • {entry.task}</p>
                      {entry.notes && (
                        <p className="text-xs text-gray-500 mt-1">{entry.notes}</p>
                      )}
                    </div>
                    <div className="text-right">
                      <p className="font-medium text-gray-900">{formatDuration(entry.duration)}</p>
                      <p className="text-sm text-green-600">{formatCurrency((entry.duration / 60) * entry.hourlyRate)}</p>
                      <div className="flex items-center space-x-2 mt-1">
                        <span className="text-xs text-gray-500">{formatDate(entry.date)}</span>
                        {entry.isRnD && (
                          <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
                            R&D
                          </span>
                        )}
                      </div>
                      {entry.invoiceNumber && (
                        <p className="text-xs text-gray-500">Invoice: {entry.invoiceNumber}</p>
                      )}
                    </div>
                  </div>
                </div>
              ))}
              {contractorTimeEntries.length === 0 && (
                <div className="text-center py-8 text-gray-500">
                  <Clock className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                  <p>No contractor time entries found</p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};