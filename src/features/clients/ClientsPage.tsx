import React from 'react';
import { Building2, Plus } from 'lucide-react';
import { Client } from '../../types';
import { ClientTable } from './ClientTable';
import { ClientForm } from './ClientForm';
import { useClients } from './useClients';

interface ClientsPageProps {
  selectedClientId: string | null;
  onSelectClient: (clientId: string) => void;
}

export const ClientsPage: React.FC<ClientsPageProps> = ({
  selectedClientId,
  onSelectClient
}) => {
  const {
    clients,
    showNewClientForm,
    setShowNewClientForm,
    handleAddClient,
    handleUpdateClient,
    handleDeleteClient
  } = useClients();

  const selectedClient = clients.find(c => c.id === selectedClientId);

  if (selectedClientId && selectedClient) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className="bg-gradient-to-r from-indigo-500 to-purple-500 p-4 rounded-2xl">
              <Building2 className="h-8 w-8 text-white" />
            </div>
            <div>
              <h2 className="text-3xl font-bold text-slate-900">{selectedClient.name}</h2>
              <p className="text-slate-600 font-medium">{selectedClient.industry}</p>
            </div>
          </div>
          <button
            onClick={() => onSelectClient('')}
            className="text-indigo-600 hover:text-indigo-700 text-sm font-bold bg-indigo-50 px-4 py-2 rounded-xl hover:bg-indigo-100 transition-all duration-300"
          >
            ← Back to Clients
          </button>
        </div>
        
        {/* Client details would go here */}
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Client Overview</h3>
          <p className="text-gray-600">Client management features will be implemented here.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-4xl font-bold text-slate-800">Client Management</h1>
          <p className="text-slate-600 mt-2">Manage your R&D tax credit clients and their information</p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={() => setShowNewClientForm(true)}
            className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2 shadow-sm"
          >
            <Plus className="h-4 w-4" />
            <span>Add Client</span>
          </button>
          <div className="bg-white px-4 py-2 rounded-lg border border-gray-200 shadow-sm">
            <span className="text-sm font-medium text-slate-600">
              {clients.length} {clients.length === 1 ? 'client' : 'clients'}
            </span>
          </div>
        </div>
      </div>

      {showNewClientForm && (
        <ClientForm
          onSubmit={handleAddClient}
          onCancel={() => setShowNewClientForm(false)}
        />
      )}

      <ClientTable
        clients={clients}
        onSelectClient={onSelectClient}
        onUpdateClient={handleUpdateClient}
        onDeleteClient={handleDeleteClient}
      />
    </div>
  );
};