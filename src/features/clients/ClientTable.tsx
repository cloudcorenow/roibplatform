import React, { useState } from 'react';
import { Building2, Users, DollarSign, Calendar, Search } from 'lucide-react';
import { Client } from '../../types';
import { formatCurrency, formatDate } from '../../utils/formatters';
import { useAdvancedSearch } from '../../hooks/useAdvancedSearch';

interface ClientTableProps {
  clients: Client[];
  onSelectClient: (clientId: string) => void;
  onUpdateClient: (id: string, updates: Partial<Client>) => void;
  onDeleteClient: (id: string) => void;
}

export const ClientTable: React.FC<ClientTableProps> = ({
  clients,
  onSelectClient,
  onUpdateClient,
  onDeleteClient
}) => {
  const { filteredData: filteredClients, filters, updateFilter } = useAdvancedSearch(
    clients,
    ['name', 'industry', 'contactPerson', 'email'],
    { query: '' }
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row items-start sm:items-center space-y-3 sm:space-y-0 sm:space-x-4">
        <div className="relative flex-1 max-w-md">
          <Search className="h-4 w-4 absolute left-3 top-3 text-gray-400" />
          <input
            type="text"
            placeholder="Search clients..."
            value={filters.query}
            onChange={(e) => updateFilter('query', e.target.value)}
            className="w-full pl-9 pr-3 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6 lg:gap-8">
        {filteredClients.map((client) => (
          <div
            key={client.id}
            onClick={() => onSelectClient(client.id)}
            className="group bg-white p-4 sm:p-6 rounded-lg shadow-md border border-gray-200 hover:shadow-lg transition-all duration-200 cursor-pointer hover:border-blue-300 touch-manipulation"
          >
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center space-x-3">
                <div className="bg-blue-600 p-2 sm:p-3 rounded-lg group-hover:bg-blue-700 transition-colors">
                  <Building2 className="h-6 w-6 text-white" />
                </div>
                <div>
                  <h3 className="text-base sm:text-lg font-semibold text-slate-800 group-hover:text-blue-600 transition-colors">
                    {client.name}
                  </h3>
                  <p className="text-sm text-slate-600">{client.industry}</p>
                </div>
              </div>
              <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-bold ${
                client.status === 'active' ? 'bg-green-100 text-green-800' :
                client.status === 'pending' ? 'bg-yellow-100 text-yellow-800' :
                'bg-gray-100 text-gray-800'
              }`}>
                {client.status}
              </span>
            </div>

            <div className="space-y-4">
              <div className="flex items-center justify-between text-sm">
                <span className="text-slate-600 flex items-center font-medium">
                  <Users className="h-4 w-4 mr-1" />
                  Projects
                </span>
                <span className="font-bold text-slate-900">{client.totalProjects}</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-slate-600 flex items-center font-medium">
                  <DollarSign className="h-4 w-4 mr-1" />
                  Est. Credit
                </span>
                <span className="font-bold text-green-600">{formatCurrency(client.estimatedCredit)}</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-slate-600 flex items-center font-medium">
                  <Calendar className="h-4 w-4 mr-1" />
                  Tax Year
                </span>
                <span className="font-bold text-slate-900">{client.taxYear}</span>
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-slate-200">
              <div className="text-sm">
                <p className="text-slate-700 font-medium">Contact: {client.contactPerson}</p>
                <p className="text-slate-500 text-xs mt-1 font-medium truncate">{client.email}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {filteredClients.length === 0 && (
        <div className="text-center py-12 text-gray-500">
          <Building2 className="h-16 w-16 mx-auto mb-4 text-gray-300" />
          <p className="text-lg font-medium">No clients found</p>
          <p className="text-sm mt-1">Try adjusting your search criteria or add a new client</p>
        </div>
      )}
    </div>
  );
};