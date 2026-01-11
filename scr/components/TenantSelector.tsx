import React, { useState, useEffect } from 'react';
import { Building2, Eye, EyeOff, Search, AlertCircle } from 'lucide-react';
import { LoadingSpinner } from './LoadingSpinner';

interface Tenant {
  id: string;
  name: string;
  domain: string | null;
  active: number;
  created_at: number;
}

interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  user_type: string;
}

interface TenantSelectorProps {
  user: User;
  onTenantSelected: (accessToken: string, tenant: Tenant) => void;
  apiUrl?: string;
}

export const TenantSelector: React.FC<TenantSelectorProps> = ({
  user,
  onTenantSelected,
  apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8787'
}) => {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [filteredTenants, setFilteredTenants] = useState<Tenant[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTenantId, setSelectedTenantId] = useState<string>('');
  const [readOnly, setReadOnly] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    loadTenants();
  }, []);

  useEffect(() => {
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      setFilteredTenants(
        tenants.filter(
          t =>
            t.name.toLowerCase().includes(query) ||
            (t.domain && t.domain.toLowerCase().includes(query))
        )
      );
    } else {
      setFilteredTenants(tenants);
    }
  }, [searchQuery, tenants]);

  const loadTenants = async () => {
    setIsLoading(true);
    setError('');
    try {
      const response = await fetch(`${apiUrl}/api/auth/tenants`);
      const data = await response.json();

      if (data.success) {
        setTenants(data.tenants);
        setFilteredTenants(data.tenants);
      } else {
        setError(data.error || 'Failed to load tenants');
      }
    } catch (err) {
      setError('Failed to connect to server');
      console.error('Load tenants error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSelectTenant = async () => {
    if (!selectedTenantId) {
      setError('Please select a tenant');
      return;
    }

    setIsLoading(true);
    setError('');

    try {
      const response = await fetch(`${apiUrl}/api/auth/select-tenant`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          userId: user.id,
          tenantId: selectedTenantId,
          readOnly
        })
      });

      const data = await response.json();

      if (data.success) {
        onTenantSelected(data.accessToken, data.tenant);
      } else {
        setError(data.error || 'Failed to select tenant');
      }
    } catch (err) {
      setError('Failed to connect to server');
      console.error('Select tenant error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#0073e6] via-[#004aad] to-[#2c3c4d] flex items-center justify-center p-8">
      <div className="bg-white rounded-3xl shadow-2xl border border-gray-100 p-10 w-full max-w-2xl">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center mb-6">
            <div className="w-20 h-20 bg-gradient-to-br from-[#0073e6] to-[#89c726] rounded-2xl flex items-center justify-center">
              <Building2 className="h-10 w-10 text-white" />
            </div>
          </div>
          <h2 className="text-3xl font-bold text-[#2c3c4d] mb-2">Select Tenant</h2>
          <p className="text-gray-600">
            Platform Admin: <span className="font-semibold text-[#0073e6]">{user.email}</span>
          </p>
          <p className="text-sm text-gray-500 mt-2">
            Choose which tenant you want to access
          </p>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-xl flex items-start">
            <AlertCircle className="h-5 w-5 text-red-600 mr-2 flex-shrink-0 mt-0.5" />
            <p className="text-sm text-red-600">{error}</p>
          </div>
        )}

        <div className="space-y-6">
          <div>
            <label className="block text-sm font-semibold text-[#2c3c4d] mb-2">
              Search Tenants
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                <Search className="h-5 w-5 text-gray-400" />
              </div>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-12 pr-4 py-3.5 border-2 border-gray-200 rounded-xl focus:ring-2 focus:ring-[#0073e6] focus:border-[#0073e6] hover:border-gray-300 transition-all"
                placeholder="Search by name or domain..."
                disabled={isLoading}
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-semibold text-[#2c3c4d] mb-3">
              Available Tenants ({filteredTenants.length})
            </label>
            <div className="border-2 border-gray-200 rounded-xl max-h-80 overflow-y-auto">
              {isLoading ? (
                <div className="p-8 text-center">
                  <LoadingSpinner size="md" />
                </div>
              ) : filteredTenants.length === 0 ? (
                <div className="p-8 text-center text-gray-500">
                  {searchQuery ? 'No tenants match your search' : 'No tenants available'}
                </div>
              ) : (
                <div className="divide-y divide-gray-200">
                  {filteredTenants.map((tenant) => (
                    <label
                      key={tenant.id}
                      className={`flex items-center p-4 cursor-pointer transition-colors ${
                        selectedTenantId === tenant.id
                          ? 'bg-[#0073e6]/10'
                          : 'hover:bg-gray-50'
                      }`}
                    >
                      <input
                        type="radio"
                        name="tenant"
                        value={tenant.id}
                        checked={selectedTenantId === tenant.id}
                        onChange={(e) => setSelectedTenantId(e.target.value)}
                        className="w-5 h-5 text-[#0073e6] focus:ring-[#0073e6]"
                        disabled={isLoading}
                      />
                      <div className="ml-3 flex-1">
                        <div className="font-semibold text-[#2c3c4d]">{tenant.name}</div>
                        {tenant.domain && (
                          <div className="text-sm text-gray-500">{tenant.domain}</div>
                        )}
                      </div>
                    </label>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="bg-amber-50 border-2 border-amber-200 rounded-xl p-4">
            <label className="flex items-start cursor-pointer">
              <input
                type="checkbox"
                checked={readOnly}
                onChange={(e) => setReadOnly(e.target.checked)}
                className="mt-1 w-5 h-5 rounded text-amber-600 focus:ring-amber-500"
                disabled={isLoading}
              />
              <div className="ml-3 flex-1">
                <div className="flex items-center">
                  {readOnly ? (
                    <Eye className="h-5 w-5 text-amber-600 mr-2" />
                  ) : (
                    <EyeOff className="h-5 w-5 text-amber-600 mr-2" />
                  )}
                  <span className="font-semibold text-amber-900">
                    Read-Only Mode {readOnly ? '(Active)' : '(Inactive)'}
                  </span>
                </div>
                <p className="text-sm text-amber-700 mt-1">
                  Enable read-only mode to prevent accidental modifications. You can only view data, not edit it.
                </p>
              </div>
            </label>
          </div>

          <button
            onClick={handleSelectTenant}
            disabled={!selectedTenantId || isLoading}
            className="w-full bg-gradient-to-r from-[#004aad] to-[#0073e6] text-white py-4 px-6 rounded-xl hover:from-[#0073e6] hover:to-[#89c726] focus:ring-4 focus:ring-[#ade5f8] transition-all duration-300 font-semibold text-lg disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center shadow-lg hover:shadow-xl"
          >
            {isLoading ? (
              <LoadingSpinner size="sm" text="" />
            ) : (
              <span>Access Tenant</span>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
