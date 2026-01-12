import React, { useState, useEffect } from 'react';
import { Settings, FolderSync as Sync, Users, Clock, CheckCircle, AlertCircle, RefreshCw, Database, Key, Globe } from 'lucide-react';
import CentralReachAPI from '../services/centralReachApi';
import { CentralReachConfig, CentralReachSyncResult } from '../types/centralreach';
import { LoadingSpinner } from './LoadingSpinner';

interface CentralReachIntegrationProps {
  onSyncComplete?: (result: CentralReachSyncResult) => void;
}

export const CentralReachIntegration: React.FC<CentralReachIntegrationProps> = ({
  onSyncComplete
}) => {
  const [config, setConfig] = useState<CentralReachConfig>({
    apiKey: '',
    baseUrl: 'https://api.centralreach.com/v1',
    organizationId: ''
  });
  const [isConfigured, setIsConfigured] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [isSyncing, setIsSyncing] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'disconnected' | 'connected' | 'error'>('disconnected');
  const [lastSync, setLastSync] = useState<string | null>(null);
  const [syncResults, setSyncResults] = useState<CentralReachSyncResult[]>([]);
  const [api, setApi] = useState<CentralReachAPI | null>(null);

  useEffect(() => {
    // Load saved configuration from localStorage
    const savedConfig = localStorage.getItem('centralreach-config');
    if (savedConfig) {
      const parsedConfig = JSON.parse(savedConfig);
      setConfig(parsedConfig);
      setIsConfigured(true);
      setApi(new CentralReachAPI(parsedConfig));
      setConnectionStatus('connected');
    }
  }, []);

  const handleSaveConfig = () => {
    if (!config.apiKey || !config.organizationId) {
      alert('Please fill in all required fields');
      return;
    }

    localStorage.setItem('centralreach-config', JSON.stringify(config));
    setApi(new CentralReachAPI(config));
    setIsConfigured(true);
    testConnection();
  };

  const testConnection = async () => {
    if (!api) return;

    setIsConnecting(true);
    try {
      // Test the connection by trying to fetch staff
      await api.getStaff();
      setConnectionStatus('connected');
    } catch (error) {
      setConnectionStatus('error');
      console.error('Connection test failed:', error);
    } finally {
      setIsConnecting(false);
    }
  };

  const handleSync = async (syncType: 'clients' | 'staff' | 'timeentries' | 'all') => {
    if (!api) return;

    setIsSyncing(true);
    const results: CentralReachSyncResult[] = [];

    try {
      if (syncType === 'clients' || syncType === 'all') {
        const clientResult = await api.syncClients();
        results.push({ ...clientResult, message: `Clients: ${clientResult.message}` });
      }

      if (syncType === 'timeentries' || syncType === 'all') {
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - 30); // Last 30 days
        const endDate = new Date();
        
        const timeResult = await api.syncTimeEntries(
          startDate.toISOString().split('T')[0],
          endDate.toISOString().split('T')[0]
        );
        results.push({ ...timeResult, message: `Time Entries: ${timeResult.message}` });
      }

      setSyncResults(results);
      setLastSync(new Date().toISOString());
      
      if (onSyncComplete) {
        const overallResult: CentralReachSyncResult = {
          success: results.every(r => r.success),
          message: results.map(r => r.message).join(', '),
          syncedRecords: results.reduce((sum, r) => sum + r.syncedRecords, 0),
          errors: results.flatMap(r => r.errors)
        };
        onSyncComplete(overallResult);
      }
    } catch (error) {
      console.error('Sync failed:', error);
    } finally {
      setIsSyncing(false);
    }
  };

  const handleDisconnect = () => {
    localStorage.removeItem('centralreach-config');
    setConfig({
      apiKey: '',
      baseUrl: 'https://api.centralreach.com/v1',
      organizationId: ''
    });
    setIsConfigured(false);
    setApi(null);
    setConnectionStatus('disconnected');
    setSyncResults([]);
    setLastSync(null);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">CentralReach Integration</h1>
          <p className="text-gray-600 mt-2">Connect and sync data from your CentralReach platform</p>
        </div>
        <div className="flex items-center space-x-2">
          <div className={`w-3 h-3 rounded-full ${
            connectionStatus === 'connected' ? 'bg-green-500' :
            connectionStatus === 'error' ? 'bg-red-500' : 'bg-gray-400'
          }`} />
          <span className="text-sm text-gray-600">
            {connectionStatus === 'connected' ? 'Connected' :
             connectionStatus === 'error' ? 'Connection Error' : 'Disconnected'}
          </span>
        </div>
      </div>

      {!isConfigured ? (
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
              <Settings className="h-5 w-5 text-white" />
            </div>
            <h3 className="text-xl font-semibold text-gray-900">Configure CentralReach Connection</h3>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                <Key className="h-4 w-4 inline mr-1" />
                API Key *
              </label>
              <input
                type="password"
                value={config.apiKey}
                onChange={(e) => setConfig({ ...config, apiKey: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Enter your CentralReach API key"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                <Database className="h-4 w-4 inline mr-1" />
                Organization ID *
              </label>
              <input
                type="text"
                value={config.organizationId}
                onChange={(e) => setConfig({ ...config, organizationId: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Enter your organization ID"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                <Globe className="h-4 w-4 inline mr-1" />
                API Base URL
              </label>
              <input
                type="url"
                value={config.baseUrl}
                onChange={(e) => setConfig({ ...config, baseUrl: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="https://api.centralreach.com/v1"
              />
            </div>
          </div>

          <div className="mt-6 p-4 bg-blue-50 rounded-lg">
            <h4 className="font-medium text-blue-900 mb-2">Setup Instructions</h4>
            <ol className="text-sm text-blue-800 space-y-1 list-decimal list-inside">
              <li>Log into your CentralReach admin panel</li>
              <li>Navigate to Settings → API Management</li>
              <li>Generate a new API key with appropriate permissions</li>
              <li>Copy your Organization ID from the account settings</li>
              <li>Enter the credentials above and click "Connect"</li>
            </ol>
          </div>

          <div className="flex justify-end space-x-3 mt-6">
            <button
              onClick={handleSaveConfig}
              disabled={isConnecting}
              className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2 disabled:opacity-50"
            >
              {isConnecting ? (
                <LoadingSpinner size="sm" text="" />
              ) : (
                <Settings className="h-4 w-4" />
              )}
              <span>{isConnecting ? 'Connecting...' : 'Connect'}</span>
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Connection Status */}
          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                  connectionStatus === 'connected' ? 'bg-green-100' : 'bg-red-100'
                }`}>
                  {connectionStatus === 'connected' ? (
                    <CheckCircle className="h-5 w-5 text-green-600" />
                  ) : (
                    <AlertCircle className="h-5 w-5 text-red-600" />
                  )}
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-gray-900">
                    {connectionStatus === 'connected' ? 'Connected to CentralReach' : 'Connection Error'}
                  </h3>
                  <p className="text-sm text-gray-600">
                    Organization: {config.organizationId}
                  </p>
                  {lastSync && (
                    <p className="text-xs text-gray-500">
                      Last sync: {new Date(lastSync).toLocaleString()}
                    </p>
                  )}
                </div>
              </div>
              <div className="flex space-x-2">
                <button
                  onClick={testConnection}
                  disabled={isConnecting}
                  className="text-blue-600 hover:text-blue-700 p-2 rounded-lg hover:bg-blue-50 transition-colors"
                  title="Test Connection"
                >
                  <RefreshCw className={`h-4 w-4 ${isConnecting ? 'animate-spin' : ''}`} />
                </button>
                <button
                  onClick={handleDisconnect}
                  className="text-red-600 hover:text-red-700 p-2 rounded-lg hover:bg-red-50 transition-colors"
                  title="Disconnect"
                >
                  <Settings className="h-4 w-4" />
                </button>
              </div>
            </div>
          </div>

          {/* Sync Controls */}
          <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Data Synchronization</h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
              <button
                onClick={() => handleSync('clients')}
                disabled={isSyncing || connectionStatus !== 'connected'}
                className="flex flex-col items-center p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-50"
              >
                <Users className="h-8 w-8 text-blue-600 mb-2" />
                <span className="text-sm font-medium">Sync Clients</span>
              </button>

              <button
                onClick={() => handleSync('staff')}
                disabled={isSyncing || connectionStatus !== 'connected'}
                className="flex flex-col items-center p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-50"
              >
                <Users className="h-8 w-8 text-green-600 mb-2" />
                <span className="text-sm font-medium">Sync Staff</span>
              </button>

              <button
                onClick={() => handleSync('timeentries')}
                disabled={isSyncing || connectionStatus !== 'connected'}
                className="flex flex-col items-center p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-50"
              >
                <Clock className="h-8 w-8 text-purple-600 mb-2" />
                <span className="text-sm font-medium">Sync Time Entries</span>
              </button>

              <button
                onClick={() => handleSync('all')}
                disabled={isSyncing || connectionStatus !== 'connected'}
                className="flex flex-col items-center p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-50 bg-blue-50"
              >
                <Sync className="h-8 w-8 text-blue-600 mb-2" />
                <span className="text-sm font-medium">Sync All</span>
              </button>
            </div>

            {isSyncing && (
              <div className="flex items-center justify-center py-4">
                <LoadingSpinner size="md" text="Synchronizing data..." />
              </div>
            )}
          </div>

          {/* Sync Results */}
          {syncResults.length > 0 && (
            <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Sync Results</h3>
              <div className="space-y-3">
                {syncResults.map((result, index) => (
                  <div key={index} className={`p-3 rounded-lg border ${
                    result.success ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'
                  }`}>
                    <div className="flex items-center space-x-2">
                      {result.success ? (
                        <CheckCircle className="h-4 w-4 text-green-600" />
                      ) : (
                        <AlertCircle className="h-4 w-4 text-red-600" />
                      )}
                      <span className={`text-sm font-medium ${
                        result.success ? 'text-green-800' : 'text-red-800'
                      }`}>
                        {result.message}
                      </span>
                      <span className="text-xs text-gray-600">
                        ({result.syncedRecords} records)
                      </span>
                    </div>
                    {result.errors.length > 0 && (
                      <div className="mt-2">
                        <p className="text-xs text-red-600 font-medium">Errors:</p>
                        <ul className="text-xs text-red-600 list-disc list-inside">
                          {result.errors.map((error, errorIndex) => (
                            <li key={errorIndex}>{error}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Integration Info */}
          <div className="bg-blue-50 p-6 rounded-xl">
            <h3 className="text-lg font-semibold text-blue-900 mb-3">Integration Features</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-blue-800">
              <div>
                <h4 className="font-medium mb-2">Data Sync</h4>
                <ul className="space-y-1 list-disc list-inside">
                  <li>Client information and demographics</li>
                  <li>Staff profiles and roles</li>
                  <li>Time tracking and billing data</li>
                  <li>Service definitions and codes</li>
                </ul>
              </div>
              <div>
                <h4 className="font-medium mb-2">R&D Integration</h4>
                <ul className="space-y-1 list-disc list-inside">
                  <li>Automatic R&D time classification</li>
                  <li>Staff qualification mapping</li>
                  <li>Project-based time allocation</li>
                  <li>Compliance documentation</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};