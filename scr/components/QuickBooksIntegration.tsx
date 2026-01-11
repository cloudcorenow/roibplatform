import React, { useState, useEffect } from 'react';
import { Settings, FolderSync as Sync, Users, Clock, CheckCircle, AlertCircle, RefreshCw, Database, Key, Globe, DollarSign, Building, CreditCard } from 'lucide-react';
import QuickBooksAPI from '../services/quickbooksApi';
import { QuickBooksConfig, QuickBooksSyncResult } from '../types/quickbooks';
import { LoadingSpinner } from './LoadingSpinner';

interface QuickBooksIntegrationProps {
  onSyncComplete?: (result: QuickBooksSyncResult) => void;
}

export const QuickBooksIntegration: React.FC<QuickBooksIntegrationProps> = ({
  onSyncComplete
}) => {
  const [config, setConfig] = useState<QuickBooksConfig>({
    clientId: '',
    clientSecret: '',
    redirectUri: `${window.location.origin}/quickbooks/callback`,
    sandbox: true,
    companyId: '',
    accessToken: '',
    refreshToken: ''
  });
  const [isConfigured, setIsConfigured] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [isSyncing, setIsSyncing] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'disconnected' | 'connected' | 'error'>('disconnected');
  const [lastSync, setLastSync] = useState<string | null>(null);
  const [syncResults, setSyncResults] = useState<QuickBooksSyncResult[]>([]);
  const [api, setApi] = useState<QuickBooksAPI | null>(null);
  const [authUrl, setAuthUrl] = useState<string>('');

  useEffect(() => {
    // Load saved configuration from localStorage
    const savedConfig = localStorage.getItem('quickbooks-config');
    if (savedConfig) {
      const parsedConfig = JSON.parse(savedConfig);
      setConfig(parsedConfig);
      if (parsedConfig.accessToken && parsedConfig.companyId) {
        setIsConfigured(true);
        setApi(new QuickBooksAPI(parsedConfig));
        setConnectionStatus('connected');
      }
    }

    // Handle OAuth callback
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const realmId = urlParams.get('realmId');
    
    if (code && realmId && !isConfigured) {
      handleOAuthCallback(code, realmId);
    }
  }, []);

  const handleSaveConfig = () => {
    if (!config.clientId || !config.clientSecret) {
      alert('Please fill in Client ID and Client Secret');
      return;
    }

    const newApi = new QuickBooksAPI(config);
    setApi(newApi);
    
    // Generate auth URL
    const url = newApi.getAuthUrl();
    setAuthUrl(url);
    
    localStorage.setItem('quickbooks-config', JSON.stringify(config));
  };

  const handleOAuthCallback = async (code: string, realmId: string) => {
    if (!api) return;

    setIsConnecting(true);
    try {
      const tokens = await api.exchangeCodeForTokens(code);
      
      const updatedConfig = {
        ...config,
        companyId: realmId,
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token
      };
      
      setConfig(updatedConfig);
      localStorage.setItem('quickbooks-config', JSON.stringify(updatedConfig));
      
      const newApi = new QuickBooksAPI(updatedConfig);
      setApi(newApi);
      setIsConfigured(true);
      setConnectionStatus('connected');
      
      // Clear URL parameters
      window.history.replaceState({}, document.title, window.location.pathname);
    } catch (error) {
      setConnectionStatus('error');
      console.error('OAuth callback failed:', error);
    } finally {
      setIsConnecting(false);
    }
  };

  const testConnection = async () => {
    if (!api) return;

    setIsConnecting(true);
    try {
      await api.getCompanyInfo();
      setConnectionStatus('connected');
    } catch (error) {
      setConnectionStatus('error');
      console.error('Connection test failed:', error);
    } finally {
      setIsConnecting(false);
    }
  };

  const handleSync = async (syncType: 'customers' | 'employees' | 'timeactivities' | 'expenses' | 'all') => {
    if (!api) return;

    setIsSyncing(true);
    const results: QuickBooksSyncResult[] = [];

    try {
      if (syncType === 'customers' || syncType === 'all') {
        const customerResult = await api.syncCustomers();
        results.push({ ...customerResult, message: `Customers: ${customerResult.message}` });
      }

      if (syncType === 'employees' || syncType === 'all') {
        const employeeResult = await api.syncEmployees();
        results.push({ ...employeeResult, message: `Employees: ${employeeResult.message}` });
      }

      if (syncType === 'timeactivities' || syncType === 'all') {
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - 30); // Last 30 days
        const endDate = new Date();
        
        const timeResult = await api.syncTimeActivities(
          startDate.toISOString().split('T')[0],
          endDate.toISOString().split('T')[0]
        );
        results.push({ ...timeResult, message: `Time Activities: ${timeResult.message}` });
      }

      if (syncType === 'expenses' || syncType === 'all') {
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - 30); // Last 30 days
        const endDate = new Date();
        
        const expenseResult = await api.syncExpenses(
          startDate.toISOString().split('T')[0],
          endDate.toISOString().split('T')[0]
        );
        results.push({ ...expenseResult, message: `Expenses: ${expenseResult.message}` });
      }

      setSyncResults(results);
      setLastSync(new Date().toISOString());
      
      if (onSyncComplete) {
        const overallResult: QuickBooksSyncResult = {
          success: results.every(r => r.success),
          message: results.map(r => r.message).join(', '),
          syncedRecords: results.reduce((sum, r) => sum + r.syncedRecords, 0),
          errors: results.flatMap(r => r.errors),
          lastSyncTime: new Date().toISOString()
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
    localStorage.removeItem('quickbooks-config');
    setConfig({
      clientId: '',
      clientSecret: '',
      redirectUri: `${window.location.origin}/quickbooks/callback`,
      sandbox: true,
      companyId: '',
      accessToken: '',
      refreshToken: ''
    });
    setIsConfigured(false);
    setApi(null);
    setConnectionStatus('disconnected');
    setSyncResults([]);
    setLastSync(null);
    setAuthUrl('');
  };

  const handleConnect = () => {
    if (authUrl) {
      window.location.href = authUrl;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">QuickBooks Online Integration</h2>
          <p className="text-gray-600 mt-1">Connect and sync financial data from QuickBooks Online</p>
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
            <h3 className="text-xl font-semibold text-gray-900">Configure QuickBooks Connection</h3>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                <Key className="h-4 w-4 inline mr-1" />
                Client ID *
              </label>
              <input
                type="text"
                value={config.clientId}
                onChange={(e) => setConfig({ ...config, clientId: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Enter your QuickBooks app Client ID"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                <Key className="h-4 w-4 inline mr-1" />
                Client Secret *
              </label>
              <input
                type="password"
                value={config.clientSecret}
                onChange={(e) => setConfig({ ...config, clientSecret: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Enter your QuickBooks app Client Secret"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                <Globe className="h-4 w-4 inline mr-1" />
                Redirect URI
              </label>
              <input
                type="url"
                value={config.redirectUri}
                onChange={(e) => setConfig({ ...config, redirectUri: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="https://yourapp.com/quickbooks/callback"
              />
            </div>

            <div className="flex items-center">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={config.sandbox}
                  onChange={(e) => setConfig({ ...config, sandbox: e.target.checked })}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700">Use Sandbox Environment</span>
              </label>
            </div>
          </div>

          <div className="mt-6 p-4 bg-blue-50 rounded-lg">
            <h4 className="font-medium text-blue-900 mb-2">Setup Instructions</h4>
            <ol className="text-sm text-blue-800 space-y-1 list-decimal list-inside">
              <li>Create a QuickBooks app at <a href="https://developer.intuit.com" target="_blank" className="underline">developer.intuit.com</a></li>
              <li>Copy your app's Client ID and Client Secret</li>
              <li>Add your redirect URI to the app settings</li>
              <li>Configure the credentials above</li>
              <li>Click "Setup OAuth" to begin authentication</li>
            </ol>
          </div>

          <div className="flex justify-end space-x-3 mt-6">
            <button
              onClick={handleSaveConfig}
              disabled={!config.clientId || !config.clientSecret}
              className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2 disabled:opacity-50"
            >
              <Settings className="h-4 w-4" />
              <span>Setup OAuth</span>
            </button>
          </div>

          {authUrl && (
            <div className="mt-4 p-4 bg-green-50 rounded-lg">
              <h4 className="font-medium text-green-900 mb-2">Ready to Connect</h4>
              <p className="text-sm text-green-800 mb-3">
                Click the button below to authenticate with QuickBooks Online.
              </p>
              <button
                onClick={handleConnect}
                className="bg-green-600 text-white px-6 py-2 rounded-lg hover:bg-green-700 transition-colors flex items-center space-x-2"
              >
                <Globe className="h-4 w-4" />
                <span>Connect to QuickBooks</span>
              </button>
            </div>
          )}
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
                    {connectionStatus === 'connected' ? 'Connected to QuickBooks Online' : 'Connection Error'}
                  </h3>
                  <p className="text-sm text-gray-600">
                    Company ID: {config.companyId}
                  </p>
                  <p className="text-xs text-gray-500">
                    Environment: {config.sandbox ? 'Sandbox' : 'Production'}
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
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
              <button
                onClick={() => handleSync('customers')}
                disabled={isSyncing || connectionStatus !== 'connected'}
                className="flex flex-col items-center p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-50"
              >
                <Building className="h-8 w-8 text-blue-600 mb-2" />
                <span className="text-sm font-medium">Sync Customers</span>
              </button>

              <button
                onClick={() => handleSync('employees')}
                disabled={isSyncing || connectionStatus !== 'connected'}
                className="flex flex-col items-center p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-50"
              >
                <Users className="h-8 w-8 text-green-600 mb-2" />
                <span className="text-sm font-medium">Sync Employees</span>
              </button>

              <button
                onClick={() => handleSync('timeactivities')}
                disabled={isSyncing || connectionStatus !== 'connected'}
                className="flex flex-col items-center p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-50"
              >
                <Clock className="h-8 w-8 text-purple-600 mb-2" />
                <span className="text-sm font-medium">Sync Time</span>
              </button>

              <button
                onClick={() => handleSync('expenses')}
                disabled={isSyncing || connectionStatus !== 'connected'}
                className="flex flex-col items-center p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-50"
              >
                <CreditCard className="h-8 w-8 text-orange-600 mb-2" />
                <span className="text-sm font-medium">Sync Expenses</span>
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
                <h4 className="font-medium mb-2">Financial Data Sync</h4>
                <ul className="space-y-1 list-disc list-inside">
                  <li>Customer and vendor information</li>
                  <li>Employee records and payroll data</li>
                  <li>Time tracking and billing records</li>
                  <li>Expense transactions and receipts</li>
                </ul>
              </div>
              <div>
                <h4 className="font-medium mb-2">R&D Integration</h4>
                <ul className="space-y-1 list-disc list-inside">
                  <li>Automatic R&D expense categorization</li>
                  <li>Employee cost allocation for R&D</li>
                  <li>Time-based R&D cost calculations</li>
                  <li>Audit-ready financial documentation</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};