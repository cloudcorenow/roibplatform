import React, { useState } from 'react';
import { Settings, X, Save, Shield, Key, Globe, Database, Trash2, Download, Upload, RefreshCw, AlertTriangle, CheckCircle } from 'lucide-react';
import { User } from '../types/users';
import { formatDateTime } from '../utils/formatters';

interface AccountSettingsProps {
  user: User;
  onClose: () => void;
  onUpdateSettings: (settings: any) => void;
}

export const AccountSettings: React.FC<AccountSettingsProps> = ({
  user,
  onClose,
  onUpdateSettings
}) => {
  const [activeTab, setActiveTab] = useState<'general' | 'security' | 'data' | 'integrations'>('general');
  const [settings, setSettings] = useState({
    // General Settings
    language: 'en',
    theme: 'light',
    autoSave: true,
    sessionTimeout: 60, // minutes
    
    // Security Settings
    twoFactorEnabled: false,
    loginNotifications: true,
    sessionManagement: true,
    
    // Data Settings
    dataRetention: 365, // days
    autoBackup: true,
    exportFormat: 'json',
    
    // Integration Settings
    apiAccess: false,
    webhookUrl: '',
    rateLimitPerHour: 1000
  });

  const [apiKeys, setApiKeys] = useState([
    {
      id: '1',
      name: 'Production API Key',
      key: 'ff_prod_****************************',
      created: '2024-01-15T10:00:00Z',
      lastUsed: '2024-12-18T14:30:00Z',
      permissions: ['read', 'write']
    }
  ]);

  const [sessions, setSessions] = useState([
    {
      id: '1',
      device: 'Chrome on Windows',
      location: 'San Francisco, CA',
      ipAddress: '192.168.1.100',
      lastActive: '2024-12-18T15:30:00Z',
      isCurrent: true
    },
    {
      id: '2',
      device: 'Safari on iPhone',
      location: 'San Francisco, CA',
      ipAddress: '192.168.1.101',
      lastActive: '2024-12-17T09:15:00Z',
      isCurrent: false
    }
  ]);

  const handleSaveSettings = () => {
    onUpdateSettings(settings);
    alert('Settings saved successfully');
  };

  const handleGenerateApiKey = () => {
    const newKey = {
      id: Date.now().toString(),
      name: 'New API Key',
      key: `ff_${Math.random().toString(36).substring(2, 15)}****************************`,
      created: new Date().toISOString(),
      lastUsed: null,
      permissions: ['read']
    };
    setApiKeys(prev => [...prev, newKey]);
  };

  const handleRevokeApiKey = (keyId: string) => {
    setApiKeys(prev => prev.filter(key => key.id !== keyId));
  };

  const handleRevokeSession = (sessionId: string) => {
    setSessions(prev => prev.filter(session => session.id !== sessionId));
  };

  const handleExportData = () => {
    // In a real app, this would trigger a data export
    alert('Data export initiated. You will receive an email when ready.');
  };

  const handleDeleteAccount = () => {
    const confirmation = prompt('Type "DELETE" to confirm account deletion:');
    if (confirmation === 'DELETE') {
      alert('Account deletion request submitted. This action cannot be undone.');
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-xl max-w-5xl w-full max-h-[90vh] overflow-hidden">
        <div className="flex items-center justify-between p-6 border-b border-gray-200">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
              <Settings className="h-5 w-5 text-white" />
            </div>
            <h2 className="text-xl font-semibold text-gray-900">Account Settings</h2>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 p-2 rounded-lg hover:bg-gray-100"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="flex h-[calc(90vh-80px)]">
          {/* Sidebar */}
          <div className="w-64 bg-gray-50 p-4 border-r border-gray-200">
            <nav className="space-y-2">
              <button
                onClick={() => setActiveTab('general')}
                className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg text-left transition-colors ${
                  activeTab === 'general'
                    ? 'bg-blue-100 text-blue-700'
                    : 'text-gray-700 hover:bg-gray-100'
                }`}
              >
                <Settings className="h-4 w-4" />
                <span>General</span>
              </button>
              <button
                onClick={() => setActiveTab('security')}
                className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg text-left transition-colors ${
                  activeTab === 'security'
                    ? 'bg-blue-100 text-blue-700'
                    : 'text-gray-700 hover:bg-gray-100'
                }`}
              >
                <Shield className="h-4 w-4" />
                <span>Security & Privacy</span>
              </button>
              <button
                onClick={() => setActiveTab('data')}
                className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg text-left transition-colors ${
                  activeTab === 'data'
                    ? 'bg-blue-100 text-blue-700'
                    : 'text-gray-700 hover:bg-gray-100'
                }`}
              >
                <Database className="h-4 w-4" />
                <span>Data & Privacy</span>
              </button>
              <button
                onClick={() => setActiveTab('integrations')}
                className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg text-left transition-colors ${
                  activeTab === 'integrations'
                    ? 'bg-blue-100 text-blue-700'
                    : 'text-gray-700 hover:bg-gray-100'
                }`}
              >
                <Globe className="h-4 w-4" />
                <span>API & Integrations</span>
              </button>
            </nav>
          </div>

          {/* Main Content */}
          <div className="flex-1 p-6 overflow-y-auto">
            {activeTab === 'general' && (
              <div className="space-y-6">
                <h3 className="text-lg font-semibold text-gray-900">General Settings</h3>

                <div className="bg-white border border-gray-200 rounded-lg p-6">
                  <h4 className="text-md font-semibold text-gray-900 mb-4">Application Preferences</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">Language</label>
                      <select
                        value={settings.language}
                        onChange={(e) => setSettings({ ...settings, language: e.target.value })}
                        className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      >
                        <option value="en">English</option>
                        <option value="es">Spanish</option>
                        <option value="fr">French</option>
                        <option value="de">German</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">Theme</label>
                      <select
                        value={settings.theme}
                        onChange={(e) => setSettings({ ...settings, theme: e.target.value })}
                        className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      >
                        <option value="light">Light</option>
                        <option value="dark">Dark</option>
                        <option value="auto">Auto (System)</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">Session Timeout (minutes)</label>
                      <input
                        type="number"
                        value={settings.sessionTimeout}
                        onChange={(e) => setSettings({ ...settings, sessionTimeout: parseInt(e.target.value) || 60 })}
                        className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        min="15"
                        max="480"
                      />
                    </div>
                    <div className="flex items-center">
                      <label className="flex items-center">
                        <input
                          type="checkbox"
                          checked={settings.autoSave}
                          onChange={(e) => setSettings({ ...settings, autoSave: e.target.checked })}
                          className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                        />
                        <span className="ml-2 text-sm text-gray-700">Auto-save changes</span>
                      </label>
                    </div>
                  </div>
                </div>

                <div className="flex justify-end">
                  <button
                    onClick={handleSaveSettings}
                    className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center space-x-2"
                  >
                    <Save className="h-4 w-4" />
                    <span>Save Settings</span>
                  </button>
                </div>
              </div>
            )}

            {activeTab === 'security' && (
              <div className="space-y-6">
                <h3 className="text-lg font-semibold text-gray-900">Security & Privacy</h3>

                {/* Two-Factor Authentication */}
                <div className="bg-white border border-gray-200 rounded-lg p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <h4 className="text-md font-semibold text-gray-900">Two-Factor Authentication</h4>
                      <p className="text-sm text-gray-600">Add an extra layer of security to your account</p>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className={`text-sm font-medium ${
                        settings.twoFactorEnabled ? 'text-green-600' : 'text-red-600'
                      }`}>
                        {settings.twoFactorEnabled ? 'Enabled' : 'Disabled'}
                      </span>
                      <button
                        onClick={() => setSettings({ ...settings, twoFactorEnabled: !settings.twoFactorEnabled })}
                        className={`px-3 py-1 rounded text-sm font-medium ${
                          settings.twoFactorEnabled 
                            ? 'bg-red-100 text-red-700 hover:bg-red-200' 
                            : 'bg-green-100 text-green-700 hover:bg-green-200'
                        }`}
                      >
                        {settings.twoFactorEnabled ? 'Disable' : 'Enable'}
                      </button>
                    </div>
                  </div>
                  {!settings.twoFactorEnabled && (
                    <div className="bg-yellow-50 p-3 rounded-lg">
                      <p className="text-sm text-yellow-800">
                        We recommend enabling two-factor authentication to secure your account.
                      </p>
                    </div>
                  )}
                </div>

                {/* Active Sessions */}
                <div className="bg-white border border-gray-200 rounded-lg p-6">
                  <h4 className="text-md font-semibold text-gray-900 mb-4">Active Sessions</h4>
                  <div className="space-y-3">
                    {sessions.map(session => (
                      <div key={session.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                        <div>
                          <p className="text-sm font-medium text-gray-900">{session.device}</p>
                          <p className="text-xs text-gray-600">{session.location} • {session.ipAddress}</p>
                          <p className="text-xs text-gray-500">Last active: {formatDateTime(session.lastActive)}</p>
                        </div>
                        <div className="flex items-center space-x-2">
                          {session.isCurrent && (
                            <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                              Current
                            </span>
                          )}
                          {!session.isCurrent && (
                            <button
                              onClick={() => handleRevokeSession(session.id)}
                              className="text-red-600 hover:text-red-700 text-sm font-medium px-2 py-1 rounded hover:bg-red-50"
                            >
                              Revoke
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Security Preferences */}
                <div className="bg-white border border-gray-200 rounded-lg p-6">
                  <h4 className="text-md font-semibold text-gray-900 mb-4">Security Preferences</h4>
                  <div className="space-y-4">
                    <label className="flex items-center justify-between">
                      <div>
                        <span className="text-sm font-medium text-gray-900">Login Notifications</span>
                        <p className="text-xs text-gray-600">Get notified when someone logs into your account</p>
                      </div>
                      <input
                        type="checkbox"
                        checked={settings.loginNotifications}
                        onChange={(e) => setSettings({ ...settings, loginNotifications: e.target.checked })}
                        className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                      />
                    </label>
                    <label className="flex items-center justify-between">
                      <div>
                        <span className="text-sm font-medium text-gray-900">Session Management</span>
                        <p className="text-xs text-gray-600">Allow multiple concurrent sessions</p>
                      </div>
                      <input
                        type="checkbox"
                        checked={settings.sessionManagement}
                        onChange={(e) => setSettings({ ...settings, sessionManagement: e.target.checked })}
                        className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                      />
                    </label>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'data' && (
              <div className="space-y-6">
                <h3 className="text-lg font-semibold text-gray-900">Data & Privacy</h3>

                {/* Data Export */}
                <div className="bg-white border border-gray-200 rounded-lg p-6">
                  <h4 className="text-md font-semibold text-gray-900 mb-4">Data Export</h4>
                  <p className="text-sm text-gray-600 mb-4">
                    Export all your data including time entries, projects, and documentation.
                  </p>
                  <div className="flex items-center space-x-3">
                    <select
                      value={settings.exportFormat}
                      onChange={(e) => setSettings({ ...settings, exportFormat: e.target.value })}
                      className="border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    >
                      <option value="json">JSON Format</option>
                      <option value="csv">CSV Format</option>
                      <option value="pdf">PDF Report</option>
                    </select>
                    <button
                      onClick={handleExportData}
                      className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center space-x-2"
                    >
                      <Download className="h-4 w-4" />
                      <span>Export Data</span>
                    </button>
                  </div>
                </div>

                {/* Data Retention */}
                <div className="bg-white border border-gray-200 rounded-lg p-6">
                  <h4 className="text-md font-semibold text-gray-900 mb-4">Data Retention</h4>
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        Retention Period (days)
                      </label>
                      <input
                        type="number"
                        value={settings.dataRetention}
                        onChange={(e) => setSettings({ ...settings, dataRetention: parseInt(e.target.value) || 365 })}
                        className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        min="30"
                        max="2555" // 7 years
                      />
                      <p className="text-xs text-gray-600 mt-1">
                        How long to keep your data before automatic deletion
                      </p>
                    </div>
                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        checked={settings.autoBackup}
                        onChange={(e) => setSettings({ ...settings, autoBackup: e.target.checked })}
                        className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                      />
                      <span className="ml-2 text-sm text-gray-700">Enable automatic backups</span>
                    </label>
                  </div>
                </div>

                {/* Danger Zone */}
                <div className="bg-red-50 border border-red-200 rounded-lg p-6">
                  <h4 className="text-md font-semibold text-red-900 mb-4 flex items-center">
                    <AlertTriangle className="h-4 w-4 mr-2" />
                    Danger Zone
                  </h4>
                  <p className="text-sm text-red-700 mb-4">
                    These actions are permanent and cannot be undone.
                  </p>
                  <button
                    onClick={handleDeleteAccount}
                    className="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 flex items-center space-x-2"
                  >
                    <Trash2 className="h-4 w-4" />
                    <span>Delete Account</span>
                  </button>
                </div>
              </div>
            )}

            {activeTab === 'integrations' && (
              <div className="space-y-6">
                <h3 className="text-lg font-semibold text-gray-900">API & Integrations</h3>

                {/* API Keys */}
                <div className="bg-white border border-gray-200 rounded-lg p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h4 className="text-md font-semibold text-gray-900">API Keys</h4>
                    <button
                      onClick={handleGenerateApiKey}
                      className="bg-blue-600 text-white px-3 py-1 rounded text-sm hover:bg-blue-700 flex items-center space-x-1"
                    >
                      <Key className="h-3 w-3" />
                      <span>Generate Key</span>
                    </button>
                  </div>
                  <div className="space-y-3">
                    {apiKeys.map(apiKey => (
                      <div key={apiKey.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                        <div>
                          <p className="text-sm font-medium text-gray-900">{apiKey.name}</p>
                          <p className="text-xs text-gray-600 font-mono">{apiKey.key}</p>
                          <p className="text-xs text-gray-500">
                            Created: {formatDateTime(apiKey.created)}
                            {apiKey.lastUsed && ` • Last used: ${formatDateTime(apiKey.lastUsed)}`}
                          </p>
                        </div>
                        <button
                          onClick={() => handleRevokeApiKey(apiKey.id)}
                          className="text-red-600 hover:text-red-700 text-sm font-medium px-2 py-1 rounded hover:bg-red-50"
                        >
                          Revoke
                        </button>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Webhook Settings */}
                <div className="bg-white border border-gray-200 rounded-lg p-6">
                  <h4 className="text-md font-semibold text-gray-900 mb-4">Webhook Configuration</h4>
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">Webhook URL</label>
                      <input
                        type="url"
                        value={settings.webhookUrl}
                        onChange={(e) => setSettings({ ...settings, webhookUrl: e.target.value })}
                        className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        placeholder="https://your-app.com/webhook"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">Rate Limit (requests/hour)</label>
                      <input
                        type="number"
                        value={settings.rateLimitPerHour}
                        onChange={(e) => setSettings({ ...settings, rateLimitPerHour: parseInt(e.target.value) || 1000 })}
                        className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        min="100"
                        max="10000"
                      />
                    </div>
                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        checked={settings.apiAccess}
                        onChange={(e) => setSettings({ ...settings, apiAccess: e.target.checked })}
                        className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                      />
                      <span className="ml-2 text-sm text-gray-700">Enable API access</span>
                    </label>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};