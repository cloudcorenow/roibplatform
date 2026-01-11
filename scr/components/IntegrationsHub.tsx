import React, { useState } from 'react';
import { Plug, Workflow, Building, CreditCard, CheckCircle, AlertCircle, Settings } from 'lucide-react';
import { QuickBooksIntegration } from './QuickBooksIntegration';
import { CentralReachIntegration } from './CentralReachIntegration';

interface IntegrationsHubProps {
  onSyncComplete?: (result: any) => void;
}

export const IntegrationsHub: React.FC<IntegrationsHubProps> = ({
  onSyncComplete
}) => {
  const [activeIntegration, setActiveIntegration] = useState<'overview' | 'quickbooks' | 'centralreach'>('overview');

  const integrations = [
    {
      id: 'quickbooks',
      name: 'QuickBooks Online',
      description: 'Sync financial data, employees, and expenses',
      icon: CreditCard,
      color: 'bg-green-100 text-green-600',
      status: 'available',
      features: ['Customer Management', 'Employee Records', 'Time Tracking', 'Expense Sync', 'Financial Reports']
    },
    {
      id: 'centralreach',
      name: 'CentralReach',
      description: 'Healthcare practice management integration',
      icon: Building,
      color: 'bg-blue-100 text-blue-600',
      status: 'available',
      features: ['Client Management', 'Staff Records', 'Time Tracking', 'Service Billing', 'Compliance Reports']
    }
  ];

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'connected': return <CheckCircle className="h-4 w-4 text-green-600" />;
      case 'error': return <AlertCircle className="h-4 w-4 text-red-600" />;
      case 'available': return <Settings className="h-4 w-4 text-gray-400" />;
      default: return <Settings className="h-4 w-4 text-gray-400" />;
    }
  };

  if (activeIntegration === 'quickbooks') {
    return (
      <div className="space-y-6">
        <div className="flex items-center space-x-3">
          <button
            onClick={() => setActiveIntegration('overview')}
            className="text-blue-600 hover:text-blue-700 text-sm font-medium"
          >
            ← Back to Integrations
          </button>
        </div>
        <QuickBooksIntegration onSyncComplete={onSyncComplete} />
      </div>
    );
  }

  if (activeIntegration === 'centralreach') {
    return (
      <div className="space-y-6">
        <div className="flex items-center space-x-3">
          <button
            onClick={() => setActiveIntegration('overview')}
            className="text-blue-600 hover:text-blue-700 text-sm font-medium"
          >
            ← Back to Integrations
          </button>
        </div>
        <CentralReachIntegration onSyncComplete={onSyncComplete} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Integrations Hub</h1>
          <p className="text-gray-600 mt-2">Connect your favorite tools and platforms to streamline R&D data management</p>
        </div>
        <div className="flex items-center space-x-2">
          <Plug className="h-5 w-5 text-blue-600" />
          <span className="text-sm text-gray-600">{integrations.length} integrations available</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {integrations.map((integration) => (
          <div key={integration.id} className="bg-white p-6 rounded-xl shadow-sm border border-gray-200 hover:shadow-md transition-all duration-200">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center space-x-3">
                <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${integration.color}`}>
                  <integration.icon className="h-6 w-6" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-gray-900">{integration.name}</h3>
                  <p className="text-sm text-gray-600">{integration.description}</p>
                </div>
              </div>
              {getStatusIcon(integration.status)}
            </div>

            <div className="mb-4">
              <h4 className="text-sm font-medium text-gray-900 mb-2">Features</h4>
              <div className="flex flex-wrap gap-1">
                {integration.features.map((feature, index) => (
                  <span key={index} className="inline-flex items-center px-2 py-1 rounded text-xs bg-gray-100 text-gray-600">
                    {feature}
                  </span>
                ))}
              </div>
            </div>

            <button
              onClick={() => setActiveIntegration(integration.id as any)}
              className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center space-x-2"
            >
              <Settings className="h-4 w-4" />
              <span>Configure Integration</span>
            </button>
          </div>
        ))}
      </div>

      <div className="bg-gradient-to-r from-blue-50 to-purple-50 p-6 rounded-xl border border-blue-200">
        <div className="flex items-center space-x-3 mb-4">
          <div className="w-10 h-10 bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg flex items-center justify-center">
            <Workflow className="h-5 w-5 text-white" />
          </div>
          <h3 className="text-lg font-semibold text-gray-900">Integration Benefits</h3>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
          <div>
            <h4 className="font-medium text-gray-900 mb-2">Automated Data Flow</h4>
            <p className="text-gray-600">
              Eliminate manual data entry by automatically syncing time, expenses, and employee data from your existing systems.
            </p>
          </div>
          <div>
            <h4 className="font-medium text-gray-900 mb-2">R&D Classification</h4>
            <p className="text-gray-600">
              Intelligent categorization of activities and expenses to identify R&D-qualified items for tax credit optimization.
            </p>
          </div>
          <div>
            <h4 className="font-medium text-gray-900 mb-2">Audit Readiness</h4>
            <p className="text-gray-600">
              Maintain comprehensive audit trails with source system references and automated compliance documentation.
            </p>
          </div>
        </div>
      </div>

      <div className="bg-yellow-50 p-4 rounded-lg border border-yellow-200">
        <h4 className="font-medium text-yellow-900 mb-2">Coming Soon</h4>
        <p className="text-sm text-yellow-800">
          Additional integrations for Salesforce, Azure DevOps, GitHub, Slack, and more are in development. 
          Contact us if you need a specific integration for your R&D workflow.
        </p>
      </div>
    </div>
  );
};