import React, { useState } from 'react';
import { Calculator, Search, TrendingUp, AlertCircle, CheckCircle, DollarSign, Calendar, FileText, Users, Zap, Brain, Bell, Target, Award, Building, Globe, X } from 'lucide-react';
import { formatCurrency, formatDate } from '../utils/formatters';

interface TaxCredit {
  id: string;
  name: string;
  type: 'federal' | 'state';
  category: 'business' | 'individual' | 'energy' | 'research' | 'employment';
  maxCredit: number;
  expirationDate?: string;
  requirements: string[];
  description: string;
  estimatedSavings: number;
  confidence: number;
  status: 'available' | 'claimed' | 'expired' | 'under-review';
  lastUpdated: string;
}

interface IRSUpdate {
  id: string;
  title: string;
  type: 'rule-change' | 'guidance' | 'deadline' | 'opportunity' | 'risk';
  priority: 'low' | 'medium' | 'high' | 'urgent';
  description: string;
  effectiveDate: string;
  impactedCredits: string[];
  publishedDate: string;
  source: string;
}

interface ScenarioAnalysis {
  id: string;
  name: string;
  description: string;
  scenarios: {
    name: string;
    taxSavings: number;
    cashFlow: number;
    riskLevel: 'low' | 'medium' | 'high';
    timeline: string;
  }[];
  recommendation: string;
  createdAt: string;
}

interface TaxPlanningHubProps {
  clientId?: string;
}

export const TaxPlanningHub: React.FC<TaxPlanningHubProps> = ({ clientId }) => {
  const [activeTab, setActiveTab] = useState<'credits' | 'updates' | 'scenarios' | 'collaboration' | 'portal'>('credits');
  const [searchTerm, setSearchTerm] = useState('');
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [selectedCredit, setSelectedCredit] = useState<TaxCredit | null>(null);

  // Mock data - in real app this would come from APIs
  const mockCredits: TaxCredit[] = [
    {
      id: '1',
      name: 'Research & Development Tax Credit',
      type: 'federal',
      category: 'research',
      maxCredit: 250000,
      requirements: ['Qualified research activities', 'Systematic experimentation', 'Technical uncertainty'],
      description: 'Credit for qualified research expenses including wages, supplies, and contract research',
      estimatedSavings: 185000,
      confidence: 0.92,
      status: 'available',
      lastUpdated: '2024-12-18T10:00:00Z'
    },
    {
      id: '2',
      name: 'Work Opportunity Tax Credit',
      type: 'federal',
      category: 'employment',
      maxCredit: 9600,
      expirationDate: '2024-12-31',
      requirements: ['Hire from targeted groups', 'Minimum work hours', 'Certification required'],
      description: 'Credit for hiring individuals from certain targeted groups',
      estimatedSavings: 7200,
      confidence: 0.78,
      status: 'available',
      lastUpdated: '2024-12-15T14:30:00Z'
    },
    {
      id: '3',
      name: 'Energy Investment Tax Credit',
      type: 'federal',
      category: 'energy',
      maxCredit: 500000,
      requirements: ['Qualified energy property', 'Placed in service', 'Business use'],
      description: 'Credit for investment in renewable energy and energy efficiency improvements',
      estimatedSavings: 125000,
      confidence: 0.65,
      status: 'available',
      lastUpdated: '2024-12-10T09:15:00Z'
    }
  ];

  const mockIRSUpdates: IRSUpdate[] = [
    {
      id: '1',
      title: 'R&D Credit Safe Harbor Provisions Extended',
      type: 'opportunity',
      priority: 'high',
      description: 'IRS extends safe harbor provisions for R&D credit calculations through 2025, providing additional certainty for taxpayers',
      effectiveDate: '2025-01-01',
      impactedCredits: ['Research & Development Tax Credit'],
      publishedDate: '2024-12-18T08:00:00Z',
      source: 'IRS Notice 2024-XX'
    },
    {
      id: '2',
      title: 'New Documentation Requirements for Energy Credits',
      type: 'rule-change',
      priority: 'medium',
      description: 'Enhanced documentation requirements for energy investment tax credits effective for 2025 tax year',
      effectiveDate: '2025-01-01',
      impactedCredits: ['Energy Investment Tax Credit'],
      publishedDate: '2024-12-15T12:00:00Z',
      source: 'Treasury Regulation 1.48-XX'
    },
    {
      id: '3',
      title: 'WOTC Program Extension Announced',
      type: 'deadline',
      priority: 'urgent',
      description: 'Work Opportunity Tax Credit program extended through 2025 with enhanced benefits for certain target groups',
      effectiveDate: '2024-12-31',
      impactedCredits: ['Work Opportunity Tax Credit'],
      publishedDate: '2024-12-12T16:45:00Z',
      source: 'Congressional Act HR-XXXX'
    }
  ];

  const mockScenarios: ScenarioAnalysis[] = [
    {
      id: '1',
      name: 'Equipment Purchase Timing Analysis',
      description: 'Comparing tax benefits of purchasing equipment in 2024 vs 2025',
      scenarios: [
        {
          name: 'Purchase in 2024',
          taxSavings: 45000,
          cashFlow: -155000,
          riskLevel: 'low',
          timeline: 'Immediate'
        },
        {
          name: 'Purchase in Q1 2025',
          taxSavings: 38000,
          cashFlow: -162000,
          riskLevel: 'medium',
          timeline: '3 months'
        },
        {
          name: 'Lease Instead',
          taxSavings: 25000,
          cashFlow: -45000,
          riskLevel: 'low',
          timeline: 'Ongoing'
        }
      ],
      recommendation: 'Purchase in 2024 to maximize Section 179 deduction and bonus depreciation benefits',
      createdAt: '2024-12-18T10:00:00Z'
    }
  ];

  const filteredCredits = mockCredits.filter(credit => {
    const matchesSearch = credit.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         credit.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = filterCategory === 'all' || credit.category === filterCategory;
    return matchesSearch && matchesCategory;
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'available': return 'bg-green-100 text-green-800';
      case 'claimed': return 'bg-blue-100 text-blue-800';
      case 'expired': return 'bg-red-100 text-red-800';
      case 'under-review': return 'bg-yellow-100 text-yellow-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'urgent': return 'bg-red-100 text-red-800 border-red-200';
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low': return 'bg-blue-100 text-blue-800 border-blue-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'opportunity': return <TrendingUp className="h-4 w-4" />;
      case 'risk': return <AlertCircle className="h-4 w-4" />;
      case 'deadline': return <Calendar className="h-4 w-4" />;
      case 'rule-change': return <FileText className="h-4 w-4" />;
      case 'guidance': return <Brain className="h-4 w-4" />;
      default: return <Bell className="h-4 w-4" />;
    }
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.8) return 'text-green-600';
    if (confidence >= 0.6) return 'text-yellow-600';
    return 'text-red-600';
  };

  const totalPotentialSavings = mockCredits.reduce((sum, credit) => sum + credit.estimatedSavings, 0);
  const availableCredits = mockCredits.filter(c => c.status === 'available').length;
  const urgentUpdates = mockIRSUpdates.filter(u => u.priority === 'urgent').length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Tax Planning & Credits</h1>
          <p className="text-gray-600 mt-2">Proactive tax planning with AI-powered credit discovery and IRS monitoring</p>
        </div>
        <div className="flex items-center space-x-2">
          <Calculator className="h-5 w-5 text-blue-600" />
          <span className="text-sm text-gray-600">AI-powered tax optimization</span>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="bg-green-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-green-900 mb-2 flex items-center">
            <DollarSign className="h-4 w-4 mr-1" />
            Potential Savings
          </h4>
          <p className="text-2xl font-bold text-green-600">{formatCurrency(totalPotentialSavings)}</p>
        </div>
        <div className="bg-blue-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-blue-900 mb-2 flex items-center">
            <Award className="h-4 w-4 mr-1" />
            Available Credits
          </h4>
          <p className="text-2xl font-bold text-blue-600">{availableCredits}</p>
        </div>
        <div className="bg-orange-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-orange-900 mb-2 flex items-center">
            <Bell className="h-4 w-4 mr-1" />
            Urgent Updates
          </h4>
          <p className="text-2xl font-bold text-orange-600">{urgentUpdates}</p>
        </div>
        <div className="bg-purple-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-purple-900 mb-2 flex items-center">
            <Target className="h-4 w-4 mr-1" />
            Active Scenarios
          </h4>
          <p className="text-2xl font-bold text-purple-600">{mockScenarios.length}</p>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200">
        <div className="border-b border-gray-200">
          <nav className="flex space-x-8 px-6">
            <button
              onClick={() => setActiveTab('credits')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'credits'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              Credit Finder
            </button>
            <button
              onClick={() => setActiveTab('updates')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'updates'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              IRS Updates
            </button>
            <button
              onClick={() => setActiveTab('scenarios')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'scenarios'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              Scenario Planning
            </button>
            <button
              onClick={() => setActiveTab('collaboration')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'collaboration'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              CPA Collaboration
            </button>
            <button
              onClick={() => setActiveTab('portal')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'portal'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              Client Portal
            </button>
          </nav>
        </div>

        <div className="p-6">
          {activeTab === 'credits' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-gray-900">Credit & Deduction Finder</h3>
                <div className="flex space-x-3">
                  <div className="relative">
                    <Search className="h-4 w-4 absolute left-3 top-3 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search credits..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="pl-9 pr-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>
                  <select
                    value={filterCategory}
                    onChange={(e) => setFilterCategory(e.target.value)}
                    className="border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    <option value="all">All Categories</option>
                    <option value="business">Business</option>
                    <option value="individual">Individual</option>
                    <option value="energy">Energy</option>
                    <option value="research">Research</option>
                    <option value="employment">Employment</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {filteredCredits.map(credit => (
                  <div
                    key={credit.id}
                    onClick={() => setSelectedCredit(credit)}
                    className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-all duration-200 cursor-pointer"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex-1">
                        <h4 className="font-semibold text-gray-900 mb-1">{credit.name}</h4>
                        <div className="flex items-center space-x-2 mb-2">
                          <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                            credit.type === 'federal' ? 'bg-blue-100 text-blue-800' : 'bg-purple-100 text-purple-800'
                          }`}>
                            {credit.type}
                          </span>
                          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-600">
                            {credit.category}
                          </span>
                          <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(credit.status)}`}>
                            {credit.status}
                          </span>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-lg font-bold text-green-600">{formatCurrency(credit.estimatedSavings)}</p>
                        <p className={`text-sm font-medium ${getConfidenceColor(credit.confidence)}`}>
                          {Math.round(credit.confidence * 100)}% confidence
                        </p>
                      </div>
                    </div>
                    
                    <p className="text-sm text-gray-600 mb-3">{credit.description}</p>
                    
                    <div className="space-y-2">
                      <h5 className="text-xs font-medium text-gray-700">Key Requirements:</h5>
                      <ul className="text-xs text-gray-600 space-y-1">
                        {credit.requirements.slice(0, 3).map((req, index) => (
                          <li key={index} className="flex items-center">
                            <CheckCircle className="h-3 w-3 text-green-500 mr-1" />
                            {req}
                          </li>
                        ))}
                      </ul>
                    </div>

                    {credit.expirationDate && (
                      <div className="mt-3 p-2 bg-red-50 rounded border border-red-200">
                        <p className="text-xs text-red-800 font-medium">
                          Expires: {formatDate(credit.expirationDate)}
                        </p>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'updates' && (
            <div className="space-y-6">
              <h3 className="text-lg font-semibold text-gray-900">IRS Update Tracker</h3>
              
              <div className="space-y-4">
                {mockIRSUpdates.map(update => (
                  <div key={update.id} className={`border rounded-lg p-4 ${getPriorityColor(update.priority)}`}>
                    <div className="flex items-start space-x-3">
                      <div className="mt-1">
                        {getTypeIcon(update.type)}
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-semibold text-gray-900">{update.title}</h4>
                          <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getPriorityColor(update.priority)}`}>
                            {update.priority} priority
                          </span>
                        </div>
                        <p className="text-sm text-gray-700 mb-3">{update.description}</p>
                        <div className="flex items-center space-x-4 text-xs text-gray-500">
                          <span>Effective: {formatDate(update.effectiveDate)}</span>
                          <span>Published: {formatDate(update.publishedDate)}</span>
                          <span>Source: {update.source}</span>
                        </div>
                        {update.impactedCredits.length > 0 && (
                          <div className="mt-2">
                            <p className="text-xs text-gray-600 mb-1">Impacted Credits:</p>
                            <div className="flex flex-wrap gap-1">
                              {update.impactedCredits.map((creditName, index) => (
                                <span key={index} className="inline-flex items-center px-2 py-1 rounded text-xs bg-blue-100 text-blue-600">
                                  {creditName}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'scenarios' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-gray-900">Scenario Planning & Forecasting</h3>
                <button className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors">
                  Create New Scenario
                </button>
              </div>

              <div className="space-y-6">
                {mockScenarios.map(scenario => (
                  <div key={scenario.id} className="bg-white border border-gray-200 rounded-lg p-6">
                    <div className="flex items-center justify-between mb-4">
                      <div>
                        <h4 className="text-lg font-semibold text-gray-900">{scenario.name}</h4>
                        <p className="text-sm text-gray-600">{scenario.description}</p>
                      </div>
                      <span className="text-xs text-gray-500">{formatDate(scenario.createdAt)}</span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                      {scenario.scenarios.map((option, index) => (
                        <div key={index} className="border border-gray-200 rounded-lg p-4">
                          <h5 className="font-medium text-gray-900 mb-2">{option.name}</h5>
                          <div className="space-y-2 text-sm">
                            <div className="flex justify-between">
                              <span className="text-gray-600">Tax Savings:</span>
                              <span className="font-medium text-green-600">{formatCurrency(option.taxSavings)}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-600">Cash Flow:</span>
                              <span className={`font-medium ${option.cashFlow < 0 ? 'text-red-600' : 'text-green-600'}`}>
                                {formatCurrency(option.cashFlow)}
                              </span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-600">Risk Level:</span>
                              <span className={`font-medium ${
                                option.riskLevel === 'low' ? 'text-green-600' :
                                option.riskLevel === 'medium' ? 'text-yellow-600' : 'text-red-600'
                              }`}>
                                {option.riskLevel}
                              </span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-600">Timeline:</span>
                              <span className="font-medium text-gray-900">{option.timeline}</span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>

                    <div className="bg-blue-50 p-4 rounded-lg">
                      <h5 className="font-medium text-blue-900 mb-2">Recommendation</h5>
                      <p className="text-sm text-blue-800">{scenario.recommendation}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'collaboration' && (
            <div className="space-y-6">
              <h3 className="text-lg font-semibold text-gray-900">CPA Collaboration Tools</h3>
              
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-white border border-gray-200 rounded-lg p-6">
                  <h4 className="font-medium text-gray-900 mb-4 flex items-center">
                    <Users className="h-5 w-5 mr-2" />
                    Workspace
                  </h4>
                  <div className="space-y-3">
                    <div className="bg-gray-50 p-3 rounded-lg">
                      <p className="text-sm font-medium text-gray-900">CPA Notes</p>
                      <p className="text-xs text-gray-600 mt-1">Collaborative workspace for tax planning notes and strategies</p>
                    </div>
                    <div className="bg-gray-50 p-3 rounded-lg">
                      <p className="text-sm font-medium text-gray-900">Client Assumptions</p>
                      <p className="text-xs text-gray-600 mt-1">Adjust client-specific assumptions for accurate planning</p>
                    </div>
                    <div className="bg-gray-50 p-3 rounded-lg">
                      <p className="text-sm font-medium text-gray-900">Strategy Templates</p>
                      <p className="text-xs text-gray-600 mt-1">Pre-built templates for common tax planning scenarios</p>
                    </div>
                  </div>
                </div>

                <div className="bg-white border border-gray-200 rounded-lg p-6">
                  <h4 className="font-medium text-gray-900 mb-4 flex items-center">
                    <FileText className="h-5 w-5 mr-2" />
                    Reporting Templates
                  </h4>
                  <div className="space-y-3">
                    <button className="w-full text-left p-3 bg-blue-50 rounded-lg hover:bg-blue-100 transition-colors">
                      <p className="text-sm font-medium text-blue-900">Annual Tax Planning Report</p>
                      <p className="text-xs text-blue-700 mt-1">Comprehensive year-end planning document</p>
                    </button>
                    <button className="w-full text-left p-3 bg-green-50 rounded-lg hover:bg-green-100 transition-colors">
                      <p className="text-sm font-medium text-green-900">Quarterly Strategy Update</p>
                      <p className="text-xs text-green-700 mt-1">Mid-year adjustments and opportunities</p>
                    </button>
                    <button className="w-full text-left p-3 bg-purple-50 rounded-lg hover:bg-purple-100 transition-colors">
                      <p className="text-sm font-medium text-purple-900">Credit Opportunity Brief</p>
                      <p className="text-xs text-purple-700 mt-1">Focused analysis on specific tax credits</p>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'portal' && (
            <div className="space-y-6">
              <h3 className="text-lg font-semibold text-gray-900">Client Portal Dashboard</h3>
              
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2 space-y-4">
                  <div className="bg-gradient-to-r from-green-50 to-blue-50 border border-green-200 rounded-lg p-4">
                    <div className="flex items-center space-x-3 mb-3">
                      <TrendingUp className="h-6 w-6 text-green-600" />
                      <h4 className="font-semibold text-green-900">New Opportunity Alert</h4>
                    </div>
                    <p className="text-sm text-green-800 mb-2">
                      You may qualify for an additional <strong>{formatCurrency(45000)}</strong> in energy tax credits if you act before December 31st.
                    </p>
                    <button className="bg-green-600 text-white px-3 py-1 rounded text-sm hover:bg-green-700">
                      Learn More
                    </button>
                  </div>

                  <div className="bg-white border border-gray-200 rounded-lg p-4">
                    <h4 className="font-medium text-gray-900 mb-3">Your Tax Planning Roadmap</h4>
                    <div className="space-y-3">
                      <div className="flex items-center space-x-3 p-3 bg-blue-50 rounded-lg">
                        <CheckCircle className="h-5 w-5 text-blue-600" />
                        <div className="flex-1">
                          <p className="text-sm font-medium text-gray-900">Q4 R&D Documentation</p>
                          <p className="text-xs text-gray-600">Complete by Dec 31, 2024</p>
                        </div>
                        <span className="text-xs text-blue-600 font-medium">In Progress</span>
                      </div>
                      <div className="flex items-center space-x-3 p-3 bg-yellow-50 rounded-lg">
                        <Calendar className="h-5 w-5 text-yellow-600" />
                        <div className="flex-1">
                          <p className="text-sm font-medium text-gray-900">Equipment Purchase Decision</p>
                          <p className="text-xs text-gray-600">Review scenarios by Jan 15, 2025</p>
                        </div>
                        <span className="text-xs text-yellow-600 font-medium">Pending</span>
                      </div>
                      <div className="flex items-center space-x-3 p-3 bg-green-50 rounded-lg">
                        <Award className="h-5 w-5 text-green-600" />
                        <div className="flex-1">
                          <p className="text-sm font-medium text-gray-900">WOTC Application</p>
                          <p className="text-xs text-gray-600">Submitted Nov 15, 2024</p>
                        </div>
                        <span className="text-xs text-green-600 font-medium">Completed</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <div className="bg-white border border-gray-200 rounded-lg p-4">
                    <h4 className="font-medium text-gray-900 mb-3">2024 Tax Summary</h4>
                    <div className="space-y-3">
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-600">Estimated Credits:</span>
                        <span className="text-sm font-medium text-green-600">{formatCurrency(totalPotentialSavings)}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-600">Credits Claimed:</span>
                        <span className="text-sm font-medium text-blue-600">{formatCurrency(125000)}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-600">Remaining Opportunity:</span>
                        <span className="text-sm font-medium text-orange-600">{formatCurrency(totalPotentialSavings - 125000)}</span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-white border border-gray-200 rounded-lg p-4">
                    <h4 className="font-medium text-gray-900 mb-3">Quick Actions</h4>
                    <div className="space-y-2">
                      <button className="w-full text-left p-2 bg-blue-50 rounded hover:bg-blue-100 transition-colors">
                        <p className="text-sm font-medium text-blue-900">Schedule CPA Meeting</p>
                      </button>
                      <button className="w-full text-left p-2 bg-green-50 rounded hover:bg-green-100 transition-colors">
                        <p className="text-sm font-medium text-green-900">Download Tax Plan</p>
                      </button>
                      <button className="w-full text-left p-2 bg-purple-50 rounded hover:bg-purple-100 transition-colors">
                        <p className="text-sm font-medium text-purple-900">Update Financial Info</p>
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Credit Details Modal */}
      {selectedCredit && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-xl max-w-2xl w-full max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between p-6 border-b border-gray-200">
              <h2 className="text-xl font-semibold text-gray-900">{selectedCredit.name}</h2>
              <button
                onClick={() => setSelectedCredit(null)}
                className="text-gray-400 hover:text-gray-600"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="p-6">
              <div className="grid grid-cols-2 gap-4 mb-6">
                <div className="bg-green-50 p-4 rounded-lg">
                  <p className="text-sm text-green-900 mb-1">Estimated Savings</p>
                  <p className="text-2xl font-bold text-green-600">{formatCurrency(selectedCredit.estimatedSavings)}</p>
                </div>
                <div className="bg-blue-50 p-4 rounded-lg">
                  <p className="text-sm text-blue-900 mb-1">Confidence Level</p>
                  <p className={`text-2xl font-bold ${getConfidenceColor(selectedCredit.confidence)}`}>
                    {Math.round(selectedCredit.confidence * 100)}%
                  </p>
                </div>
              </div>

              <div className="space-y-4">
                <div>
                  <h4 className="font-medium text-gray-900 mb-2">Description</h4>
                  <p className="text-gray-700">{selectedCredit.description}</p>
                </div>

                <div>
                  <h4 className="font-medium text-gray-900 mb-2">Requirements</h4>
                  <ul className="space-y-2">
                    {selectedCredit.requirements.map((req, index) => (
                      <li key={index} className="flex items-center text-sm text-gray-700">
                        <CheckCircle className="h-4 w-4 text-green-500 mr-2" />
                        {req}
                      </li>
                    ))}
                  </ul>
                </div>

                {selectedCredit.expirationDate && (
                  <div className="bg-red-50 p-4 rounded-lg border border-red-200">
                    <h4 className="font-medium text-red-900 mb-1">Important Deadline</h4>
                    <p className="text-sm text-red-800">
                      This credit expires on {formatDate(selectedCredit.expirationDate)}. Act soon to secure these benefits.
                    </p>
                  </div>
                )}
              </div>

              <div className="flex justify-end space-x-3 mt-6">
                <button
                  onClick={() => setSelectedCredit(null)}
                  className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
                >
                  Close
                </button>
                <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
                  Start Application Process
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};