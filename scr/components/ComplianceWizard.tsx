import React, { useState } from 'react';
import { CheckCircle, Circle, AlertTriangle, BookOpen, FileText, Users, DollarSign, Clock, Award } from 'lucide-react';
import { ComplianceItem, ClientCompliance } from '../types';

interface ComplianceWizardProps {
  clientCompliance: ClientCompliance;
  onUpdateCompliance: (clientId: string, completedItems: string[]) => void;
}

const complianceItems: ComplianceItem[] = [
  {
    id: 'project-qualification',
    title: 'Project R&D Qualification',
    description: 'Ensure your project meets the four-part test for R&D activities',
    category: 'qualification',
    isRequired: true,
    helpText: 'Your project must involve technological uncertainty, systematic experimentation, qualified research, and be conducted in the United States.',
    relatedDocs: ['Technical documentation', 'Project objectives', 'Uncertainty descriptions']
  },
  {
    id: 'time-tracking',
    title: 'Comprehensive Time Tracking',
    description: 'Track all employee time spent on R&D activities',
    category: 'documentation',
    isRequired: true,
    helpText: 'Maintain detailed records of time spent by each employee on qualified R&D activities, including specific tasks and project assignments.',
    relatedDocs: ['Time tracking logs', 'Employee timesheets', 'Project assignments']
  },
  {
    id: 'technical-documentation',
    title: 'Technical Documentation',
    description: 'Document technical uncertainties and experimentation processes',
    category: 'documentation',
    isRequired: true,
    helpText: 'Keep detailed records of technical challenges, hypotheses tested, experiments conducted, and results obtained.',
    relatedDocs: ['Research notes', 'Experiment logs', 'Technical specifications']
  },
  {
    id: 'employee-qualification',
    title: 'Employee Qualification Records',
    description: 'Maintain records of employee qualifications and R&D involvement',
    category: 'documentation',
    isRequired: true,
    helpText: 'Document employee education, experience, and percentage of time spent on R&D activities.',
    relatedDocs: ['Employee resumes', 'Job descriptions', 'Training records']
  },
  {
    id: 'expense-tracking',
    title: 'R&D Expense Documentation',
    description: 'Track and categorize all R&D-related expenses',
    category: 'documentation',
    isRequired: true,
    helpText: 'Maintain detailed records of supplies, equipment, and contractor costs directly related to R&D activities.',
    relatedDocs: ['Receipts', 'Invoices', 'Purchase orders', 'Contractor agreements']
  },
  {
    id: 'source-control',
    title: 'Source Code Management',
    description: 'Maintain version control and development activity records',
    category: 'documentation',
    isRequired: false,
    helpText: 'Keep records of code commits, development activities, and technical progress through version control systems.',
    relatedDocs: ['Git logs', 'Commit messages', 'Code review records']
  },
  {
    id: 'project-management',
    title: 'Project Management Records',
    description: 'Document project timelines, milestones, and deliverables',
    category: 'ongoing',
    isRequired: true,
    helpText: 'Maintain project plans, milestone tracking, and progress reports that demonstrate systematic approach to R&D.',
    relatedDocs: ['Project plans', 'Milestone reports', 'Status updates']
  },
  {
    id: 'financial-records',
    title: 'Financial Record Keeping',
    description: 'Maintain accurate financial records for all R&D activities',
    category: 'ongoing',
    isRequired: true,
    helpText: 'Keep detailed financial records that can substantiate R&D credit claims during an audit.',
    relatedDocs: ['General ledger', 'Payroll records', 'Expense reports']
  },
  {
    id: 'audit-preparation',
    title: 'Audit Readiness',
    description: 'Prepare comprehensive documentation package for potential audits',
    category: 'audit-prep',
    isRequired: true,
    helpText: 'Organize all documentation in a format that can be easily reviewed by IRS auditors.',
    relatedDocs: ['Audit file', 'Documentation index', 'Summary reports']
  },
  {
    id: 'nexus-study',
    title: 'Nexus Study Documentation',
    description: 'Document the connection between expenses and R&D activities',
    category: 'audit-prep',
    isRequired: false,
    helpText: 'Prepare detailed analysis showing how claimed expenses directly relate to qualified R&D activities.',
    relatedDocs: ['Nexus analysis', 'Expense allocation methods', 'Supporting calculations']
  }
];

export const ComplianceWizard: React.FC<ComplianceWizardProps> = ({
  clientCompliance,
  onUpdateCompliance
}) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [expandedItem, setExpandedItem] = useState<string | null>(null);

  const toggleItemCompletion = (itemId: string) => {
    const isCompleted = clientCompliance.completedItems.includes(itemId);
    const updatedItems = isCompleted
      ? clientCompliance.completedItems.filter(id => id !== itemId)
      : [...clientCompliance.completedItems, itemId];
    
    onUpdateCompliance(clientCompliance.clientId, updatedItems);
  };

  const filteredItems = selectedCategory === 'all' 
    ? complianceItems 
    : complianceItems.filter(item => item.category === selectedCategory);

  const completedCount = clientCompliance.completedItems.length;
  const totalCount = complianceItems.length;
  const requiredCount = complianceItems.filter(item => item.isRequired).length;
  const completedRequiredCount = clientCompliance.completedItems.filter(itemId => 
    complianceItems.find(item => item.id === itemId)?.isRequired
  ).length;

  const overallProgress = (completedCount / totalCount) * 100;
  const requiredProgress = (completedRequiredCount / requiredCount) * 100;

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'qualification': return <Award className="h-4 w-4" />;
      case 'documentation': return <FileText className="h-4 w-4" />;
      case 'ongoing': return <Clock className="h-4 w-4" />;
      case 'audit-prep': return <BookOpen className="h-4 w-4" />;
      default: return <Circle className="h-4 w-4" />;
    }
  };

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'qualification': return 'bg-purple-100 text-purple-800';
      case 'documentation': return 'bg-blue-100 text-blue-800';
      case 'ongoing': return 'bg-green-100 text-green-800';
      case 'audit-prep': return 'bg-orange-100 text-orange-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">R&D Compliance Wizard</h1>
        <div className="text-right">
          <p className="text-sm text-gray-600">Overall Progress</p>
          <p className="text-2xl font-bold text-blue-600">{Math.round(overallProgress)}%</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        <div className="bg-blue-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-blue-900 mb-2">Total Progress</h4>
          <div className="flex items-center space-x-3">
            <div className="flex-1 bg-blue-200 rounded-full h-2">
              <div
                className="bg-blue-600 h-2 rounded-full"
                style={{ width: `${overallProgress}%` }}
              />
            </div>
            <span className="text-sm font-medium text-blue-600">{completedCount}/{totalCount}</span>
          </div>
        </div>
        <div className="bg-red-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-red-900 mb-2">Required Items</h4>
          <div className="flex items-center space-x-3">
            <div className="flex-1 bg-red-200 rounded-full h-2">
              <div
                className="bg-red-600 h-2 rounded-full"
                style={{ width: `${requiredProgress}%` }}
              />
            </div>
            <span className="text-sm font-medium text-red-600">{completedRequiredCount}/{requiredCount}</span>
          </div>
        </div>
        <div className="bg-green-50 p-4 rounded-lg">
          <h4 className="text-sm font-medium text-green-900 mb-2">Audit Readiness</h4>
          <p className="text-2xl font-bold text-green-600">
            {requiredProgress >= 100 ? 'Ready' : 'In Progress'}
          </p>
        </div>
      </div>

      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-gray-900">Compliance Checklist</h3>
          <div className="flex space-x-2">
            <button
              onClick={() => setSelectedCategory('all')}
              className={`px-3 py-1 rounded text-sm font-medium ${
                selectedCategory === 'all' ? 'bg-blue-100 text-blue-600' : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              All
            </button>
            <button
              onClick={() => setSelectedCategory('qualification')}
              className={`px-3 py-1 rounded text-sm font-medium ${
                selectedCategory === 'qualification' ? 'bg-purple-100 text-purple-600' : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              Qualification
            </button>
            <button
              onClick={() => setSelectedCategory('documentation')}
              className={`px-3 py-1 rounded text-sm font-medium ${
                selectedCategory === 'documentation' ? 'bg-blue-100 text-blue-600' : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              Documentation
            </button>
            <button
              onClick={() => setSelectedCategory('ongoing')}
              className={`px-3 py-1 rounded text-sm font-medium ${
                selectedCategory === 'ongoing' ? 'bg-green-100 text-green-600' : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              Ongoing
            </button>
            <button
              onClick={() => setSelectedCategory('audit-prep')}
              className={`px-3 py-1 rounded text-sm font-medium ${
                selectedCategory === 'audit-prep' ? 'bg-orange-100 text-orange-600' : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              Audit Prep
            </button>
          </div>
        </div>

        <div className="space-y-4">
          {filteredItems.map((item) => {
            const isCompleted = clientCompliance.completedItems.includes(item.id);
            const isExpanded = expandedItem === item.id;

            return (
              <div key={item.id} className="border border-gray-200 rounded-lg">
                <div className="p-4">
                  <div className="flex items-start space-x-3">
                    <button
                      onClick={() => toggleItemCompletion(item.id)}
                      className={`mt-1 ${isCompleted ? 'text-green-600' : 'text-gray-400'}`}
                    >
                      {isCompleted ? <CheckCircle className="h-5 w-5" /> : <Circle className="h-5 w-5" />}
                    </button>
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <h4 className={`font-medium ${isCompleted ? 'text-gray-500 line-through' : 'text-gray-900'}`}>
                            {item.title}
                          </h4>
                          <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getCategoryColor(item.category)}`}>
                            {getCategoryIcon(item.category)}
                            <span className="ml-1 capitalize">{item.category.replace('-', ' ')}</span>
                          </span>
                          {item.isRequired && (
                            <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800">
                              <AlertTriangle className="h-3 w-3 mr-1" />
                              Required
                            </span>
                          )}
                        </div>
                        <button
                          onClick={() => setExpandedItem(isExpanded ? null : item.id)}
                          className="text-gray-400 hover:text-gray-600"
                        >
                          {isExpanded ? '−' : '+'}
                        </button>
                      </div>
                      <p className={`text-sm mt-1 ${isCompleted ? 'text-gray-400' : 'text-gray-600'}`}>
                        {item.description}
                      </p>
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="mt-4 pl-8 space-y-3">
                      <div className="bg-blue-50 p-3 rounded-lg">
                        <h5 className="text-sm font-medium text-blue-900 mb-1">Why This Matters</h5>
                        <p className="text-sm text-blue-800">{item.helpText}</p>
                      </div>
                      <div>
                        <h5 className="text-sm font-medium text-gray-900 mb-2">Related Documentation</h5>
                        <div className="flex flex-wrap gap-2">
                          {item.relatedDocs.map((doc, index) => (
                            <span key={index} className="inline-flex items-center px-2 py-1 rounded text-xs bg-gray-100 text-gray-600">
                              <FileText className="h-3 w-3 mr-1" />
                              {doc}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {requiredProgress >= 100 && (
          <div className="mt-6 p-4 bg-green-50 border border-green-200 rounded-lg">
            <div className="flex items-center space-x-2">
              <CheckCircle className="h-5 w-5 text-green-600" />
              <h4 className="font-medium text-green-900">Congratulations!</h4>
            </div>
            <p className="text-sm text-green-800 mt-1">
              You have completed all required compliance items. Your R&D documentation is audit-ready.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};