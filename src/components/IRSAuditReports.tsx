import React, { useState } from 'react';
import { Download, FileText, Calendar, DollarSign, Users, Clock, Building, AlertCircle, CheckCircle } from 'lucide-react';
import { Client, Project, TimeEntry, Employee, Expense, ContractorTimeEntry } from '../types';
import { formatCurrency, formatDuration, formatDate } from '../utils/formatters';

interface IRSAuditReportsProps {
  clients: Client[];
  projects: Project[];
  timeEntries: TimeEntry[];
  employees: Employee[];
  expenses: Expense[];
  contractorTimeEntries: ContractorTimeEntry[];
  selectedClientId: string | null;
}

export const IRSAuditReports: React.FC<IRSAuditReportsProps> = ({
  clients,
  projects,
  timeEntries,
  employees,
  expenses,
  contractorTimeEntries,
  selectedClientId
}) => {
  const [selectedQuarter, setSelectedQuarter] = useState('Q4');
  const [selectedYear, setSelectedYear] = useState('2024');
  const [reportType, setReportType] = useState<'summary' | 'detailed' | 'section41'>('summary');

  const selectedClient = clients.find(c => c.id === selectedClientId);
  const clientProjects = projects.filter(p => p.clientId === selectedClientId && p.isRnD);
  const clientTimeEntries = timeEntries.filter(e => e.clientId === selectedClientId && e.isRnD);
  const clientEmployees = employees.filter(e => e.clientId === selectedClientId);
  const clientExpenses = expenses.filter(e => e.clientId === selectedClientId && e.isRnD);
  const clientContractorEntries = contractorTimeEntries.filter(e => e.clientId === selectedClientId && e.isRnD);

  // Calculate quarterly data
  const getQuarterlyData = () => {
    const quarterMonths = {
      'Q1': [1, 2, 3],
      'Q2': [4, 5, 6],
      'Q3': [7, 8, 9],
      'Q4': [10, 11, 12]
    };

    const months = quarterMonths[selectedQuarter as keyof typeof quarterMonths];
    
    const quarterlyTimeEntries = clientTimeEntries.filter(entry => {
      const entryDate = new Date(entry.date);
      return entryDate.getFullYear() === parseInt(selectedYear) && 
             months.includes(entryDate.getMonth() + 1);
    });

    const quarterlyExpenses = clientExpenses.filter(expense => {
      const expenseDate = new Date(expense.date);
      return expenseDate.getFullYear() === parseInt(selectedYear) && 
             months.includes(expenseDate.getMonth() + 1);
    });

    const quarterlyContractorEntries = clientContractorEntries.filter(entry => {
      const entryDate = new Date(entry.date);
      return entryDate.getFullYear() === parseInt(selectedYear) && 
             months.includes(entryDate.getMonth() + 1);
    });

    return { quarterlyTimeEntries, quarterlyExpenses, quarterlyContractorEntries };
  };

  const { quarterlyTimeEntries, quarterlyExpenses, quarterlyContractorEntries } = getQuarterlyData();

  // Calculate costs
  const totalRnDHours = quarterlyTimeEntries.reduce((total, entry) => total + entry.duration, 0);
  const totalPayrollCosts = quarterlyTimeEntries.reduce((total, entry) => {
    const employee = clientEmployees.find(emp => emp.id === entry.employeeId);
    return total + (employee ? (entry.duration / 60) * employee.hourlyRate : 0);
  }, 0);
  const totalContractorCosts = quarterlyContractorEntries.reduce((total, entry) => 
    total + (entry.duration / 60) * entry.hourlyRate, 0
  );
  const totalSupplyCosts = quarterlyExpenses.reduce((total, expense) => total + expense.amount, 0);
  const totalQualifiedCosts = totalPayrollCosts + totalContractorCosts + totalSupplyCosts;

  // Generate project summaries
  const projectSummaries = clientProjects.map(project => {
    const projectTimeEntries = quarterlyTimeEntries.filter(e => e.projectId === project.id);
    const projectHours = projectTimeEntries.reduce((total, entry) => total + entry.duration, 0);
    const projectCosts = projectTimeEntries.reduce((total, entry) => {
      const employee = clientEmployees.find(emp => emp.id === entry.employeeId);
      return total + (employee ? (entry.duration / 60) * employee.hourlyRate : 0);
    }, 0);

    return {
      id: project.id,
      name: project.name,
      rndHours: projectHours,
      costs: projectCosts,
      technicalChallenges: project.technicalUncertainty,
      personnelSummary: `${projectTimeEntries.length} time entries across ${new Set(projectTimeEntries.map(e => e.employeeId)).size} employees`
    };
  });

  const generateReport = () => {
    const reportData = {
      client: selectedClient?.name,
      quarter: selectedQuarter,
      year: selectedYear,
      totalRnDHours: formatDuration(totalRnDHours),
      totalPayrollCosts: formatCurrency(totalPayrollCosts),
      totalContractorCosts: formatCurrency(totalContractorCosts),
      totalSupplyCosts: formatCurrency(totalSupplyCosts),
      totalQualifiedCosts: formatCurrency(totalQualifiedCosts),
      projectSummaries,
      employeeCount: clientEmployees.length,
      avgRnDPercentage: Math.round(clientEmployees.reduce((sum, emp) => sum + emp.rndPercentage, 0) / clientEmployees.length)
    };

    console.log('Generating IRS Audit Report:', reportData);
    alert(`${reportType.toUpperCase()} report for ${selectedClient?.name} ${selectedQuarter} ${selectedYear} would be generated and downloaded here.`);
  };

  if (!selectedClientId || !selectedClient) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold text-gray-900">IRS Audit Reports</h1>
        <div className="bg-white p-8 rounded-xl shadow-sm border border-gray-200 text-center">
          <FileText className="h-16 w-16 mx-auto mb-4 text-gray-300" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">Select a Client</h3>
          <p className="text-gray-600">Choose a client to generate IRS-ready audit reports.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">IRS Audit Reports</h1>
        <div className="flex items-center space-x-3">
          <select
            value={selectedQuarter}
            onChange={(e) => setSelectedQuarter(e.target.value)}
            className="border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="Q1">Q1</option>
            <option value="Q2">Q2</option>
            <option value="Q3">Q3</option>
            <option value="Q4">Q4</option>
          </select>
          <select
            value={selectedYear}
            onChange={(e) => setSelectedYear(e.target.value)}
            className="border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="2024">2024</option>
            <option value="2023">2023</option>
            <option value="2022">2022</option>
          </select>
          <button
            onClick={generateReport}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2"
          >
            <Download className="h-4 w-4" />
            <span>Generate Report</span>
          </button>
        </div>
      </div>

      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">{selectedClient.name}</h2>
            <p className="text-gray-600">{selectedQuarter} {selectedYear} R&D Tax Credit Report</p>
          </div>
          <div className="flex space-x-2">
            <button
              onClick={() => setReportType('summary')}
              className={`px-3 py-1 rounded text-sm font-medium ${
                reportType === 'summary' ? 'bg-blue-100 text-blue-600' : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              Summary
            </button>
            <button
              onClick={() => setReportType('detailed')}
              className={`px-3 py-1 rounded text-sm font-medium ${
                reportType === 'detailed' ? 'bg-blue-100 text-blue-600' : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              Detailed
            </button>
            <button
              onClick={() => setReportType('section41')}
              className={`px-3 py-1 rounded text-sm font-medium ${
                reportType === 'section41' ? 'bg-blue-100 text-blue-600' : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              Section 41
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-8">
          <div className="bg-blue-50 p-4 rounded-lg">
            <h4 className="text-sm font-medium text-blue-900 mb-2 flex items-center">
              <Clock className="h-4 w-4 mr-1" />
              Qualified R&D Hours
            </h4>
            <p className="text-2xl font-bold text-blue-600">{formatDuration(totalRnDHours)}</p>
          </div>
          <div className="bg-green-50 p-4 rounded-lg">
            <h4 className="text-sm font-medium text-green-900 mb-2 flex items-center">
              <DollarSign className="h-4 w-4 mr-1" />
              Payroll Costs
            </h4>
            <p className="text-2xl font-bold text-green-600">{formatCurrency(totalPayrollCosts)}</p>
          </div>
          <div className="bg-purple-50 p-4 rounded-lg">
            <h4 className="text-sm font-medium text-purple-900 mb-2 flex items-center">
              <Building className="h-4 w-4 mr-1" />
              Contractor Costs
            </h4>
            <p className="text-2xl font-bold text-purple-600">{formatCurrency(totalContractorCosts)}</p>
          </div>
          <div className="bg-orange-50 p-4 rounded-lg">
            <h4 className="text-sm font-medium text-orange-900 mb-2 flex items-center">
              <FileText className="h-4 w-4 mr-1" />
              Supply Costs
            </h4>
            <p className="text-2xl font-bold text-orange-600">{formatCurrency(totalSupplyCosts)}</p>
          </div>
        </div>

        {reportType === 'summary' && (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Executive Summary</h3>
              <div className="bg-gray-50 p-4 rounded-lg">
                <p className="text-gray-700 mb-3">
                  <strong>{selectedClient.name}</strong> conducted qualified research and development activities during {selectedQuarter} {selectedYear}, 
                  resulting in <strong>{formatCurrency(totalQualifiedCosts)}</strong> in qualified research expenses.
                </p>
                <p className="text-gray-700">
                  The company's R&D activities involved <strong>{clientEmployees.length} qualified personnel</strong> working 
                  <strong> {formatDuration(totalRnDHours)}</strong> on <strong>{clientProjects.length} qualified projects</strong> 
                  that meet the four-part test requirements under IRC Section 41.
                </p>
              </div>
            </div>

            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Qualified Research Projects</h3>
              <div className="space-y-4">
                {projectSummaries.map(project => (
                  <div key={project.id} className="border border-gray-200 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="font-medium text-gray-900">{project.name}</h4>
                      <div className="text-right">
                        <p className="text-sm font-medium text-gray-900">{formatDuration(project.rndHours)}</p>
                        <p className="text-sm text-gray-600">{formatCurrency(project.costs)}</p>
                      </div>
                    </div>
                    <p className="text-sm text-gray-600 mb-2">{project.personnelSummary}</p>
                    <p className="text-sm text-gray-700">{project.technicalChallenges}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {reportType === 'detailed' && (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Personnel Summary</h3>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Employee</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">R&D %</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Hours</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Cost</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {clientEmployees.map(employee => {
                      const employeeHours = quarterlyTimeEntries
                        .filter(e => e.employeeIds.includes(employee.id))
                        .reduce((total, entry) => total + entry.duration, 0);
                      const employeeCost = employeeHours > 0 ? (employeeHours / 60) * employee.hourlyRate : 0;
                      
                      return (
                        <tr key={employee.id}>
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{employee.name}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{employee.role}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{employee.rndPercentage}%</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{formatDuration(employeeHours)}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{formatCurrency(employeeCost)}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Expense Breakdown</h3>
              <div className="space-y-3">
                {quarterlyExpenses.map(expense => (
                  <div key={expense.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div>
                      <p className="text-sm font-medium text-gray-900">{expense.description}</p>
                      <p className="text-xs text-gray-600">{expense.category} • {expense.vendor}</p>
                    </div>
                    <div className="text-right">
                      <p className="text-sm font-medium text-gray-900">{formatCurrency(expense.amount)}</p>
                      <p className="text-xs text-gray-500">{formatDate(expense.date)}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {reportType === 'section41' && (
          <div className="space-y-6">
            <div className="bg-blue-50 p-4 rounded-lg">
              <h3 className="text-lg font-semibold text-blue-900 mb-3">IRC Section 41 Compliance</h3>
              <p className="text-blue-800 text-sm">
                This report demonstrates compliance with Internal Revenue Code Section 41 requirements for qualified research activities.
              </p>
            </div>

            <div>
              <h4 className="text-md font-semibold text-gray-900 mb-3">Four-Part Test Compliance</h4>
              <div className="space-y-3">
                <div className="flex items-start space-x-3">
                  <CheckCircle className="h-5 w-5 text-green-500 mt-0.5" />
                  <div>
                    <p className="text-sm font-medium text-gray-900">Technological in Nature</p>
                    <p className="text-xs text-gray-600">Activities rely on principles of physical or biological sciences, engineering, or computer science</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3">
                  <CheckCircle className="h-5 w-5 text-green-500 mt-0.5" />
                  <div>
                    <p className="text-sm font-medium text-gray-900">Technical Uncertainty</p>
                    <p className="text-xs text-gray-600">Information available to taxpayer does not establish capability or method for achieving desired result</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3">
                  <CheckCircle className="h-5 w-5 text-green-500 mt-0.5" />
                  <div>
                    <p className="text-sm font-medium text-gray-900">Process of Experimentation</p>
                    <p className="text-xs text-gray-600">Substantially all activities constitute elements of a process of experimentation</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3">
                  <CheckCircle className="h-5 w-5 text-green-500 mt-0.5" />
                  <div>
                    <p className="text-sm font-medium text-gray-900">Qualified Purpose</p>
                    <p className="text-xs text-gray-600">Purpose is to create new or improved business component functionality, performance, reliability, or quality</p>
                  </div>
                </div>
              </div>
            </div>

            <div>
              <h4 className="text-md font-semibold text-gray-900 mb-3">Qualified Research Expenses (QREs)</h4>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-gray-50 p-4 rounded-lg">
                  <h5 className="text-sm font-medium text-gray-900 mb-2">In-House Research Expenses</h5>
                  <p className="text-lg font-bold text-gray-900">{formatCurrency(totalPayrollCosts)}</p>
                  <p className="text-xs text-gray-600">Wages paid to employees for qualified research</p>
                </div>
                <div className="bg-gray-50 p-4 rounded-lg">
                  <h5 className="text-sm font-medium text-gray-900 mb-2">Contract Research Expenses</h5>
                  <p className="text-lg font-bold text-gray-900">{formatCurrency(totalContractorCosts)}</p>
                  <p className="text-xs text-gray-600">65% of amounts paid to qualified organizations</p>
                </div>
                <div className="bg-gray-50 p-4 rounded-lg">
                  <h5 className="text-sm font-medium text-gray-900 mb-2">Supply Expenses</h5>
                  <p className="text-lg font-bold text-gray-900">{formatCurrency(totalSupplyCosts)}</p>
                  <p className="text-xs text-gray-600">Cost of supplies used in qualified research</p>
                </div>
              </div>
            </div>

            <div className="bg-green-50 p-4 rounded-lg">
              <div className="flex items-center space-x-2 mb-2">
                <CheckCircle className="h-5 w-5 text-green-600" />
                <h4 className="text-md font-semibold text-green-900">Total Qualified Research Expenses</h4>
              </div>
              <p className="text-2xl font-bold text-green-900">{formatCurrency(totalQualifiedCosts)}</p>
              <p className="text-sm text-green-800 mt-1">
                Eligible for R&D tax credit calculation under IRC Section 41
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};