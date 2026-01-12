import { TimeEntry, Project, TechnicalNote, Expense, ContractorTimeEntry } from '../types';
import { formatDuration, formatCurrency, formatDate } from './formatters';

export interface ExportData {
  timeEntries?: TimeEntry[];
  projects?: Project[];
  technicalNotes?: TechnicalNote[];
  expenses?: Expense[];
  contractorTimeEntries?: ContractorTimeEntry[];
}

export function exportToCSV(data: any[], filename: string, headers?: string[]) {
  if (data.length === 0) return;

  const csvHeaders = headers || Object.keys(data[0]);
  
  // Properly escape CSV values
  const escapeCSVValue = (value: any): string => {
    if (value === null || value === undefined) return '';
    const stringValue = String(value);
    // If value contains comma, quote, or newline, wrap in quotes and escape internal quotes
    if (stringValue.includes(',') || stringValue.includes('"') || stringValue.includes('\n') || stringValue.includes('\r')) {
      return `"${stringValue.replace(/"/g, '""')}"`;
    }
    return stringValue;
  };
  
  const csvContent = [
    csvHeaders.join(','),
    ...data.map(row => 
      csvHeaders.map(header => escapeCSVValue(row[header])).join(',')
    )
  ].join('\n');

  // Add BOM for Excel compatibility
  downloadFile('\ufeff' + csvContent, `${filename}.csv`, 'text/csv;charset=utf-8;');
}

export function exportTimeEntriesToCSV(timeEntries: TimeEntry[], filename = 'time-entries') {
  const csvData = timeEntries.map(entry => ({
    Date: formatDate(entry.date),
    Project: entry.projectName,
    Employee: entry.employeeName,
    Task: entry.task,
    Duration: formatDuration(entry.duration),
    'R&D Qualified': entry.isRnD ? 'Yes' : 'No',
    Status: entry.status,
    Notes: entry.notes || ''
  }));

  exportToCSV(csvData, filename);
}

export function exportProjectsToCSV(projects: Project[], filename = 'projects') {
  const csvData = projects.map(project => ({
    Name: project.name,
    Description: project.description,
    Status: project.status,
    Progress: `${project.progress}%`,
    'Total Hours': formatDuration(project.totalHours),
    'R&D Qualified': project.isRnD ? 'Yes' : 'No',
    'Start Date': formatDate(project.startDate),
    'End Date': project.endDate ? formatDate(project.endDate) : '',
    Budget: formatCurrency(project.budget),
    'Team Members': project.teamMembers.join('; ')
  }));

  exportToCSV(csvData, filename);
}

export function exportExpensesToCSV(expenses: Expense[], filename = 'expenses') {
  const csvData = expenses.map(expense => ({
    Date: formatDate(expense.date),
    Description: expense.description,
    Amount: formatCurrency(expense.amount),
    Category: expense.category,
    Vendor: expense.vendor,
    'R&D Qualified': expense.isRnD ? 'Yes' : 'No',
    Justification: expense.justification
  }));

  exportToCSV(csvData, filename);
}

export function exportTechnicalNotesToCSV(notes: TechnicalNote[], filename = 'technical-notes') {
  const csvData = notes.map(note => ({
    Title: note.title,
    Project: note.projectName,
    Author: note.author,
    'Created Date': formatDate(note.createdAt),
    'Updated Date': formatDate(note.updatedAt),
    'R&D Qualified': note.isRnDQualified ? 'Yes' : 'No',
    Tags: note.tags.join('; '),
    'Content Preview': note.content.substring(0, 100) + '...'
  }));

  exportToCSV(csvData, filename);
}

export function generateRnDSummaryReport(data: ExportData): string {
  const { timeEntries = [], projects = [], expenses = [], contractorTimeEntries = [] } = data;
  
  const rndTimeEntries = timeEntries.filter(entry => entry.isRnD);
  const rndProjects = projects.filter(project => project.isRnD);
  const rndExpenses = expenses.filter(expense => expense.isRnD);
  const rndContractorEntries = contractorTimeEntries.filter(entry => entry.isRnD);

  const totalRnDHours = rndTimeEntries.reduce((total, entry) => total + entry.duration, 0);
  const totalRnDExpenses = rndExpenses.reduce((total, expense) => total + expense.amount, 0);
  const totalContractorCosts = rndContractorEntries.reduce((total, entry) => 
    total + (entry.duration / 60) * entry.hourlyRate, 0
  );

  return `
R&D TAX CREDIT SUMMARY REPORT
Generated: ${new Date().toLocaleDateString()}

OVERVIEW
========
Total R&D Projects: ${rndProjects.length}
Total R&D Hours: ${formatDuration(totalRnDHours)}
Total R&D Expenses: ${formatCurrency(totalRnDExpenses)}
Total Contractor Costs: ${formatCurrency(totalContractorCosts)}
Total Qualified Costs: ${formatCurrency(totalRnDExpenses + totalContractorCosts)}

R&D PROJECTS
============
${rndProjects.map(project => `
- ${project.name}
  Status: ${project.status}
  Progress: ${project.progress}%
  Hours: ${formatDuration(project.totalHours)}
  Budget: ${formatCurrency(project.budget)}
  Objective: ${project.rndObjective}
  Technical Uncertainty: ${project.technicalUncertainty}
`).join('\n')}

TIME SUMMARY BY PROJECT
======================
${rndProjects.map(project => {
  const projectHours = rndTimeEntries
    .filter(entry => entry.projectId === project.id)
    .reduce((total, entry) => total + entry.duration, 0);
  return `${project.name}: ${formatDuration(projectHours)}`;
}).join('\n')}

EXPENSE SUMMARY
===============
${rndExpenses.map(expense => 
  `${formatDate(expense.date)} - ${expense.description}: ${formatCurrency(expense.amount)}`
).join('\n')}
`;
}

export function downloadFile(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export function exportToJSON(data: any, filename: string) {
  const jsonContent = JSON.stringify(data, null, 2);
  downloadFile(jsonContent, `${filename}.json`, 'application/json');
}