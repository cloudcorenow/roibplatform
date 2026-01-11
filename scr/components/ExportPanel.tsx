import React, { useState } from 'react';
import { Download, FileText, Table, Database } from 'lucide-react';
import { LoadingSpinner } from './LoadingSpinner';
import { 
  exportTimeEntriesToCSV, 
  exportProjectsToCSV, 
  exportExpensesToCSV,
  exportTechnicalNotesToCSV,
  generateRnDSummaryReport,
  downloadFile,
  exportToJSON,
  ExportData
} from '../utils/exportUtils';

interface ExportPanelProps {
  data: ExportData;
  clientName?: string;
}

export const ExportPanel: React.FC<ExportPanelProps> = ({ data, clientName = 'client' }) => {
  const [isExporting, setIsExporting] = useState(false);
  const [exportType, setExportType] = useState<string>('');

  const handleExport = async (type: string, exportFunction: () => void) => {
    setIsExporting(true);
    setExportType(type);
    
    try {
      // Simulate processing time for better UX
      await new Promise(resolve => setTimeout(resolve, 1000));
      exportFunction();
    } catch (error) {
      console.error('Export failed:', error);
    } finally {
      setIsExporting(false);
      setExportType('');
    }
  };

  const exportOptions = [
    {
      id: 'time-entries-csv',
      title: 'Time Entries (CSV)',
      description: 'Export all time tracking data',
      icon: Table,
      action: () => data.timeEntries && exportTimeEntriesToCSV(data.timeEntries, `${clientName}-time-entries`)
    },
    {
      id: 'projects-csv',
      title: 'Projects (CSV)',
      description: 'Export project information and progress',
      icon: Table,
      action: () => data.projects && exportProjectsToCSV(data.projects, `${clientName}-projects`)
    },
    {
      id: 'expenses-csv',
      title: 'Expenses (CSV)',
      description: 'Export R&D expense records',
      icon: Table,
      action: () => data.expenses && exportExpensesToCSV(data.expenses, `${clientName}-expenses`)
    },
    {
      id: 'technical-notes-csv',
      title: 'Technical Notes (CSV)',
      description: 'Export technical documentation summary',
      icon: Table,
      action: () => data.technicalNotes && exportTechnicalNotesToCSV(data.technicalNotes, `${clientName}-technical-notes`)
    },
    {
      id: 'rnd-summary',
      title: 'R&D Summary Report',
      description: 'Comprehensive R&D tax credit summary',
      icon: FileText,
      action: () => {
        const report = generateRnDSummaryReport(data);
        downloadFile(report, `${clientName}-rnd-summary.txt`, 'text/plain');
      }
    },
    {
      id: 'full-data-json',
      title: 'Complete Data (JSON)',
      description: 'Export all data in JSON format',
      icon: Database,
      action: () => exportToJSON(data, `${clientName}-complete-data`)
    }
  ];

  return (
    <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
      <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
        <Download className="h-5 w-5 mr-2" />
        Export Data
      </h3>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {exportOptions.map(option => (
          <div key={option.id} className="border border-gray-200 rounded-lg p-4">
            <div className="flex items-start space-x-3 mb-3">
              <div className="bg-blue-100 p-2 rounded-lg">
                <option.icon className="h-5 w-5 text-blue-600" />
              </div>
              <div className="flex-1">
                <h4 className="font-medium text-gray-900">{option.title}</h4>
                <p className="text-sm text-gray-600 mt-1">{option.description}</p>
              </div>
            </div>
            
            <button
              onClick={() => handleExport(option.id, option.action)}
              disabled={isExporting}
              className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2"
            >
              {isExporting && exportType === option.id ? (
                <LoadingSpinner size="sm" text="" />
              ) : (
                <>
                  <Download className="h-4 w-4" />
                  <span>Export</span>
                </>
              )}
            </button>
          </div>
        ))}
      </div>
      
      <div className="mt-6 p-4 bg-blue-50 rounded-lg">
        <h4 className="font-medium text-blue-900 mb-2">Export Notes</h4>
        <ul className="text-sm text-blue-800 space-y-1">
          <li>• CSV files can be opened in Excel or Google Sheets</li>
          <li>• JSON files contain complete data structure for technical use</li>
          <li>• Summary reports are formatted for easy reading and audit purposes</li>
          <li>• All exports include only data for the selected client</li>
        </ul>
      </div>
    </div>
  );
};