import React from 'react';
import { TimeEntry } from '../types/time';
import { formatDate, formatDuration } from '../utils/formatters';

interface ResponsiveTableProps {
  entries: TimeEntry[];
  onEntryClick?: (entry: TimeEntry) => void;
}

export const ResponsiveTable: React.FC<ResponsiveTableProps> = ({
  entries,
  onEntryClick
}) => {
  return (
    <>
      {/* Desktop Table */}
      <div className="hidden md:block overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Date
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Client
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Project
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Service
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Duration
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {entries.map((entry) => (
              <tr 
                key={entry.id}
                onClick={() => onEntryClick?.(entry)}
                className="hover:bg-gray-50 cursor-pointer"
              >
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                  {formatDate(entry.date)}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                  {entry.client}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                  {entry.project}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                  {entry.service}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                  {formatDuration(entry.durationMin)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Mobile Card View */}
      <div className="md:hidden space-y-3">
        {entries.map((entry) => (
          <div
            key={entry.id}
            onClick={() => onEntryClick?.(entry)}
            className="bg-white border border-gray-200 rounded-lg p-4 shadow-sm active:bg-gray-50 transition-colors"
          >
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-medium text-gray-900">{entry.project}</h3>
              <span className="text-sm font-bold text-blue-600">
                {formatDuration(entry.durationMin)}
              </span>
            </div>
            <p className="text-sm text-gray-600 mb-2">{entry.service}</p>
            <div className="flex items-center justify-between text-xs text-gray-500">
              <span>{entry.client}</span>
              <span>{formatDate(entry.date)}</span>
            </div>
            {entry.isRnD && (
              <div className="mt-2">
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                  R&D Qualified
                </span>
              </div>
            )}
          </div>
        ))}
      </div>
    </>
  );
};