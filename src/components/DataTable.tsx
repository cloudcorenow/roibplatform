import React from 'react';
import React from 'react';
import { VirtualizedTimeTable } from './VirtualizedTimeTable';
import { TimeEntry } from '../types/time';

export type Column<T> = {
  key: keyof T;
  header: React.ReactNode;
  width?: string;
  render?: (row: T) => React.ReactNode;
  onSort?: () => void;
  isSorted?: 'asc' | 'desc' | false;
};

type Props<T> = {
  columns: Column<T>[];
  rows: T[];
  empty?: React.ReactNode;
  virtualized?: boolean;
  virtualizedHeight?: number;
};

export function DataTable<T extends { id: string }>({ 
  columns, 
  rows, 
  empty,
  virtualized = false,
  virtualizedHeight = 400
}: Props<T>) {
  // Use virtualized table for large datasets
  if (virtualized && rows.length > 100) {
    return (
      <VirtualizedTimeTable
        entries={rows as TimeEntry[]}
        height={virtualizedHeight}
      />
    );
  }

  return (
    <div className="w-full overflow-auto rounded-2xl shadow-sm ring-1 ring-black/5" role="region" aria-label="Data table">
      <table className="min-w-full text-sm">
        <caption className="sr-only">
          Time entries data table with {rows.length} entries. Use arrow keys to navigate and Enter to select rows.
        </caption>
        <thead className="bg-gray-50 dark:bg-gray-800">
          <tr>
            {columns.map((c, i) => (
              <th
                key={String(c.key) + i}
                className="text-left font-medium px-4 py-3 whitespace-nowrap select-none"
                style={{ width: c.width }}
                scope="col"
                aria-sort={c.isSorted ? (c.isSorted === 'asc' ? 'ascending' : 'descending') : 'none'}
              >
                {c.onSort ? (
                  <button
                    className="inline-flex items-center gap-1 hover:underline focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-opacity-50 rounded px-1 py-1"
                    aria-label={`Sort by ${typeof c.header === 'string' ? c.header : 'column'}`}
                    onClick={c.onSort}
                  >
                    {c.header}
                    {c.isSorted && (
                      <span aria-hidden>{c.isSorted === 'asc' ? '▲' : '▼'}</span>
                    )}
                  </button>
                ) : (
                  c.header
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
          {rows.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="px-4 py-8 text-center text-gray-500">
                {empty ?? 'No data'}
              </td>
            </tr>
          ) : (
            rows.map(r => (
              <tr 
                key={r.id} 
                className="hover:bg-gray-50/70 dark:hover:bg-gray-800/50 focus-within:bg-blue-50 focus-within:ring-2 focus-within:ring-blue-500 focus-within:ring-opacity-50"
                tabIndex={0}
                role="row"
                aria-label={`Time entry for ${(r as any).project} on ${(r as any).date}`}
              >
                {columns.map((c, i) => (
                  <td key={String(c.key) + i} className="px-4 py-3 whitespace-nowrap">
                    {c.render ? c.render(r) : (r as any)[c.key]}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}