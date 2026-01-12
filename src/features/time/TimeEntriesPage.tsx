import React, { useEffect } from 'react';
import { ChevronLeft, ChevronRight, Loader2, AlertTriangle } from 'lucide-react';
import { TimeEntryTable } from './TimeEntryTable';
import { downloadCsv, toCsv } from '../../utils/exportCsv';
import { useTimeEntries } from './useTimeEntries';

interface TimeEntriesPageProps {
  selectedClientId?: string | null;
  projects?: any[];
}

export default function TimeEntriesPage({ selectedClientId, projects }: TimeEntriesPageProps) {
  const {
    entries,
    total,
    query,
    setQuery,
    sortKey,
    sortDir,
    toggleSort,
    isLoading,
    isFetching,
    error,
    nextPage,
    prevPage,
    hasNextPage,
    hasPrevPage,
    currentPage,
    totalPages
  } = useTimeEntries();

  function onExportCsv() {
    const csv = toCsv(entries, ['date','client','project','service','durationMin','notes']);
    downloadCsv(csv, 'time-entries.csv');
  }

  // Sync localStorage across tabs
  useEffect(() => {
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === 'firmflowz-timeentries' && e.newValue) {
        setQuery(JSON.parse(e.newValue));
      }
    };
    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, [setQuery]);

  if (error) {
    return (
      <div className="space-y-6">
        <h1 className="text-4xl font-bold text-slate-800">Time Entries</h1>
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <p className="text-red-800">Error loading time entries: {error.message}</p>
        </div>
      </div>
    );
  }
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-slate-800">Time Entries</h1>
        <div className="flex items-center space-x-4 mt-2">
          <p className="text-slate-600">{total} total entries • {entries.length} shown</p>
          {(isLoading || isFetching) && (
            <div className="flex items-center space-x-2 text-blue-600">
              <Loader2 className="h-4 w-4 animate-spin" />
              <span className="text-sm">{isLoading ? 'Loading...' : 'Refreshing...'}</span>
            </div>
          )}
        </div>
      </div>
      
      <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
        <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center w-full sm:w-auto">
          <input
            type="text"
            placeholder="Search entries..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full sm:w-auto px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent min-h-[44px]"
          />
          <button
            onClick={onExportCsv}
            disabled={isLoading}
            className="w-full sm:w-auto bg-blue-600 text-white px-4 py-3 rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 min-h-[44px]"
          >
            Export CSV
          </button>
        </div>
        
        {/* Pagination Controls */}
        <div className="flex items-center space-x-4 w-full sm:w-auto justify-between sm:justify-end">
          <span className="text-sm text-gray-600">
            Page {currentPage} of {totalPages}
          </span>
          <div className="flex space-x-2">
            <button
              onClick={prevPage}
              disabled={!hasPrevPage || isLoading}
              className="p-3 border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50 min-h-[44px] min-w-[44px]"
              title="Previous page"
              aria-label="Go to previous page"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <button
              onClick={nextPage}
              disabled={!hasNextPage || isLoading}
              className="p-3 border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50 min-h-[44px] min-w-[44px]"
              title="Next page"
              aria-label="Go to next page"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      <div className="bg-white p-4 sm:p-6 rounded-lg shadow-md border border-gray-200">
        {isLoading && entries.length === 0 ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
            <span className="ml-2 text-gray-600">Loading time entries...</span>
          </div>
        ) : (
          <TimeEntryTable
            rows={entries}
            sortKey={sortKey}
            sortDir={sortDir}
            onToggleSort={toggleSort}
          />
        )}
      </div>
    </div>
  );
}