import React from 'react';
import React from 'react';
import { ResponsiveTable } from '../../components/ResponsiveTable';
import { TimeEntry } from '../../types/time';
import { formatDate, formatDuration } from '../../utils/formatters';

export function TimeEntryTable(props: {
  rows: TimeEntry[];
  sortKey: 'date' | 'client' | 'project' | 'service' | 'durationMin';
  sortDir: 'asc' | 'desc';
  onToggleSort: (k: 'date' | 'client' | 'project' | 'service' | 'durationMin') => void;
}) {
  const { rows, sortKey, sortDir, onToggleSort } = props;


  return (
    <ResponsiveTable
      entries={rows}
    />
  );
}