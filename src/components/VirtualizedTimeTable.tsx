import React from 'react';
import { FixedSizeList as List } from 'react-window';
import { TimeEntry } from '../types/time';
import { formatDate, formatDuration } from '../utils/formatters';

interface VirtualizedTimeTableProps {
  entries: TimeEntry[];
  height: number;
  onEntryClick?: (entry: TimeEntry) => void;
}

interface RowProps {
  index: number;
  style: React.CSSProperties;
  data: {
    entries: TimeEntry[];
    onEntryClick?: (entry: TimeEntry) => void;
  };
}

const Row: React.FC<RowProps> = ({ index, style, data }) => {
  const entry = data.entries[index];
  
  return (
    <div
      style={style}
      className="flex items-center px-4 py-2 border-b border-gray-100 hover:bg-gray-50 cursor-pointer"
      onClick={() => data.onEntryClick?.(entry)}
    >
      <div className="flex-1 grid grid-cols-5 gap-4">
        <div className="text-sm text-gray-900">{formatDate(entry.date)}</div>
        <div className="text-sm text-gray-900">{entry.client}</div>
        <div className="text-sm text-gray-900">{entry.project}</div>
        <div className="text-sm text-gray-900">{entry.service}</div>
        <div className="text-sm font-medium text-gray-900">{formatDuration(entry.durationMin)}</div>
      </div>
    </div>
  );
};

export const VirtualizedTimeTable: React.FC<VirtualizedTimeTableProps> = ({
  entries,
  height,
  onEntryClick
}) => {
  const itemData = {
    entries,
    onEntryClick
  };

  return (
    <div className="border border-gray-200 rounded-lg overflow-hidden">
      {/* Header */}
      <div className="bg-gray-50 px-4 py-3 border-b border-gray-200">
        <div className="grid grid-cols-5 gap-4">
          <div className="text-sm font-medium text-gray-700">Date</div>
          <div className="text-sm font-medium text-gray-700">Client</div>
          <div className="text-sm font-medium text-gray-700">Project</div>
          <div className="text-sm font-medium text-gray-700">Service</div>
          <div className="text-sm font-medium text-gray-700">Duration</div>
        </div>
      </div>
      
      {/* Virtualized List */}
      <List
        height={height}
        itemCount={entries.length}
        itemSize={60}
        itemData={itemData}
      >
        {Row}
      </List>
    </div>
  );
};