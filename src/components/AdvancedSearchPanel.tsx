import React from 'react';
import { Search, Filter, X, Calendar, Tag } from 'lucide-react';
import { SearchFilters } from '../hooks/useAdvancedSearch';

interface AdvancedSearchPanelProps {
  filters: SearchFilters;
  onUpdateFilter: (key: keyof SearchFilters, value: any) => void;
  onClearFilters: () => void;
  availableTags?: string[];
  availableStatuses?: string[];
  availableCategories?: string[];
  showDateRange?: boolean;
  showRnDFilter?: boolean;
}

export const AdvancedSearchPanel: React.FC<AdvancedSearchPanelProps> = ({
  filters,
  onUpdateFilter,
  onClearFilters,
  availableTags = [],
  availableStatuses = [],
  availableCategories = [],
  showDateRange = false,
  showRnDFilter = false
}) => {
  const hasActiveFilters = filters.query || 
    filters.dateRange || 
    (filters.tags && filters.tags.length > 0) ||
    filters.status ||
    filters.category ||
    filters.isRnD !== undefined;

  return (
    <div className="bg-white p-4 rounded-lg border border-gray-200 mb-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-medium text-gray-900 flex items-center">
          <Filter className="h-5 w-5 mr-2" />
          Advanced Search & Filters
        </h3>
        {hasActiveFilters && (
          <button
            onClick={onClearFilters}
            className="text-sm text-gray-500 hover:text-gray-700 flex items-center space-x-1"
          >
            <X className="h-4 w-4" />
            <span>Clear All</span>
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* Search Query */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Search Text
          </label>
          <div className="relative">
            <Search className="h-4 w-4 absolute left-3 top-3 text-gray-400" />
            <input
              type="text"
              value={filters.query}
              onChange={(e) => onUpdateFilter('query', e.target.value)}
              className="w-full pl-9 pr-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="Search..."
            />
          </div>
        </div>

        {/* Date Range */}
        {showDateRange && (
          <>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Start Date
              </label>
              <input
                type="date"
                value={filters.dateRange?.start || ''}
                onChange={(e) => onUpdateFilter('dateRange', {
                  ...filters.dateRange,
                  start: e.target.value
                })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                End Date
              </label>
              <input
                type="date"
                value={filters.dateRange?.end || ''}
                onChange={(e) => onUpdateFilter('dateRange', {
                  ...filters.dateRange,
                  end: e.target.value
                })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </>
        )}

        {/* Status Filter */}
        {availableStatuses.length > 0 && (
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Status
            </label>
            <select
              value={filters.status || ''}
              onChange={(e) => onUpdateFilter('status', e.target.value || undefined)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="">All Statuses</option>
              {availableStatuses.map(status => (
                <option key={status} value={status}>
                  {status.charAt(0).toUpperCase() + status.slice(1)}
                </option>
              ))}
            </select>
          </div>
        )}

        {/* Category Filter */}
        {availableCategories.length > 0 && (
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Category
            </label>
            <select
              value={filters.category || ''}
              onChange={(e) => onUpdateFilter('category', e.target.value || undefined)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="">All Categories</option>
              {availableCategories.map(category => (
                <option key={category} value={category}>
                  {category.charAt(0).toUpperCase() + category.slice(1).replace('-', ' ')}
                </option>
              ))}
            </select>
          </div>
        )}

        {/* R&D Filter */}
        {showRnDFilter && (
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              R&D Qualification
            </label>
            <select
              value={filters.isRnD === undefined ? '' : filters.isRnD.toString()}
              onChange={(e) => {
                const value = e.target.value;
                onUpdateFilter('isRnD', value === '' ? undefined : value === 'true');
              }}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="">All Activities</option>
              <option value="true">R&D Qualified Only</option>
              <option value="false">Non-R&D Only</option>
            </select>
          </div>
        )}
      </div>

      {/* Tags Filter */}
      {availableTags.length > 0 && (
        <div className="mt-4">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Tags
          </label>
          <div className="flex flex-wrap gap-2">
            {availableTags.map(tag => {
              const isSelected = filters.tags?.includes(tag);
              return (
                <button
                  key={tag}
                  onClick={() => {
                    const currentTags = filters.tags || [];
                    const newTags = isSelected
                      ? currentTags.filter(t => t !== tag)
                      : [...currentTags, tag];
                    onUpdateFilter('tags', newTags.length > 0 ? newTags : undefined);
                  }}
                  className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium transition-colors ${
                    isSelected
                      ? 'bg-blue-100 text-blue-800 border border-blue-200'
                      : 'bg-gray-100 text-gray-700 border border-gray-200 hover:bg-gray-200'
                  }`}
                >
                  <Tag className="h-3 w-3 mr-1" />
                  {tag}
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};