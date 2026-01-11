import { useState, useMemo } from 'react';

export interface SearchFilters {
  query: string;
  dateRange?: {
    start: string;
    end: string;
  };
  tags?: string[];
  status?: string;
  category?: string;
  isRnD?: boolean;
}

export function useAdvancedSearch<T>(
  data: T[],
  searchFields: (keyof T)[],
  initialFilters: SearchFilters = { query: '' }
) {
  const [filters, setFilters] = useState<SearchFilters>(initialFilters);

  const filteredData = useMemo(() => {
    return data.filter(item => {
      // Text search
      if (filters.query) {
        const searchText = filters.query.toLowerCase();
        const matchesText = searchFields.some(field => {
          const value = item[field];
          if (typeof value === 'string') {
            return value.toLowerCase().includes(searchText);
          }
          if (Array.isArray(value)) {
            return value.some(v => 
              typeof v === 'string' && v.toLowerCase().includes(searchText)
            );
          }
          return false;
        });
        if (!matchesText) return false;
      }

      // Date range filter
      if (filters.dateRange && 'date' in item) {
        const itemDate = new Date(item.date as string);
        const startDate = new Date(filters.dateRange.start);
        const endDate = new Date(filters.dateRange.end);
        if (itemDate < startDate || itemDate > endDate) return false;
      }

      // Tags filter
      if (filters.tags && filters.tags.length > 0 && 'tags' in item) {
        const itemTags = item.tags as string[];
        const hasMatchingTag = filters.tags.some(tag => 
          itemTags.includes(tag)
        );
        if (!hasMatchingTag) return false;
      }

      // Status filter
      if (filters.status && 'status' in item) {
        if (item.status !== filters.status) return false;
      }

      // Category filter
      if (filters.category && 'category' in item) {
        if (item.category !== filters.category) return false;
      }

      // R&D filter
      if (filters.isRnD !== undefined && 'isRnD' in item) {
        if (item.isRnD !== filters.isRnD) return false;
      }

      return true;
    });
  }, [data, searchFields, filters]);

  const updateFilter = (key: keyof SearchFilters, value: any) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  };

  const clearFilters = () => {
    setFilters({ query: '' });
  };

  return {
    filteredData,
    filters,
    updateFilter,
    clearFilters
  };
}