import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { timeEntriesApi, ListTimeEntriesParams, CreateTimeEntryRequest } from '../services/timeEntriesApi';
import { TimeEntry } from '../types/time';

export function useTimeEntriesQuery(params: ListTimeEntriesParams = {}) {
  return useQuery({
    queryKey: ['timeEntries', params],
    queryFn: () => timeEntriesApi.listTimeEntries(params),
    staleTime: 30000, // 30 seconds
    gcTime: 300000, // 5 minutes
  });
}

export function useCreateTimeEntryMutation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (entry: CreateTimeEntryRequest) => timeEntriesApi.createTimeEntry(entry),
    onSuccess: () => {
      // Invalidate and refetch time entries
      queryClient.invalidateQueries({ queryKey: ['timeEntries'] });
    },
  });
}

export function useDeleteTimeEntryMutation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => timeEntriesApi.deleteTimeEntry(id),
    onSuccess: () => {
      // Invalidate and refetch time entries
      queryClient.invalidateQueries({ queryKey: ['timeEntries'] });
    },
  });
}

export function useTimeEntriesWithPagination() {
  const [params, setParams] = useState<ListTimeEntriesParams>({ limit: 50, offset: 0 });
  const [query, setQuery] = useState('');
  
  const { data, isLoading, isFetching, error } = useTimeEntriesQuery(params);
  const createMutation = useCreateTimeEntryMutation();
  const deleteMutation = useDeleteTimeEntryMutation();

  // Filter data based on search query
  const filteredEntries = useMemo(() => {
    if (!data?.items || !query.trim()) return data?.items || [];
    
    const searchTerm = query.toLowerCase();
    return data.items.filter(entry =>
      entry.client.toLowerCase().includes(searchTerm) ||
      entry.project.toLowerCase().includes(searchTerm) ||
      entry.service.toLowerCase().includes(searchTerm) ||
      (entry.notes && entry.notes.toLowerCase().includes(searchTerm))
    );
  }, [data?.items, query]);

  const nextPage = () => {
    if (data?.paging?.nextOffset != null) {
      setParams(prev => ({ ...prev, offset: data.paging.nextOffset! }));
    }
  };

  const prevPage = () => {
    if (data?.paging?.prevOffset != null) {
      setParams(prev => ({ ...prev, offset: data.paging.prevOffset! }));
    } else if (params.offset > 0) {
      setParams(prev => ({ ...prev, offset: 0 }));
    }
  };

  const hasNextPage = data?.paging?.nextOffset != null;
  const hasPrevPage = data?.paging?.prevOffset != null || params.offset > 0;

  return {
    entries: filteredEntries,
    total: data?.total || 0,
    isLoading,
    isFetching,
    error,
    query,
    setQuery,
    createEntry: createMutation.mutate,
    deleteEntry: deleteMutation.mutate,
    isCreating: createMutation.isPending,
    isDeleting: deleteMutation.isPending,
    nextPage,
    prevPage,
    hasNextPage,
    hasPrevPage,
    currentPage: Math.floor(params.offset / params.limit) + 1,
    totalPages: data?.total ? Math.ceil(data.total / params.limit) : 0
  };
}