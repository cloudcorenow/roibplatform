import { useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { TimeEntry, TimeEntryCreateRequest } from '../../types/time';
import { listTimeEntries, createTimeEntry, deleteTimeEntry } from '../../services/timeEntriesApi';

export type SortKey = keyof Pick<TimeEntry, 'date' | 'client' | 'project' | 'service' | 'durationMin'>;
export type SortDir = 'asc' | 'desc';

export function useTimeEntries() {
  const queryClient = useQueryClient();
  const [query, setQuery] = useState('');
  const [from, setFrom] = useState<string | undefined>();
  const [to, setTo] = useState<string | undefined>();
  const [limit, setLimit] = useState(50);
  const [offset, setOffset] = useState(0);
  const [sortKey, setSortKey] = useState<SortKey>('date');
  const [sortDir, setSortDir] = useState<SortDir>('desc');

  // React Query for data fetching
  const { data, isLoading, isFetching, error } = useQuery({
    queryKey: ['timeEntries', { from, to, limit, offset }],
    queryFn: () => listTimeEntries({ from, to, limit, offset }),
    keepPreviousData: true,
    staleTime: 60_000, // 1 minute
    gcTime: 300_000, // 5 minutes
    retry: (failureCount, error) => {
      // Don't retry on 4xx errors
      if (error instanceof Error && error.message.includes('4')) {
        return false;
      }
      return failureCount < 3;
    }
  });

  const pageItems = data?.items ?? [];
  
  // Client-side filtering and sorting
  const filtered = useMemo(() => {
    let result = pageItems;
    
    // Apply search filter
    const needle = query.trim().toLowerCase();
    if (needle) {
      result = result.filter(entry =>
        [entry.client, entry.project, entry.service, entry.notes, entry.date]
          .filter(Boolean)
          .some(value => String(value).toLowerCase().includes(needle))
      );
    }

    // Apply sorting
    result = [...result].sort((a, b) => {
      const aValue = a[sortKey];
      const bValue = b[sortKey];
      const comparison = aValue < bValue ? -1 : aValue > bValue ? 1 : 0;
      return sortDir === 'asc' ? comparison : -comparison;
    });
    
    return result;
  }, [pageItems, query, sortKey, sortDir]);

  // Pagination helpers
  const nextPage = () => {
    if (data?.paging?.nextOffset != null) {
      setOffset(data.paging.nextOffset);
    }
  };

  const prevPage = () => {
    if (data?.paging?.prevOffset != null) {
      setOffset(data.paging.prevOffset);
    } else if (offset > 0) {
      setOffset(0);
    }
  };

  const hasNextPage = data?.paging?.nextOffset != null;
  const hasPrevPage = data?.paging?.prevOffset != null || offset > 0;
  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = data?.total ? Math.ceil(data.total / limit) : 0;

  // Sorting helpers
  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortKey(key);
      setSortDir('asc');
    }
  }

  // Mutations with optimistic updates
  const createMutation = useMutation({
    mutationFn: (entry: TimeEntryCreateRequest) => createTimeEntry(entry),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['timeEntries'] });
    },
    onError: (error) => {
      console.error('Failed to create time entry:', error);
    }
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteTimeEntry(id),
    onMutate: async (id) => {
      // Cancel outgoing refetches
      await queryClient.cancelQueries({ queryKey: ['timeEntries'] });
      
      // Snapshot previous value
      const previousData = queryClient.getQueryData(['timeEntries', { from, to, limit, offset }]);
      
      // Optimistically remove from cache
      queryClient.setQueryData(['timeEntries', { from, to, limit, offset }], (old: any) => {
        if (!old) return old;
        return {
          ...old,
          items: old.items.filter((entry: TimeEntry) => entry.id !== id),
          total: old.total - 1
        };
      });
      
      return { previousData };
    },
    onError: (error, id, context) => {
      // Rollback on error
      if (context?.previousData) {
        queryClient.setQueryData(['timeEntries', { from, to, limit, offset }], context.previousData);
      }
      console.error('Failed to delete time entry:', error);
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ['timeEntries'] });
    }
  });

  return {
    entries: filtered,
    total: data?.total || 0,
    isLoading,
    isFetching,
    error,
    query,
    setQuery,
    from,
    setFrom,
    to,
    setTo,
    limit,
    setLimit,
    offset,
    setOffset,
    sortKey,
    sortDir,
    toggleSort,
    createMut: createMutation,
    deleteMut: deleteMutation,
    nextPage,
    prevPage,
    hasNextPage,
    hasPrevPage,
    currentPage,
    totalPages
  };
}