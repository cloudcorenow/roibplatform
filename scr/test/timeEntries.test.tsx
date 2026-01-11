import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useTimeEntries } from '../features/time/useTimeEntries';
import TimeEntriesPage from '../features/time/TimeEntriesPage';
import { timeEntriesApi } from '../services/timeEntriesApi';

// Mock the API with proper Cloudflare Worker responses
vi.mock('../services/timeEntriesApi');
const mockTimeEntriesApi = vi.mocked(timeEntriesApi);

// Mock the hook
vi.mock('../features/time/useTimeEntries');
const mockUseTimeEntries = vi.mocked(useTimeEntries);

describe('TimeEntriesPage', () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    });

    // Mock API responses
    mockTimeEntriesApi.listTimeEntries.mockResolvedValue({
      items: [
        {
          id: '1',
          date: '2024-12-18',
          client: 'Test Client',
          project: 'Test Project',
          service: 'Development',
          durationMin: 120,
          notes: 'Test notes'
        }
      ],
      paging: {
        from: '0000-01-01',
        to: '9999-12-31',
        limit: 50,
        offset: 0,
        prevOffset: null,
        nextOffset: null
      },
      total: 1
    });

    mockTimeEntriesApi.createTimeEntry.mockResolvedValue({
      id: '2',
      date: '2024-12-18',
      client: 'New Client',
      project: 'New Project',
      service: 'Testing',
      durationMin: 60,
      notes: 'New entry'
    });

    mockTimeEntriesApi.deleteTimeEntry.mockResolvedValue();

    mockUseTimeEntries.mockReturnValue({
      entries: [
        {
          id: '1',
          date: '2024-12-18',
          client: 'Test Client',
          project: 'Test Project',
          service: 'Development',
          durationMin: 120,
          notes: 'Test notes'
        }
      ],
      total: 1,
      isLoading: false,
      error: null,
      query: '',
      setQuery: vi.fn(),
      from: undefined,
      setFrom: vi.fn(),
      to: undefined,
      setTo: vi.fn(),
      limit: 50,
      setLimit: vi.fn(),
      offset: 0,
      setOffset: vi.fn(),
      sortKey: 'date',
      sortDir: 'desc',
      toggleSort: vi.fn(),
      createMut: { mutate: vi.fn(), isPending: false },
      deleteMut: { mutate: vi.fn(), isPending: false },
      nextPage: vi.fn(),
      prevPage: vi.fn(),
      hasNextPage: false,
      hasPrevPage: false,
      currentPage: 1,
      totalPages: 1
    });
  });

  const renderWithQueryClient = (component: React.ReactElement) => {
    return render(
      <QueryClientProvider client={queryClient}>
        {component}
      </QueryClientProvider>
    );
  };

  it('renders time entries page with data', () => {
    renderWithQueryClient(<TimeEntriesPage />);
    
    expect(screen.getByText('Time Entries')).toBeInTheDocument();
    expect(screen.getByText('1 total entries • 1 shown')).toBeInTheDocument();
    expect(screen.getByText('Test Client')).toBeInTheDocument();
  });

  it('shows loading state', () => {
    mockUseTimeEntries.mockReturnValue({
      entries: [],
      total: 0,
      isLoading: true,
      error: null,
      query: '',
      setQuery: vi.fn(),
      from: undefined,
      setFrom: vi.fn(),
      to: undefined,
      setTo: vi.fn(),
      limit: 50,
      setLimit: vi.fn(),
      offset: 0,
      setOffset: vi.fn(),
      sortKey: 'date',
      sortDir: 'desc',
      toggleSort: vi.fn(),
      createMut: { mutate: vi.fn(), isPending: false },
      deleteMut: { mutate: vi.fn(), isPending: false },
      nextPage: vi.fn(),
      prevPage: vi.fn(),
      hasNextPage: false,
      hasPrevPage: false,
      currentPage: 1,
      totalPages: 1
    });

    renderWithQueryClient(<TimeEntriesPage />);
    
    expect(screen.getByText('Loading...')).toBeInTheDocument();
  });

  it('shows error state', () => {
    mockUseTimeEntries.mockReturnValue({
      entries: [],
      total: 0,
      isLoading: false,
      error: new Error('Test error'),
      query: '',
      setQuery: vi.fn(),
      from: undefined,
      setFrom: vi.fn(),
      to: undefined,
      setTo: vi.fn(),
      limit: 50,
      setLimit: vi.fn(),
      offset: 0,
      setOffset: vi.fn(),
      sortKey: 'date',
      sortDir: 'desc',
      toggleSort: vi.fn(),
      createMut: { mutate: vi.fn(), isPending: false },
      deleteMut: { mutate: vi.fn(), isPending: false },
      nextPage: vi.fn(),
      prevPage: vi.fn(),
      hasNextPage: false,
      hasPrevPage: false,
      currentPage: 1,
      totalPages: 1
    });

    renderWithQueryClient(<TimeEntriesPage />);
    
    expect(screen.getByText(/Error loading time entries/)).toBeInTheDocument();
  });

  it('handles search input', () => {
    const setQuery = vi.fn();
    mockUseTimeEntries.mockReturnValue({
      entries: [],
      total: 0,
      isLoading: false,
      error: null,
      query: '',
      setQuery,
      from: undefined,
      setFrom: vi.fn(),
      to: undefined,
      setTo: vi.fn(),
      limit: 50,
      setLimit: vi.fn(),
      offset: 0,
      setOffset: vi.fn(),
      sortKey: 'date',
      sortDir: 'desc',
      toggleSort: vi.fn(),
      createMut: { mutate: vi.fn(), isPending: false },
      deleteMut: { mutate: vi.fn(), isPending: false },
      nextPage: vi.fn(),
      prevPage: vi.fn(),
      hasNextPage: false,
      hasPrevPage: false,
      currentPage: 1,
      totalPages: 1
    });

    renderWithQueryClient(<TimeEntriesPage />);
    
    const searchInput = screen.getByPlaceholderText('Search entries...');
    fireEvent.change(searchInput, { target: { value: 'test search' } });
    
    expect(setQuery).toHaveBeenCalledWith('test search');
  });

  it('handles pagination', () => {
    const nextPage = vi.fn();
    const prevPage = vi.fn();
    
    mockUseTimeEntries.mockReturnValue({
      entries: [],
      total: 100,
      isLoading: false,
      error: null,
      query: '',
      setQuery: vi.fn(),
      from: undefined,
      setFrom: vi.fn(),
      to: undefined,
      setTo: vi.fn(),
      limit: 50,
      setLimit: vi.fn(),
      offset: 0,
      setOffset: vi.fn(),
      sortKey: 'date',
      sortDir: 'desc',
      toggleSort: vi.fn(),
      createMut: { mutate: vi.fn(), isPending: false },
      deleteMut: { mutate: vi.fn(), isPending: false },
      hasNextPage: true,
      hasPrevPage: true,
      nextPage,
      prevPage,
      currentPage: 2,
      totalPages: 5
    });

    renderWithQueryClient(<TimeEntriesPage />);
    
    expect(screen.getByText('Page 2 of 5')).toBeInTheDocument();
    
    const nextButton = screen.getByTitle('Next page');
    const prevButton = screen.getByTitle('Previous page');
    
    fireEvent.click(nextButton);
    expect(nextPage).toHaveBeenCalled();
    
    fireEvent.click(prevButton);
    expect(prevPage).toHaveBeenCalled();
  });

  it('handles API errors gracefully', async () => {
    mockTimeEntriesApi.listTimeEntries.mockRejectedValue(new Error('Network error'));
    
    mockUseTimeEntries.mockReturnValue({
      entries: [],
      total: 0,
      isLoading: false,
      error: new Error('Network error'),
      query: '',
      setQuery: vi.fn(),
      from: undefined,
      setFrom: vi.fn(),
      to: undefined,
      setTo: vi.fn(),
      limit: 50,
      setLimit: vi.fn(),
      offset: 0,
      setOffset: vi.fn(),
      sortKey: 'date',
      sortDir: 'desc',
      toggleSort: vi.fn(),
      createMut: { mutate: vi.fn(), isPending: false },
      deleteMut: { mutate: vi.fn(), isPending: false },
      nextPage: vi.fn(),
      prevPage: vi.fn(),
      hasNextPage: false,
      hasPrevPage: false,
      currentPage: 1,
      totalPages: 1
    });

    renderWithQueryClient(<TimeEntriesPage />);
    
    expect(screen.getByText(/Error loading time entries/)).toBeInTheDocument();
    expect(screen.getByText(/Network error/)).toBeInTheDocument();
  });
});