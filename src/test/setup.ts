import '@testing-library/jest-dom';

// Mock environment variables
Object.defineProperty(import.meta, 'env', {
  value: {
    VITE_API_URL: 'http://localhost:8787/api'
  }
});

// Mock fetch for tests
global.fetch = vi.fn();