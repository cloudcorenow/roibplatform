import { beforeAll, afterAll } from 'vitest';

// Mock Cloudflare Worker environment for testing
beforeAll(() => {
  global.crypto = {
    randomUUID: () => 'test-uuid-' + Math.random().toString(36).substr(2, 9),
    subtle: {
      digest: async () => new ArrayBuffer(32)
    }
  } as any;

  // Mock environment variables
  process.env.CENTRALREACH_API_KEY = 'test-api-key';
  process.env.CENTRALREACH_BASE_URL = 'https://api.test.com';
  process.env.QUICKBOOKS_CLIENT_ID = 'test-client-id';
  process.env.JWT_SECRET = 'test-jwt-secret';
});

afterAll(() => {
  // Cleanup if needed
});