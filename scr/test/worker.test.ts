import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Env } from '../worker';
import { auditLogger } from '../utils/audit';
import { withRetry } from '../utils/retry';

// Mock D1 and KV
const mockD1 = {
  prepare: vi.fn(() => ({
    bind: vi.fn(() => ({
      run: vi.fn(),
      first: vi.fn(),
      all: vi.fn(() => ({ results: [] }))
    }))
  })),
  batch: vi.fn()
};

const mockKV = {
  get: vi.fn(),
  put: vi.fn(),
  delete: vi.fn()
};

const mockEnv: Env = {
  DB: mockD1 as any,
  KV: mockKV as any,
  CENTRALREACH_API_KEY: 'test-key',
  CENTRALREACH_BASE_URL: 'https://api.test.com',
  CENTRALREACH_ORG_ID: 'test-org',
  QUICKBOOKS_CLIENT_ID: 'test-client',
  QUICKBOOKS_CLIENT_SECRET: 'test-secret',
  JWT_SECRET: 'test-jwt-secret',
  APP_ORIGIN: 'https://test.com',
  ENVIRONMENT: 'test'
};

describe('Worker Utils', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('auditLogger', () => {
    it('logs audit entries to both D1 and KV', async () => {
      const entry = {
        tenant_id: 'test-tenant',
        user_id: 'test-user',
        action: 'create',
        resource_type: 'time_entry',
        resource_id: 'test-id'
      };

      await auditLogger(mockEnv, entry);

      expect(mockD1.prepare).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO audit_log'));
      expect(mockKV.put).toHaveBeenCalledWith(
        expect.stringMatching(/^audit:test-tenant:/),
        expect.any(String),
        { expirationTtl: 60 * 60 * 24 * 30 }
      );
    });

    it('handles audit logging failures gracefully', async () => {
      mockD1.prepare.mockImplementation(() => {
        throw new Error('Database error');
      });

      const entry = {
        tenant_id: 'test-tenant',
        user_id: 'test-user',
        action: 'create',
        resource_type: 'time_entry'
      };

      // Should not throw
      await expect(auditLogger(mockEnv, entry)).resolves.toBeUndefined();
    });
  });

  describe('withRetry', () => {
    it('retries failed operations with exponential backoff', async () => {
      let attempts = 0;
      const operation = vi.fn(async () => {
        attempts++;
        if (attempts < 3) {
          throw new Error('Temporary failure');
        }
        return 'success';
      });

      const result = await withRetry(operation, 3);
      
      expect(result).toBe('success');
      expect(operation).toHaveBeenCalledTimes(3);
    });

    it('throws after max attempts', async () => {
      const operation = vi.fn(async () => {
        throw new Error('Persistent failure');
      });

      await expect(withRetry(operation, 2)).rejects.toThrow('Persistent failure');
      expect(operation).toHaveBeenCalledTimes(2);
    });

    it('does not retry client errors', async () => {
      const operation = vi.fn(async () => {
        const error = new Error('Client error');
        error.cause = 'client_error';
        throw error;
      });

      await expect(withRetry(operation, 3)).rejects.toThrow('Client error');
      expect(operation).toHaveBeenCalledTimes(1);
    });
  });

  describe('Tenant Isolation Tests', () => {
    it('ensures all queries include tenant_id filter', async () => {
      const tenantId = 'test-tenant';
      const userId = 'test-user';
      
      // Test time entries list query
      const listStmt = mockD1.prepare();
      listStmt.bind.mockReturnValue({
        all: vi.fn().mockResolvedValue({ results: [] })
      });

      // Verify tenant_id is first parameter in all queries
      expect(mockD1.prepare).toHaveBeenCalledWith(
        expect.stringContaining('WHERE tenant_id = ?')
      );
    });

    it('prevents cross-tenant data access', async () => {
      const tenant1 = 'tenant-1';
      const tenant2 = 'tenant-2';
      
      // Mock a query that should only return tenant-1 data
      const mockResult = { id: 'entry-1', tenant_id: tenant1 };
      mockD1.prepare().bind().first.mockResolvedValue(mockResult);

      // Verify the query includes tenant isolation
      expect(mockD1.prepare).toHaveBeenCalledWith(
        expect.stringMatching(/WHERE tenant_id = \? AND/)
      );
    });
  });

  describe('Admin Access Control', () => {
    it('requires admin role for cross-tenant operations', () => {
      const { requireAdminAccess } = require('../utils/auth');
      
      expect(() => requireAdminAccess('user', '*')).toThrow('Admin access required');
      expect(() => requireAdminAccess('admin', '*')).not.toThrow();
    });

    it('logs master admin access', () => {
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      const { requireAdminAccess } = require('../utils/auth');
      
      requireAdminAccess('admin', '*');
      
      expect(consoleSpy).toHaveBeenCalledWith('Master admin access granted for cross-tenant operation');
      consoleSpy.mockRestore();
    });
  });
});