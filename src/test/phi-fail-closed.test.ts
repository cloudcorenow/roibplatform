import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Hono } from 'hono';
import { enforceHIPAAMiddleware, auditRouteAccess, registerPHIRoute } from '../middleware/phi-route-guard';
import { initializeHIPAASecurity } from '../middleware/hipaa-security';

type Bindings = {
  DB: D1Database;
  MASTER_ENCRYPTION_KEY: string;
};

describe('PHI Route Fail-Closed Security', () => {
  let app: Hono<{ Bindings: Bindings }>;
  let mockDb: any;
  let mockEnv: Bindings;

  beforeEach(() => {
    app = new Hono<{ Bindings: Bindings }>();

    mockDb = {
      prepare: vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          first: vi.fn().mockResolvedValue(null),
          all: vi.fn().mockResolvedValue({ results: [] }),
          run: vi.fn().mockResolvedValue({ success: true })
        })
      })
    };

    mockEnv = {
      DB: mockDb as any,
      MASTER_ENCRYPTION_KEY: 'test-master-key-32-bytes-long-12'
    };
  });

  describe('Test 1: PHI routes MUST fail without HIPAA middleware', () => {
    it('should return 500 when HIPAA middleware not initialized', async () => {
      registerPHIRoute({
        route: '/api/test-phi',
        method: 'POST',
        phiRoute: 'assessments',
        requiresHIPAAMiddleware: true,
        requiresSession: true,
        requiresAudit: true
      });

      app.use('*', async (c, next) => {
        c.set('userId', 'user-123');
        c.set('tenantId', 'tenant-123');
        await next();
      });

      app.use('*', enforceHIPAAMiddleware());

      app.post('/api/test-phi', async (c) => {
        return c.json({ data: 'sensitive' });
      });

      const req = new Request('http://localhost/api/test-phi', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer valid-jwt',
          'X-Session-ID': 'session-123'
        }
      });

      const res = await app.fetch(req, mockEnv);

      expect(res.status).toBe(500);
      const body = await res.json();
      expect(body.error).toBe('Security configuration error');
      expect(body.message).toContain('HIPAA security middleware');
    });

    it('should succeed when HIPAA middleware IS initialized', async () => {
      registerPHIRoute({
        route: '/api/test-phi-ok',
        method: 'POST',
        phiRoute: 'assessments',
        requiresHIPAAMiddleware: true,
        requiresSession: true,
        requiresAudit: true
      });

      app.use('*', async (c, next) => {
        c.set('DB', mockEnv.DB);
        c.set('MASTER_ENCRYPTION_KEY', mockEnv.MASTER_ENCRYPTION_KEY);
        await next();
      });

      app.use('*', initializeHIPAASecurity());

      app.use('*', async (c, next) => {
        c.set('userId', 'user-123');
        c.set('tenantId', 'tenant-123');
        c.set('ipAddress', '1.2.3.4');
        c.set('userAgent', 'test-agent');
        c.set('requestId', 'req-123');
        await next();
      });

      mockDb.prepare.mockImplementation((sql: string) => {
        const mockChain = {
          bind: vi.fn().mockReturnValue({
            first: vi.fn().mockResolvedValue({
              id: 'session-123',
              user_id: 'user-123',
              tenant_id: 'tenant-123',
              last_activity_at: Math.floor(Date.now() / 1000),
              created_at: Math.floor(Date.now() / 1000),
              ip_address: '1.2.3.4',
              user_agent: 'test-agent'
            }),
            all: vi.fn().mockResolvedValue({ results: [] }),
            run: vi.fn().mockResolvedValue({ success: true })
          })
        };
        return mockChain;
      });

      app.use('*', enforceHIPAAMiddleware());
      app.use('*', auditRouteAccess());

      app.post('/api/test-phi-ok', async (c) => {
        return c.json({ data: 'sensitive' });
      });

      const req = new Request('http://localhost/api/test-phi-ok', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer valid-jwt',
          'X-Session-ID': 'session-123'
        }
      });

      const res = await app.fetch(req, mockEnv);

      expect(res.status).toBe(200);
    });
  });

  describe('Test 2: PHI routes MUST fail without valid session', () => {
    it('should return 401 when X-Session-ID header missing', async () => {
      registerPHIRoute({
        route: '/api/assessments',
        method: 'GET',
        phiRoute: 'assessments',
        requiresHIPAAMiddleware: true,
        requiresSession: true,
        requiresAudit: true
      });

      app.use('*', async (c, next) => {
        c.set('DB', mockEnv.DB);
        c.set('MASTER_ENCRYPTION_KEY', mockEnv.MASTER_ENCRYPTION_KEY);
        await next();
      });

      app.use('*', initializeHIPAASecurity());

      app.use('*', async (c, next) => {
        c.set('userId', 'user-123');
        c.set('tenantId', 'tenant-123');
        c.set('ipAddress', '1.2.3.4');
        c.set('userAgent', 'test-agent');
        c.set('requestId', 'req-123');
        await next();
      });

      app.use('*', enforceHIPAAMiddleware());

      app.get('/api/assessments', async (c) => {
        return c.json({ data: 'phi-data' });
      });

      const req = new Request('http://localhost/api/assessments', {
        method: 'GET',
        headers: {
          'Authorization': 'Bearer valid-jwt'
        }
      });

      const res = await app.fetch(req, mockEnv);

      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.error).toBe('Session required');
      expect(body.message).toContain('X-Session-ID');
    });

    it('should return 401 when session is expired (idle timeout)', async () => {
      registerPHIRoute({
        route: '/api/assessments',
        method: 'GET',
        phiRoute: 'assessments',
        requiresHIPAAMiddleware: true,
        requiresSession: true,
        requiresAudit: true
      });

      app.use('*', async (c, next) => {
        c.set('DB', mockEnv.DB);
        c.set('MASTER_ENCRYPTION_KEY', mockEnv.MASTER_ENCRYPTION_KEY);
        await next();
      });

      app.use('*', initializeHIPAASecurity());

      app.use('*', async (c, next) => {
        c.set('userId', 'user-123');
        c.set('tenantId', 'tenant-123');
        c.set('ipAddress', '1.2.3.4');
        c.set('userAgent', 'test-agent');
        c.set('requestId', 'req-123');
        await next();
      });

      mockDb.prepare.mockImplementation((sql: string) => {
        return {
          bind: vi.fn().mockReturnValue({
            first: vi.fn().mockResolvedValue({
              id: 'session-123',
              user_id: 'user-123',
              tenant_id: 'tenant-123',
              last_activity_at: Math.floor(Date.now() / 1000) - (16 * 60),
              created_at: Math.floor(Date.now() / 1000) - (16 * 60),
              ip_address: '1.2.3.4',
              user_agent: 'test-agent'
            }),
            all: vi.fn().mockResolvedValue({ results: [] }),
            run: vi.fn().mockResolvedValue({ success: true })
          })
        };
      });

      app.use('*', enforceHIPAAMiddleware());

      app.get('/api/assessments', async (c) => {
        return c.json({ data: 'phi-data' });
      });

      const req = new Request('http://localhost/api/assessments', {
        method: 'GET',
        headers: {
          'Authorization': 'Bearer valid-jwt',
          'X-Session-ID': 'session-123'
        }
      });

      const res = await app.fetch(req, mockEnv);

      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.error).toBe('Session invalid');
      expect(body.code).toContain('SESSION');
    });

    it('should return 401 when session IP address mismatches', async () => {
      registerPHIRoute({
        route: '/api/assessments',
        method: 'GET',
        phiRoute: 'assessments',
        requiresHIPAAMiddleware: true,
        requiresSession: true,
        requiresAudit: true
      });

      app.use('*', async (c, next) => {
        c.set('DB', mockEnv.DB);
        c.set('MASTER_ENCRYPTION_KEY', mockEnv.MASTER_ENCRYPTION_KEY);
        await next();
      });

      app.use('*', initializeHIPAASecurity());

      app.use('*', async (c, next) => {
        c.set('userId', 'user-123');
        c.set('tenantId', 'tenant-123');
        c.set('ipAddress', '5.6.7.8');
        c.set('userAgent', 'test-agent');
        c.set('requestId', 'req-123');
        await next();
      });

      mockDb.prepare.mockImplementation((sql: string) => {
        return {
          bind: vi.fn().mockReturnValue({
            first: vi.fn().mockResolvedValue({
              id: 'session-123',
              user_id: 'user-123',
              tenant_id: 'tenant-123',
              last_activity_at: Math.floor(Date.now() / 1000),
              created_at: Math.floor(Date.now() / 1000),
              ip_address: '1.2.3.4',
              user_agent: 'test-agent'
            }),
            all: vi.fn().mockResolvedValue({ results: [] }),
            run: vi.fn().mockResolvedValue({ success: true })
          })
        };
      });

      app.use('*', enforceHIPAAMiddleware());

      app.get('/api/assessments', async (c) => {
        return c.json({ data: 'phi-data' });
      });

      const req = new Request('http://localhost/api/assessments', {
        method: 'GET',
        headers: {
          'Authorization': 'Bearer valid-jwt',
          'X-Session-ID': 'session-123'
        }
      });

      const res = await app.fetch(req, mockEnv);

      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.error).toBe('Session invalid');
    });
  });

  describe('Test 3: PHI routes MUST fail when route not registered', () => {
    it('should return 500 when PHI route not registered with HIPAA middleware', async () => {
      app.use('*', async (c, next) => {
        c.set('DB', mockEnv.DB);
        c.set('MASTER_ENCRYPTION_KEY', mockEnv.MASTER_ENCRYPTION_KEY);
        await next();
      });

      app.use('*', initializeHIPAASecurity());

      app.use('*', async (c, next) => {
        c.set('userId', 'user-123');
        c.set('tenantId', 'tenant-123');
        c.set('ipAddress', '1.2.3.4');
        c.set('userAgent', 'test-agent');
        c.set('requestId', 'req-123');
        await next();
      });

      mockDb.prepare.mockImplementation((sql: string) => {
        return {
          bind: vi.fn().mockReturnValue({
            first: vi.fn().mockResolvedValue({
              id: 'session-123',
              user_id: 'user-123',
              tenant_id: 'tenant-123',
              last_activity_at: Math.floor(Date.now() / 1000),
              created_at: Math.floor(Date.now() / 1000),
              ip_address: '1.2.3.4',
              user_agent: 'test-agent'
            }),
            all: vi.fn().mockResolvedValue({ results: [] }),
            run: vi.fn().mockResolvedValue({ success: true })
          })
        };
      });

      app.use('*', enforceHIPAAMiddleware());

      app.get('/api/patient-records', async (c) => {
        return c.json({ data: 'unprotected-phi' });
      });

      const req = new Request('http://localhost/api/patient-records', {
        method: 'GET',
        headers: {
          'Authorization': 'Bearer valid-jwt',
          'X-Session-ID': 'session-123'
        }
      });

      const res = await app.fetch(req, mockEnv);

      expect(res.status).toBe(500);
      const body = await res.json();
      expect(body.error).toBe('Security configuration error');
      expect(body.message).toContain('not registered');
    });
  });

  describe('Test 4: Audit logging MUST be guaranteed', () => {
    it('should write audit log for successful PHI access', async () => {
      let auditLogWritten = false;

      registerPHIRoute({
        route: '/api/documents',
        method: 'GET',
        phiRoute: 'documents',
        requiresHIPAAMiddleware: true,
        requiresSession: true,
        requiresAudit: true
      });

      app.use('*', async (c, next) => {
        c.set('DB', mockEnv.DB);
        c.set('MASTER_ENCRYPTION_KEY', mockEnv.MASTER_ENCRYPTION_KEY);
        await next();
      });

      app.use('*', initializeHIPAASecurity());

      app.use('*', async (c, next) => {
        c.set('userId', 'user-123');
        c.set('tenantId', 'tenant-123');
        c.set('ipAddress', '1.2.3.4');
        c.set('userAgent', 'test-agent');
        c.set('requestId', 'req-123');
        await next();
      });

      mockDb.prepare.mockImplementation((sql: string) => {
        if (sql.includes('INSERT INTO audit_logs')) {
          auditLogWritten = true;
        }

        return {
          bind: vi.fn().mockReturnValue({
            first: vi.fn().mockResolvedValue({
              id: 'session-123',
              user_id: 'user-123',
              tenant_id: 'tenant-123',
              last_activity_at: Math.floor(Date.now() / 1000),
              created_at: Math.floor(Date.now() / 1000),
              ip_address: '1.2.3.4',
              user_agent: 'test-agent',
              current_hash: 'prev-hash-123'
            }),
            all: vi.fn().mockResolvedValue({ results: [] }),
            run: vi.fn().mockResolvedValue({ success: true })
          })
        };
      });

      app.use('*', enforceHIPAAMiddleware());
      app.use('*', auditRouteAccess());

      app.get('/api/documents', async (c) => {
        return c.json({ data: 'document-list' });
      });

      const req = new Request('http://localhost/api/documents', {
        method: 'GET',
        headers: {
          'Authorization': 'Bearer valid-jwt',
          'X-Session-ID': 'session-123'
        }
      });

      const res = await app.fetch(req, mockEnv);

      expect(res.status).toBe(200);
      expect(auditLogWritten).toBe(true);
    });

    it('should write audit log for failed PHI access attempts', async () => {
      let auditLogWritten = false;

      registerPHIRoute({
        route: '/api/documents',
        method: 'GET',
        phiRoute: 'documents',
        requiresHIPAAMiddleware: true,
        requiresSession: true,
        requiresAudit: true
      });

      app.use('*', async (c, next) => {
        c.set('DB', mockEnv.DB);
        c.set('MASTER_ENCRYPTION_KEY', mockEnv.MASTER_ENCRYPTION_KEY);
        await next();
      });

      app.use('*', initializeHIPAASecurity());

      app.use('*', async (c, next) => {
        c.set('userId', 'user-123');
        c.set('tenantId', 'tenant-123');
        c.set('ipAddress', '1.2.3.4');
        c.set('userAgent', 'test-agent');
        c.set('requestId', 'req-123');
        await next();
      });

      mockDb.prepare.mockImplementation((sql: string) => {
        if (sql.includes('INSERT INTO audit_logs')) {
          auditLogWritten = true;
        }

        return {
          bind: vi.fn().mockReturnValue({
            first: vi.fn().mockResolvedValue({
              id: 'session-123',
              user_id: 'user-123',
              tenant_id: 'tenant-123',
              last_activity_at: Math.floor(Date.now() / 1000),
              created_at: Math.floor(Date.now() / 1000),
              ip_address: '1.2.3.4',
              user_agent: 'test-agent',
              current_hash: 'prev-hash-123'
            }),
            all: vi.fn().mockResolvedValue({ results: [] }),
            run: vi.fn().mockResolvedValue({ success: true })
          })
        };
      });

      app.use('*', enforceHIPAAMiddleware());
      app.use('*', auditRouteAccess());

      app.get('/api/documents', async (c) => {
        throw new Error('Unauthorized access');
      });

      const req = new Request('http://localhost/api/documents', {
        method: 'GET',
        headers: {
          'Authorization': 'Bearer valid-jwt',
          'X-Session-ID': 'session-123'
        }
      });

      try {
        await app.fetch(req, mockEnv);
      } catch (e) {
      }

      expect(auditLogWritten).toBe(true);
    });
  });

  describe('Test 5: Non-PHI routes should NOT be affected', () => {
    it('should allow non-PHI routes without session', async () => {
      app.use('*', async (c, next) => {
        c.set('DB', mockEnv.DB);
        c.set('MASTER_ENCRYPTION_KEY', mockEnv.MASTER_ENCRYPTION_KEY);
        await next();
      });

      app.use('*', initializeHIPAASecurity());

      app.use('*', async (c, next) => {
        c.set('userId', 'user-123');
        c.set('tenantId', 'tenant-123');
        c.set('ipAddress', '1.2.3.4');
        c.set('userAgent', 'test-agent');
        await next();
      });

      app.use('*', enforceHIPAAMiddleware());

      app.get('/api/health', async (c) => {
        return c.json({ status: 'ok' });
      });

      const req = new Request('http://localhost/api/health', {
        method: 'GET',
        headers: {
          'Authorization': 'Bearer valid-jwt'
        }
      });

      const res = await app.fetch(req, mockEnv);

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.status).toBe('ok');
    });
  });
});
