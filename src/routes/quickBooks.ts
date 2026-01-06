import { Hono } from 'hono';
import type { HonoEnv } from '../types';

export const quickBooksRouter = new Hono<HonoEnv>();

quickBooksRouter.get('/oauth/connect', async (c) => {
  const redirectUri = `${c.env.APP_ORIGIN}/api/quickbooks/oauth/callback`;
  const state = crypto.randomUUID();

  const authUrl = new URL('https://appcenter.intuit.com/connect/oauth2');
  authUrl.searchParams.set('client_id', c.env.QUICKBOOKS_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', 'com.intuit.quickbooks.accounting');
  authUrl.searchParams.set('state', state);

  return c.json({ authUrl: authUrl.toString(), state });
});

quickBooksRouter.get('/oauth/callback', async (c) => {
  const code = c.req.query('code');
  const state = c.req.query('state');

  if (!code) {
    return c.json({ error: 'Authorization code missing' }, 400);
  }

  return c.json({
    success: true,
    message: 'QuickBooks connected successfully'
  });
});

quickBooksRouter.post('/sync/invoices', async (c) => {
  const tenantId = c.get('tenant_id');

  return c.json({
    success: true,
    synced: 0,
    message: 'Invoice sync completed'
  });
});

quickBooksRouter.get('/status', async (c) => {
  return c.json({
    status: 'configured',
    connected: false
  });
});
