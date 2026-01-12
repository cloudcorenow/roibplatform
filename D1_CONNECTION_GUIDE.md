# D1 Database Connection Guide

## Overview

Your frontend is now connected to the Cloudflare D1 database through a Cloudflare Worker API. Here's how everything works:

## Architecture

```
Frontend (React/Vite)
    ↓ HTTP Requests
Worker API (Hono/Cloudflare Workers)
    ↓ SQL Queries
D1 Database (Cloudflare)
```

## Current Setup

### 1. Database Configuration

**Database Name:** `roiblplatform`
**Database ID:** `409e74c6-6687-4b06-b3d2-e5f265779c25`
**Binding:** `DB` (available in worker as `c.env.DB`)

### 2. Worker API

**Local Dev URL:** `http://localhost:8787`
**Production URL:** Will be assigned when deployed

**API Endpoints:**
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/me` - Get current user
- `GET /api/time-entries` - List time entries
- `POST /api/time-entries` - Create time entry
- `DELETE /api/time-entries/:id` - Delete time entry
- `POST /api/time-entries/batch` - Batch create time entries
- Plus routes for analytics, documents, assessments, etc.

### 3. Frontend Configuration

The frontend is configured to connect to the worker API via:
- **Environment Variable:** `VITE_API_URL=http://localhost:8787`
- **API Services:** Located in `src/services/` directory

## Running Locally

### Step 1: Start the Worker (Terminal 1)

```bash
npm run dev:worker
```

This starts the Cloudflare Worker at `http://localhost:8787`

### Step 2: Start the Frontend (Terminal 2)

```bash
npm run dev
```

This starts the Vite dev server at `http://localhost:5173`

## Database Migrations

Your database tables have already been created. To run migrations again or update the schema:

```bash
# Apply migrations to production database
npm run db:migrate

# Apply migrations to staging database
npm run db:migrate:staging
```

## Environment Secrets

Some features require environment secrets. Set them using:

```bash
# JWT Secret (for authentication)
npx wrangler secret put JWT_SECRET

# CentralReach Integration
npx wrangler secret put CENTRALREACH_API_KEY

# QuickBooks Integration
npx wrangler secret put QUICKBOOKS_CLIENT_ID
npx wrangler secret put QUICKBOOKS_CLIENT_SECRET
```

## Testing the Connection

1. Start both the worker and frontend
2. Navigate to `http://localhost:5173`
3. Try registering a new user
4. Create some time entries
5. Check the browser console for any API errors

## How It Works

### Frontend → Worker Communication

The frontend makes authenticated API requests:

```typescript
// Example from src/services/timeEntriesApi.ts
const token = localStorage.getItem('auth_token');
const response = await fetch(`${VITE_API_URL}/api/time-entries`, {
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  }
});
```

### Worker → D1 Communication

The worker queries the D1 database:

```typescript
// Example from src/routes/timeEntries.ts
const result = await c.env.DB.prepare(
  'SELECT * FROM time_entries WHERE tenant_id = ? LIMIT ?'
).bind(tenantId, limit).all();
```

## Database Schema

Key tables:
- `users` - User accounts and authentication
- `sessions` - Refresh tokens for JWT auth
- `time_entries` - Time tracking records
- `documents` - Document metadata (files stored in R2)
- `assessments` - R&D assessment data

Full schema is in `schema.sql`

## Deployment

To deploy the worker to production:

```bash
npm run deploy:worker
```

Your worker will be deployed to Cloudflare's edge network and get a production URL.

## Next Steps

1. **Set JWT Secret:** Required for authentication to work
   ```bash
   npx wrangler secret put JWT_SECRET
   # Enter a random secure string (at least 32 characters)
   ```

2. **Test Authentication:** Try registering and logging in

3. **Test Data Operations:** Create, read, update, and delete time entries

4. **Deploy to Production:** Once everything works locally, deploy the worker

## Troubleshooting

### CORS Errors

The worker is configured to allow requests from:
- `http://localhost:5173` (local dev)
- `https://localhost:5173`
- `https://meek-cheesecake-1382d7.netlify.app` (production)

### Authentication Errors

Make sure you've set the `JWT_SECRET`:
```bash
npx wrangler secret put JWT_SECRET
```

### Database Errors

Verify your tables exist:
```bash
npx wrangler d1 execute roiblplatform --command "SELECT name FROM sqlite_master WHERE type='table';"
```

### Worker Not Starting

Check that port 8787 isn't in use:
```bash
lsof -i :8787
```
