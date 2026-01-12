# ROI BLUEPRINT - R&D Tax Credit Platform

A comprehensive platform for managing R&D tax credit documentation and compliance, built with React, TypeScript, and Cloudflare Workers.

## Tech Stack

- **Frontend Framework**: React 18.3 + TypeScript 5.7
- **Build Tool**: Vite 7.3.0
- **Styling**: Tailwind CSS 3.4
- **Icons**: Lucide React 0.469
- **Backend Framework**: Hono 4.6
- **Testing**: Vitest 3.2 + React Testing Library
- **Type Safety**: Zod 3.24 for runtime validation

## Architecture

- **Frontend**: React + TypeScript + Vite + Tailwind CSS
- **Backend**: Cloudflare Workers with Hono framework
- **Database**: Cloudflare D1 (SQLite)
- **Storage**: Cloudflare R2 (document storage)
- **Cache**: Cloudflare KV
- **Deployment**: Cloudflare Pages (frontend) + Cloudflare Workers (API)

## Development Setup

### Prerequisites
- Node.js 18+
- Cloudflare account
- Wrangler CLI

### Installation

```bash
# Install dependencies
npm install

# Install Wrangler globally
npm install -g wrangler

# Login to Cloudflare
wrangler login
```

### Cloudflare Resources Setup

```bash
# Create D1 database
wrangler d1 create roiblueprint
# Copy the database_id and update wrangler.toml line 17

# Create staging D1 database (optional)
wrangler d1 create roiblueprint-staging
# Copy the database_id and update wrangler.toml line 22

# Create KV namespace
wrangler kv:namespace create "KV"
# Copy the id and update wrangler.toml line 26

# Create R2 bucket for document storage
wrangler r2 bucket create roiblueprint-documents

# Run migrations
npm run db:migrate

# For staging environment
npm run db:migrate:staging
```

### Environment Variables

**Frontend (.env):**
```bash
VITE_API_URL=http://localhost:8787
```

**Worker Secrets (required for production):**
```bash
# Set secrets for production environment
wrangler secret put CENTRALREACH_API_KEY
wrangler secret put CENTRALREACH_BASE_URL
wrangler secret put CENTRALREACH_ORG_ID
wrangler secret put QUICKBOOKS_CLIENT_ID
wrangler secret put QUICKBOOKS_CLIENT_SECRET
wrangler secret put JWT_SECRET
wrangler secret put RESEND_API_KEY

# Set secrets for staging environment (optional)
wrangler secret put CENTRALREACH_API_KEY --env staging
wrangler secret put JWT_SECRET --env staging
wrangler secret put RESEND_API_KEY --env staging
```

**Email Configuration:**
- Email service: Resend
- From address: `noreply@notifications.roiblueprint.com`
- Get your API key from: https://resend.com/api-keys

**Note:** The `APP_ORIGIN` is configured in `wrangler.toml` and should match your frontend URL.

### Development

```bash
# Start frontend dev server
npm run dev

# Start Worker dev server (in another terminal)
npm run dev:worker
```

### Deployment

**Deploy Backend (Cloudflare Workers):**
```bash
# Deploy to production
npm run deploy:worker

# Deploy to staging
wrangler deploy --env staging

# Your API will be available at:
# https://roiblueprint-api.YOUR_SUBDOMAIN.workers.dev
```

**Deploy Frontend (Cloudflare Pages):**
```bash
# Build the frontend
npm run build

# Deploy to Cloudflare Pages
npx wrangler pages deploy dist --project-name=roiblueprint

# Or connect GitHub for automatic deployments:
# 1. Go to Cloudflare Dashboard → Pages
# 2. Connect your GitHub repository
# 3. Set build command: npm run build
# 4. Set build output directory: dist
# 5. Add environment variables from .env

# Your frontend will be available at:
# https://roiblueprint.pages.dev
```

**Update CORS after deployment:**
After deploying to Cloudflare Pages, update `wrangler.toml` line 44:
```toml
APP_ORIGIN = "https://roiblueprint.pages.dev"
```
Then redeploy the Worker with `npm run deploy:worker`.

## Features

- **Time Tracking**: Comprehensive time entry management with R&D classification
- **Project Management**: Track R&D projects and their progress
- **Expense Tracking**: Monitor R&D-qualified expenses
- **Document Management**: Store and organize R&D documentation
- **Compliance Wizard**: Ensure IRS Section 41 compliance
- **Analytics Dashboard**: Visualize R&D activities and metrics
- **Integrations**: CentralReach and QuickBooks Online sync
- **User Management**: Role-based access control
- **Audit Reports**: Generate IRS-ready documentation
- **Email Notifications**: Automated notifications via Resend (noreply@notifications.roiblueprint.com)

## API Endpoints

### Time Entries
- `GET /api/time-entries` - List time entries (paginated)
- `POST /api/time-entries` - Create time entry
- `DELETE /api/time-entries/:id` - Delete time entry

### CentralReach Integration
- `GET /api/centralreach/clients` - Fetch clients
- `GET /api/centralreach/staff` - Fetch staff
- `GET /api/centralreach/timeentries` - Fetch time entries
- `POST /api/centralreach/sync` - Sync data

### QuickBooks Integration
- `GET /api/quickbooks/customers` - Fetch customers
- `GET /api/quickbooks/employees` - Fetch employees
- `POST /api/quickbooks/config` - Save configuration

### Email Notifications
- `POST /api/notifications/send` - Send email notification
- Uses Resend API with `noreply@notifications.roiblueprint.com`

## Testing

```bash
# Run tests
npm test

# Run tests with UI
npm run test:ui

# Type checking
npm run typecheck

# Linting
npm run lint
```

## Security

- **Tenant isolation**: All data is filtered by tenant_id
- **JWT authentication**: Secure API access
- **Input validation**: Zod schemas for all inputs
- **Rate limiting**: Built into Cloudflare Workers
- **CORS protection**: Configured for specific origins

## Performance

- **Server-side pagination**: Efficient data loading
- **Virtualized tables**: Handle large datasets
- **KV caching**: Cache external API responses
- **React Query**: Optimistic updates and caching
- **Edge deployment**: Global low-latency access via Cloudflare network
- **R2 storage**: Fast document retrieval with built-in CDN

## Scaling & Costs

**Current Setup (6 users, 25 clients):**
- All services stay on **Cloudflare free tier**
- Cloudflare D1: 5M reads/day, 100K writes/day, 5GB storage
- Cloudflare R2: 10GB storage, 1M writes/month, 10M reads/month
- Cloudflare Workers: 100K requests/day
- Cloudflare Pages: Unlimited bandwidth, 500 builds/month
- **Estimated monthly cost: $0**

**Scaling headroom:**
- Can handle 100x current traffic before hitting free tier limits
- D1 paid tier ($0.50/month): Unlimited reads/writes for production scale
- Enterprise-ready with minimal configuration changes