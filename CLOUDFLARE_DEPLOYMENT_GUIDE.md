# Cloudflare Full Stack Deployment Guide

## Architecture Overview

```
Frontend (Cloudflare Pages)
    ↓ HTTPS/TLS 1.3
Cloudflare Workers (Hono API)
    ↓ Internal
├── D1 Database (SQLite)
├── KV Namespace (Sessions/Cache)
└── R2 Bucket (Document Storage)
```

## Prerequisites

1. Cloudflare account with Workers Paid plan ($5/month minimum)
2. `wrangler` CLI installed: `npm install -g wrangler`
3. Logged in: `wrangler login`

## Step 1: Deploy D1 Database

The D1 database is already configured in `wrangler.toml`:
- Database name: `roibplatform`
- Database ID: `409e74c6-6687-4b06-b3d2-e5f265779c25`

Deploy the schema:

```bash
# Deploy to production database
npm run db:migrate

# Or manually:
wrangler d1 execute roibplatform --file=./schema.sql
```

Verify the tables were created:

```bash
wrangler d1 execute roibplatform --command="SELECT name FROM sqlite_master WHERE type='table';"
```

You should see:
- tenants
- users
- sessions
- time_entries
- documents
- assessments
- tenant_switches
- emergency_access_requests
- audit_log

## Step 2: Set Up Secrets

Set required environment secrets:

```bash
# JWT Secret (generate a strong random string)
wrangler secret put JWT_SECRET

# CentralReach Integration (if using)
wrangler secret put CENTRALREACH_API_KEY
wrangler secret put CENTRALREACH_BASE_URL
wrangler secret put CENTRALREACH_ORG_ID

# QuickBooks Integration (if using)
wrangler secret put QUICKBOOKS_CLIENT_ID
wrangler secret put QUICKBOOKS_CLIENT_SECRET
```

**Generate a secure JWT secret:**
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## Step 3: Deploy Worker API

```bash
npm run deploy:worker

# Or manually:
wrangler deploy
```

Your API will be available at:
- **Production**: `https://roiblueprint-api.YOUR_SUBDOMAIN.workers.dev`

Update your `.env` file with the production URL:
```env
VITE_API_URL=https://roiblueprint-api.YOUR_SUBDOMAIN.workers.dev
```

## Step 4: Deploy Frontend to Cloudflare Pages

### Option A: Connect Git Repository (Recommended)

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com) → Pages
2. Click "Create a project" → "Connect to Git"
3. Select your repository
4. Configure build settings:
   - **Framework preset**: Vite
   - **Build command**: `npm run build`
   - **Build output directory**: `dist`
5. Add environment variable:
   - `VITE_API_URL` = `https://roiblueprint-api.YOUR_SUBDOMAIN.workers.dev`
6. Click "Save and Deploy"

### Option B: Direct Upload

```bash
# Build the frontend
npm run build

# Deploy to Pages
wrangler pages deploy dist --project-name=roiblueprint
```

## Step 5: Configure Custom Domain (Optional)

1. Go to Cloudflare Dashboard → Pages → Your Project
2. Click "Custom domains"
3. Add your domain (e.g., `app.yourdomain.com`)
4. Cloudflare will automatically provision SSL certificate

## Step 6: Verify Deployment

Test your API:
```bash
curl https://roiblueprint-api.YOUR_SUBDOMAIN.workers.dev/health
```

Expected response:
```json
{
  "status": "ok",
  "timestamp": "2026-01-05T...",
  "environment": "production"
}
```

## Environment Configuration

### Development
- Frontend: `http://localhost:5173`
- API: `http://localhost:8787`
- Database: Local D1 (wrangler dev)

### Production
- Frontend: `https://roiblueprint.pages.dev` or custom domain
- API: `https://roiblueprint-api.YOUR_SUBDOMAIN.workers.dev`
- Database: Cloudflare D1 (live)

## Monitoring & Logs

### View Worker Logs
```bash
wrangler tail
```

### View D1 Database
```bash
# Execute queries
wrangler d1 execute roibplatform --command="SELECT COUNT(*) FROM users;"

# Export data
wrangler d1 export roibplatform --output=backup.sql
```

### Check R2 Storage
```bash
wrangler r2 bucket list
wrangler r2 object list roiblueprint-documents
```

## Costs (Approximate)

### Workers Paid Plan: $5/month + usage
- 10M requests/month included
- $0.50 per additional million

### D1 Database
- 5GB storage included
- First 25M row reads free/month
- First 50M row writes free/month

### R2 Storage
- 10GB storage free/month
- 10M Class A operations free/month

### Pages (Free)
- Unlimited static requests
- 500 builds/month
- 100GB bandwidth/month

**Typical monthly cost for small-medium app: $5-20**

## Scaling Considerations

### Database
- D1 supports up to 10GB per database
- For larger datasets, consider multiple databases or Cloudflare Hyperdrive with external PostgreSQL

### File Storage
- R2 has no egress fees (unlike S3)
- Suitable for any file volume

### Global Performance
- Workers run on 300+ edge locations worldwide
- Automatic request routing to nearest datacenter
- Sub-10ms latency for most users

## Backup Strategy

### Database Backups
```bash
# Create backup
wrangler d1 export roibplatform --output=backup-$(date +%Y%m%d).sql

# Restore from backup
wrangler d1 execute roibplatform --file=backup-20260105.sql
```

### Document Backups
Use R2 replication or periodic downloads:
```bash
wrangler r2 object download roiblueprint-documents/file.pdf --file=backup/file.pdf
```

## Troubleshooting

### Worker not updating
```bash
wrangler deploy --force
```

### Database migration issues
```bash
# Check current schema
wrangler d1 execute roibplatform --command=".schema"

# Reset database (⚠️ DESTRUCTIVE)
wrangler d1 execute roibplatform --command="DROP TABLE IF EXISTS table_name;"
```

### CORS errors
- Verify `APP_ORIGIN` in `wrangler.toml` matches your frontend URL
- Check CORS middleware in `src/worker.ts`

## Security Checklist

✅ JWT_SECRET is strong and secret
✅ All API endpoints validate authentication
✅ Tenant isolation enforced at database level
✅ Rate limiting enabled
✅ Audit logging active
✅ HTTPS/TLS enforced
✅ No secrets in code or repository

## Next Steps

- [ ] Set up Cloudflare Analytics
- [ ] Configure alerts for errors/downtime
- [ ] Set up staging environment
- [ ] Enable Cloudflare WAF (Web Application Firewall)
- [ ] Review HIPAA compliance documentation
