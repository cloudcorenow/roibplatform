# ROI Blueprint - Quick Start Guide

## Full Cloudflare Stack Setup

This guide will get your application running in **under 15 minutes**.

## Prerequisites

- Node.js 18+ installed
- Cloudflare account (free tier is fine for development)
- Git

## Step 1: Install Dependencies (2 minutes)

```bash
npm install
```

## Step 2: Set Up Cloudflare (5 minutes)

### A. Login to Cloudflare

```bash
npx wrangler login
```

This opens your browser to authenticate.

### B. Create D1 Database

The database is already configured, but verify it exists:

```bash
npx wrangler d1 list
```

If `roibplatform` is not listed, create it:

```bash
npx wrangler d1 create roibplatform
```

Copy the database ID and update `wrangler.toml` line 15.

### C. Deploy Database Schema

```bash
npm run db:migrate
```

Expected output:
```
✅ Successfully executed SQL
```

Verify tables were created:

```bash
npx wrangler d1 execute roibplatform --command="SELECT name FROM sqlite_master WHERE type='table';"
```

You should see 9 tables including `users`, `time_entries`, `documents`, etc.

### D. Create KV Namespace

```bash
npx wrangler kv:namespace create "KV"
```

Copy the ID and update `wrangler.toml` line 24.

### E. Create R2 Bucket

```bash
npx wrangler r2 bucket create roiblueprint-documents
```

## Step 3: Set Up Secrets (3 minutes)

### Generate JWT Secret

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Copy the output.

### Set Secrets

```bash
# Paste the JWT secret you just generated
npx wrangler secret put JWT_SECRET

# Optional: CentralReach integration (press Enter to skip)
npx wrangler secret put CENTRALREACH_API_KEY
npx wrangler secret put CENTRALREACH_BASE_URL
npx wrangler secret put CENTRALREACH_ORG_ID

# Optional: QuickBooks integration (press Enter to skip)
npx wrangler secret put QUICKBOOKS_CLIENT_ID
npx wrangler secret put QUICKBOOKS_CLIENT_SECRET
```

For development, you can skip the optional integrations.

## Step 4: Start Development Servers (1 minute)

### Terminal 1: Start Backend (Cloudflare Worker)

```bash
npm run dev:worker
```

Backend will be available at: `http://localhost:8787`

Test it:
```bash
curl http://localhost:8787/health
```

Expected response:
```json
{"status":"ok","timestamp":"2026-01-05T...","environment":"production"}
```

### Terminal 2: Start Frontend (Vite)

Open a new terminal:

```bash
npm run dev
```

Frontend will be available at: `http://localhost:5173`

## Step 5: Create Your First User (2 minutes)

### Option A: Via API (Recommended)

```bash
curl -X POST http://localhost:8787/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "SecurePass123!",
    "name": "Admin User",
    "role": "admin"
  }'
```

### Option B: Via UI

1. Open http://localhost:5173
2. Click "Sign Up"
3. Fill in your details
4. Click "Create Account"

### Login

1. Go to http://localhost:5173
2. Enter your email and password
3. Click "Sign In"

## Step 6: Verify Everything Works (2 minutes)

### Test Time Entries

1. Navigate to "Time Tracker" in the sidebar
2. Click "Add Entry"
3. Fill in:
   - Task: "Testing"
   - Hours: 1
   - Date: Today
4. Click "Save"

You should see your time entry in the list.

### Test Documents

1. Navigate to "Documents" in the sidebar
2. Click "Upload Document"
3. Select a test file
4. Add category (e.g., "Invoices")
5. Click "Upload"

You should see your document in the list.

### Test Audit Logs

Check that audit logs are being created:

```bash
npx wrangler d1 execute roibplatform --command="SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 10;"
```

You should see entries for login, time entry creation, etc.

## Common Issues

### Issue: "Database not found"

**Solution:**
```bash
# Make sure database was created
npx wrangler d1 list

# If not listed, create it
npx wrangler d1 create roibplatform
```

### Issue: "JWT_SECRET not found"

**Solution:**
```bash
# Set the secret
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
npx wrangler secret put JWT_SECRET
```

### Issue: "CORS error"

**Solution:**
Check that `wrangler.toml` line 42 includes your frontend URL:
```toml
APP_ORIGIN = "http://localhost:5173"
```

### Issue: "Port already in use"

**Solution:**
```bash
# Kill processes using ports
lsof -ti:8787 | xargs kill -9  # Backend
lsof -ti:5173 | xargs kill -9  # Frontend
```

### Issue: Worker changes not reflecting

**Solution:**
```bash
# Restart the worker
# Press Ctrl+C to stop
npm run dev:worker
```

## Project Structure

```
roiblueprint/
├── src/
│   ├── worker.ts              # Cloudflare Worker (API entry point)
│   ├── routes/                # API routes
│   │   ├── auth.ts           # Authentication endpoints
│   │   ├── timeEntries.ts    # Time tracking endpoints
│   │   ├── documents.ts      # Document management endpoints
│   │   └── ...
│   ├── components/            # React components
│   ├── utils/                 # Utilities and security
│   │   ├── auth.ts           # JWT handling
│   │   ├── security.ts       # Security utilities
│   │   ├── audit.ts          # Audit logging
│   │   └── ...
│   └── App.tsx               # React app entry
├── schema.sql                 # D1 database schema
├── wrangler.toml             # Cloudflare configuration
└── package.json              # Dependencies
```

## Next Steps

### Development

1. **Add Features**: Modify components in `src/components/`
2. **Add API Endpoints**: Create new routes in `src/routes/`
3. **Customize UI**: Edit styles in components (Tailwind CSS)

### Testing

```bash
# Run tests
npm test

# Run with UI
npm run test:ui

# Test worker specifically
npm run test:worker
```

### Deployment

See `CLOUDFLARE_DEPLOYMENT_GUIDE.md` for production deployment.

## Useful Commands

```bash
# Development
npm run dev                    # Start frontend
npm run dev:worker            # Start backend
npm test                      # Run tests

# Database
npm run db:migrate            # Deploy schema
npx wrangler d1 execute roibplatform --command="SELECT * FROM users;" # Query

# Deployment
npm run build                 # Build frontend
npm run deploy:worker         # Deploy backend
npx wrangler pages deploy dist # Deploy frontend

# Debugging
npx wrangler tail             # View worker logs
npx wrangler d1 execute roibplatform --command=".schema" # View schema
```

## Getting Help

- **Documentation**: See README.md and other docs in project root
- **Cloudflare Docs**: https://developers.cloudflare.com
- **Issues**: Check existing GitHub issues or create a new one

## Security Notes

⚠️ **For Development Only:**
- JWT_SECRET is stored in Cloudflare (secure)
- Database is local D1 instance
- Don't commit secrets to Git

⚠️ **Before Production:**
- Review `CLOUDFLARE_HIPAA_COMPLIANCE.md`
- Set up proper monitoring
- Enable WAF and security features
- Sign BAA with Cloudflare if handling PHI

---

## You're All Set! 🎉

Your full-stack Cloudflare application is now running:
- ✅ Frontend: React + TypeScript + Tailwind CSS
- ✅ Backend: Cloudflare Workers + Hono
- ✅ Database: Cloudflare D1 (SQLite)
- ✅ Storage: R2 (documents) + KV (sessions)
- ✅ Security: JWT auth, audit logging, tenant isolation

Happy coding!
