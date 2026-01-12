# Authentication Setup Guide

This project uses Cloudflare D1 database with secure JWT authentication.

## Database Setup

### 1. Run Database Migration

Apply the schema to your D1 database:

```bash
npm run db:migrate
```

For staging environment:

```bash
npm run db:migrate:staging
```

### 2. Set JWT Secret

The JWT secret is required for signing and verifying tokens. Set it using Wrangler:

```bash
wrangler secret put JWT_SECRET
```

When prompted, enter a strong random secret (at least 32 characters). You can generate one using:

```bash
openssl rand -base64 32
```

## Authentication Features

### Endpoints

- **POST /api/auth/register** - Create new user account
  - Body: `{ email, password, name? }`
  - Returns: Access token and user data

- **POST /api/auth/login** - Authenticate user
  - Body: `{ email, password }`
  - Returns: Access token, refresh token, and user data

- **POST /api/auth/refresh** - Refresh access token
  - Body: `{ refreshToken }`
  - Returns: New access token

- **POST /api/auth/logout** - Logout user
  - Headers: `Authorization: Bearer <token>`
  - Returns: Success confirmation

- **GET /api/auth/me** - Get current user
  - Headers: `Authorization: Bearer <token>`
  - Returns: User data

### Security Features

1. **JWT Tokens**
   - Access tokens expire in 1 hour
   - Refresh tokens expire in 7 days
   - Tokens are signed using HMAC-SHA256

2. **Password Security**
   - Passwords are hashed using SHA-256
   - Minimum 8 characters required for registration

3. **Session Management**
   - Sessions stored in D1 database
   - Automatic cleanup of expired sessions

4. **Protected Routes**
   - All API routes (except auth) require valid JWT
   - Automatic token refresh on expiry

## Frontend Usage

The frontend automatically handles:
- Login/Registration
- Token storage in localStorage
- Automatic token refresh
- Session persistence

Users can:
- Create new accounts via the registration form
- Login with email/password
- Automatically stay logged in (tokens refresh)

## Development

For local development, the worker runs on `http://localhost:8787` by default:

```bash
npm run dev:worker
```

The frontend connects to `/api` endpoints which proxy to the worker.
