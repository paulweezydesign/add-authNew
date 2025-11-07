# Advanced Authentication Features Setup

This document covers the implementation of advanced authentication features including Redis session management, OAuth integration, and role-based access control.

## Features Implemented

### 1. Redis Session Management & Security
- **Redis-based session store** for scalable session management
- **Secure cookie configuration** with httpOnly, secure, and sameSite options
- **Session fingerprinting** for enhanced security (IP and User-Agent tracking)
- **Automated session cleanup** and rotation mechanisms
- **Session activity tracking** with timeout management

### 2. OAuth Social Login Integration
- **Google OAuth 2.0** authentication
- **GitHub OAuth 2.0** authentication
- **Account linking** for existing users
- **Automatic user creation** from OAuth providers
- **Token management** and refresh handling

### 3. Role-Based Access Control (RBAC)
- **Flexible permission system** with role-based access
- **Middleware for route protection** based on roles and permissions
- **Resource ownership validation**
- **Trust score-based access control**
- **Comprehensive permission checking utilities**

## Configuration

### Environment Variables

Create a `.env` file with the following variables:

```env
# Database
DATABASE_URL=postgresql://username:password@localhost:5432/add_auth
DB_HOST=localhost
DB_PORT=5432
DB_NAME=add_auth
DB_USER=postgres
DB_PASSWORD=password
DB_SSL=false

# Server
PORT=3000
NODE_ENV=development

# Security
JWT_SECRET=your-super-secure-jwt-secret-key-min-32-chars
JWT_EXPIRES_IN=24h
JWT_REFRESH_EXPIRES_IN=7d
SESSION_SECRET=your-super-secure-session-secret-key-min-32-chars
SESSION_TIMEOUT=86400000
BCRYPT_ROUNDS=12

# Redis
REDIS_URL=redis://localhost:6379
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0
REDIS_KEY_PREFIX=auth:

# OAuth - Google
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# OAuth - GitHub
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# OAuth Callback
OAUTH_CALLBACK_URL=http://localhost:3000/auth/callback

# Logging
LOG_LEVEL=info

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

### OAuth Provider Setup

#### Google OAuth Setup
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add authorized redirect URIs: `http://localhost:3000/auth/callback/google`

#### GitHub OAuth Setup
1. Go to GitHub Settings > Developer settings > OAuth Apps
2. Create a new OAuth App
3. Set Authorization callback URL: `http://localhost:3000/auth/callback/github`

## Installation & Setup

### 1. Install Dependencies
```bash
npm install
```

### 2. Setup Database
```bash
# Run migrations
npm run migrate migrate
```

### 3. Setup Redis
```bash
# Install Redis (Ubuntu/Debian)
sudo apt update
sudo apt install redis-server

# Start Redis
sudo systemctl start redis-server
sudo systemctl enable redis-server

# Test Redis connection
redis-cli ping
```

### 4. Start Development Server
```bash
npm run dev
```

## Usage Examples

### Basic Authentication Routes

```typescript
import { requireAuth, requireRole, requirePermission } from './middleware/rbac';
import { PERMISSIONS } from './utils/permissions';

// Basic authentication
app.get('/dashboard', requireAuth, (req, res) => {
  res.json({ message: 'Protected dashboard' });
});

// Role-based access
app.get('/admin', requireRole('admin'), (req, res) => {
  res.json({ message: 'Admin only area' });
});

// Multiple roles (user needs ANY of these roles)
app.get('/moderator', requireRole(['admin', 'moderator']), (req, res) => {
  res.json({ message: 'Moderator area' });
});

// Permission-based access
app.get('/users', requirePermission(PERMISSIONS.USER_READ), (req, res) => {
  res.json({ message: 'User list' });
});

// Multiple permissions (user needs ALL permissions)
app.get('/system', requirePermission(
  [PERMISSIONS.SYSTEM_ADMIN, PERMISSIONS.SYSTEM_MONITORING], 
  { requireAll: true }
), (req, res) => {
  res.json({ message: 'System administration' });
});
```

### OAuth Authentication Flow

```typescript
// OAuth login links
app.get('/login', (req, res) => {
  res.json({
    oauth: {
      google: '/auth/google',
      github: '/auth/github'
    }
  });
});

// OAuth account linking (for logged-in users)
app.get('/settings', requireAuth, (req, res) => {
  res.json({
    link: {
      google: '/auth/link/google',
      github: '/auth/link/github'
    },
    unlink: {
      google: 'POST /auth/unlink/google',
      github: 'POST /auth/unlink/github'
    }
  });
});
```

### Session Management

```typescript
import { FingerprintService } from './utils/fingerprint';
import { SessionModel } from './models/Session';

// Get current session info
app.get('/session', requireAuth, (req, res) => {
  res.json({
    sessionId: req.sessionID,
    userId: req.session.userId,
    trustScore: req.session.trustScore,
    lastActivity: req.session.lastActivity,
    fingerprint: req.session.fingerprint
  });
});

// Get all user sessions
app.get('/sessions', requireAuth, async (req, res) => {
  const sessions = await SessionModel.findByUserId(req.session.userId);
  res.json({ sessions });
});

// Invalidate specific session
app.delete('/sessions/:sessionId', requireAuth, async (req, res) => {
  await SessionModel.invalidateByToken(req.params.sessionId);
  res.json({ message: 'Session invalidated' });
});
```

### Permission Checking Utilities

```typescript
import { PermissionService, PERMISSIONS } from './utils/permissions';

// Check specific permission
const canReadUsers = await PermissionService.hasPermission(userId, PERMISSIONS.USER_READ);

// Check multiple permissions (ANY)
const canModerate = await PermissionService.hasAnyPermission(userId, [
  PERMISSIONS.USER_WRITE,
  PERMISSIONS.ROLE_ASSIGN
]);

// Check multiple permissions (ALL)
const canAdminister = await PermissionService.hasAllPermissions(userId, [
  PERMISSIONS.SYSTEM_ADMIN,
  PERMISSIONS.AUDIT_READ
]);

// Check resource-specific permissions
const canEditUser = await PermissionService.canPerformAction(
  userId, 
  'write', 
  'user', 
  targetUserId // Resource owner ID
);

// Check admin status
const isAdmin = await PermissionService.isAdmin(userId);

// Get all user permissions
const permissions = await PermissionService.getUserPermissions(userId);
```

### Role Management

```typescript
import { RoleModel } from './models/Role';

// Create role
const adminRole = await RoleModel.create({
  name: 'admin',
  description: 'System administrator',
  permissions: [
    PERMISSIONS.USER_READ,
    PERMISSIONS.USER_WRITE,
    PERMISSIONS.USER_DELETE,
    PERMISSIONS.ROLE_READ,
    PERMISSIONS.ROLE_WRITE,
    PERMISSIONS.SYSTEM_ADMIN
  ]
});

// Assign role to user
await RoleModel.assignToUser({
  user_id: userId,
  role_id: adminRole.id,
  assigned_by: currentUserId
});

// Check user permissions
const hasPermission = await RoleModel.hasPermission(userId, PERMISSIONS.USER_WRITE);
```

## Security Features

### Session Fingerprinting

```typescript
import { FingerprintService } from './utils/fingerprint';

// Generate fingerprint
const fingerprint = FingerprintService.generateFingerprint(req);

// Validate fingerprint
const validation = FingerprintService.validateFingerprint(currentFingerprint, storedFingerprint);

if (!validation.isValid) {
  // Handle based on risk level
  switch (validation.risk) {
    case 'high':
      // Force re-authentication
      break;
    case 'medium':
      // Update fingerprint, reduce trust score
      break;
    case 'low':
      // Log and continue
      break;
  }
}

// Detect potential session hijacking
const isHijacked = FingerprintService.detectSessionHijacking(currentFingerprint, storedFingerprint);
```

### Trust Score Management

```typescript
// Middleware to require minimum trust score
import { requireTrustScore } from './middleware/rbac';

app.get('/sensitive-operation', 
  requireAuth,
  requireTrustScore(0.8), // Require high trust score
  (req, res) => {
    res.json({ message: 'High-security operation' });
  }
);

// Calculate trust score based on fingerprint history
const trustScore = FingerprintService.calculateTrustScore(fingerprintHistory, currentFingerprint);
```

## API Endpoints

### Authentication
- `GET /auth/google` - Google OAuth login
- `GET /auth/github` - GitHub OAuth login
- `GET /auth/callback/google` - Google OAuth callback
- `GET /auth/callback/github` - GitHub OAuth callback
- `POST /logout` - Logout user

### Account Management
- `GET /auth/link/google` - Link Google account
- `GET /auth/link/github` - Link GitHub account
- `POST /auth/unlink/:provider` - Unlink OAuth account
- `GET /auth/accounts` - Get linked OAuth accounts
- `GET /auth/status` - Get OAuth configuration status

### Session Management
- `GET /session` - Get current session info
- `GET /sessions` - Get all user sessions
- `DELETE /sessions/:sessionId` - Invalidate session

### Protected Resources
- `GET /dashboard` - User dashboard (requires auth)
- `GET /admin` - Admin panel (requires admin role)
- `GET /moderator` - Moderator panel (requires moderator/admin role)
- `GET /users` - User list (requires user:read permission)
- `POST /users` - Create user (requires user:write permission)
- `DELETE /users/:id` - Delete user (requires user:delete permission)

## Error Handling

The system provides comprehensive error handling with specific error codes:

```json
{
  "error": "Forbidden",
  "message": "Insufficient permissions - required roles not found",
  "code": "INSUFFICIENT_PERMISSIONS"
}
```

Common error codes:
- `AUTHENTICATION_REQUIRED` - User not logged in
- `INSUFFICIENT_PERMISSIONS` - User lacks required permissions
- `FINGERPRINT_VALIDATION_FAILED` - Session security validation failed
- `SESSION_EXPIRED` - Session has expired
- `OAUTH_CALLBACK_ERROR` - OAuth authentication failed

## Database Schema

### OAuth Tables
```sql
-- OAuth accounts table
CREATE TABLE oauth_accounts (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    provider VARCHAR(50),
    provider_id VARCHAR(255),
    access_token TEXT,
    refresh_token TEXT,
    profile_data JSONB,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

-- Updated users table with OAuth support
ALTER TABLE users 
ADD COLUMN oauth_providers JSONB DEFAULT '[]',
ADD COLUMN first_name VARCHAR(100),
ADD COLUMN last_name VARCHAR(100);
```

### Role and Permission System
```sql
-- Roles table
CREATE TABLE roles (
    id UUID PRIMARY KEY,
    name VARCHAR(100) UNIQUE,
    description TEXT,
    permissions JSONB,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

-- User roles junction table
CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id),
    role_id UUID REFERENCES roles(id),
    assigned_at TIMESTAMP,
    assigned_by UUID REFERENCES users(id),
    PRIMARY KEY (user_id, role_id)
);
```

## Monitoring and Logging

The system includes comprehensive logging and audit trails:

```typescript
// Audit logging
await AuditLogModel.create({
  user_id: userId,
  action: 'oauth_login',
  resource_type: 'user',
  resource_id: userId,
  details: {
    provider: 'google',
    ip_address: fingerprint.ip,
    user_agent: fingerprint.userAgent
  }
});
```

## Production Considerations

1. **Redis Configuration**: Use Redis Cluster for high availability
2. **Session Security**: Enable secure cookies in production
3. **OAuth Secrets**: Store OAuth credentials securely
4. **Rate Limiting**: Implement rate limiting for OAuth endpoints
5. **Monitoring**: Set up monitoring for session metrics
6. **Backup**: Regular backup of session data and user accounts

## Troubleshooting

### Common Issues

1. **Redis Connection Failed**
   - Check Redis server is running
   - Verify connection credentials
   - Check firewall settings

2. **OAuth Callback Errors**
   - Verify OAuth app configuration
   - Check callback URLs match exactly
   - Ensure OAuth credentials are correct

3. **Permission Denied Errors**
   - Check user has required roles assigned
   - Verify permissions are correctly configured
   - Check role assignment in database

4. **Session Issues**
   - Clear Redis session data if corrupted
   - Check session timeout configuration
   - Verify fingerprint validation settings