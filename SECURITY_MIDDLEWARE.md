# Security Middleware Implementation

## Overview

This document describes the comprehensive security middleware implementation for the Add-Auth system. The implementation includes multiple layers of security protection against common web application vulnerabilities.

## Implemented Security Middleware

### 1. Rate Limiting & Redis Integration (Task 5)

**Files:**
- `/src/middleware/rateLimiter.ts`

**Features:**
- Redis-based distributed rate limiting
- Multiple rate limiting strategies:
  - General API: 100 requests per 15 minutes
  - Authentication: 10 attempts per 15 minutes
  - Password Reset: 3 attempts per hour
  - Registration: 5 attempts per hour
- IP-based and user-based rate limiting
- Configurable rate limits
- Redis connection health monitoring
- Graceful degradation when Redis is unavailable

**Usage:**
```typescript
import { rateLimiters } from '../middleware';

// Apply to routes
app.use('/api/auth/login', rateLimiters.auth);
app.use('/api/password-reset', rateLimiters.passwordReset);
```

### 2. CSRF Protection (Task 5)

**Files:**
- `/src/middleware/csrfProtection.ts`

**Features:**
- Token-based CSRF protection
- Redis storage for token persistence
- Configurable token expiration
- Support for multiple token sources (headers, body, cookies)
- Same-site request exemption option
- Token cleanup automation

**Usage:**
```typescript
import { csrfProtection } from '../middleware';

// Protect state-changing operations
app.post('/api/auth/login', csrfProtection(), loginHandler);

// Get CSRF token endpoint
app.get('/api/csrf-token', csrfProtection(), (req, res) => {
  res.json({ csrfToken: res.locals.csrfToken });
});
```

### 3. Input Validation with Joi (Task 6)

**Files:**
- `/src/middleware/validation.ts`

**Features:**
- Comprehensive input validation using Joi
- Pre-defined validation schemas for common operations:
  - User registration
  - User login
  - Password reset
  - Password change
  - Profile updates
- Request sanitization
- Support for body, query, params, and headers validation
- Password strength validation
- Email validation utilities

**Usage:**
```typescript
import { validateBody, validationSchemas } from '../middleware';

// Validate registration data
app.post('/api/auth/register', 
  validateBody(validationSchemas.userRegistration),
  registerHandler
);

// Validate login credentials
app.post('/api/auth/login',
  validateBody(validationSchemas.userLogin),
  loginHandler
);
```

### 4. XSS Protection (Task 6)

**Files:**
- `/src/middleware/xssProtection.ts`

**Features:**
- Comprehensive XSS sanitization using the `xss` library
- Multiple protection levels (basic, strict)
- HTML tag and attribute filtering
- URL sanitization
- Content Security Policy (CSP) headers
- XSS attack detection and logging
- Recursive object sanitization
- Safe JSON parsing

**Usage:**
```typescript
import { xssProtection, strictXSSProtection } from '../middleware';

// Basic XSS protection
app.use('/api', xssProtection());

// Strict protection (no HTML allowed)
app.use('/api/admin', strictXSSProtection());
```

### 5. SQL Injection Prevention (Task 6)

**Files:**
- `/src/middleware/sqlInjectionPrevention.ts`

**Features:**
- Pattern-based SQL injection detection
- Support for both basic and advanced detection modes
- Input sanitization
- Parameterized query helpers
- Safe query builders
- SQL identifier validation
- Whitelist support for specific fields
- NoSQL injection protection

**Usage:**
```typescript
import { sqlInjectionPrevention, buildSafeQuery } from '../middleware';

// Apply SQL injection protection
app.use('/api', sqlInjectionPrevention());

// Use safe query builder
const query = buildSafeQuery('users', { email: userEmail }, 'SELECT');
```

### 6. Password Reset System (Task 8)

**Files:**
- `/src/security/passwordReset.ts`
- `/src/controllers/passwordResetController.ts`
- `/src/routes/passwordReset.ts`

**Features:**
- Secure token generation using crypto.randomBytes
- Redis-based token storage with expiration
- Token validation and single-use enforcement
- Rate limiting for reset requests
- Email integration for notifications
- Comprehensive audit logging
- Token revocation capabilities
- Admin endpoints for token management

**API Endpoints:**
```
POST /api/password-reset/request    - Request password reset
GET  /api/password-reset/verify/:token - Verify reset token
POST /api/password-reset/reset     - Reset password with token
GET  /api/password-reset/attempts/:email - Get attempt count
DELETE /api/password-reset/revoke/:token - Revoke token
```

### 7. Email Service Integration (Task 8)

**Files:**
- `/src/utils/emailService.ts`

**Features:**
- SMTP email integration using Nodemailer
- HTML and text email templates
- Password reset notifications
- Registration confirmations
- Security alerts
- Email verification
- Connection testing and health checks
- Graceful fallback when email service is unavailable

**Templates Available:**
- Password reset request
- Password reset confirmation
- Account registration welcome
- Email verification
- Security alerts

## Security Middleware Stack

### Pre-configured Security Stacks

```typescript
import { securityMiddleware } from '../middleware';

// Basic security for general APIs
app.use('/api', securityMiddleware.basic);

// Enhanced security for authentication
app.use('/api/auth', securityMiddleware.auth);

// Maximum security for admin operations
app.use('/api/admin', securityMiddleware.admin);

// Specialized stack for password reset
app.use('/api/password-reset', securityMiddleware.passwordReset);
```

### Environment-specific Configuration

```typescript
import { applySecurityMiddleware } from '../middleware';

// Apply configuration based on environment
const environment = process.env.NODE_ENV;
app.use(applySecurityMiddleware(environment));
```

## Configuration

### Environment Variables

```bash
# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password

# Email Configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_SECURE=false
EMAIL_USER=your_email@domain.com
EMAIL_PASS=your_email_password
EMAIL_FROM=noreply@add-auth.com

# Frontend URL for email links
FRONTEND_URL=http://localhost:3000
```

### Security Configuration Presets

The system includes three pre-configured security levels:

1. **Production**: Maximum security, strict validation
2. **Development**: Balanced security, easier development
3. **Testing**: Minimal security for testing purposes

## Health Monitoring

### Security Health Check

```typescript
import { securityHealthCheck } from '../middleware';

// Check all security components
app.get('/api/health/security', async (req, res) => {
  const health = await securityHealthCheck();
  res.json(health);
});
```

Health check verifies:
- Redis connectivity
- CSRF token generation
- Input validation functionality
- XSS protection
- SQL injection detection

## Performance Considerations

### Redis Performance
- Connection pooling for rate limiting
- Automatic cleanup of expired tokens
- Configurable TTL for all cached data

### Validation Performance
- Schema compilation optimization
- Early validation failures
- Selective validation based on endpoints

### Memory Management
- Automatic cleanup of expired CSRF tokens
- Periodic cleanup of password reset tokens
- Configurable memory limits for validation

## Security Best Practices Implemented

### 1. Defense in Depth
- Multiple layers of protection
- Redundant security checks
- Graceful degradation

### 2. Secure by Default
- Conservative default configurations
- Automatic security header setting
- Built-in rate limiting

### 3. Monitoring and Logging
- Comprehensive security event logging
- Attack detection and alerting
- Performance monitoring

### 4. Data Protection
- Input sanitization at multiple levels
- Secure token generation
- Encrypted storage where applicable

## Integration Examples

### Complete Authentication Route

```typescript
import { 
  rateLimiters,
  csrfProtection,
  validateBody,
  validationSchemas,
  xssProtection,
  sqlInjectionPrevention
} from '../middleware';

router.post('/login',
  rateLimiters.auth,           // Rate limiting
  csrfProtection(),            // CSRF protection
  xssProtection(),             // XSS protection
  sqlInjectionPrevention(),    // SQL injection protection
  validateBody(validationSchemas.userLogin), // Input validation
  loginController              // Business logic
);
```

### Password Reset Flow

```typescript
// Request reset
router.post('/password-reset/request',
  rateLimiters.passwordReset,
  csrfProtection(),
  validateBody(validationSchemas.passwordResetRequest),
  requestPasswordResetController
);

// Reset password
router.post('/password-reset/reset',
  rateLimiters.passwordReset,
  csrfProtection(),
  validateBody(validationSchemas.passwordReset),
  resetPasswordController
);
```

## Testing

### Security Testing Commands

```bash
# Test rate limiting
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test"}'

# Test CSRF protection
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: invalid-token" \
  -d '{"email":"test@example.com","password":"test"}'

# Test XSS protection
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","username":"<script>alert(\"xss\")</script>"}'
```

## Troubleshooting

### Common Issues

1. **Redis Connection Issues**
   - Check Redis server status
   - Verify connection credentials
   - Review network connectivity

2. **Email Service Issues**
   - Verify SMTP credentials
   - Check firewall settings
   - Test email server connectivity

3. **Rate Limiting Issues**
   - Check Redis key expiration
   - Verify IP detection
   - Review rate limit configurations

### Debug Logging

Enable detailed security logging:
```javascript
// In your environment variables
DEBUG=security:*
LOG_LEVEL=debug
```

## Security Headers

The middleware automatically sets the following security headers:

```
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'; ...
X-CSRF-Token: <token>
```

## Future Enhancements

### Planned Improvements
- OAuth 2.0 integration
- Advanced threat detection
- Machine learning-based anomaly detection
- Enhanced audit logging
- Multi-factor authentication support

### Extensibility
The middleware system is designed to be extensible:
- Plugin architecture for custom validators
- Configurable security rules
- Custom rate limiting strategies
- Additional authentication providers

---

**Note**: This security middleware implementation provides comprehensive protection against common web application vulnerabilities. Regular security audits and updates are recommended to maintain optimal protection.