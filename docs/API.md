# API Documentation

This document provides detailed information about all API endpoints in the authentication system.

## Table of Contents

- [Authentication](#authentication)
- [Base URL](#base-url)
- [Common Headers](#common-headers)
- [Error Handling](#error-handling)
- [Authentication Endpoints](#authentication-endpoints)
- [User Management](#user-management)
- [Admin Endpoints](#admin-endpoints)
- [Rate Limiting](#rate-limiting)
- [API Versioning](#api-versioning)

## Authentication

The API uses JWT (JSON Web Tokens) for authentication. Include the access token in the Authorization header:

```
Authorization: Bearer <access-token>
```

## Base URL

```
http://localhost:3000/api/v1
```

For production environments, replace with your actual domain.

## Common Headers

### Required Headers

```
Content-Type: application/json
Accept: application/json
```

### Optional Headers

```
X-Request-ID: <unique-request-id>
X-Client-Version: <client-version>
User-Agent: <user-agent-string>
```

## Error Handling

All API responses follow a consistent format:

### Success Response Format

```json
{
  "success": true,
  "message": "Operation completed successfully",
  "data": {
    // Response data
  },
  "meta": {
    "timestamp": "2024-01-01T00:00:00.000Z",
    "requestId": "req-123456",
    "version": "v1"
  }
}
```

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": [
      {
        "field": "fieldName",
        "message": "Field-specific error message",
        "code": "FIELD_ERROR_CODE"
      }
    ]
  },
  "meta": {
    "timestamp": "2024-01-01T00:00:00.000Z",
    "requestId": "req-123456",
    "version": "v1"
  }
}
```

### HTTP Status Codes

- `200 OK`: Successful request
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request data
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `409 Conflict`: Resource already exists
- `422 Unprocessable Entity`: Validation failed
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

## Authentication Endpoints

### Register User

Creates a new user account.

**Endpoint:** `POST /auth/register`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "firstName": "John",
  "lastName": "Doe",
  "acceptTerms": true
}
```

**Validation Rules:**
- `email`: Valid email format, unique, max 255 characters
- `password`: Min 8 characters, must contain uppercase, lowercase, number, and special character
- `firstName`: Required, max 50 characters
- `lastName`: Required, max 50 characters
- `acceptTerms`: Must be true

**Response (201 Created):**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "emailVerified": false,
    "createdAt": "2024-01-01T00:00:00.000Z",
    "updatedAt": "2024-01-01T00:00:00.000Z"
  }
}
```

**Error Responses:**
```json
// Email already exists
{
  "success": false,
  "error": {
    "code": "EMAIL_ALREADY_EXISTS",
    "message": "An account with this email already exists",
    "details": []
  }
}

// Validation error
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": [
      {
        "field": "password",
        "message": "Password must contain at least one uppercase letter",
        "code": "PASSWORD_WEAK"
      }
    ]
  }
}
```

### Login

Authenticates a user and returns JWT tokens.

**Endpoint:** `POST /auth/login`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "rememberMe": false
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresIn": 900,
    "tokenType": "Bearer",
    "user": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "roles": ["user"],
      "lastLogin": "2024-01-01T00:00:00.000Z"
    }
  }
}
```

**Error Responses:**
```json
// Invalid credentials
{
  "success": false,
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password",
    "details": []
  }
}

// Account locked
{
  "success": false,
  "error": {
    "code": "ACCOUNT_LOCKED",
    "message": "Account is temporarily locked due to multiple failed login attempts",
    "details": [
      {
        "field": "unlockAt",
        "message": "Account will be unlocked at 2024-01-01T01:00:00.000Z"
      }
    ]
  }
}
```

### Refresh Token

Refreshes the access token using a refresh token.

**Endpoint:** `POST /auth/refresh`

**Request Body:**
```json
{
  "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Token refreshed successfully",
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresIn": 900,
    "tokenType": "Bearer"
  }
}
```

### Logout

Logs out the user and blacklists the current token.

**Endpoint:** `POST /auth/logout`

**Headers:**
```
Authorization: Bearer <access-token>
```

**Request Body:**
```json
{
  "logoutAll": false
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Logout successful",
  "data": null
}
```

### Get Current User

Returns information about the currently authenticated user.

**Endpoint:** `GET /auth/me`

**Headers:**
```
Authorization: Bearer <access-token>
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "User information retrieved successfully",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "emailVerified": true,
    "roles": ["user"],
    "permissions": ["read:profile", "update:profile"],
    "lastLogin": "2024-01-01T00:00:00.000Z",
    "createdAt": "2024-01-01T00:00:00.000Z",
    "updatedAt": "2024-01-01T00:00:00.000Z"
  }
}
```

### Password Reset Request

Initiates a password reset process by sending a reset link to the user's email.

**Endpoint:** `POST /auth/password/reset-request`

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Password reset link sent to your email",
  "data": {
    "resetTokenSent": true,
    "expiresAt": "2024-01-01T01:00:00.000Z"
  }
}
```

### Password Reset Confirm

Confirms the password reset using the token from the email.

**Endpoint:** `POST /auth/password/reset-confirm`

**Request Body:**
```json
{
  "token": "reset-token-from-email",
  "newPassword": "NewSecurePassword123!",
  "confirmPassword": "NewSecurePassword123!"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Password reset successful",
  "data": {
    "passwordChanged": true,
    "changedAt": "2024-01-01T00:00:00.000Z"
  }
}
```

### Change Password

Changes the user's password (requires current password).

**Endpoint:** `POST /auth/password/change`

**Headers:**
```
Authorization: Bearer <access-token>
```

**Request Body:**
```json
{
  "currentPassword": "OldPassword123!",
  "newPassword": "NewSecurePassword123!",
  "confirmPassword": "NewSecurePassword123!"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Password changed successfully",
  "data": {
    "passwordChanged": true,
    "changedAt": "2024-01-01T00:00:00.000Z"
  }
}
```

### Email Verification

Verifies the user's email address using a verification token.

**Endpoint:** `POST /auth/email/verify`

**Request Body:**
```json
{
  "token": "email-verification-token"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Email verified successfully",
  "data": {
    "emailVerified": true,
    "verifiedAt": "2024-01-01T00:00:00.000Z"
  }
}
```

### Resend Email Verification

Resends the email verification link.

**Endpoint:** `POST /auth/email/resend-verification`

**Headers:**
```
Authorization: Bearer <access-token>
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Verification email sent",
  "data": {
    "emailSent": true,
    "expiresAt": "2024-01-01T01:00:00.000Z"
  }
}
```

## OAuth Social Login

### OAuth Login Initiate

Initiates OAuth login with a social provider.

**Endpoint:** `GET /auth/oauth/{provider}/login`

**Supported Providers:** `google`, `github`

**Query Parameters:**
- `redirect_uri`: Optional redirect URI after authentication
- `state`: Optional state parameter for CSRF protection

**Response (302 Redirect):**
Redirects to the OAuth provider's authorization URL.

### OAuth Callback

Handles OAuth callback from social providers.

**Endpoint:** `GET /auth/oauth/{provider}/callback`

**Query Parameters:**
- `code`: Authorization code from provider
- `state`: State parameter for CSRF protection

**Response (302 Redirect):**
Redirects to the frontend with authentication tokens in URL parameters or sets cookies.

## User Management

### Update Profile

Updates the user's profile information.

**Endpoint:** `PATCH /users/profile`

**Headers:**
```
Authorization: Bearer <access-token>
```

**Request Body:**
```json
{
  "firstName": "John",
  "lastName": "Doe",
  "phoneNumber": "+1234567890",
  "dateOfBirth": "1990-01-01",
  "timezone": "UTC"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Profile updated successfully",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "phoneNumber": "+1234567890",
    "dateOfBirth": "1990-01-01",
    "timezone": "UTC",
    "updatedAt": "2024-01-01T00:00:00.000Z"
  }
}
```

### Get User Sessions

Lists all active sessions for the user.

**Endpoint:** `GET /users/sessions`

**Headers:**
```
Authorization: Bearer <access-token>
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Sessions retrieved successfully",
  "data": {
    "sessions": [
      {
        "id": "session-id-1",
        "ipAddress": "192.168.1.100",
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "location": "New York, NY",
        "current": true,
        "createdAt": "2024-01-01T00:00:00.000Z",
        "lastActivity": "2024-01-01T00:30:00.000Z"
      }
    ],
    "totalCount": 1
  }
}
```

### Revoke Session

Revokes a specific session.

**Endpoint:** `DELETE /users/sessions/{sessionId}`

**Headers:**
```
Authorization: Bearer <access-token>
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Session revoked successfully",
  "data": null
}
```

## Admin Endpoints

### List Users

Lists all users with pagination (Admin only).

**Endpoint:** `GET /admin/users`

**Headers:**
```
Authorization: Bearer <access-token>
```

**Query Parameters:**
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 20, max: 100)
- `search`: Search term for email or name
- `status`: Filter by status (active, inactive, locked)
- `role`: Filter by role

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Users retrieved successfully",
  "data": {
    "users": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "email": "user@example.com",
        "firstName": "John",
        "lastName": "Doe",
        "status": "active",
        "roles": ["user"],
        "lastLogin": "2024-01-01T00:00:00.000Z",
        "createdAt": "2024-01-01T00:00:00.000Z"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 20,
      "totalPages": 5,
      "totalCount": 100,
      "hasNext": true,
      "hasPrevious": false
    }
  }
}
```

### Get User Details

Get detailed information about a specific user (Admin only).

**Endpoint:** `GET /admin/users/{userId}`

**Headers:**
```
Authorization: Bearer <access-token>
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "User details retrieved successfully",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "status": "active",
    "roles": ["user"],
    "permissions": ["read:profile", "update:profile"],
    "lastLogin": "2024-01-01T00:00:00.000Z",
    "loginAttempts": 0,
    "lockedUntil": null,
    "emailVerified": true,
    "createdAt": "2024-01-01T00:00:00.000Z",
    "updatedAt": "2024-01-01T00:00:00.000Z"
  }
}
```

### Update User Status

Updates a user's status (Admin only).

**Endpoint:** `PATCH /admin/users/{userId}/status`

**Headers:**
```
Authorization: Bearer <access-token>
```

**Request Body:**
```json
{
  "status": "inactive",
  "reason": "Account suspended for policy violation"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "User status updated successfully",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "inactive",
    "updatedAt": "2024-01-01T00:00:00.000Z"
  }
}
```

### Assign Role

Assigns a role to a user (Admin only).

**Endpoint:** `POST /admin/users/{userId}/roles`

**Headers:**
```
Authorization: Bearer <access-token>
```

**Request Body:**
```json
{
  "roleId": "role-id-here",
  "expiresAt": "2024-12-31T23:59:59.000Z"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Role assigned successfully",
  "data": {
    "userId": "550e8400-e29b-41d4-a716-446655440000",
    "roleId": "role-id-here",
    "assignedAt": "2024-01-01T00:00:00.000Z",
    "expiresAt": "2024-12-31T23:59:59.000Z"
  }
}
```

## Rate Limiting

The API implements rate limiting to prevent abuse:

### Rate Limit Headers

All responses include rate limit information:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 99
X-RateLimit-Reset: 1609459200
X-RateLimit-Window: 900
```

### Rate Limit Exceeded Response

When rate limit is exceeded, the API returns:

```json
{
  "success": false,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests. Please try again later.",
    "details": [
      {
        "field": "retryAfter",
        "message": "Retry after 300 seconds"
      }
    ]
  }
}
```

### Rate Limit Policies

- **General API**: 100 requests per 15 minutes per IP
- **Authentication**: 5 login attempts per 15 minutes per IP
- **Password Reset**: 3 requests per hour per IP
- **Email Verification**: 5 requests per hour per user

## API Versioning

The API uses URL versioning:

- Current version: `v1`
- Base URL: `/api/v1`
- Future versions: `/api/v2`, `/api/v3`, etc.

### Version Headers

Optionally specify API version in headers:

```
Accept: application/vnd.api+json;version=1
API-Version: v1
```

## Webhook Events

The system can send webhook events for important authentication events:

### Webhook Endpoint Configuration

Configure webhook endpoints in your application settings:

```json
{
  "webhookUrl": "https://your-app.com/webhooks/auth",
  "secret": "webhook-secret-key",
  "events": [
    "user.registered",
    "user.login",
    "user.logout",
    "user.password_changed",
    "user.locked",
    "user.unlocked"
  ]
}
```

### Webhook Payload Format

```json
{
  "event": "user.registered",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "data": {
    "userId": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "ipAddress": "192.168.1.100",
    "userAgent": "Mozilla/5.0..."
  },
  "signature": "sha256=webhook-signature"
}
```

## SDK and Code Examples

### JavaScript/Node.js

```javascript
const AuthAPI = require('@your-org/auth-api');

const client = new AuthAPI({
  baseURL: 'https://api.yourapp.com/v1',
  apiKey: 'your-api-key'
});

// Login
const loginResult = await client.auth.login({
  email: 'user@example.com',
  password: 'password123'
});

// Get current user
const user = await client.auth.getCurrentUser();

// Refresh token
const newTokens = await client.auth.refresh(refreshToken);
```

### Python

```python
from auth_api import AuthClient

client = AuthClient(
    base_url='https://api.yourapp.com/v1',
    api_key='your-api-key'
)

# Login
login_result = client.auth.login(
    email='user@example.com',
    password='password123'
)

# Get current user
user = client.auth.get_current_user()

# Refresh token
new_tokens = client.auth.refresh(refresh_token)
```

### cURL Examples

```bash
# Login
curl -X POST https://api.yourapp.com/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'

# Get current user
curl -X GET https://api.yourapp.com/v1/auth/me \
  -H "Authorization: Bearer <access-token>"

# Refresh token
curl -X POST https://api.yourapp.com/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refresh-token>"}'
```

## Testing

### Test Accounts

For testing purposes, you can use these test accounts:

```
Email: test@example.com
Password: TestPassword123!
Role: user

Email: admin@example.com
Password: AdminPassword123!
Role: admin
```

### Postman Collection

Download the Postman collection: [Auth API Collection](./postman-collection.json)

### API Testing Tools

- **Postman**: Import the collection for interactive testing
- **Insomnia**: REST client for API testing
- **curl**: Command-line tool for API requests
- **HTTPie**: User-friendly command-line HTTP client

---

This API documentation is automatically generated and kept up to date. For questions or issues, please create an issue in the GitHub repository.