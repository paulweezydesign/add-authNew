# Password Security System

A comprehensive password security implementation with bcrypt hashing, strength validation, history tracking, and timing attack protection.

## Features

### 🔐 Secure Password Hashing
- **Bcrypt with minimum 12 salt rounds** for industry-standard security
- **Configurable salt rounds** for performance tuning
- **Async operations** with proper error handling
- **Secure random salt generation**

### 🛡️ Password Strength Validation
- **Configurable requirements**: length, character types, complexity
- **Common password detection** against known weak passwords
- **Sequential character detection** (123, abc, etc.)
- **Repeated character detection** (aaa, 111, etc.)
- **Dictionary word detection** for common terms
- **Detailed feedback** with suggestions and scoring

### 📚 Password History Tracking
- **Configurable history depth** (default: 5 previous passwords)
- **Secure storage** of hashed passwords only
- **Reuse prevention** with timing-safe comparison
- **Automatic cleanup** of old entries
- **Database-ready** with in-memory fallback

### ⚡ Timing Attack Protection
- **Constant-time comparisons** for all security operations
- **Configurable timing windows** (100-200ms default)
- **Random jitter** to prevent timing analysis
- **Rate limiting** with exponential backoff
- **Account lockout** after failed attempts

## Quick Start

```typescript
import { PasswordSecurityManager } from './security';

// Create password security manager
const passwordSecurity = new PasswordSecurityManager();

// Hash a password
const hash = await passwordSecurity.hashPassword('user123', 'MySecureP@ssw0rd123!');

// Verify a password
const isValid = await passwordSecurity.verifyPassword('MySecureP@ssw0rd123!', hash);

// Validate password strength
const validation = await passwordSecurity.validatePassword('user123', 'WeakPassword');
console.log(validation.errors); // ['Password must contain uppercase letters', ...]

// Generate secure password
const securePassword = passwordSecurity.generateSecurePassword(16);
```

## Configuration

### Password Requirements
```typescript
const config = {
  saltRounds: 12,           // Minimum 12 for security
  minLength: 8,             // Minimum password length
  requireUppercase: true,   // Require A-Z
  requireLowercase: true,   // Require a-z
  requireNumbers: true,     // Require 0-9
  requireSpecialChars: true, // Require special characters
  specialChars: '!@#$%^&*()_+-=[]{}|;:,.<>?',
  historyCount: 5           // Number of previous passwords to track
};

const securityOptions = {
  enableTimingAttackProtection: true,
  minComparisonTime: 100,   // Minimum comparison time (ms)
  maxComparisonTime: 200    // Maximum comparison time (ms)
};

const passwordSecurity = new PasswordSecurityManager(config, securityOptions);
```

## API Reference

### PasswordSecurityManager

#### Core Methods
- `validatePassword(userId, password)` - Comprehensive password validation
- `hashPassword(userId, password)` - Secure password hashing with history
- `verifyPassword(password, hash)` - Timing-safe password verification
- `authenticateUser(userId, password, hash, attempts)` - Full authentication with rate limiting

#### Password Management
- `changePassword(userId, currentPassword, newPassword, currentHash)` - Secure password change
- `resetPassword(userId, newPassword, resetToken, tokenHash)` - Password reset with token
- `generateSecurePassword(length)` - Generate cryptographically secure passwords

#### Utility Methods
- `getPasswordFeedback(password)` - Detailed password analysis
- `meetsMinimumRequirements(password)` - Quick requirement check
- `cleanupPasswordHistory(retentionDays)` - Clean old history entries
- `getSecurityStatistics()` - Get configuration and usage stats

### Token Generation
```typescript
// Generate secure tokens
const sessionToken = passwordSecurity.generateToken.session(32);
const apiKey = passwordSecurity.generateToken.apiKey('api');
const resetToken = passwordSecurity.generateToken.reset(60); // 60 min expiry
```

## Security Best Practices

### 1. Salt Rounds
- **Minimum 12 rounds** for current security standards
- **Increase rounds** as hardware improves (test performance)
- **Monitor hashing time** (should be 100-300ms per hash)

### 2. Password Requirements
- **Minimum 8 characters** (consider 12+ for high security)
- **Character diversity** (uppercase, lowercase, numbers, symbols)
- **Avoid common patterns** (sequential, repeated, dictionary words)

### 3. History Tracking
- **Track 5+ previous passwords** to prevent reuse
- **Store hashes only** - never plain text
- **Regular cleanup** of old entries
- **Secure comparison** to prevent timing attacks

### 4. Rate Limiting
- **Exponential backoff** for failed attempts
- **Account lockout** after 5 failed attempts
- **Timing consistency** for all operations
- **Log security events** for monitoring

### 5. Token Security
- **Cryptographically secure** random generation
- **Appropriate length** (32+ bytes for tokens)
- **Time-limited** expiration
- **Secure storage** (hash tokens in database)

## Testing

Run the comprehensive test suite:

```bash
npm test
# or
ts-node src/security/password-security.test.ts
```

### Test Coverage
- ✅ Password strength validation
- ✅ Hashing and verification
- ✅ History tracking and reuse detection
- ✅ Authentication with rate limiting
- ✅ Password generation
- ✅ Password change process
- ✅ Edge cases and error handling
- ✅ Performance benchmarks

## Architecture

### Components
1. **PasswordHasher** - Bcrypt operations with timing protection
2. **PasswordValidator** - Strength validation and feedback
3. **PasswordHistoryManager** - History tracking and reuse prevention
4. **SecurePasswordComparator** - Timing-safe comparisons
5. **AuthenticationUtils** - Token generation and utilities
6. **PasswordConfigManager** - Configuration management

### Data Flow
```
Password Input → Validation → History Check → Hashing → Storage
                     ↓
              Feedback & Errors
                     ↓
            Authentication Flow
```

## Performance Considerations

### Hashing Performance
- **Bcrypt is intentionally slow** - expect 100-300ms per hash
- **Async operations** prevent blocking
- **Configurable rounds** for performance tuning

### Memory Usage
- **In-memory history storage** for development
- **Database integration** for production
- **Cleanup mechanisms** for long-running processes

### Timing Attacks
- **Constant-time operations** where possible
- **Minimum timing windows** for consistency
- **Random jitter** to prevent analysis

## Production Deployment

### Environment Variables
```bash
# Optional: Override default configuration
PASSWORD_MIN_LENGTH=12
PASSWORD_SALT_ROUNDS=12
PASSWORD_HISTORY_COUNT=5
TIMING_PROTECTION_ENABLED=true
```

### Database Integration
The system is designed to work with database storage:
```typescript
// When database is available
const dbHistoryManager = new DatabasePasswordHistoryManager(
  databaseConnection,
  configManager,
  passwordHasher
);
```

### Monitoring
- **Hash timing** - should be consistent
- **Failed attempts** - watch for patterns
- **Account lockouts** - investigate unusual activity
- **Performance metrics** - optimize salt rounds

## Security Considerations

### Threats Mitigated
- ✅ **Brute force attacks** - bcrypt + rate limiting
- ✅ **Dictionary attacks** - strength validation
- ✅ **Timing attacks** - constant-time operations
- ✅ **Password reuse** - history tracking
- ✅ **Weak passwords** - comprehensive validation

### Compliance
- **OWASP Password Guidelines** - fully compliant
- **NIST SP 800-63B** - authentication guidelines
- **PCI DSS** - payment card industry standards
- **GDPR** - data protection regulations

## License

MIT License - see LICENSE file for details.