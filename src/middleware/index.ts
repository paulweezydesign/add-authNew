/**
 * Security Middleware Index
 * Centralized exports for all security middleware components
 */

// Rate Limiting
export {
  rateLimiters,
  createCustomRateLimiter,
  createUserRateLimiter,
  rateLimiterHealthCheck,
  closeRedisConnection,
  redisClient
} from './rateLimiter';

// CSRF Protection
export {
  generateCSRFToken,
  validateCSRFToken,
  generateCSRFMiddleware,
  validateCSRFMiddleware,
  getCSRFTokenEndpoint,
  cleanupExpiredCSRFTokens,
  csrfProtection
} from './csrfProtection';
export type { CSRFConfig } from './csrfProtection';

// Input Validation
export {
  validate,
  validateBody,
  validateQuery,
  validateParams,
  validateHeaders,
  sanitizeInput,
  validateAndSanitize,
  validationSchemas,
  isValidEmail,
  isStrongPassword
} from './validation';
export type { ValidationTarget, ValidationOptions } from './validation';

// XSS Protection
export {
  sanitizeString,
  sanitizeObject,
  xssProtection,
  strictXSSProtection,
  xssProtectFields,
  contentSecurityPolicy,
  escapeHtml,
  sanitizeUrl,
  safeJsonParse,
  detectXSS,
  xssDetection
} from './xssProtection';
export type { XSSProtectionConfig } from './xssProtection';

// SQL Injection Prevention
export {
  sqlInjectionPrevention,
  sqlInjectionSanitization,
  sqlInjectionDetectionFields,
  detectSQLInjection,
  sanitizeSQLInput,
  sanitizeObjectSQL,
  createParameterizedQuery,
  buildSafeQuery,
  validateIdentifier,
  escapeIdentifier
} from './sqlInjectionPrevention';
export type { SQLInjectionConfig } from './sqlInjectionPrevention';

/**
 * Combined security middleware stack
 */
export const securityMiddleware = {
  // Basic security stack
  basic: [
    rateLimiters.general,
    xssProtection(),
    sqlInjectionPrevention()
  ],

  // Authentication security stack
  auth: [
    rateLimiters.auth,
    csrfProtection(),
    xssProtection(),
    sqlInjectionPrevention(),
    sanitizeInput('body')
  ],

  // Admin security stack
  admin: [
    rateLimiters.general,
    csrfProtection(),
    strictXSSProtection(),
    sqlInjectionPrevention({ strict: true }),
    sanitizeInput('body'),
    sanitizeInput('query')
  ],

  // Password reset security stack
  passwordReset: [
    rateLimiters.passwordReset,
    csrfProtection(),
    xssProtection(),
    sqlInjectionPrevention(),
    sanitizeInput('body')
  ],

  // Registration security stack
  registration: [
    rateLimiters.registration,
    csrfProtection(),
    xssProtection(),
    sqlInjectionPrevention(),
    sanitizeInput('body')
  ]
};

/**
 * Security configuration presets
 */
export const securityConfigs = {
  // Production configuration
  production: {
    csrf: {
      saltLength: 32,
      secretLength: 64,
      tokenExpiry: 60 * 60 * 1000, // 1 hour
      skipOnSameSite: false,
      exemptMethods: ['GET', 'HEAD', 'OPTIONS']
    },
    xss: {
      stripIgnoreTag: true,
      stripIgnoreTagBody: true,
      css: false,
      allowCommentTag: false
    },
    sqlInjection: {
      strict: true,
      logAttempts: true,
      blockRequests: true
    }
  },

  // Development configuration
  development: {
    csrf: {
      saltLength: 16,
      secretLength: 32,
      tokenExpiry: 2 * 60 * 60 * 1000, // 2 hours
      skipOnSameSite: true,
      exemptMethods: ['GET', 'HEAD', 'OPTIONS']
    },
    xss: {
      stripIgnoreTag: true,
      stripIgnoreTagBody: ['script', 'style'],
      css: false,
      allowCommentTag: false
    },
    sqlInjection: {
      strict: false,
      logAttempts: true,
      blockRequests: false
    }
  },

  // Testing configuration
  testing: {
    csrf: {
      saltLength: 8,
      secretLength: 16,
      tokenExpiry: 10 * 60 * 1000, // 10 minutes
      skipOnSameSite: true,
      exemptMethods: ['GET', 'HEAD', 'OPTIONS', 'POST']
    },
    xss: {
      stripIgnoreTag: false,
      stripIgnoreTagBody: false,
      css: false,
      allowCommentTag: true
    },
    sqlInjection: {
      strict: false,
      logAttempts: false,
      blockRequests: false
    }
  }
};

/**
 * Apply security middleware based on environment
 */
export const applySecurityMiddleware = (environment: 'production' | 'development' | 'testing' = 'production') => {
  const config = securityConfigs[environment];
  
  return [
    rateLimiters.general,
    csrfProtection(config.csrf),
    xssProtection(config.xss),
    sqlInjectionPrevention(config.sqlInjection),
    sanitizeInput('body'),
    sanitizeInput('query'),
    sanitizeInput('params')
  ];
};

/**
 * Health check for all security middleware
 */
export const securityHealthCheck = async () => {
  const results = {
    redis: false,
    csrf: false,
    validation: false,
    xss: false,
    sqlInjection: false
  };

  try {
    // Check Redis connection
    await redisClient.ping();
    results.redis = true;
  } catch (error) {
    results.redis = false;
  }

  // CSRF check
  try {
    await generateCSRFToken('test-session');
    results.csrf = true;
  } catch (error) {
    results.csrf = false;
  }

  // Validation check
  try {
    const testData = { email: 'test@example.com' };
    const { error } = validationSchemas.passwordResetRequest.validate(testData);
    results.validation = !error;
  } catch (error) {
    results.validation = false;
  }

  // XSS check
  try {
    const testInput = '<script>alert("test")</script>';
    const sanitized = sanitizeString(testInput);
    results.xss = !sanitized.includes('<script>');
  } catch (error) {
    results.xss = false;
  }

  // SQL injection check
  try {
    const testInput = "'; DROP TABLE users; --";
    const detection = detectSQLInjection(testInput);
    results.sqlInjection = detection.detected;
  } catch (error) {
    results.sqlInjection = false;
  }

  return results;
};

export default {
  rateLimiters,
  csrfProtection,
  xssProtection,
  sqlInjectionPrevention,
  validation: {
    validateBody,
    validateQuery,
    validateParams,
    validateHeaders,
    validationSchemas
  },
  securityMiddleware,
  securityConfigs,
  applySecurityMiddleware,
  securityHealthCheck
};