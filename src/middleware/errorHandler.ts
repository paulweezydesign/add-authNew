import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import { appConfig } from '../config';

export interface ApiError extends Error {
  statusCode?: number;
  code?: string;
  details?: any;
}

/**
 * Global error handler middleware
 */
export function globalErrorHandler(
  err: ApiError,
  req: Request,
  res: Response,
  next: NextFunction
): void {
  logger.error('Global error handler:', {
    error: err,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id
  });

  // Default error response
  let statusCode = err.statusCode || 500;
  let message = err.message || 'Internal server error';
  let code = err.code || 'INTERNAL_ERROR';

  // Handle specific error types
  if (err.name === 'ValidationError') {
    statusCode = 400;
    message = 'Validation failed';
    code = 'VALIDATION_ERROR';
  } else if (err.name === 'CastError') {
    statusCode = 400;
    message = 'Invalid ID format';
    code = 'INVALID_ID';
  } else if (err.name === 'MongoServerError' && (err as any).code === 11000) {
    statusCode = 409;
    message = 'Duplicate entry';
    code = 'DUPLICATE_ENTRY';
  } else if (err.name === 'JsonWebTokenError') {
    statusCode = 401;
    message = 'Invalid token';
    code = 'INVALID_TOKEN';
  } else if (err.name === 'TokenExpiredError') {
    statusCode = 401;
    message = 'Token expired';
    code = 'TOKEN_EXPIRED';
  } else if (err.name === 'MulterError') {
    statusCode = 400;
    message = 'File upload error';
    code = 'FILE_UPLOAD_ERROR';
  }

  // Database errors
  if ((err as any).code === '23505') { // PostgreSQL unique constraint violation
    statusCode = 409;
    message = 'Duplicate entry';
    code = 'DUPLICATE_ENTRY';
  } else if ((err as any).code === '23503') { // PostgreSQL foreign key constraint violation
    statusCode = 400;
    message = 'Referenced record not found';
    code = 'FOREIGN_KEY_CONSTRAINT';
  } else if ((err as any).code === '23502') { // PostgreSQL not null constraint violation
    statusCode = 400;
    message = 'Required field missing';
    code = 'NOT_NULL_CONSTRAINT';
  }

  // Security: Don't expose internal error details in production
  const isDevelopment = appConfig.server.nodeEnv === 'development';
  
  res.status(statusCode).json({
    error: code,
    message,
    ...(isDevelopment && { 
      stack: err.stack,
      details: err.details 
    }),
    timestamp: new Date().toISOString(),
    path: req.path
  });
}

/**
 * 404 handler
 */
export function notFoundHandler(req: Request, res: Response): void {
  res.status(404).json({
    error: 'NOT_FOUND',
    message: 'The requested resource was not found',
    path: req.path,
    timestamp: new Date().toISOString()
  });
}

/**
 * Async error wrapper
 */
export function asyncHandler(fn: Function) {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/**
 * Rate limiting error handler
 */
export function rateLimitHandler(req: Request, res: Response): void {
  logger.warn('Rate limit exceeded', {
    ip: req.ip,
    path: req.path,
    userAgent: req.get('User-Agent')
  });

  res.status(429).json({
    error: 'RATE_LIMIT_EXCEEDED',
    message: 'Too many requests, please try again later',
    retryAfter: Math.ceil(appConfig.rateLimiting.windowMs / 1000),
    timestamp: new Date().toISOString()
  });
}

/**
 * Validation error formatter
 */
export function formatValidationError(errors: any[]): any {
  const formatted: any = {};
  
  errors.forEach(error => {
    if (error.path) {
      formatted[error.path.join('.')] = error.message;
    }
  });
  
  return formatted;
}