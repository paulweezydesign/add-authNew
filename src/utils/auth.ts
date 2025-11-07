import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { appConfig } from '../config';
import { logger } from './logger';

export interface JWTPayload {
  userId: string;
  email: string;
  sessionId: string;
  iat?: number;
  exp?: number;
}

export class AuthUtils {
  /**
   * Hash a password using bcrypt
   */
  static async hashPassword(password: string): Promise<string> {
    try {
      const saltRounds = appConfig.security.bcryptRounds;
      return await bcrypt.hash(password, saltRounds);
    } catch (error) {
      logger.error('Error hashing password:', error);
      throw new Error('Failed to hash password');
    }
  }

  /**
   * Verify a password against its hash
   */
  static async verifyPassword(password: string, hash: string): Promise<boolean> {
    try {
      return await bcrypt.compare(password, hash);
    } catch (error) {
      logger.error('Error verifying password:', error);
      throw new Error('Failed to verify password');
    }
  }

  /**
   * Generate a JWT token
   */
  static generateToken(payload: Omit<JWTPayload, 'iat' | 'exp'>): string {
    try {
      return jwt.sign(payload as any, appConfig.security.jwtSecret, {
        expiresIn: appConfig.security.jwtExpiresIn,
      });
    } catch (error) {
      logger.error('Error generating JWT token:', error);
      throw new Error('Failed to generate token');
    }
  }

  /**
   * Generate a refresh token
   */
  static generateRefreshToken(payload: Omit<JWTPayload, 'iat' | 'exp'>): string {
    try {
      return jwt.sign(payload as any, appConfig.security.jwtSecret, {
        expiresIn: appConfig.security.jwtRefreshExpiresIn,
      });
    } catch (error) {
      logger.error('Error generating refresh token:', error);
      throw new Error('Failed to generate refresh token');
    }
  }

  /**
   * Verify and decode a JWT token
   */
  static verifyToken(token: string): JWTPayload {
    try {
      return jwt.verify(token, appConfig.security.jwtSecret) as JWTPayload;
    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        throw new Error('Invalid token');
      } else if (error instanceof jwt.TokenExpiredError) {
        throw new Error('Token expired');
      } else {
        logger.error('Error verifying JWT token:', error);
        throw new Error('Failed to verify token');
      }
    }
  }

  /**
   * Extract token from Authorization header
   */
  static extractTokenFromHeader(authHeader: string | undefined): string | null {
    if (!authHeader) return null;
    
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return null;
    }
    
    return parts[1];
  }

  /**
   * Generate a secure random token (for session tokens, etc.)
   */
  static generateSecureToken(length = 32): string {
    const crypto = require('crypto');
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Calculate session expiration time
   */
  static calculateSessionExpiration(): Date {
    const now = new Date();
    return new Date(now.getTime() + appConfig.security.sessionTimeout);
  }

  /**
   * Check if a session is expired
   */
  static isSessionExpired(expiresAt: Date): boolean {
    return new Date() > expiresAt;
  }

  /**
   * Validate email format
   */
  static isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Validate password strength
   */
  static isValidPassword(password: string): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    
    if (password.length < 8) {
      errors.push('Password must be at least 8 characters long');
    }
    
    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    
    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    
    if (!/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }
    
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }
    
    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Sanitize user input
   */
  static sanitizeInput(input: string): string {
    return input.trim().replace(/[<>]/g, '');
  }

  /**
   * Get IP address from request
   */
  static getClientIp(req: any): string {
    return req.ip || 
           req.connection?.remoteAddress || 
           req.socket?.remoteAddress ||
           req.headers['x-forwarded-for']?.split(',')[0] ||
           req.headers['x-real-ip'] ||
           '127.0.0.1';
  }

  /**
   * Get user agent from request
   */
  static getUserAgent(req: any): string | null {
    return req.headers['user-agent'] || null;
  }

  /**
   * Check if account is locked
   */
  static isAccountLocked(lockedUntil: Date | null): boolean {
    if (!lockedUntil) return false;
    return new Date() < lockedUntil;
  }

  /**
   * Calculate lockout time based on failed attempts
   */
  static calculateLockoutTime(failedAttempts: number): Date | null {
    if (failedAttempts < 5) return null;
    
    // Progressive lockout: 5 attempts = 30 min, 10 attempts = 1 hour, etc.
    const lockoutMinutes = Math.min(30 * Math.pow(2, failedAttempts - 5), 1440); // Max 24 hours
    const lockoutTime = new Date();
    lockoutTime.setMinutes(lockoutTime.getMinutes() + lockoutMinutes);
    
    return lockoutTime;
  }
}