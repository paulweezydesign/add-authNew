/**
 * Password Reset System
 * Implements secure password reset functionality with token generation, validation, and storage
 */

import * as crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';
import { redisClient } from '../middleware/rateLimiter';
import { PasswordSecurityManager } from './password-security';

/**
 * Password reset token interface
 */
export interface PasswordResetToken {
  id: string;
  userId: string;
  email: string;
  token: string;
  hashedToken: string;
  expiresAt: Date;
  createdAt: Date;
  isUsed: boolean;
  ipAddress?: string;
  userAgent?: string;
}

/**
 * Password reset request interface
 */
export interface PasswordResetRequest {
  email: string;
  ipAddress?: string;
  userAgent?: string;
}

/**
 * Password reset configuration
 */
export interface PasswordResetConfig {
  tokenLength: number;
  tokenExpiry: number; // in milliseconds
  maxAttempts: number;
  attemptWindow: number; // in milliseconds
  cleanupInterval: number; // in milliseconds
  requireStrongPassword: boolean;
  notifyOriginalEmail: boolean;
}

/**
 * Default password reset configuration
 */
const defaultConfig: PasswordResetConfig = {
  tokenLength: 64,
  tokenExpiry: 60 * 60 * 1000, // 1 hour
  maxAttempts: 3,
  attemptWindow: 60 * 60 * 1000, // 1 hour
  cleanupInterval: 24 * 60 * 60 * 1000, // 24 hours
  requireStrongPassword: true,
  notifyOriginalEmail: true
};

/**
 * Password Reset Manager
 */
export class PasswordResetManager {
  private config: PasswordResetConfig;
  private passwordSecurity: PasswordSecurityManager;

  constructor(config: Partial<PasswordResetConfig> = {}) {
    this.config = { ...defaultConfig, ...config };
    this.passwordSecurity = new PasswordSecurityManager();
    
    // Schedule cleanup of expired tokens
    setInterval(() => {
      this.cleanupExpiredTokens();
    }, this.config.cleanupInterval);
  }

  /**
   * Generate a secure password reset token
   */
  private generateToken(): { token: string; hashedToken: string } {
    const token = crypto.randomBytes(this.config.tokenLength).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    
    return { token, hashedToken };
  }

  /**
   * Hash a token for secure storage
   */
  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  /**
   * Create a password reset token
   */
  async createPasswordResetToken(
    userId: string,
    email: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{ token: string; expiresAt: Date }> {
    try {
      // Check rate limiting
      await this.checkRateLimit(email, ipAddress);

      // Generate token
      const { token, hashedToken } = this.generateToken();
      const expiresAt = new Date(Date.now() + this.config.tokenExpiry);
      
      const resetToken: PasswordResetToken = {
        id: uuidv4(),
        userId,
        email,
        token,
        hashedToken,
        expiresAt,
        createdAt: new Date(),
        isUsed: false,
        ipAddress,
        userAgent
      };

      // Store in Redis with expiration
      const key = `password-reset:${hashedToken}`;
      await redisClient.setex(
        key,
        Math.floor(this.config.tokenExpiry / 1000),
        JSON.stringify(resetToken)
      );

      // Store by email for rate limiting
      const emailKey = `password-reset-email:${email}`;
      const emailData = {
        attempts: 1,
        lastAttempt: Date.now()
      };
      await redisClient.setex(
        emailKey,
        Math.floor(this.config.attemptWindow / 1000),
        JSON.stringify(emailData)
      );

      logger.info('Password reset token created', {
        userId,
        email,
        tokenId: resetToken.id,
        expiresAt: expiresAt.toISOString(),
        ipAddress,
        userAgent
      });

      return { token, expiresAt };
    } catch (error) {
      logger.error('Failed to create password reset token:', error);
      throw new Error('Failed to create password reset token');
    }
  }

  /**
   * Validate a password reset token
   */
  async validatePasswordResetToken(token: string): Promise<PasswordResetToken | null> {
    try {
      const hashedToken = this.hashToken(token);
      const key = `password-reset:${hashedToken}`;
      const tokenDataStr = await redisClient.get(key);

      if (!tokenDataStr) {
        logger.warn('Password reset token not found', { hashedToken });
        return null;
      }

      const tokenData: PasswordResetToken = JSON.parse(tokenDataStr);

      // Check if token is expired
      if (new Date() > new Date(tokenData.expiresAt)) {
        logger.warn('Password reset token expired', {
          tokenId: tokenData.id,
          expiresAt: tokenData.expiresAt
        });
        await redisClient.del(key); // Clean up expired token
        return null;
      }

      // Check if token is already used
      if (tokenData.isUsed) {
        logger.warn('Password reset token already used', {
          tokenId: tokenData.id,
          userId: tokenData.userId
        });
        return null;
      }

      return tokenData;
    } catch (error) {
      logger.error('Failed to validate password reset token:', error);
      return null;
    }
  }

  /**
   * Use a password reset token
   */
  async usePasswordResetToken(token: string, newPassword: string): Promise<boolean> {
    try {
      const tokenData = await this.validatePasswordResetToken(token);
      
      if (!tokenData) {
        return false;
      }

      // Validate password strength if required
      if (this.config.requireStrongPassword) {
        const validation = await this.passwordSecurity.validatePassword(
          tokenData.userId,
          newPassword
        );
        
        if (!validation.isValid) {
          logger.warn('Password reset failed - weak password', {
            tokenId: tokenData.id,
            userId: tokenData.userId,
            errors: validation.errors
          });
          throw new Error(`Password requirements not met: ${validation.errors.join(', ')}`);
        }
      }

      // Hash the new password
      const hashedPassword = await this.passwordSecurity.hashPassword(
        tokenData.userId,
        newPassword
      );

      // Mark token as used
      tokenData.isUsed = true;
      const hashedToken = this.hashToken(token);
      const key = `password-reset:${hashedToken}`;
      await redisClient.setex(
        key,
        Math.floor(this.config.tokenExpiry / 1000),
        JSON.stringify(tokenData)
      );

      logger.info('Password reset token used successfully', {
        tokenId: tokenData.id,
        userId: tokenData.userId,
        email: tokenData.email
      });

      return true;
    } catch (error) {
      logger.error('Failed to use password reset token:', error);
      throw error;
    }
  }

  /**
   * Revoke a password reset token
   */
  async revokePasswordResetToken(token: string): Promise<boolean> {
    try {
      const hashedToken = this.hashToken(token);
      const key = `password-reset:${hashedToken}`;
      const result = await redisClient.del(key);
      
      if (result > 0) {
        logger.info('Password reset token revoked', { hashedToken });
        return true;
      }
      
      return false;
    } catch (error) {
      logger.error('Failed to revoke password reset token:', error);
      return false;
    }
  }

  /**
   * Check rate limiting for password reset requests
   */
  private async checkRateLimit(email: string, ipAddress?: string): Promise<void> {
    const emailKey = `password-reset-email:${email}`;
    const emailDataStr = await redisClient.get(emailKey);

    if (emailDataStr) {
      const emailData = JSON.parse(emailDataStr);
      
      if (emailData.attempts >= this.config.maxAttempts) {
        const timeSinceLastAttempt = Date.now() - emailData.lastAttempt;
        
        if (timeSinceLastAttempt < this.config.attemptWindow) {
          logger.warn('Password reset rate limit exceeded', {
            email,
            attempts: emailData.attempts,
            ipAddress
          });
          throw new Error('Too many password reset attempts. Please try again later.');
        }
      }
    }

    // Check IP-based rate limiting if IP is provided
    if (ipAddress) {
      const ipKey = `password-reset-ip:${ipAddress}`;
      const ipDataStr = await redisClient.get(ipKey);

      if (ipDataStr) {
        const ipData = JSON.parse(ipDataStr);
        
        if (ipData.attempts >= this.config.maxAttempts) {
          const timeSinceLastAttempt = Date.now() - ipData.lastAttempt;
          
          if (timeSinceLastAttempt < this.config.attemptWindow) {
            logger.warn('Password reset IP rate limit exceeded', {
              ipAddress,
              attempts: ipData.attempts
            });
            throw new Error('Too many password reset attempts from this IP. Please try again later.');
          }
        }
      }
    }
  }

  /**
   * Get password reset attempts for an email
   */
  async getPasswordResetAttempts(email: string): Promise<{ attempts: number; lastAttempt: Date | null }> {
    try {
      const emailKey = `password-reset-email:${email}`;
      const emailDataStr = await redisClient.get(emailKey);

      if (!emailDataStr) {
        return { attempts: 0, lastAttempt: null };
      }

      const emailData = JSON.parse(emailDataStr);
      return {
        attempts: emailData.attempts,
        lastAttempt: new Date(emailData.lastAttempt)
      };
    } catch (error) {
      logger.error('Failed to get password reset attempts:', error);
      return { attempts: 0, lastAttempt: null };
    }
  }

  /**
   * Clean up expired password reset tokens
   */
  async cleanupExpiredTokens(): Promise<void> {
    try {
      const keys = await redisClient.keys('password-reset:*');
      let cleaned = 0;

      for (const key of keys) {
        const tokenDataStr = await redisClient.get(key);
        if (tokenDataStr) {
          const tokenData: PasswordResetToken = JSON.parse(tokenDataStr);
          
          if (new Date() > new Date(tokenData.expiresAt)) {
            await redisClient.del(key);
            cleaned++;
          }
        }
      }

      if (cleaned > 0) {
        logger.info(`Cleaned up ${cleaned} expired password reset tokens`);
      }
    } catch (error) {
      logger.error('Failed to cleanup expired password reset tokens:', error);
    }
  }

  /**
   * Get all active password reset tokens for a user
   */
  async getActiveTokensForUser(userId: string): Promise<PasswordResetToken[]> {
    try {
      const keys = await redisClient.keys('password-reset:*');
      const activeTokens: PasswordResetToken[] = [];

      for (const key of keys) {
        const tokenDataStr = await redisClient.get(key);
        if (tokenDataStr) {
          const tokenData: PasswordResetToken = JSON.parse(tokenDataStr);
          
          if (tokenData.userId === userId && 
              !tokenData.isUsed && 
              new Date() <= new Date(tokenData.expiresAt)) {
            activeTokens.push(tokenData);
          }
        }
      }

      return activeTokens;
    } catch (error) {
      logger.error('Failed to get active tokens for user:', error);
      return [];
    }
  }

  /**
   * Revoke all password reset tokens for a user
   */
  async revokeAllTokensForUser(userId: string): Promise<number> {
    try {
      const activeTokens = await this.getActiveTokensForUser(userId);
      let revoked = 0;

      for (const tokenData of activeTokens) {
        const key = `password-reset:${tokenData.hashedToken}`;
        await redisClient.del(key);
        revoked++;
      }

      if (revoked > 0) {
        logger.info(`Revoked ${revoked} password reset tokens for user`, { userId });
      }

      return revoked;
    } catch (error) {
      logger.error('Failed to revoke all tokens for user:', error);
      return 0;
    }
  }

  /**
   * Get password reset statistics
   */
  async getPasswordResetStats(): Promise<{
    totalActiveTokens: number;
    totalUsedTokens: number;
    totalExpiredTokens: number;
  }> {
    try {
      const keys = await redisClient.keys('password-reset:*');
      let activeTokens = 0;
      let usedTokens = 0;
      let expiredTokens = 0;

      for (const key of keys) {
        const tokenDataStr = await redisClient.get(key);
        if (tokenDataStr) {
          const tokenData: PasswordResetToken = JSON.parse(tokenDataStr);
          
          if (tokenData.isUsed) {
            usedTokens++;
          } else if (new Date() > new Date(tokenData.expiresAt)) {
            expiredTokens++;
          } else {
            activeTokens++;
          }
        }
      }

      return {
        totalActiveTokens: activeTokens,
        totalUsedTokens: usedTokens,
        totalExpiredTokens: expiredTokens
      };
    } catch (error) {
      logger.error('Failed to get password reset stats:', error);
      return {
        totalActiveTokens: 0,
        totalUsedTokens: 0,
        totalExpiredTokens: 0
      };
    }
  }
}

// Export default instance
export const passwordResetManager = new PasswordResetManager();

export default passwordResetManager;