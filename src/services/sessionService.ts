import { v4 as uuidv4 } from 'uuid';
import { Request } from 'express';
import { getRedisClient } from '../utils/redis';
import { FingerprintService, DeviceFingerprint } from '../utils/fingerprint';
import { SessionModel } from '../models/Session';
import { Session, CreateSessionInput } from '../types/session';
import { appConfig } from '../config';
import { logger } from '../utils/logger';

export interface RedisSession extends Session {
  fingerprint: DeviceFingerprint;
  trust_score: number;
  concurrent_count: number;
}

export interface SessionValidationResult {
  isValid: boolean;
  session?: RedisSession;
  reason?: string;
  requiresReauth?: boolean;
}

export interface CreateRedisSessionInput extends CreateSessionInput {
  fingerprint: DeviceFingerprint;
}

export class SessionService {
  private static readonly MAX_SESSIONS_PER_USER = 5;
  private static readonly SESSION_PREFIX = 'session:';
  private static readonly USER_SESSIONS_PREFIX = 'user_sessions:';
  private static readonly FINGERPRINT_HISTORY_PREFIX = 'fingerprint_history:';
  private static readonly DEFAULT_TTL = 86400; // 24 hours
  private static readonly EXTENDED_TTL = 604800; // 7 days

  /**
   * Create a new Redis-based session
   */
  static async createSession(
    input: CreateRedisSessionInput,
    rememberMe: boolean = false
  ): Promise<RedisSession> {
    const sessionId = uuidv4();
    const now = new Date();
    const ttl = rememberMe ? this.EXTENDED_TTL : this.DEFAULT_TTL;
    
    // Check and enforce concurrent session limits
    await this.enforceSessionLimits(input.user_id, sessionId);

    // Calculate trust score based on fingerprint history
    const fingerprintHistory = await this.getFingerprintHistory(input.user_id);
    const trustScore = FingerprintService.calculateTrustScore(
      fingerprintHistory,
      input.fingerprint
    );

    // Get current session count for user
    const userSessions = await this.getUserSessions(input.user_id);
    const concurrentCount = userSessions.length;

    const redisSession: RedisSession = {
      id: sessionId,
      user_id: input.user_id,
      token: input.token,
      expires_at: input.expires_at,
      created_at: now,
      ip_address: input.ip_address,
      user_agent: input.user_agent || null,
      is_active: true,
      last_accessed: now,
      fingerprint: input.fingerprint,
      trust_score: trustScore,
      concurrent_count: concurrentCount + 1,
    };

    try {
      const redis = getRedisClient();
      
      // Store session in Redis
      await redis.setEx(
        `${this.SESSION_PREFIX}${sessionId}`,
        ttl,
        JSON.stringify(redisSession)
      );

      // Add session to user's session list
      await redis.sAdd(`${this.USER_SESSIONS_PREFIX}${input.user_id}`, sessionId);
      await redis.expire(`${this.USER_SESSIONS_PREFIX}${input.user_id}`, ttl);

      // Store fingerprint in history
      await this.storeFingerprintHistory(input.user_id, input.fingerprint);

      // Also create backup in PostgreSQL for persistence
      await SessionModel.create({
        user_id: input.user_id,
        token: input.token,
        expires_at: input.expires_at,
        ip_address: input.ip_address,
        user_agent: input.user_agent,
      });

      logger.info('Redis session created successfully', {
        sessionId,
        userId: input.user_id,
        trustScore,
        concurrentCount: concurrentCount + 1,
        ttl,
      });

      return redisSession;
    } catch (error) {
      logger.error('Failed to create Redis session', {
        sessionId,
        userId: input.user_id,
        error,
      });
      throw error;
    }
  }

  /**
   * Retrieve session by ID from Redis
   */
  static async getSession(sessionId: string): Promise<RedisSession | null> {
    try {
      const redis = getRedisClient();
      const sessionData = await redis.get(`${this.SESSION_PREFIX}${sessionId}`);
      
      if (!sessionData) {
        return null;
      }

      const session: RedisSession = JSON.parse(sessionData);
      
      // Convert date strings back to Date objects
      session.created_at = new Date(session.created_at);
      session.expires_at = new Date(session.expires_at);
      session.last_accessed = new Date(session.last_accessed);
      session.fingerprint.timestamp = new Date(session.fingerprint.timestamp);

      return session;
    } catch (error) {
      logger.error('Failed to get session from Redis', { sessionId, error });
      return null;
    }
  }

  /**
   * Validate session with fingerprint checking
   */
  static async validateSession(
    sessionId: string,
    req: Request
  ): Promise<SessionValidationResult> {
    const session = await this.getSession(sessionId);
    
    if (!session) {
      return {
        isValid: false,
        reason: 'Session not found',
      };
    }

    // Check if session is expired
    if (new Date() > session.expires_at) {
      await this.destroySession(sessionId);
      return {
        isValid: false,
        reason: 'Session expired',
      };
    }

    // Check if session is active
    if (!session.is_active) {
      return {
        isValid: false,
        reason: 'Session inactive',
      };
    }

    // Generate current fingerprint and validate
    const currentFingerprint = FingerprintService.generateFingerprint(req);
    const fingerprintValidation = FingerprintService.validateFingerprint(
      currentFingerprint,
      session.fingerprint
    );

    // Check for session hijacking
    const hijackingDetected = FingerprintService.detectSessionHijacking(
      currentFingerprint,
      session.fingerprint
    );

    if (hijackingDetected) {
      logger.warn('Session hijacking detected, invalidating session', {
        sessionId,
        userId: session.user_id,
        currentFingerprint: currentFingerprint.hash,
        storedFingerprint: session.fingerprint.hash,
      });
      
      await this.destroySession(sessionId);
      return {
        isValid: false,
        reason: 'Session hijacking detected',
        requiresReauth: true,
      };
    }

    // Handle fingerprint validation based on risk level
    if (!fingerprintValidation.isValid) {
      logger.info('Fingerprint validation failed', {
        sessionId,
        userId: session.user_id,
        risk: fingerprintValidation.risk,
        changes: fingerprintValidation.changes,
      });

      if (fingerprintValidation.risk === 'high') {
        await this.destroySession(sessionId);
        return {
          isValid: false,
          reason: 'High-risk fingerprint change detected',
          requiresReauth: true,
        };
      }

      // For medium risk, update fingerprint but continue
      if (fingerprintValidation.risk === 'medium') {
        session.fingerprint = currentFingerprint;
        session.trust_score *= 0.8; // Reduce trust score
        await this.updateSession(sessionId, session);
      }
    }

    // Update last accessed time
    await this.updateLastAccessed(sessionId);

    return {
      isValid: true,
      session,
    };
  }

  /**
   * Update session data
   */
  static async updateSession(
    sessionId: string,
    updates: Partial<RedisSession>
  ): Promise<RedisSession | null> {
    try {
      const session = await this.getSession(sessionId);
      if (!session) {
        return null;
      }

      const updatedSession = { ...session, ...updates };
      const redis = getRedisClient();

      // Get remaining TTL
      const ttl = await redis.ttl(`${this.SESSION_PREFIX}${sessionId}`);
      const remainingTtl = ttl > 0 ? ttl : this.DEFAULT_TTL;

      await redis.setEx(
        `${this.SESSION_PREFIX}${sessionId}`,
        remainingTtl,
        JSON.stringify(updatedSession)
      );

      logger.debug('Session updated successfully', { sessionId });
      return updatedSession;
    } catch (error) {
      logger.error('Failed to update session', { sessionId, error });
      throw error;
    }
  }

  /**
   * Update session last accessed time
   */
  static async updateLastAccessed(sessionId: string): Promise<void> {
    try {
      const session = await this.getSession(sessionId);
      if (session) {
        session.last_accessed = new Date();
        await this.updateSession(sessionId, { last_accessed: session.last_accessed });
      }
    } catch (error) {
      logger.error('Failed to update last accessed time', { sessionId, error });
    }
  }

  /**
   * Extend session expiration
   */
  static async extendSession(
    sessionId: string,
    additionalSeconds: number = this.DEFAULT_TTL
  ): Promise<RedisSession | null> {
    try {
      const session = await this.getSession(sessionId);
      if (!session) {
        return null;
      }

      const newExpiresAt = new Date(Date.now() + additionalSeconds * 1000);
      const updatedSession = await this.updateSession(sessionId, {
        expires_at: newExpiresAt,
        last_accessed: new Date(),
      });

      // Also extend TTL in Redis
      const redis = getRedisClient();
      await redis.expire(`${this.SESSION_PREFIX}${sessionId}`, additionalSeconds);

      logger.info('Session extended successfully', {
        sessionId,
        newExpiresAt,
        additionalSeconds,
      });

      return updatedSession;
    } catch (error) {
      logger.error('Failed to extend session', { sessionId, error });
      throw error;
    }
  }

  /**
   * Destroy a session
   */
  static async destroySession(sessionId: string): Promise<boolean> {
    try {
      const session = await this.getSession(sessionId);
      if (!session) {
        return false;
      }

      const redis = getRedisClient();
      
      // Remove session from Redis
      await redis.del(`${this.SESSION_PREFIX}${sessionId}`);
      
      // Remove from user's session list
      await redis.sRem(`${this.USER_SESSIONS_PREFIX}${session.user_id}`, sessionId);
      
      // Mark as inactive in PostgreSQL
      await SessionModel.invalidateByToken(session.token);

      logger.info('Session destroyed successfully', {
        sessionId,
        userId: session.user_id,
      });

      return true;
    } catch (error) {
      logger.error('Failed to destroy session', { sessionId, error });
      return false;
    }
  }

  /**
   * Get all sessions for a user
   */
  static async getUserSessions(userId: string): Promise<RedisSession[]> {
    try {
      const redis = getRedisClient();
      const sessionIds = await redis.sMembers(`${this.USER_SESSIONS_PREFIX}${userId}`);
      
      const sessions: RedisSession[] = [];
      
      for (const sessionId of sessionIds) {
        const session = await this.getSession(sessionId);
        if (session && session.is_active && new Date() <= session.expires_at) {
          sessions.push(session);
        } else if (session) {
          // Clean up expired or inactive session
          await redis.sRem(`${this.USER_SESSIONS_PREFIX}${userId}`, sessionId);
        }
      }

      return sessions.sort((a, b) => b.last_accessed.getTime() - a.last_accessed.getTime());
    } catch (error) {
      logger.error('Failed to get user sessions', { userId, error });
      return [];
    }
  }

  /**
   * Destroy all sessions for a user (except optionally one)
   */
  static async destroyUserSessions(
    userId: string,
    exceptSessionId?: string
  ): Promise<number> {
    try {
      const sessions = await this.getUserSessions(userId);
      let destroyedCount = 0;

      for (const session of sessions) {
        if (session.id !== exceptSessionId) {
          const destroyed = await this.destroySession(session.id);
          if (destroyed) destroyedCount++;
        }
      }

      logger.info('User sessions destroyed', {
        userId,
        destroyedCount,
        exceptSessionId,
      });

      return destroyedCount;
    } catch (error) {
      logger.error('Failed to destroy user sessions', { userId, error });
      return 0;
    }
  }

  /**
   * Enforce concurrent session limits
   */
  private static async enforceSessionLimits(
    userId: string,
    newSessionId: string
  ): Promise<void> {
    const sessions = await this.getUserSessions(userId);
    
    if (sessions.length >= this.MAX_SESSIONS_PER_USER) {
      // Remove oldest sessions to make room
      const sessionsToRemove = sessions
        .sort((a, b) => a.last_accessed.getTime() - b.last_accessed.getTime())
        .slice(0, sessions.length - this.MAX_SESSIONS_PER_USER + 1);

      for (const session of sessionsToRemove) {
        await this.destroySession(session.id);
      }

      logger.info('Enforced session limits', {
        userId,
        removedSessions: sessionsToRemove.length,
        maxSessions: this.MAX_SESSIONS_PER_USER,
      });
    }
  }

  /**
   * Store fingerprint in history
   */
  private static async storeFingerprintHistory(
    userId: string,
    fingerprint: DeviceFingerprint
  ): Promise<void> {
    try {
      const redis = getRedisClient();
      const historyKey = `${this.FINGERPRINT_HISTORY_PREFIX}${userId}`;
      
      // Add to sorted set with timestamp as score
      await redis.zAdd(historyKey, {
        score: fingerprint.timestamp.getTime(),
        value: JSON.stringify(fingerprint),
      });

      // Keep only last 10 fingerprints
      await redis.zRemRangeByRank(historyKey, 0, -11);
      
      // Set expiry for history
      await redis.expire(historyKey, this.EXTENDED_TTL);
    } catch (error) {
      logger.error('Failed to store fingerprint history', { userId, error });
    }
  }

  /**
   * Get fingerprint history for a user
   */
  private static async getFingerprintHistory(userId: string): Promise<DeviceFingerprint[]> {
    try {
      const redis = getRedisClient();
      const historyKey = `${this.FINGERPRINT_HISTORY_PREFIX}${userId}`;
      
      const history = await redis.zRange(historyKey, 0, -1);
      
      return history.map(item => {
        const fingerprint = JSON.parse(item);
        fingerprint.timestamp = new Date(fingerprint.timestamp);
        return fingerprint;
      });
    } catch (error) {
      logger.error('Failed to get fingerprint history', { userId, error });
      return [];
    }
  }

  /**
   * Cleanup expired sessions
   */
  static async cleanupExpiredSessions(): Promise<number> {
    try {
      const redis = getRedisClient();
      let cleanupCount = 0;

      // Get all session keys
      const sessionKeys = await redis.keys(`${this.SESSION_PREFIX}*`);
      
      for (const key of sessionKeys) {
        const ttl = await redis.ttl(key);
        if (ttl === -2) { // Key doesn't exist
          cleanupCount++;
        } else if (ttl === -1) { // Key exists but has no expiry
          await redis.del(key);
          cleanupCount++;
        }
      }

      // Also cleanup user session lists
      const userSessionKeys = await redis.keys(`${this.USER_SESSIONS_PREFIX}*`);
      for (const key of userSessionKeys) {
        const sessionIds = await redis.sMembers(key);
        for (const sessionId of sessionIds) {
          const sessionExists = await redis.exists(`${this.SESSION_PREFIX}${sessionId}`);
          if (!sessionExists) {
            await redis.sRem(key, sessionId);
          }
        }
      }

      logger.info('Cleaned up expired sessions', { cleanupCount });
      return cleanupCount;
    } catch (error) {
      logger.error('Failed to cleanup expired sessions', { error });
      return 0;
    }
  }

  /**
   * Get session statistics
   */
  static async getSessionStats(): Promise<{
    totalSessions: number;
    activeSessions: number;
    userCounts: Record<string, number>;
  }> {
    try {
      const redis = getRedisClient();
      const sessionKeys = await redis.keys(`${this.SESSION_PREFIX}*`);
      const userCounts: Record<string, number> = {};
      let activeSessions = 0;

      for (const key of sessionKeys) {
        const sessionData = await redis.get(key);
        if (sessionData) {
          const session: RedisSession = JSON.parse(sessionData);
          if (session.is_active && new Date(session.expires_at) > new Date()) {
            activeSessions++;
            userCounts[session.user_id] = (userCounts[session.user_id] || 0) + 1;
          }
        }
      }

      return {
        totalSessions: sessionKeys.length,
        activeSessions,
        userCounts,
      };
    } catch (error) {
      logger.error('Failed to get session stats', { error });
      return {
        totalSessions: 0,
        activeSessions: 0,
        userCounts: {},
      };
    }
  }
}