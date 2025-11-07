/**
 * Token Blacklisting System
 * 
 * This module provides secure token blacklisting functionality for logout,
 * token revocation, and security incident response. It efficiently manages
 * blacklisted tokens and provides fast lookup operations.
 */

import {
  BlacklistedToken,
  TokenValidationResult,
  JWTError,
  TokenBlacklistedError
} from '../types/jwt';
import {
  getTokenId,
  getUserIdFromToken,
  getTokenMetadata,
  isTokenExpired
} from './jwt';

// In-memory blacklist storage (in production, use Redis or database)
const blacklistStore = new Map<string, BlacklistedToken>();

// Set to store blacklisted token IDs for faster lookup
const blacklistedTokenIds = new Set<string>();

/**
 * Adds a token to the blacklist
 * @param token - The JWT token to blacklist
 * @param reason - Reason for blacklisting
 * @param userId - Optional user ID (extracted from token if not provided)
 * @returns Promise<boolean> - True if successfully blacklisted
 */
export async function addToBlacklist(
  token: string,
  reason: 'logout' | 'revoked' | 'security',
  userId?: string
): Promise<boolean> {
  try {
    const tokenId = getTokenId(token);
    if (!tokenId) {
      throw new JWTError('Invalid token: cannot extract token ID', 'INVALID_TOKEN_ID', 400);
    }

    // Extract user ID from token if not provided
    const extractedUserId = userId || getUserIdFromToken(token);
    if (!extractedUserId) {
      throw new JWTError('Invalid token: cannot extract user ID', 'INVALID_USER_ID', 400);
    }

    // Get token metadata for expiration
    const metadata = getTokenMetadata(token);
    if (!metadata) {
      throw new JWTError('Invalid token: cannot extract metadata', 'INVALID_TOKEN_METADATA', 400);
    }

    // Create blacklist entry
    const blacklistedToken: BlacklistedToken = {
      tokenId,
      userId: extractedUserId,
      expiresAt: metadata.expiresAt,
      blacklistedAt: new Date(),
      reason
    };

    // Store in both the map and set for efficient lookups
    blacklistStore.set(tokenId, blacklistedToken);
    blacklistedTokenIds.add(tokenId);

    return true;
  } catch (error) {
    console.error('Error adding token to blacklist:', error);
    return false;
  }
}

/**
 * Checks if a token is blacklisted
 * @param token - The JWT token to check
 * @returns Promise<boolean> - True if token is blacklisted
 */
export async function isTokenBlacklisted(token: string): Promise<boolean> {
  try {
    const tokenId = getTokenId(token);
    if (!tokenId) {
      return false; // Invalid tokens are handled elsewhere
    }

    return blacklistedTokenIds.has(tokenId);
  } catch (error) {
    console.error('Error checking token blacklist status:', error);
    return false;
  }
}

/**
 * Validates that a token is not blacklisted
 * @param token - The JWT token to validate
 * @returns Promise<TokenValidationResult> - Validation result
 */
export async function validateTokenNotBlacklisted(token: string): Promise<TokenValidationResult> {
  try {
    const isBlacklisted = await isTokenBlacklisted(token);
    
    if (isBlacklisted) {
      const tokenId = getTokenId(token);
      const blacklistEntry = tokenId ? blacklistStore.get(tokenId) : null;
      
      return {
        valid: false,
        error: `Token has been blacklisted (reason: ${blacklistEntry?.reason || 'unknown'})`
      };
    }

    return {
      valid: true
    };
  } catch (error) {
    return {
      valid: false,
      error: `Blacklist validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
    };
  }
}

/**
 * Removes a token from the blacklist (for administrative purposes)
 * @param token - The JWT token to remove from blacklist
 * @returns Promise<boolean> - True if successfully removed
 */
export async function removeFromBlacklist(token: string): Promise<boolean> {
  try {
    const tokenId = getTokenId(token);
    if (!tokenId) {
      return false;
    }

    // Remove from both storage mechanisms
    const removed = blacklistStore.delete(tokenId);
    blacklistedTokenIds.delete(tokenId);

    return removed;
  } catch (error) {
    console.error('Error removing token from blacklist:', error);
    return false;
  }
}

/**
 * Blacklists all tokens for a specific user
 * @param userId - The user ID
 * @param reason - Reason for blacklisting
 * @returns Promise<number> - Number of tokens blacklisted
 */
export async function blacklistAllUserTokens(
  userId: string,
  reason: 'logout' | 'revoked' | 'security' = 'security'
): Promise<number> {
  let blacklistedCount = 0;
  
  // Note: This would typically involve querying active tokens from storage
  // For now, we'll add a placeholder mechanism
  console.log(`Blacklisting all tokens for user ${userId} with reason: ${reason}`);
  
  // In a real implementation, you would:
  // 1. Query all active tokens for the user from your token storage
  // 2. Add each token to the blacklist
  // 3. Return the count
  
  return blacklistedCount;
}

/**
 * Gets blacklist information for a token
 * @param token - The JWT token
 * @returns Promise<BlacklistedToken | null> - Blacklist entry or null if not blacklisted
 */
export async function getBlacklistInfo(token: string): Promise<BlacklistedToken | null> {
  try {
    const tokenId = getTokenId(token);
    if (!tokenId) {
      return null;
    }

    return blacklistStore.get(tokenId) || null;
  } catch (error) {
    console.error('Error getting blacklist info:', error);
    return null;
  }
}

/**
 * Cleans up expired tokens from the blacklist
 * @returns Promise<number> - Number of expired tokens cleaned up
 */
export async function cleanupExpiredBlacklistedTokens(): Promise<number> {
  const now = new Date();
  let cleanupCount = 0;
  
  for (const [tokenId, blacklistEntry] of blacklistStore.entries()) {
    if (now > blacklistEntry.expiresAt) {
      blacklistStore.delete(tokenId);
      blacklistedTokenIds.delete(tokenId);
      cleanupCount++;
    }
  }
  
  return cleanupCount;
}

/**
 * Gets all blacklisted tokens for a user
 * @param userId - The user ID
 * @returns Promise<BlacklistedToken[]> - Array of blacklisted tokens for the user
 */
export async function getUserBlacklistedTokens(userId: string): Promise<BlacklistedToken[]> {
  const userTokens: BlacklistedToken[] = [];
  
  for (const blacklistEntry of blacklistStore.values()) {
    if (blacklistEntry.userId === userId) {
      userTokens.push(blacklistEntry);
    }
  }
  
  return userTokens;
}

/**
 * Gets blacklist statistics
 * @returns Promise<{total: number, expired: number, byReason: Record<string, number>}> - Statistics
 */
export async function getBlacklistStats(): Promise<{
  total: number;
  expired: number;
  byReason: Record<string, number>;
}> {
  const now = new Date();
  let expired = 0;
  const byReason: Record<string, number> = {
    logout: 0,
    revoked: 0,
    security: 0
  };

  for (const blacklistEntry of blacklistStore.values()) {
    if (now > blacklistEntry.expiresAt) {
      expired++;
    }
    byReason[blacklistEntry.reason]++;
  }

  return {
    total: blacklistStore.size,
    expired,
    byReason
  };
}

/**
 * Performs a logout operation by blacklisting the token
 * @param token - The access token to blacklist
 * @param refreshToken - Optional refresh token to also blacklist
 * @returns Promise<boolean> - True if successfully logged out
 */
export async function performLogout(
  token: string,
  refreshToken?: string
): Promise<boolean> {
  try {
    let success = true;
    
    // Blacklist the access token
    const accessTokenBlacklisted = await addToBlacklist(token, 'logout');
    if (!accessTokenBlacklisted) {
      success = false;
    }

    // Blacklist the refresh token if provided
    if (refreshToken) {
      const refreshTokenBlacklisted = await addToBlacklist(refreshToken, 'logout');
      if (!refreshTokenBlacklisted) {
        success = false;
      }
    }

    return success;
  } catch (error) {
    console.error('Error during logout:', error);
    return false;
  }
}

/**
 * Performs a security revocation by blacklisting all user tokens
 * @param userId - The user ID
 * @param tokens - Array of specific tokens to blacklist
 * @returns Promise<{success: boolean, blacklistedCount: number}> - Operation result
 */
export async function performSecurityRevocation(
  userId: string,
  tokens: string[] = []
): Promise<{ success: boolean; blacklistedCount: number }> {
  let blacklistedCount = 0;
  let success = true;

  try {
    // Blacklist specific tokens if provided
    for (const token of tokens) {
      const blacklisted = await addToBlacklist(token, 'security', userId);
      if (blacklisted) {
        blacklistedCount++;
      } else {
        success = false;
      }
    }

    // If no specific tokens provided, blacklist all user tokens
    if (tokens.length === 0) {
      blacklistedCount = await blacklistAllUserTokens(userId, 'security');
    }

    return { success, blacklistedCount };
  } catch (error) {
    console.error('Error during security revocation:', error);
    return { success: false, blacklistedCount };
  }
}

/**
 * Middleware function to check token blacklist status
 * @param token - The JWT token to check
 * @returns Promise<void> - Throws TokenBlacklistedError if blacklisted
 */
export async function enforceTokenBlacklist(token: string): Promise<void> {
  const isBlacklisted = await isTokenBlacklisted(token);
  
  if (isBlacklisted) {
    const blacklistInfo = await getBlacklistInfo(token);
    throw new TokenBlacklistedError(
      `Token has been blacklisted (reason: ${blacklistInfo?.reason || 'unknown'})`
    );
  }
}

/**
 * Starts periodic cleanup of expired blacklisted tokens
 * @param intervalMinutes - Cleanup interval in minutes (default: 60)
 * @returns NodeJS.Timeout - The interval timer
 */
export function startBlacklistCleanup(intervalMinutes: number = 60): NodeJS.Timeout {
  return setInterval(async () => {
    try {
      const cleaned = await cleanupExpiredBlacklistedTokens();
      if (cleaned > 0) {
        console.log(`Cleaned up ${cleaned} expired blacklisted tokens`);
      }
    } catch (error) {
      console.error('Error during blacklist cleanup:', error);
    }
  }, intervalMinutes * 60 * 1000);
}

/**
 * Initializes the blacklist system
 * @param options - Initialization options
 */
export function initializeBlacklistSystem(options?: {
  cleanupInterval?: number; // in minutes
  autoCleanup?: boolean;
}): NodeJS.Timeout | null {
  const { cleanupInterval = 60, autoCleanup = true } = options || {};
  
  console.log('Initializing token blacklist system...');
  
  if (autoCleanup) {
    return startBlacklistCleanup(cleanupInterval);
  }
  
  return null;
}