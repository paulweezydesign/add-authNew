/**
 * Refresh Token Management
 * 
 * This module provides secure refresh token generation, validation, and rotation
 * for maintaining user sessions without requiring frequent re-authentication.
 */

import {
  UserPayload,
  TokenPair,
  RefreshTokenData,
  TokenValidationResult,
  JWTError,
  TokenExpiredError,
  TokenInvalidError
} from '../types/jwt';
import {
  generateAccessToken,
  generateRefreshToken,
  validateRefreshToken as validateRefreshTokenJWT,
  getUserIdFromToken,
  getTokenId,
  isTokenExpired
} from './jwt';

// In-memory storage for refresh tokens (in production, use Redis or database)
const refreshTokenStore = new Map<string, RefreshTokenData>();

/**
 * Generates a new refresh token and stores its metadata
 * @param payload - User payload
 * @param metadata - Additional metadata (IP, user agent, etc.)
 * @returns Promise<string> - The generated refresh token
 */
export async function createRefreshToken(
  payload: UserPayload,
  metadata?: {
    ipAddress?: string;
    userAgent?: string;
  }
): Promise<string> {
  try {
    // Generate the JWT refresh token
    const refreshToken = await generateRefreshToken(payload);
    const tokenId = getTokenId(refreshToken);
    
    if (!tokenId) {
      throw new JWTError('Failed to generate token ID', 'TOKEN_ID_GENERATION_FAILED', 500);
    }

    // Store refresh token metadata
    const refreshTokenData: RefreshTokenData = {
      userId: payload.id,
      tokenId,
      expiresAt: new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)), // 7 days
      createdAt: new Date(),
      ipAddress: metadata?.ipAddress,
      userAgent: metadata?.userAgent
    };

    refreshTokenStore.set(tokenId, refreshTokenData);

    return refreshToken;
  } catch (error) {
    throw new JWTError(
      `Refresh token creation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      'REFRESH_TOKEN_CREATION_FAILED',
      500
    );
  }
}

/**
 * Validates a refresh token and checks if it's been revoked
 * @param token - The refresh token to validate
 * @returns Promise<TokenValidationResult> - The validation result
 */
export async function validateRefreshToken(token: string): Promise<TokenValidationResult> {
  try {
    // First validate the JWT structure and signature
    const jwtValidation = await validateRefreshTokenJWT(token);
    
    if (!jwtValidation.valid) {
      return jwtValidation;
    }

    const tokenId = getTokenId(token);
    if (!tokenId) {
      return {
        valid: false,
        error: 'Token ID not found'
      };
    }

    // Check if token exists in our store
    const tokenData = refreshTokenStore.get(tokenId);
    if (!tokenData) {
      return {
        valid: false,
        error: 'Refresh token not found or has been revoked'
      };
    }

    // Check if token has been manually revoked
    if (tokenData.revokedAt) {
      return {
        valid: false,
        error: 'Refresh token has been revoked'
      };
    }

    // Check expiration
    if (tokenData.expiresAt && new Date() > tokenData.expiresAt) {
      // Clean up expired token
      refreshTokenStore.delete(tokenId);
      return {
        valid: false,
        error: 'Refresh token has expired',
        expired: true
      };
    }

    return jwtValidation;
  } catch (error) {
    return {
      valid: false,
      error: `Refresh token validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
    };
  }
}

/**
 * Refreshes an access token using a valid refresh token
 * @param refreshToken - The refresh token
 * @param rotateRefreshToken - Whether to generate a new refresh token (recommended)
 * @returns Promise<TokenPair> - New token pair
 */
export async function refreshAccessToken(
  refreshToken: string,
  rotateRefreshToken: boolean = true
): Promise<TokenPair> {
  try {
    // Validate the refresh token
    const validation = await validateRefreshToken(refreshToken);
    
    if (!validation.valid || !validation.payload) {
      throw new TokenInvalidError('Invalid refresh token');
    }

    // Extract user payload
    const userPayload: UserPayload = {
      id: validation.payload.id,
      email: validation.payload.email,
      roles: validation.payload.roles
    };

    // Generate new access token
    const newAccessToken = await generateAccessToken(userPayload);

    let newRefreshToken = refreshToken;
    
    if (rotateRefreshToken) {
      // Revoke the old refresh token
      await revokeRefreshToken(refreshToken);
      
      // Generate new refresh token
      newRefreshToken = await createRefreshToken(userPayload);
    }

    // Calculate expiration time in seconds (15 minutes)
    const expiresIn = 15 * 60;

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      expiresIn,
      tokenType: 'Bearer'
    };
  } catch (error) {
    if (error instanceof JWTError) {
      throw error;
    }
    throw new JWTError(
      `Token refresh failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      'TOKEN_REFRESH_FAILED',
      401
    );
  }
}

/**
 * Revokes a refresh token
 * @param token - The refresh token to revoke
 * @returns Promise<boolean> - True if successfully revoked
 */
export async function revokeRefreshToken(token: string): Promise<boolean> {
  try {
    const tokenId = getTokenId(token);
    if (!tokenId) {
      return false;
    }

    const tokenData = refreshTokenStore.get(tokenId);
    if (!tokenData) {
      return false; // Token doesn't exist
    }

    // Mark as revoked
    tokenData.revokedAt = new Date();
    refreshTokenStore.set(tokenId, tokenData);

    return true;
  } catch (error) {
    return false;
  }
}

/**
 * Revokes all refresh tokens for a specific user
 * @param userId - The user ID
 * @returns Promise<number> - Number of tokens revoked
 */
export async function revokeAllUserRefreshTokens(userId: string): Promise<number> {
  let revokedCount = 0;
  
  for (const [tokenId, tokenData] of refreshTokenStore.entries()) {
    if (tokenData.userId === userId && !tokenData.revokedAt) {
      tokenData.revokedAt = new Date();
      refreshTokenStore.set(tokenId, tokenData);
      revokedCount++;
    }
  }
  
  return revokedCount;
}

/**
 * Gets refresh token metadata
 * @param token - The refresh token
 * @returns RefreshTokenData | null - Token metadata or null if not found
 */
export async function getRefreshTokenMetadata(token: string): Promise<RefreshTokenData | null> {
  const tokenId = getTokenId(token);
  if (!tokenId) {
    return null;
  }

  return refreshTokenStore.get(tokenId) || null;
}

/**
 * Cleans up expired refresh tokens from storage
 * @returns Promise<number> - Number of tokens cleaned up
 */
export async function cleanupExpiredRefreshTokens(): Promise<number> {
  const now = new Date();
  let cleanupCount = 0;
  
  for (const [tokenId, tokenData] of refreshTokenStore.entries()) {
    if (tokenData.expiresAt && now > tokenData.expiresAt) {
      refreshTokenStore.delete(tokenId);
      cleanupCount++;
    }
  }
  
  return cleanupCount;
}

/**
 * Gets all refresh tokens for a user (for admin purposes)
 * @param userId - The user ID
 * @returns Promise<RefreshTokenData[]> - Array of user's refresh tokens
 */
export async function getUserRefreshTokens(userId: string): Promise<RefreshTokenData[]> {
  const userTokens: RefreshTokenData[] = [];
  
  for (const tokenData of refreshTokenStore.values()) {
    if (tokenData.userId === userId) {
      userTokens.push(tokenData);
    }
  }
  
  return userTokens;
}

/**
 * Validates refresh token rotation settings
 * @param token - The refresh token
 * @returns boolean - True if token should be rotated
 */
export async function shouldRotateRefreshToken(token: string): Promise<boolean> {
  const tokenData = await getRefreshTokenMetadata(token);
  if (!tokenData) {
    return true; // Default to rotation if no data
  }

  // Rotate if token is older than 1 day
  const oneDayAgo = new Date(Date.now() - (24 * 60 * 60 * 1000));
  return tokenData.createdAt < oneDayAgo;
}

/**
 * Creates a complete authentication token pair
 * @param payload - User payload
 * @param metadata - Additional metadata
 * @returns Promise<TokenPair> - Complete token pair
 */
export async function createAuthenticationTokens(
  payload: UserPayload,
  metadata?: {
    ipAddress?: string;
    userAgent?: string;
  }
): Promise<TokenPair> {
  try {
    const [accessToken, refreshToken] = await Promise.all([
      generateAccessToken(payload),
      createRefreshToken(payload, metadata)
    ]);

    // Calculate expiration time in seconds (15 minutes)
    const expiresIn = 15 * 60;

    return {
      accessToken,
      refreshToken,
      expiresIn,
      tokenType: 'Bearer'
    };
  } catch (error) {
    throw new JWTError(
      `Authentication token creation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      'AUTH_TOKEN_CREATION_FAILED',
      500
    );
  }
}

// Periodic cleanup function (call this in your application startup)
export function startRefreshTokenCleanup(intervalMinutes: number = 60): NodeJS.Timeout {
  return setInterval(async () => {
    try {
      const cleaned = await cleanupExpiredRefreshTokens();
      if (cleaned > 0) {
        console.log(`Cleaned up ${cleaned} expired refresh tokens`);
      }
    } catch (error) {
      console.error('Error during refresh token cleanup:', error);
    }
  }, intervalMinutes * 60 * 1000);
}