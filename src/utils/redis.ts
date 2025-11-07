import { createClient } from 'redis';
import { appConfig } from '../config';
import { logger } from './logger';

export type RedisClient = ReturnType<typeof createClient>;

let redisClient: RedisClient | null = null;

export const createRedisClient = async (): Promise<RedisClient> => {
  if (redisClient) {
    return redisClient;
  }

  const clientOptions = {
    url: appConfig.redis.url,
    socket: {
      host: appConfig.redis.host,
      port: appConfig.redis.port,
    },
    password: appConfig.redis.password,
    database: appConfig.redis.db,
    keyPrefix: appConfig.redis.keyPrefix,
  };

  // Remove undefined values
  const cleanOptions = Object.fromEntries(
    Object.entries(clientOptions).filter(([_, value]) => value !== undefined)
  );

  redisClient = createClient(cleanOptions);

  redisClient.on('error', (err) => {
    logger.error('Redis connection error:', err);
  });

  redisClient.on('connect', () => {
    logger.info('Redis client connected');
  });

  redisClient.on('ready', () => {
    logger.info('Redis client ready');
  });

  redisClient.on('end', () => {
    logger.info('Redis client disconnected');
  });

  try {
    await redisClient.connect();
    logger.info('Redis client connected successfully');
  } catch (error) {
    logger.error('Failed to connect to Redis:', error);
    throw error;
  }

  return redisClient;
};

export const getRedisClient = (): RedisClient => {
  if (!redisClient) {
    throw new Error('Redis client not initialized. Call createRedisClient() first.');
  }
  return redisClient;
};

export const closeRedisConnection = async (): Promise<void> => {
  if (redisClient) {
    await redisClient.quit();
    redisClient = null;
    logger.info('Redis connection closed');
  }
};

// Redis session store utilities
export const sessionStore = {
  async set(sessionId: string, session: any, ttl: number): Promise<void> {
    const client = getRedisClient();
    const key = `session:${sessionId}`;
    await client.setEx(key, ttl, JSON.stringify(session));
  },

  async get(sessionId: string): Promise<any | null> {
    const client = getRedisClient();
    const key = `session:${sessionId}`;
    const data = await client.get(key);
    return data ? JSON.parse(data) : null;
  },

  async destroy(sessionId: string): Promise<void> {
    const client = getRedisClient();
    const key = `session:${sessionId}`;
    await client.del(key);
  },

  async touch(sessionId: string, ttl: number): Promise<void> {
    const client = getRedisClient();
    const key = `session:${sessionId}`;
    await client.expire(key, ttl);
  },

  async clear(): Promise<void> {
    const client = getRedisClient();
    const keys = await client.keys('session:*');
    if (keys.length > 0) {
      await client.del(keys);
    }
  },

  async length(): Promise<number> {
    const client = getRedisClient();
    const keys = await client.keys('session:*');
    return keys.length;
  },
};

export default redisClient;