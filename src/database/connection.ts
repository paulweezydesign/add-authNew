import { Pool, PoolClient } from 'pg';
import { appConfig } from '../config';
import { logger } from '../utils/logger';

class DatabaseConnection {
  private pool: Pool;
  private static instance: DatabaseConnection;

  private constructor() {
    const connectionConfig = appConfig.database.url
      ? { connectionString: appConfig.database.url, ssl: appConfig.database.ssl }
      : {
          host: appConfig.database.host,
          port: appConfig.database.port,
          database: appConfig.database.name,
          user: appConfig.database.user,
          password: appConfig.database.password,
          ssl: appConfig.database.ssl,
        };

    this.pool = new Pool({
      ...connectionConfig,
      max: 20, // Maximum number of clients in the pool
      idleTimeoutMillis: 30000, // Close idle clients after 30 seconds
      connectionTimeoutMillis: 10000, // Return an error after 10 seconds if connection could not be established
    });

    this.pool.on('error', (err) => {
      logger.error('Unexpected error on idle client', err);
    });

    this.pool.on('connect', () => {
      logger.info('New client connected to database');
    });

    this.pool.on('remove', () => {
      logger.info('Client removed from pool');
    });
  }

  public static getInstance(): DatabaseConnection {
    if (!DatabaseConnection.instance) {
      DatabaseConnection.instance = new DatabaseConnection();
    }
    return DatabaseConnection.instance;
  }

  public async getClient(): Promise<PoolClient> {
    try {
      const client = await this.pool.connect();
      return client;
    } catch (error) {
      logger.error('Error getting database client', error);
      throw error;
    }
  }

  public async query(text: string, params?: any[]): Promise<any> {
    const client = await this.getClient();
    try {
      const result = await client.query(text, params);
      return result;
    } catch (error) {
      logger.error('Database query error', { query: text, params, error });
      throw error;
    } finally {
      client.release();
    }
  }

  public async transaction<T>(
    callback: (client: PoolClient) => Promise<T>
  ): Promise<T> {
    const client = await this.getClient();
    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error('Transaction error', error);
      throw error;
    } finally {
      client.release();
    }
  }

  public async testConnection(): Promise<boolean> {
    try {
      const result = await this.query('SELECT NOW()');
      logger.info('Database connection test successful', {
        serverTime: result.rows[0].now,
      });
      return true;
    } catch (error) {
      logger.error('Database connection test failed', error);
      return false;
    }
  }

  public async close(): Promise<void> {
    await this.pool.end();
    logger.info('Database connection pool closed');
  }
}

export const db = DatabaseConnection.getInstance();
export default db;