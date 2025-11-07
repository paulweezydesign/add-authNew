import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';
import { db } from './connection';
import { logger } from '../utils/logger';

interface Migration {
  version: string;
  filename: string;
  sql: string;
}

class MigrationManager {
  private migrationsDir = join(__dirname, 'migrations');

  private async getMigrations(): Promise<Migration[]> {
    const files = readdirSync(this.migrationsDir)
      .filter(file => file.endsWith('.sql'))
      .sort();

    return files.map(filename => {
      const version = filename.replace('.sql', '');
      const sql = readFileSync(join(this.migrationsDir, filename), 'utf8');
      return { version, filename, sql };
    });
  }

  private async getAppliedMigrations(): Promise<string[]> {
    try {
      const result = await db.query(
        'SELECT version FROM schema_migrations ORDER BY version'
      );
      return result.rows.map((row: any) => row.version);
    } catch (error) {
      // If schema_migrations table doesn't exist, no migrations have been applied
      logger.info('Schema migrations table does not exist, assuming no migrations applied');
      return [];
    }
  }

  private async applyMigration(migration: Migration): Promise<void> {
    const client = await db.getClient();
    try {
      await client.query('BEGIN');
      
      logger.info(`Applying migration: ${migration.filename}`);
      
      // Execute the migration SQL
      await client.query(migration.sql);
      
      // Record the migration as applied
      await client.query(
        'INSERT INTO schema_migrations (version) VALUES ($1)',
        [migration.version]
      );
      
      await client.query('COMMIT');
      logger.info(`Migration applied successfully: ${migration.filename}`);
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error(`Error applying migration ${migration.filename}:`, error);
      throw error;
    } finally {
      client.release();
    }
  }

  public async migrate(): Promise<void> {
    try {
      logger.info('Starting database migrations...');
      
      // Test database connection
      const connectionTest = await db.testConnection();
      if (!connectionTest) {
        throw new Error('Database connection test failed');
      }

      const migrations = await this.getMigrations();
      const appliedMigrations = await this.getAppliedMigrations();

      const pendingMigrations = migrations.filter(
        migration => !appliedMigrations.includes(migration.version)
      );

      if (pendingMigrations.length === 0) {
        logger.info('No pending migrations');
        return;
      }

      logger.info(`Found ${pendingMigrations.length} pending migrations`);

      for (const migration of pendingMigrations) {
        await this.applyMigration(migration);
      }

      logger.info('All migrations completed successfully');
    } catch (error) {
      logger.error('Migration failed:', error);
      throw error;
    }
  }

  public async rollback(steps = 1): Promise<void> {
    try {
      logger.info(`Rolling back ${steps} migration(s)...`);
      
      const appliedMigrations = await this.getAppliedMigrations();
      
      if (appliedMigrations.length === 0) {
        logger.info('No migrations to rollback');
        return;
      }

      const migrationsToRollback = appliedMigrations
        .slice(-steps)
        .reverse();

      for (const version of migrationsToRollback) {
        await this.rollbackMigration(version);
      }

      logger.info('Rollback completed successfully');
    } catch (error) {
      logger.error('Rollback failed:', error);
      throw error;
    }
  }

  private async rollbackMigration(version: string): Promise<void> {
    const client = await db.getClient();
    try {
      await client.query('BEGIN');
      
      logger.info(`Rolling back migration: ${version}`);
      
      // Check if rollback file exists
      const rollbackFile = join(this.migrationsDir, 'rollbacks', `${version}.sql`);
      try {
        const rollbackSql = readFileSync(rollbackFile, 'utf8');
        await client.query(rollbackSql);
      } catch (error) {
        logger.warn(`No rollback file found for ${version}, skipping SQL rollback`);
      }
      
      // Remove migration record
      await client.query(
        'DELETE FROM schema_migrations WHERE version = $1',
        [version]
      );
      
      await client.query('COMMIT');
      logger.info(`Migration rolled back successfully: ${version}`);
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error(`Error rolling back migration ${version}:`, error);
      throw error;
    } finally {
      client.release();
    }
  }

  public async getStatus(): Promise<void> {
    try {
      const migrations = await this.getMigrations();
      const appliedMigrations = await this.getAppliedMigrations();

      console.log('\n=== Migration Status ===');
      console.log(`Total migrations: ${migrations.length}`);
      console.log(`Applied migrations: ${appliedMigrations.length}`);
      console.log(`Pending migrations: ${migrations.length - appliedMigrations.length}`);
      
      console.log('\n=== Migration Details ===');
      migrations.forEach(migration => {
        const status = appliedMigrations.includes(migration.version) ? '✓' : '✗';
        console.log(`${status} ${migration.filename}`);
      });
      console.log('');
    } catch (error) {
      logger.error('Error getting migration status:', error);
      throw error;
    }
  }
}

// Export singleton instance
export const migrationManager = new MigrationManager();

// Command line interface
async function main(): Promise<void> {
  const command = process.argv[2];
  
  try {
    switch (command) {
      case 'migrate':
        await migrationManager.migrate();
        break;
      case 'rollback':
        const steps = parseInt(process.argv[3] || '1', 10);
        await migrationManager.rollback(steps);
        break;
      case 'status':
        await migrationManager.getStatus();
        break;
      default:
        console.log('Usage: ts-node migrate.ts <command>');
        console.log('Commands:');
        console.log('  migrate        - Run pending migrations');
        console.log('  rollback [n]   - Rollback n migrations (default: 1)');
        console.log('  status         - Show migration status');
        process.exit(1);
    }
  } catch (error) {
    logger.error('Migration command failed:', error);
    process.exit(1);
  } finally {
    await db.close();
  }
}

// Run if called directly
if (require.main === module) {
  main();
}

// Helper function to get applied migrations (needed for the migrate method)
async function getAppliedMigrations(): Promise<string[]> {
  try {
    const result = await db.query(
      'SELECT version FROM schema_migrations ORDER BY version'
    );
    return result.rows.map((row: any) => row.version);
  } catch (error) {
    logger.info('Schema migrations table does not exist, assuming no migrations applied');
    return [];
  }
}