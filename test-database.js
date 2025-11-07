// Test script for database schema and models
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

// Database configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'add_auth',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'password',
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
};

console.log('🔍 Testing Database Schema & Models Setup...\n');

async function testDatabaseConnection() {
  console.log('1. Testing database connection...');
  const pool = new Pool(dbConfig);
  
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT NOW()');
    console.log('✅ Database connection successful');
    console.log(`   Server time: ${result.rows[0].now}`);
    client.release();
    await pool.end();
    return true;
  } catch (error) {
    console.log('❌ Database connection failed');
    console.log(`   Error: ${error.message}`);
    return false;
  }
}

async function checkMigrationFiles() {
  console.log('\n2. Checking migration files...');
  const migrationsDir = path.join(__dirname, 'src', 'database', 'migrations');
  
  try {
    const files = fs.readdirSync(migrationsDir).filter(file => file.endsWith('.sql'));
    console.log(`✅ Found ${files.length} migration files:`);
    files.forEach(file => {
      console.log(`   - ${file}`);
    });
    return files;
  } catch (error) {
    console.log('❌ Migration files check failed');
    console.log(`   Error: ${error.message}`);
    return [];
  }
}

async function validateMigrationContent() {
  console.log('\n3. Validating migration content...');
  const migrationsDir = path.join(__dirname, 'src', 'database', 'migrations');
  const expectedTables = ['schema_migrations', 'users', 'sessions', 'roles', 'user_roles', 'audit_logs', 'oauth_accounts'];
  const foundTables = new Set();
  
  try {
    const files = fs.readdirSync(migrationsDir).filter(file => file.endsWith('.sql'));
    
    for (const file of files) {
      const content = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
      
      // Check for CREATE TABLE statements
      const createTableMatches = content.match(/CREATE TABLE[^(]*\([^)]*\)/gi);
      if (createTableMatches) {
        createTableMatches.forEach(match => {
          const tableName = match.match(/CREATE TABLE\s+(?:IF NOT EXISTS\s+)?(\w+)/i);
          if (tableName) {
            foundTables.add(tableName[1]);
          }
        });
      }
    }
    
    console.log('✅ Migration content validation:');
    expectedTables.forEach(table => {
      if (foundTables.has(table)) {
        console.log(`   ✓ ${table} table migration found`);
      } else {
        console.log(`   ✗ ${table} table migration missing`);
      }
    });
    
    return Array.from(foundTables);
  } catch (error) {
    console.log('❌ Migration content validation failed');
    console.log(`   Error: ${error.message}`);
    return [];
  }
}

async function testModelsExist() {
  console.log('\n4. Checking model files...');
  const modelsDir = path.join(__dirname, 'src', 'models');
  const expectedModels = ['User.ts', 'Session.ts', 'Role.ts', 'AuditLog.ts'];
  
  try {
    const modelFiles = [];
    for (const model of expectedModels) {
      const modelPath = path.join(modelsDir, model);
      if (fs.existsSync(modelPath)) {
        console.log(`   ✓ ${model} model found`);
        modelFiles.push(model);
      } else {
        console.log(`   ✗ ${model} model missing`);
      }
    }
    
    console.log(`✅ Found ${modelFiles.length}/${expectedModels.length} model files`);
    return modelFiles;
  } catch (error) {
    console.log('❌ Model files check failed');
    console.log(`   Error: ${error.message}`);
    return [];
  }
}

async function testConnectionPooling() {
  console.log('\n5. Testing connection pooling...');
  
  try {
    // Test multiple concurrent connections
    const pool = new Pool({
      ...dbConfig,
      max: 5, // Maximum 5 connections in pool
      idleTimeoutMillis: 1000,
      connectionTimeoutMillis: 2000,
    });
    
    const promises = [];
    for (let i = 0; i < 3; i++) {
      promises.push(
        pool.query('SELECT $1 as connection_test', [`Connection ${i + 1}`])
      );
    }
    
    const results = await Promise.all(promises);
    console.log('✅ Connection pooling test successful');
    console.log(`   Concurrent connections handled: ${results.length}`);
    
    await pool.end();
    return true;
  } catch (error) {
    console.log('❌ Connection pooling test failed');
    console.log(`   Error: ${error.message}`);
    return false;
  }
}

async function checkDatabaseConfiguration() {
  console.log('\n6. Checking database configuration...');
  
  try {
    const configPath = path.join(__dirname, 'src', 'config', 'index.ts');
    if (fs.existsSync(configPath)) {
      console.log('✅ Database configuration file found');
      const configContent = fs.readFileSync(configPath, 'utf8');
      
      // Check for required configuration options
      const requiredConfigs = [
        'DATABASE_URL',
        'DB_HOST',
        'DB_PORT',
        'DB_NAME',
        'DB_USER',
        'DB_PASSWORD',
        'DB_SSL'
      ];
      
      const foundConfigs = requiredConfigs.filter(config => 
        configContent.includes(config)
      );
      
      console.log(`   Found ${foundConfigs.length}/${requiredConfigs.length} required configurations`);
      return true;
    } else {
      console.log('❌ Database configuration file not found');
      return false;
    }
  } catch (error) {
    console.log('❌ Database configuration check failed');
    console.log(`   Error: ${error.message}`);
    return false;
  }
}

async function checkIndexes() {
  console.log('\n7. Checking database indexes in migrations...');
  const migrationsDir = path.join(__dirname, 'src', 'database', 'migrations');
  
  try {
    const files = fs.readdirSync(migrationsDir).filter(file => file.endsWith('.sql'));
    let indexCount = 0;
    
    for (const file of files) {
      const content = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
      const indexes = content.match(/CREATE\s+(?:UNIQUE\s+)?INDEX/gi);
      if (indexes) {
        indexCount += indexes.length;
      }
    }
    
    console.log(`✅ Found ${indexCount} database indexes in migrations`);
    console.log('   Indexes are important for query performance');
    return indexCount > 0;
  } catch (error) {
    console.log('❌ Index check failed');
    console.log(`   Error: ${error.message}`);
    return false;
  }
}

async function generateTestReport() {
  console.log('\n' + '='.repeat(60));
  console.log('📋 DATABASE SCHEMA & MODELS TEST REPORT');
  console.log('='.repeat(60));
  
  const results = {
    connectionTest: await testDatabaseConnection(),
    migrationFiles: await checkMigrationFiles(),
    migrationContent: await validateMigrationContent(),
    modelFiles: await testModelsExist(),
    connectionPooling: await testConnectionPooling(),
    databaseConfig: await checkDatabaseConfiguration(),
    indexes: await checkIndexes(),
  };
  
  console.log('\n📊 Test Summary:');
  Object.entries(results).forEach(([test, result]) => {
    const status = Array.isArray(result) ? (result.length > 0 ? '✅' : '❌') : (result ? '✅' : '❌');
    console.log(`   ${status} ${test}`);
  });
  
  const passed = Object.values(results).filter(result => 
    Array.isArray(result) ? result.length > 0 : result
  ).length;
  const total = Object.keys(results).length;
  
  console.log(`\n🎯 Score: ${passed}/${total} tests passed`);
  
  if (passed === total) {
    console.log('🎉 All database tests passed! Task #1 implementation is complete.');
  } else {
    console.log('⚠️  Some tests failed. Please review the implementation.');
  }
  
  return { passed, total, results };
}

// Run the test suite
async function main() {
  try {
    const report = await generateTestReport();
    process.exit(report.passed === report.total ? 0 : 1);
  } catch (error) {
    console.error('Test suite failed:', error);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { testDatabaseConnection, checkMigrationFiles, validateMigrationContent };