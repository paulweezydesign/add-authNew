# Development Setup Guide

This guide provides detailed instructions for setting up the authentication system for local development.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Initial Setup](#initial-setup)
- [Database Setup](#database-setup)
- [Redis Setup](#redis-setup)
- [Environment Configuration](#environment-configuration)
- [Security Keys Generation](#security-keys-generation)
- [Development Tools](#development-tools)
- [Code Quality](#code-quality)
- [Testing](#testing)
- [Debugging](#debugging)
- [Troubleshooting](#troubleshooting)

## Prerequisites

Ensure you have the following installed on your development machine:

### Required Software

- **Node.js**: Version 18.x or higher
- **npm**: Version 9.x or higher (comes with Node.js)
- **PostgreSQL**: Version 14.x or higher
- **Redis**: Version 6.x or higher
- **Git**: Version 2.x or higher

### Optional but Recommended

- **Docker & Docker Compose**: For containerized development
- **Visual Studio Code**: With recommended extensions
- **Postman**: For API testing
- **pgAdmin**: For database management

### Installation Instructions

#### Node.js and npm

**macOS (using Homebrew):**
```bash
brew install node
```

**Ubuntu/Debian:**
```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

**Windows:**
Download from [nodejs.org](https://nodejs.org/)

#### PostgreSQL

**macOS (using Homebrew):**
```bash
brew install postgresql
brew services start postgresql
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

**Windows:**
Download from [postgresql.org](https://www.postgresql.org/download/)

#### Redis

**macOS (using Homebrew):**
```bash
brew install redis
brew services start redis
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install redis-server
sudo systemctl start redis-server
sudo systemctl enable redis-server
```

**Windows:**
Use Docker or WSL2 with Linux installation

## Initial Setup

### 1. Clone the Repository

```bash
git clone <repository-url>
cd add-auth
```

### 2. Install Dependencies

```bash
# Install project dependencies
npm install

# Install global development tools (optional)
npm install -g nodemon ts-node typescript
```

### 3. Verify Installation

```bash
# Check Node.js version
node --version  # Should be 18.x or higher

# Check npm version
npm --version   # Should be 9.x or higher

# Check PostgreSQL
psql --version  # Should be 14.x or higher

# Check Redis
redis-cli ping  # Should return PONG
```

## Database Setup

### 1. Create Database User

```bash
# Connect to PostgreSQL as superuser
sudo -u postgres psql

# Create database user
CREATE USER auth_user WITH PASSWORD 'your_secure_password';

# Create database
CREATE DATABASE auth_db OWNER auth_user;

# Grant privileges
GRANT ALL PRIVILEGES ON DATABASE auth_db TO auth_user;

# Exit PostgreSQL
\q
```

### 2. Database Configuration

Create a `.env` file in the project root:

```env
# Database Configuration
DATABASE_URL=postgresql://auth_user:your_secure_password@localhost:5432/auth_db
DB_HOST=localhost
DB_PORT=5432
DB_NAME=auth_db
DB_USER=auth_user
DB_PASSWORD=your_secure_password
```

### 3. Test Database Connection

```bash
# Test connection
npm run db:test

# Or manually with psql
psql -h localhost -U auth_user -d auth_db
```

## Redis Setup

### 1. Configure Redis

Edit Redis configuration (usually at `/etc/redis/redis.conf`):

```conf
# Bind to localhost only for development
bind 127.0.0.1

# Set a password (optional for development)
requirepass your_redis_password

# Set maximum memory (optional)
maxmemory 256mb
maxmemory-policy allkeys-lru

# Enable AOF persistence
appendonly yes
```

### 2. Restart Redis

```bash
# macOS
brew services restart redis

# Ubuntu/Debian
sudo systemctl restart redis-server
```

### 3. Test Redis Connection

```bash
# Test without password
redis-cli ping

# Test with password
redis-cli -a your_redis_password ping
```

## Environment Configuration

### 1. Create Environment File

Copy the example environment file:

```bash
cp .env.example .env
```

### 2. Configure Environment Variables

Edit `.env` file with your development settings:

```env
# Application Configuration
NODE_ENV=development
PORT=3000
API_PREFIX=/api/v1
FRONTEND_URL=http://localhost:3000

# Database Configuration
DATABASE_URL=postgresql://auth_user:your_secure_password@localhost:5432/auth_db
DB_HOST=localhost
DB_PORT=5432
DB_NAME=auth_db
DB_USER=auth_user
DB_PASSWORD=your_secure_password

# Redis Configuration
REDIS_URL=redis://localhost:6379
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-here-minimum-32-characters
JWT_REFRESH_SECRET=your-refresh-token-secret-here-minimum-32-characters
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# RSA Keys for JWT Signing
JWT_PRIVATE_KEY_PATH=./keys/private.key
JWT_PUBLIC_KEY_PATH=./keys/public.key

# Email Configuration (for development)
EMAIL_SERVICE=smtp
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
EMAIL_FROM=noreply@localhost

# OAuth Configuration (optional for development)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Security Configuration
BCRYPT_SALT_ROUNDS=12
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100
SESSION_SECRET=your-session-secret-key-minimum-32-characters
CSRF_SECRET=your-csrf-secret-key-minimum-32-characters

# Development Configuration
DEBUG=auth:*
LOG_LEVEL=debug
ENABLE_CORS=true
ENABLE_SWAGGER=true
```

### 3. Generate Secure Secrets

```bash
# Generate random secrets
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Or use openssl
openssl rand -hex 32
```

## Security Keys Generation

### 1. Create Keys Directory

```bash
mkdir -p keys
chmod 700 keys
```

### 2. Generate RSA Key Pair

```bash
# Generate private key
openssl genrsa -out keys/private.key 2048

# Generate public key
openssl rsa -in keys/private.key -pubout -out keys/public.key

# Set proper permissions
chmod 600 keys/private.key
chmod 644 keys/public.key
```

### 3. Verify Keys

```bash
# Check private key
openssl rsa -in keys/private.key -check

# Check public key
openssl rsa -in keys/public.key -pubin -text -noout
```

## Development Tools

### 1. Install Recommended VS Code Extensions

Create `.vscode/extensions.json`:

```json
{
  "recommendations": [
    "ms-vscode.vscode-typescript-next",
    "bradlc.vscode-tailwindcss",
    "esbenp.prettier-vscode",
    "dbaeumer.vscode-eslint",
    "ms-vscode.vscode-json",
    "redhat.vscode-yaml",
    "ms-vscode.vscode-jest",
    "formulahendry.auto-rename-tag",
    "christian-kohler.path-intellisense",
    "ms-vscode.vscode-thunder-client"
  ]
}
```

### 2. Configure VS Code Settings

Create `.vscode/settings.json`:

```json
{
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true
  },
  "typescript.preferences.importModuleSpecifier": "relative",
  "jest.autoRun": "off",
  "files.exclude": {
    "**/node_modules": true,
    "**/dist": true,
    "**/.git": true
  }
}
```

### 3. Configure Debug Configuration

Create `.vscode/launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug Server",
      "type": "node",
      "request": "launch",
      "program": "${workspaceFolder}/src/index.ts",
      "outFiles": ["${workspaceFolder}/dist/**/*.js"],
      "runtimeArgs": ["-r", "ts-node/register"],
      "env": {
        "NODE_ENV": "development"
      },
      "envFile": "${workspaceFolder}/.env",
      "console": "integratedTerminal",
      "internalConsoleOptions": "neverOpen"
    },
    {
      "name": "Debug Tests",
      "type": "node",
      "request": "launch",
      "program": "${workspaceFolder}/node_modules/.bin/jest",
      "args": ["--runInBand", "--no-cache", "--no-coverage"],
      "console": "integratedTerminal",
      "internalConsoleOptions": "neverOpen"
    }
  ]
}
```

## Code Quality

### 1. ESLint Configuration

The project includes ESLint configuration in `.eslintrc.json`:

```json
{
  "env": {
    "node": true,
    "es2021": true
  },
  "extends": [
    "eslint:recommended",
    "@typescript-eslint/recommended",
    "plugin:security/recommended"
  ],
  "parser": "@typescript-eslint/parser",
  "parserOptions": {
    "ecmaVersion": 12,
    "sourceType": "module"
  },
  "plugins": [
    "@typescript-eslint",
    "security"
  ],
  "rules": {
    "no-console": "warn",
    "no-unused-vars": "off",
    "@typescript-eslint/no-unused-vars": "error",
    "@typescript-eslint/explicit-function-return-type": "warn",
    "@typescript-eslint/no-explicit-any": "warn",
    "security/detect-non-literal-regexp": "error",
    "security/detect-unsafe-regex": "error",
    "security/detect-buffer-noassert": "error",
    "security/detect-child-process": "error",
    "security/detect-disable-mustache-escape": "error",
    "security/detect-eval-with-expression": "error",
    "security/detect-no-csrf-before-method-override": "error",
    "security/detect-non-literal-fs-filename": "error",
    "security/detect-non-literal-require": "error",
    "security/detect-possible-timing-attacks": "error",
    "security/detect-pseudoRandomBytes": "error"
  }
}
```

### 2. Prettier Configuration

Create `.prettierrc`:

```json
{
  "semi": true,
  "trailingComma": "es5",
  "singleQuote": true,
  "printWidth": 100,
  "tabWidth": 2,
  "useTabs": false,
  "bracketSpacing": true,
  "arrowParens": "avoid"
}
```

### 3. Pre-commit Hooks

Install Husky for pre-commit hooks:

```bash
npm install --save-dev husky
npx husky install
```

Create `.husky/pre-commit`:

```bash
#!/bin/sh
. "$(dirname "$0")/_/husky.sh"

npm run lint
npm run test
```

## Testing

### 1. Test Configuration

Jest configuration in `jest.config.js`:

```javascript
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/*.test.ts',
    '!src/**/*.spec.ts',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  testTimeout: 10000,
};
```

### 2. Test Database Setup

Create `tests/setup.ts`:

```typescript
import { PrismaClient } from '@prisma/client';

let prisma: PrismaClient;

beforeAll(async () => {
  prisma = new PrismaClient({
    datasources: {
      db: {
        url: process.env.TEST_DATABASE_URL,
      },
    },
  });

  // Run migrations
  await prisma.$executeRaw`DROP SCHEMA IF EXISTS public CASCADE`;
  await prisma.$executeRaw`CREATE SCHEMA public`;
  // Add migration commands here
});

afterAll(async () => {
  await prisma.$disconnect();
});

beforeEach(async () => {
  // Clean database before each test
  await prisma.user.deleteMany();
  await prisma.session.deleteMany();
  await prisma.auditLog.deleteMany();
});

export { prisma };
```

### 3. Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage

# Run specific test file
npm test -- auth.test.ts

# Run tests matching pattern
npm test -- --testNamePattern="login"
```

## Debugging

### 1. Enable Debug Logging

```bash
# Enable all debug logs
DEBUG=auth:* npm run dev

# Enable specific debug logs
DEBUG=auth:database,auth:redis npm run dev
```

### 2. Debug with VS Code

1. Set breakpoints in your code
2. Press `F5` or go to Run > Start Debugging
3. Select "Debug Server" configuration
4. The debugger will attach and stop at breakpoints

### 3. Debug Tests

```bash
# Debug specific test
npm run test:debug -- --testNamePattern="login test"

# Or use VS Code debug configuration "Debug Tests"
```

### 4. Database Debugging

```bash
# Enable query logging
DEBUG=prisma:query npm run dev

# Check database connections
npm run db:status

# View active connections
psql -U auth_user -d auth_db -c "SELECT * FROM pg_stat_activity;"
```

## Development Workflow

### 1. Daily Development

```bash
# Start development server with hot reload
npm run dev

# Run tests in watch mode (separate terminal)
npm run test:watch

# Run linter
npm run lint

# Fix linting issues
npm run lint:fix
```

### 2. Database Migrations

```bash
# Create a new migration
npm run migrate:create -- add-user-table

# Run pending migrations
npm run migrate

# Rollback last migration
npm run migrate:rollback

# Reset database (development only)
npm run migrate:reset
```

### 3. Git Workflow

```bash
# Create feature branch
git checkout -b feature/new-feature

# Make changes and commit
git add .
git commit -m "feat: add new authentication feature"

# Push to remote
git push origin feature/new-feature

# Create pull request
gh pr create --title "Add new authentication feature"
```

## Troubleshooting

### Common Issues

#### Database Connection Issues

```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check if PostgreSQL is listening
sudo netstat -tlnp | grep :5432

# Test connection
psql -h localhost -U auth_user -d auth_db -c "SELECT 1;"
```

#### Redis Connection Issues

```bash
# Check Redis status
sudo systemctl status redis-server

# Test Redis connection
redis-cli ping

# Check Redis logs
sudo journalctl -u redis-server -f
```

#### Node.js Issues

```bash
# Clear npm cache
npm cache clean --force

# Remove node_modules and reinstall
rm -rf node_modules package-lock.json
npm install

# Check Node.js version
node --version
```

#### TypeScript Issues

```bash
# Clean TypeScript build
npm run build:clean

# Check TypeScript configuration
npx tsc --noEmit

# Rebuild project
npm run build
```

### Performance Issues

#### Database Performance

```sql
-- Check slow queries
SELECT query, mean_time, calls, total_time
FROM pg_stat_statements
ORDER BY mean_time DESC
LIMIT 10;

-- Check database size
SELECT pg_size_pretty(pg_database_size('auth_db'));
```

#### Redis Performance

```bash
# Check Redis memory usage
redis-cli info memory

# Monitor Redis commands
redis-cli monitor
```

### Security Issues

#### File Permissions

```bash
# Set proper permissions for keys
chmod 600 keys/private.key
chmod 644 keys/public.key
chmod 700 keys/

# Check file permissions
ls -la keys/
```

#### Environment Variables

```bash
# Check for sensitive data in environment
env | grep -i secret

# Validate environment configuration
npm run env:validate
```

## Docker Development (Optional)

### 1. Docker Compose Setup

Create `docker-compose.dev.yml`:

```yaml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile.dev
    ports:
      - "3000:3000"
    environment:
      NODE_ENV: development
    volumes:
      - .:/app
      - /app/node_modules
    depends_on:
      - postgres
      - redis
    command: npm run dev

  postgres:
    image: postgres:14
    environment:
      POSTGRES_DB: auth_db
      POSTGRES_USER: auth_user
      POSTGRES_PASSWORD: password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:6-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

### 2. Development Dockerfile

Create `Dockerfile.dev`:

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

EXPOSE 3000

CMD ["npm", "run", "dev"]
```

### 3. Running with Docker

```bash
# Start development environment
docker-compose -f docker-compose.dev.yml up

# Stop environment
docker-compose -f docker-compose.dev.yml down

# Rebuild containers
docker-compose -f docker-compose.dev.yml up --build
```

## Useful Commands

### Development Commands

```bash
# Start development server
npm run dev

# Build project
npm run build

# Start production server
npm start

# Run tests
npm test

# Run linter
npm run lint

# Fix linting issues
npm run lint:fix

# Check types
npm run type-check
```

### Database Commands

```bash
# Run migrations
npm run migrate

# Rollback migration
npm run migrate:rollback

# Reset database
npm run migrate:reset

# Seed database
npm run seed
```

### Utility Commands

```bash
# Generate JWT keypair
npm run generate:keys

# Validate environment
npm run env:validate

# Check security
npm run security:check

# Update dependencies
npm run deps:update
```

---

This development guide provides everything needed to set up and work with the authentication system locally. For questions or issues, please refer to the main README.md or create an issue in the repository.