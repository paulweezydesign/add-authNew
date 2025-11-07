import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { appConfig } from './config';
import { logger } from './utils/logger';
import { db } from './database/connection';
import { createRedisClient } from './utils/redis';
import { 
  applySecurityMiddleware,
  securityHealthCheck,
  closeRedisConnection 
} from './middleware';
import authRoutes from './routes/auth';
import passwordResetRoutes from './routes/passwordReset';

const app = express();

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false
}));

// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  exposedHeaders: ['X-CSRF-Token']
}));

// Trust proxy for accurate IP addresses
app.set('trust proxy', true);

// Apply security middleware based on environment
const environment = (appConfig.server.nodeEnv as 'production' | 'development' | 'testing') || 'development';
app.use(applySecurityMiddleware(environment));

// Basic middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    const dbStatus = await db.testConnection();
    const securityStatus = await securityHealthCheck();
    
    // Check Redis connection
    let redisStatus = false;
    try {
      const redisClient = await createRedisClient();
      await redisClient.ping();
      redisStatus = true;
    } catch (error) {
      logger.warn('Redis health check failed:', error);
    }
    
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      database: dbStatus ? 'connected' : 'disconnected',
      redis: redisStatus ? 'connected' : 'disconnected',
      security: securityStatus,
      version: process.env.npm_package_version || '1.0.0',
    });
  } catch (error) {
    logger.error('Health check failed:', error);
    res.status(500).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Health check failed',
    });
  }
});

// Basic route
app.get('/', (req, res) => {
  res.json({
    message: 'Add-Auth API',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/password-reset', passwordResetRoutes);

// Error handling middleware (these should be defined in the appropriate files)
// app.use(handleAuthErrors);
// app.use(globalErrorHandler);

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    message: 'The requested resource was not found',
  });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('Received SIGTERM signal, shutting down gracefully');
  await Promise.all([
    db.close(),
    closeRedisConnection()
  ]);
  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.info('Received SIGINT signal, shutting down gracefully');
  await Promise.all([
    db.close(),
    closeRedisConnection()
  ]);
  process.exit(0);
});

// Initialize Redis and start server
async function startServer() {
  try {
    // Initialize Redis connection
    logger.info('Initializing Redis connection...');
    await createRedisClient();
    logger.info('Redis connection established');
    
    // Start server
    const PORT = appConfig.server.port;
    app.listen(PORT, () => {
      logger.info(`Server running on port ${PORT}`, {
        environment: appConfig.server.nodeEnv,
        port: PORT,
        redis: 'connected'
      });
    });
  } catch (error) {
    logger.error('Failed to initialize Redis, starting without Redis support:', error);
    
    // Start server without Redis
    const PORT = appConfig.server.port;
    app.listen(PORT, () => {
      logger.info(`Server running on port ${PORT} (Redis disabled)`, {
        environment: appConfig.server.nodeEnv,
        port: PORT,
        redis: 'disconnected'
      });
    });
  }
}

startServer();

export default app;