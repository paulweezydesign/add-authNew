import { Router } from 'express';
import authRoutes from './auth';
import roleRoutes from './roles';

const router = Router();

// Mount auth routes
router.use('/auth', authRoutes);

// Mount role management routes
router.use('/roles', roleRoutes);

// API info endpoint
router.get('/', (req, res) => {
  res.json({
    message: 'Add-Auth API',
    version: '1.0.0',
    endpoints: {
      auth: {
        register: 'POST /api/auth/register',
        login: 'POST /api/auth/login',
        logout: 'POST /api/auth/logout',
        refresh: 'POST /api/auth/refresh',
        me: 'GET /api/auth/me',
        profile: 'PUT /api/auth/profile'
      },
      roles: {
        list: 'GET /api/roles',
        create: 'POST /api/roles',
        update: 'PUT /api/roles/:id',
        delete: 'DELETE /api/roles/:id',
        assign: 'POST /api/roles/assign',
        remove: 'POST /api/roles/remove',
        userRoles: 'GET /api/roles/users/:userId',
        userPermissions: 'GET /api/roles/users/:userId/permissions',
        permissions: 'GET /api/roles/permissions',
        roleUsers: 'GET /api/roles/:roleId/users'
      }
    }
  });
});

export default router;