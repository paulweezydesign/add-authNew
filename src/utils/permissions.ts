import { RoleModel } from '../models/Role';
import { logger } from './logger';

/**
 * Standard permission constants
 */
export const PERMISSIONS = {
  // User permissions
  USER_READ: 'user:read',
  USER_READ_OWN: 'user:read_own',
  USER_WRITE: 'user:write',
  USER_WRITE_OWN: 'user:write_own',
  USER_DELETE: 'user:delete',
  USER_DELETE_OWN: 'user:delete_own',
  
  // Role permissions
  ROLE_READ: 'role:read',
  ROLE_WRITE: 'role:write',
  ROLE_DELETE: 'role:delete',
  ROLE_ASSIGN: 'role:assign',
  
  // Session permissions
  SESSION_READ: 'session:read',
  SESSION_READ_OWN: 'session:read_own',
  SESSION_WRITE: 'session:write',
  SESSION_WRITE_OWN: 'session:write_own',
  SESSION_DELETE: 'session:delete',
  SESSION_DELETE_OWN: 'session:delete_own',
  
  // Audit permissions
  AUDIT_READ: 'audit:read',
  AUDIT_WRITE: 'audit:write',
  
  // System permissions
  SYSTEM_ADMIN: 'system:admin',
  SYSTEM_MAINTENANCE: 'system:maintenance',
  SYSTEM_MONITORING: 'system:monitoring',
} as const;

/**
 * Permission groups for easier management
 */
export const PERMISSION_GROUPS = {
  USER_MANAGEMENT: [
    PERMISSIONS.USER_READ,
    PERMISSIONS.USER_WRITE,
    PERMISSIONS.USER_DELETE,
  ],
  ROLE_MANAGEMENT: [
    PERMISSIONS.ROLE_READ,
    PERMISSIONS.ROLE_WRITE,
    PERMISSIONS.ROLE_DELETE,
    PERMISSIONS.ROLE_ASSIGN,
  ],
  SESSION_MANAGEMENT: [
    PERMISSIONS.SESSION_READ,
    PERMISSIONS.SESSION_WRITE,
    PERMISSIONS.SESSION_DELETE,
  ],
  AUDIT_MANAGEMENT: [
    PERMISSIONS.AUDIT_READ,
    PERMISSIONS.AUDIT_WRITE,
  ],
  SYSTEM_MANAGEMENT: [
    PERMISSIONS.SYSTEM_ADMIN,
    PERMISSIONS.SYSTEM_MAINTENANCE,
    PERMISSIONS.SYSTEM_MONITORING,
  ],
} as const;

/**
 * Permission validation and checking utilities
 */
export class PermissionService {
  /**
   * Check if a user has a specific permission
   */
  static async hasPermission(userId: string, permission: string): Promise<boolean> {
    try {
      return await RoleModel.hasPermission(userId, permission);
    } catch (error) {
      logger.error('Error checking permission', { userId, permission, error });
      return false;
    }
  }

  /**
   * Check if a user has any of the specified permissions
   */
  static async hasAnyPermission(userId: string, permissions: string[]): Promise<boolean> {
    try {
      const userPermissions = await RoleModel.getUserPermissions(userId);
      return permissions.some(permission => userPermissions.includes(permission));
    } catch (error) {
      logger.error('Error checking any permission', { userId, permissions, error });
      return false;
    }
  }

  /**
   * Check if a user has all of the specified permissions
   */
  static async hasAllPermissions(userId: string, permissions: string[]): Promise<boolean> {
    try {
      const userPermissions = await RoleModel.getUserPermissions(userId);
      return permissions.every(permission => userPermissions.includes(permission));
    } catch (error) {
      logger.error('Error checking all permissions', { userId, permissions, error });
      return false;
    }
  }

  /**
   * Get all permissions for a user
   */
  static async getUserPermissions(userId: string): Promise<string[]> {
    try {
      return await RoleModel.getUserPermissions(userId);
    } catch (error) {
      logger.error('Error getting user permissions', { userId, error });
      return [];
    }
  }

  /**
   * Check if a user can perform an action on a resource
   */
  static async canPerformAction(
    userId: string,
    action: string,
    resource: string,
    resourceOwnerId?: string
  ): Promise<boolean> {
    try {
      const permission = `${resource}:${action}`;
      const ownPermission = `${resource}:${action}_own`;

      // Check if user has general permission
      if (await this.hasPermission(userId, permission)) {
        return true;
      }

      // Check if user has own permission and is the resource owner
      if (resourceOwnerId && userId === resourceOwnerId) {
        return await this.hasPermission(userId, ownPermission);
      }

      return false;
    } catch (error) {
      logger.error('Error checking action permission', { 
        userId, 
        action, 
        resource, 
        resourceOwnerId, 
        error 
      });
      return false;
    }
  }

  /**
   * Check if a user can read a resource
   */
  static async canRead(userId: string, resource: string, resourceOwnerId?: string): Promise<boolean> {
    return this.canPerformAction(userId, 'read', resource, resourceOwnerId);
  }

  /**
   * Check if a user can write to a resource
   */
  static async canWrite(userId: string, resource: string, resourceOwnerId?: string): Promise<boolean> {
    return this.canPerformAction(userId, 'write', resource, resourceOwnerId);
  }

  /**
   * Check if a user can delete a resource
   */
  static async canDelete(userId: string, resource: string, resourceOwnerId?: string): Promise<boolean> {
    return this.canPerformAction(userId, 'delete', resource, resourceOwnerId);
  }

  /**
   * Check if a user has admin privileges
   */
  static async isAdmin(userId: string): Promise<boolean> {
    try {
      const userRoles = await RoleModel.getUserRoles(userId);
      return userRoles.some(role => role.name === 'admin');
    } catch (error) {
      logger.error('Error checking admin status', { userId, error });
      return false;
    }
  }

  /**
   * Check if a user has moderator privileges
   */
  static async isModerator(userId: string): Promise<boolean> {
    try {
      const userRoles = await RoleModel.getUserRoles(userId);
      return userRoles.some(role => ['admin', 'moderator'].includes(role.name));
    } catch (error) {
      logger.error('Error checking moderator status', { userId, error });
      return false;
    }
  }

  /**
   * Check if a user has system-level permissions
   */
  static async hasSystemPermission(userId: string, permission: string): Promise<boolean> {
    try {
      if (!permission.startsWith('system:')) {
        return false;
      }

      // Only admins can have system permissions
      if (!(await this.isAdmin(userId))) {
        return false;
      }

      return await this.hasPermission(userId, permission);
    } catch (error) {
      logger.error('Error checking system permission', { userId, permission, error });
      return false;
    }
  }

  /**
   * Validate permission format
   */
  static validatePermission(permission: string): boolean {
    const permissionPattern = /^[a-z_]+:[a-z_]+$/;
    return permissionPattern.test(permission);
  }

  /**
   * Get permission hierarchy (permissions that grant access to other permissions)
   */
  static getPermissionHierarchy(): Record<string, string[]> {
    return {
      [PERMISSIONS.SYSTEM_ADMIN]: Object.values(PERMISSIONS),
      [PERMISSIONS.USER_WRITE]: [PERMISSIONS.USER_READ],
      [PERMISSIONS.USER_DELETE]: [PERMISSIONS.USER_READ, PERMISSIONS.USER_WRITE],
      [PERMISSIONS.ROLE_WRITE]: [PERMISSIONS.ROLE_READ],
      [PERMISSIONS.ROLE_DELETE]: [PERMISSIONS.ROLE_READ, PERMISSIONS.ROLE_WRITE],
      [PERMISSIONS.SESSION_WRITE]: [PERMISSIONS.SESSION_READ],
      [PERMISSIONS.SESSION_DELETE]: [PERMISSIONS.SESSION_READ, PERMISSIONS.SESSION_WRITE],
      [PERMISSIONS.AUDIT_WRITE]: [PERMISSIONS.AUDIT_READ],
    };
  }

  /**
   * Check if a permission implies other permissions
   */
  static getImpliedPermissions(permission: string): string[] {
    const hierarchy = this.getPermissionHierarchy();
    return hierarchy[permission] || [];
  }

  /**
   * Filter permissions based on user's access level
   */
  static async filterPermissions(userId: string, permissions: string[]): Promise<string[]> {
    try {
      const userPermissions = await this.getUserPermissions(userId);
      
      return permissions.filter(permission => {
        // Check direct permission
        if (userPermissions.includes(permission)) {
          return true;
        }

        // Check implied permissions
        const impliedPermissions = this.getImpliedPermissions(permission);
        return impliedPermissions.some(implied => userPermissions.includes(implied));
      });
    } catch (error) {
      logger.error('Error filtering permissions', { userId, permissions, error });
      return [];
    }
  }

  /**
   * Check if user has elevated permissions for sensitive operations
   */
  static async hasElevatedPermissions(userId: string): Promise<boolean> {
    try {
      const sensitivePermissions = [
        PERMISSIONS.SYSTEM_ADMIN,
        PERMISSIONS.SYSTEM_MAINTENANCE,
        PERMISSIONS.USER_DELETE,
        PERMISSIONS.ROLE_DELETE,
        PERMISSIONS.AUDIT_WRITE,
      ];

      return await this.hasAnyPermission(userId, sensitivePermissions);
    } catch (error) {
      logger.error('Error checking elevated permissions', { userId, error });
      return false;
    }
  }

  /**
   * Get resource-specific permissions for a user
   */
  static async getResourcePermissions(userId: string, resource: string): Promise<{
    canRead: boolean;
    canWrite: boolean;
    canDelete: boolean;
  }> {
    try {
      const [canRead, canWrite, canDelete] = await Promise.all([
        this.canRead(userId, resource),
        this.canWrite(userId, resource),
        this.canDelete(userId, resource),
      ]);

      return { canRead, canWrite, canDelete };
    } catch (error) {
      logger.error('Error getting resource permissions', { userId, resource, error });
      return { canRead: false, canWrite: false, canDelete: false };
    }
  }

  /**
   * Check if user can access admin interface
   */
  static async canAccessAdmin(userId: string): Promise<boolean> {
    try {
      const adminPermissions = [
        PERMISSIONS.SYSTEM_ADMIN,
        PERMISSIONS.USER_WRITE,
        PERMISSIONS.ROLE_WRITE,
        PERMISSIONS.AUDIT_READ,
      ];

      return await this.hasAnyPermission(userId, adminPermissions);
    } catch (error) {
      logger.error('Error checking admin access', { userId, error });
      return false;
    }
  }

  /**
   * Audit permission check
   */
  static async auditPermissionCheck(
    userId: string,
    permission: string,
    granted: boolean,
    context?: any
  ): Promise<void> {
    try {
      // Import AuditLogModel dynamically to avoid circular dependency
      const { AuditLogModel } = await import('../models/AuditLog');
      
      await AuditLogModel.create({
        user_id: userId,
        action: 'permission_check',
        resource_type: 'permission',
        resource_id: permission,
        ip_address: context?.ip || 'unknown',
        success: granted,
        details: {
          permission,
          granted,
          context,
          timestamp: new Date().toISOString(),
        },
      });
    } catch (error) {
      logger.error('Error auditing permission check', { 
        userId, 
        permission, 
        granted, 
        error 
      });
    }
  }
}

export default PermissionService;