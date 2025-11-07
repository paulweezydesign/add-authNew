-- Create roles table
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create user_roles junction table
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    assigned_by UUID NOT NULL REFERENCES users(id),
    PRIMARY KEY (user_id, role_id)
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);
CREATE INDEX IF NOT EXISTS idx_roles_created_at ON roles(created_at);

-- Create indexes for user_roles table
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_assigned_by ON user_roles(assigned_by);
CREATE INDEX IF NOT EXISTS idx_user_roles_assigned_at ON user_roles(assigned_at);

-- Create GIN index for permissions JSONB column for efficient querying
CREATE INDEX IF NOT EXISTS idx_roles_permissions ON roles USING GIN (permissions);

-- Create trigger to automatically update updated_at for roles
CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON roles
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Add comments for documentation
COMMENT ON TABLE roles IS 'User roles and permissions';
COMMENT ON COLUMN roles.id IS 'Unique identifier for the role';
COMMENT ON COLUMN roles.name IS 'Role name (unique)';
COMMENT ON COLUMN roles.description IS 'Role description';
COMMENT ON COLUMN roles.permissions IS 'JSON array of permissions for this role';

COMMENT ON TABLE user_roles IS 'Junction table linking users to roles';
COMMENT ON COLUMN user_roles.user_id IS 'Reference to the user';
COMMENT ON COLUMN user_roles.role_id IS 'Reference to the role';
COMMENT ON COLUMN user_roles.assigned_at IS 'When the role was assigned';
COMMENT ON COLUMN user_roles.assigned_by IS 'Who assigned the role';

-- Insert default roles
INSERT INTO roles (name, description, permissions) VALUES
('admin', 'System administrator with full access', '["user:read", "user:write", "user:delete", "role:read", "role:write", "role:delete", "audit:read", "session:read", "session:write"]'),
('user', 'Regular user with basic permissions', '["user:read_own", "session:read_own", "session:write_own"]'),
('moderator', 'Moderator with user management permissions', '["user:read", "user:write", "role:read", "audit:read", "session:read"]')
ON CONFLICT (name) DO NOTHING;