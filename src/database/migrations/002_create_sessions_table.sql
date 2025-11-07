-- Create sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address INET NOT NULL,
    user_agent TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    last_accessed TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_is_active ON sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_last_accessed ON sessions(last_accessed);

-- Create composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_sessions_user_active ON sessions(user_id, is_active, expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_token_active ON sessions(token, is_active, expires_at);

-- Add comments for documentation
COMMENT ON TABLE sessions IS 'User authentication sessions';
COMMENT ON COLUMN sessions.id IS 'Unique identifier for the session';
COMMENT ON COLUMN sessions.user_id IS 'Reference to the user who owns this session';
COMMENT ON COLUMN sessions.token IS 'Unique session token (JWT or similar)';
COMMENT ON COLUMN sessions.expires_at IS 'When the session expires';
COMMENT ON COLUMN sessions.ip_address IS 'IP address from which the session was created';
COMMENT ON COLUMN sessions.user_agent IS 'User agent string from the client';
COMMENT ON COLUMN sessions.is_active IS 'Whether the session is currently active';
COMMENT ON COLUMN sessions.last_accessed IS 'When the session was last accessed';