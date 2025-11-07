-- Add OAuth support to users table
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS oauth_providers JSONB DEFAULT '[]',
ADD COLUMN IF NOT EXISTS first_name VARCHAR(100),
ADD COLUMN IF NOT EXISTS last_name VARCHAR(100),
ALTER COLUMN password_hash DROP NOT NULL;

-- Create indexes for OAuth fields
CREATE INDEX IF NOT EXISTS idx_users_oauth_providers ON users USING GIN (oauth_providers);

-- Create oauth_accounts table for detailed OAuth account information
CREATE TABLE IF NOT EXISTS oauth_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    provider_id VARCHAR(255) NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,
    scope TEXT,
    token_type VARCHAR(50) DEFAULT 'Bearer',
    profile_data JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(provider, provider_id)
);

-- Create indexes for oauth_accounts
CREATE INDEX IF NOT EXISTS idx_oauth_accounts_user_id ON oauth_accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_accounts_provider ON oauth_accounts(provider);
CREATE INDEX IF NOT EXISTS idx_oauth_accounts_provider_id ON oauth_accounts(provider_id);
CREATE INDEX IF NOT EXISTS idx_oauth_accounts_expires_at ON oauth_accounts(expires_at);

-- Create trigger to automatically update updated_at for oauth_accounts
CREATE TRIGGER update_oauth_accounts_updated_at BEFORE UPDATE ON oauth_accounts
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Add comments for documentation
COMMENT ON TABLE oauth_accounts IS 'OAuth provider account information for users';
COMMENT ON COLUMN oauth_accounts.id IS 'Unique identifier for the OAuth account';
COMMENT ON COLUMN oauth_accounts.user_id IS 'Reference to the user who owns this OAuth account';
COMMENT ON COLUMN oauth_accounts.provider IS 'OAuth provider name (google, github, etc.)';
COMMENT ON COLUMN oauth_accounts.provider_id IS 'User ID from the OAuth provider';
COMMENT ON COLUMN oauth_accounts.access_token IS 'OAuth access token';
COMMENT ON COLUMN oauth_accounts.refresh_token IS 'OAuth refresh token';
COMMENT ON COLUMN oauth_accounts.expires_at IS 'When the access token expires';
COMMENT ON COLUMN oauth_accounts.scope IS 'OAuth scope/permissions granted';
COMMENT ON COLUMN oauth_accounts.profile_data IS 'Additional profile data from OAuth provider';

COMMENT ON COLUMN users.oauth_providers IS 'List of OAuth providers linked to this user';
COMMENT ON COLUMN users.first_name IS 'User first name';
COMMENT ON COLUMN users.last_name IS 'User last name';