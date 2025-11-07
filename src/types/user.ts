export interface User {
  id: string;
  email: string;
  password_hash: string;
  created_at: Date;
  updated_at: Date;
  status: UserStatus;
  email_verified: boolean;
  last_login: Date | null;
  failed_login_attempts: number;
  locked_until: Date | null;
  first_name?: string;
  last_name?: string;
  oauth_providers?: string[];
}

export enum UserStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  SUSPENDED = 'suspended',
  DELETED = 'deleted',
}

export interface CreateUserInput {
  email: string;
  password: string;
}

export interface UpdateUserInput {
  email?: string;
  status?: UserStatus;
  email_verified?: boolean;
}

export interface UserWithoutPassword extends Omit<User, 'password_hash'> {}

export interface LoginInput {
  email: string;
  password: string;
}

export interface CreateOAuthUserInput {
  provider: string;
  providerId: string;
  email: string;
  name: string;
  emailVerified?: boolean;
  oauthData?: {
    accessToken?: string;
    refreshToken?: string;
    profile?: any;
  };
}

export interface OAuthAccount {
  id: string;
  user_id: string;
  provider: string;
  provider_id: string;
  access_token?: string;
  refresh_token?: string;
  expires_at?: Date;
  scope?: string;
  token_type?: string;
  profile_data: any;
  created_at: Date;
  updated_at: Date;
}