export interface Session {
  id: string;
  user_id: string;
  token: string;
  expires_at: Date;
  created_at: Date;
  ip_address: string;
  user_agent: string | null;
  is_active: boolean;
  last_accessed: Date;
}

export interface CreateSessionInput {
  user_id: string;
  token: string;
  expires_at: Date;
  ip_address: string;
  user_agent?: string;
}

export interface UpdateSessionInput {
  expires_at?: Date;
  is_active?: boolean;
  last_accessed?: Date;
}