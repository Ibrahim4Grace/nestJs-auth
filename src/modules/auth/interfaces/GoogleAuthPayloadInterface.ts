import { UserRole } from '@modules/auth/enum/usertype';

export interface GoogleAuthPayload {
  access_token: string;
  expires_in: number;
  refresh_token: string;
  scope: string;
  token_type: string;
  id_token: string;
  expires_at: number;
  provider: string;
  type: string;
  providerAccountId: string;
}

export interface CreateUserResponse {
  message: string;
  data: {
    user: {
      id: string;
      name: string;
      email: string;
      role: UserRole;
    };
    token: string;
  };
}
