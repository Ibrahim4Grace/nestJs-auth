

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



export const UserRole = {
  ADMIN: 'admin',
  SUPER_ADMIN: 'super_admin',
  USER: 'user',
  EMPLOYEE: 'employee',
} as const;

export type UserRole = typeof UserRole[keyof typeof UserRole];
