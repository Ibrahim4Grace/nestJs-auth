export interface AuthJwtPayload {
  userId: string;
  role: string; // Adjust based on your UserRole enum/type
}

export interface EmailVerificationPayload {
  userId: string;
  email: string;
}
