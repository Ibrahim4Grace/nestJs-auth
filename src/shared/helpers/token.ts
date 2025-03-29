import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as jwt from 'jsonwebtoken';

export enum UserType {
  SUPER_ADMIN = 'super-admin',
  ADMIN = 'admin',
  USER = 'customer',
}

export type UserRole = (typeof UserType)[keyof typeof UserType];

export interface AuthJwtPayload {
  userId: string;
  role: UserRole;
}

export interface EmailVerificationPayload {
  userId: string;
  email: string;
}

@Injectable()
export class TokenService {
  constructor(private readonly configService: ConfigService) {}

  // Authentication token methods
  createAuthToken(payload: { userId: string; role: UserRole }): string {
    const secret = this.configService.get<string>('JWT_AUTH_SECRET');
    if (!secret) {
      throw new Error('JWT_AUTH_SECRET is not defined');
    }

    return jwt.sign(payload, secret, {
      expiresIn: '1d', // Hardcoded for now; can be made configurable via ConfigService
    });
  }

  async verifyAuthToken(token: string): Promise<AuthJwtPayload> {
    const secret = this.configService.get<string>('JWT_AUTH_SECRET');
    if (!secret) {
      throw new Error('JWT_AUTH_SECRET is not defined');
    }

    return new Promise((resolve, reject) => {
      jwt.verify(token, secret, (err, decoded) => {
        if (err || !decoded) {
          return reject(new UnauthorizedException('Invalid authentication token'));
        }
        resolve(decoded as AuthJwtPayload);
      });
    });
  }

  // Email verification token methods
  createEmailVerificationToken(payload: { userId: string; email: string }): string {
    const secret = this.configService.get<string>('JWT_EMAIL_SECRET');
    if (!secret) {
      throw new Error('JWT_EMAIL_SECRET is not defined');
    }

    return jwt.sign(payload, secret, {
      expiresIn: '1h', // Hardcoded for now; can be made configurable
    });
  }

  async verifyEmailToken(token: string): Promise<EmailVerificationPayload> {
    const secret = this.configService.get<string>('JWT_EMAIL_SECRET');
    if (!secret) {
      throw new Error('JWT_EMAIL_SECRET is not defined');
    }

    return new Promise((resolve, reject) => {
      jwt.verify(token, secret, (err, decoded) => {
        if (err || !decoded) {
          return reject(new UnauthorizedException('Invalid or expired verification token'));
        }
        resolve(decoded as EmailVerificationPayload);
      });
    });
  }
}
