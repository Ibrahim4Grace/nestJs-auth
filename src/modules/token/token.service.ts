import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { AuthJwtPayload, EmailVerificationPayload } from './interface/token.interface';

@Injectable()
export class TokenService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  // Authentication token methods
  createAuthToken(payload: { userId: string; role: string }): string {
    const secret = this.configService.get<string>('JWT_AUTH_SECRET');
    if (!secret) throw new Error('JWT_AUTH_SECRET is not defined');

    return this.jwtService.sign(payload, {
      secret,
      expiresIn: '1d',
    });
  }

  async verifyAuthToken(token: string): Promise<AuthJwtPayload> {
    const secret = this.configService.get<string>('JWT_AUTH_SECRET');
    if (!secret) throw new Error('JWT_AUTH_SECRET is not defined');

    return this.jwtService.verify<AuthJwtPayload>(token, { secret });
  }

  // Email verification token methods
  createEmailVerificationToken(payload: { userId: string; role: string }): string {
    const secret = this.configService.get<string>('JWT_EMAIL_SECRET');
    if (!secret) throw new Error('JWT_EMAIL_SECRET is not defined');

    return this.jwtService.sign(payload, {
      secret,
      expiresIn: '1d',
    });
  }

  async verifyEmailToken(token: string): Promise<EmailVerificationPayload> {
    const secret = this.configService.get<string>('JWT_EMAIL_SECRET');
    if (!secret) throw new Error('JWT_EMAIL_SECRET is not defined');

    return this.jwtService.verify<EmailVerificationPayload>(token, { secret });
  }
}
