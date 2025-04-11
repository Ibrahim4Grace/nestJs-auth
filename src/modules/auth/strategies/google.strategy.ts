import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { ConfigService } from '@nestjs/config';
import { UserService } from '@modules/user/user.service';
import { UserRole } from '@modules/auth/enum/usertype';
import * as crypto from 'crypto';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    private readonly configService: ConfigService,
    private readonly userService: UserService,
  ) {
    super({
      clientID: configService.get<string>('GOOGLE_CLIENT_ID'),
      clientSecret: configService.get<string>('GOOGLE_CLIENT_SECRET'),
      callbackURL: configService.get<string>('GOOGLE_CALLBACK_URL'),
      scope: ['email', 'profile'],
      passReqToCallback: true,
    });
  }

  async validate(
    request: any,
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    try {
      const { name, emails, photos } = profile;
      console.log('profile', profile);
      const user = {
        email: emails[0].value,
        name: name.name,
        picture: photos[0].value,
        accessToken,
        emailVerified: true,
      };

      let existingUser = await this.userService.getUserRecord({
        identifier: user.email,
        identifierType: 'email',
      });

      if (!existingUser) {
        // Generate a random password for Google-authenticated users
        const randomPassword = crypto.randomBytes(16).toString('hex');

        // Create new user with the USER role
        const newUser = await this.userService.createUser({
          email: user.email,
          name: user.name,
          password: randomPassword,
          role: UserRole.USER,
        });

        existingUser = newUser;
      }
      return done(null, user);
      // done(null, existingUser);
    } catch (error) {
      done(new HttpException('Google authentication failed', HttpStatus.UNAUTHORIZED), null);
    }
  }
}
