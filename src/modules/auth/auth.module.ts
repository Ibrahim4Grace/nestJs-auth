import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '@modules/user/entities/user.entity';
import { AuthService } from './auth.service';
import { Repository } from 'typeorm';
import { UserService } from '@modules/user/user.service';
import { OtpService } from '@modules/otp/otp.service';
import { EmailService } from '@modules/email/email.service';
import { Otp } from '@modules/otp/entities/otp.entity';
import { TokenService } from '@shared/token/token.service';
import { OtpModule } from '@modules/otp/otp.module';
import { EmailModule } from '@modules/email/email.module';
import { ConfigModule } from '@nestjs/config';
import { PasswordService } from '../auth/password.service';
import { AuthHelperService } from './auth-helper.service';
import { JwtService } from '@nestjs/jwt';
import { SharedModule } from '@shared/shared.module';

@Module({
  controllers: [AuthController],
  providers: [
    AuthService,
    Repository,
    UserService,
    OtpService,
    TokenService,
    EmailService,
    PasswordService,
    AuthHelperService,
    {
      provide: 'JWT_REFRESH_SERVICE',
      useExisting: JwtService, // Use the global JwtService
    },
  ],
  imports: [
    TypeOrmModule.forFeature([User, Otp]),
    OtpModule,
    EmailModule,
    ConfigModule,
    SharedModule,
  ],
  exports: [AuthService],
})
export class AuthModule { }
