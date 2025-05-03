import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { User } from './entities/user.entity';
import { PasswordService } from '../auth/password.service';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { EmailService } from '@modules/email/email.service';
import { EmailModule } from '@modules/email/email.module';
import { CloudinaryService } from '@shared/services/cloudinary.service';

@Module({
  controllers: [UserController],
  providers: [UserService, Repository, PasswordService, EmailService, CloudinaryService],
  imports: [
    TypeOrmModule.forFeature([User]),
    EmailModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_AUTH_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('JWT_AUTH_EXPIRES_IN'),
        },
      }),
      inject: [ConfigService],
    }),
  ],
  exports: [UserService],
})
export class UserModule { }
