import { Module, ValidationPipe } from '@nestjs/common';
import { BorrowerModule } from './modules/borrower/borrower.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { LoggerModule } from 'nestjs-pino';
import { TypeOrmModule } from '@nestjs/typeorm';
import { APP_PIPE } from '@nestjs/core';
import { ClaimModule } from './modules/claim/claim.module';
import { GuaranteeModule } from './modules/guarantee/guarantee.module';
import { CollateralModule } from './modules/collateral/collateral.module';
import { MailerModule } from '@nestjs-modules/mailer';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';
import { BullModule } from '@nestjs/bull';
import dataSource from '@database/data-source';
import authConfig from '@config/auth.config';
import { AuthGuard } from '@guards/auth.guard';
import { AuthModule } from './modules/auth/auth.module';
import serverConfig from '@config/server.config';
import { OtpModule } from '@modules/otp/otp.module';
import { EmailModule } from '@modules/email/email.module';
import { UserModule } from '@modules/user/user.module';
import { RoleModule } from '@modules/role/role.module';
import { TokenModule } from '@modules/token/token.module';
import { parse } from 'url';

@Module({
  providers: [
    {
      provide: 'CONFIG',
      useClass: ConfigService,
    },
    {
      provide: APP_PIPE,
      useFactory: () =>
        new ValidationPipe({
          whitelist: true,
          forbidNonWhitelisted: true,
        }),
    },
    {
      provide: 'APP_GUARD',
      useClass: AuthGuard,
    },
  ],
  imports: [
    ConfigModule.forRoot({
      envFilePath: ['.env', `.env.${process.env.PROFILE}`],
      load: [serverConfig, authConfig],
      isGlobal: true,
    }),
    LoggerModule.forRoot(),
    TypeOrmModule.forRootAsync({
      useFactory: async () => ({
        ...dataSource.options,
      }),
      dataSourceFactory: async () => dataSource,
    }),
    BorrowerModule,
    ClaimModule,
    GuaranteeModule,
    CollateralModule,
    AuthModule,
    TokenModule,
    UserModule,
    OtpModule,
    EmailModule,
    RoleModule,
    MailerModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        transport: {
          service: 'gmail',
          auth: {
            user: configService.get<string>('SMTP_USER'),
            pass: configService.get<string>('SMTP_PASSWORD'),
          },
        },
        defaults: {
          from: `"Spot-light" <${configService.get<string>('SMTP_USER')}>`,
        },
        template: {
          dir: process.cwd() + '/src/modules/email/templates',
          adapter: new HandlebarsAdapter(),
          options: {
            strict: true,
          },
        },
      }),
      inject: [ConfigService],
    }),

    BullModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => {
        const redisUrl = configService.get<string>('REDIS_URL');
        if (redisUrl) {
          const parsedUrl = parse(redisUrl);
          const [username, password] = parsedUrl.auth ? parsedUrl.auth.split(':') : [null, null];
          return {
            redis: {
              host: parsedUrl.hostname,
              port: parsedUrl.port ? parseInt(parsedUrl.port, 10) : 6379,
              username: username || undefined,
              password: password || undefined,
            },
          };
        }
        // Fallback to individual variables for local dev
        return {
          redis: {
            host: configService.get<string>('REDIS_HOST', 'localhost'),
            port: configService.get<number>('REDIS_PORT', 6379),
            username: configService.get<string>('REDIS_USERNAME'),
            password: configService.get<string>('REDIS_PASSWORD'),
          },
        };
      },
      inject: [ConfigService],
    }),
    TokenModule,
  ],
})
export class AppModule {}
