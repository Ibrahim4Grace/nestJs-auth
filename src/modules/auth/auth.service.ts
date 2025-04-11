import { HttpStatus, Injectable, HttpException } from '@nestjs/common';
import * as SYS_MSG from '@shared/constants/SystemMessages';
import { UserService } from '@modules/user/user.service';
import { OtpService } from '@modules/otp/otp.service';
import { EmailService } from '@modules/email/email.service';
import { CustomHttpException } from '@shared/helpers/custom-http-filter';
import { CreateUserResponse, GoogleAuthPayload } from './interfaces/GoogleAuthPayloadInterface';
import { DataSource, EntityManager } from 'typeorm';
import { TokenService } from '../token/token.service';
import { PasswordService } from './password.service';
import { Logger } from '@nestjs/common';
import { AuthHelperService } from './auth-helper.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';

const timestamp = new Date().toLocaleString('en-US', { dateStyle: 'long', timeStyle: 'short' });

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  constructor(
    private readonly userService: UserService,
    private readonly otpService: OtpService,
    private readonly emailService: EmailService,
    private readonly dataSource: DataSource,
    private readonly tokenService: TokenService,
    private passwordService: PasswordService,
    private readonly authHelperService: AuthHelperService,
  ) {}

  // create(createAuthDto: CreateAuthDto) {
  //   return 'This action adds a new auth';
  // }

  async create(createUserDto: CreateAuthDto): Promise<CreateUserResponse> {
    const result = await this.dataSource.transaction(async (manager: EntityManager) => {
      const userExists = await this.userService.getUserRecord({
        identifier: createUserDto.email,
        identifierType: 'email',
      });
      if (userExists) throw new CustomHttpException(SYS_MSG.USER_ACCOUNT_EXIST, HttpStatus.BAD_REQUEST);

      const user = await this.userService.createUser(createUserDto, manager);
      if (!user) throw new CustomHttpException(SYS_MSG.FAILED_TO_CREATE_USER, HttpStatus.BAD_REQUEST);

      const otpResult = await this.otpService.create(user.id, manager);
      if (!otpResult) throw new CustomHttpException(SYS_MSG.FAILED, HttpStatus.INTERNAL_SERVER_ERROR);

      const preliminaryToken = this.tokenService.createEmailVerificationToken({
        userId: user.id,
        role: user.role,
      });

      const responsePayload = {
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
        token: preliminaryToken,
      };
      return {
        message: SYS_MSG.VERIFY_OTP_SENT,
        data: responsePayload,
        otp: otpResult.plainOtp,
      };
    });

    try {
      await this.emailService.sendUserEmailConfirmationOtp(result.data.user.email, result.data.user.name, result.otp);
      this.logger.log(`Successfully sent OTP email to ${result.data.user.email} with OTP: ${result.otp}`);
    } catch (emailError) {
      this.logger.error('Error sending confirmation email:', emailError);
    }

    return {
      message: result.message,
      data: result.data,
    };
  }

  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
}
