import { HttpStatus, Injectable } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import * as SYS_MSG from '@shared/constants/SystemMessages';

import UserService from '@modules/user/user.service';
import { OtpService } from '@modules/otp/otp.service';
import { EmailService } from '@modules/email/email.service';
import { CustomHttpException } from '@shared/helpers/custom-http-filter';
import { GoogleAuthPayload, CreateUserResponse } from './interfaces/GoogleAuthPayloadInterface';
import { TokenPayload } from 'google-auth-library';
import { OtpDto } from '@modules/otp/dto/otp.dto';
import { DataSource, EntityManager } from 'typeorm';
import { TokenService } from '../token/token.service';
import { PasswordService } from './password.service';
import { Logger } from '@nestjs/common';
import { AuthHelperService } from './auth-helper.service';
import {
  RequestSigninTokenDto,
  LoginResponseDto,
  LoginDto,
  UpdatePasswordDto,
  ForgotPasswordDto,
  CreateUserDTO,
  ChangePasswordDto,
  AuthResponseDto,
  GoogleAuthPayloadDto,
  GenericAuthResponseDto,
  LoginErrorResponseDto,
  UpdateUserPasswordResponseDTO,
} from './dto/auth-response.dto';
import { User } from '@modules/user/entities/user.entity';

const timestamp = new Date().toLocaleString('en-US', { dateStyle: 'long', timeStyle: 'short' });

@Injectable()
export default class AuthenticationService {
  private readonly logger = new Logger(AuthenticationService.name);
  constructor(
    private readonly userService: UserService,
    private readonly otpService: OtpService,
    private readonly emailService: EmailService,
    private readonly dataSource: DataSource,
    private readonly tokenService: TokenService,
    private passwordService: PasswordService,
    private readonly authHelperService: AuthHelperService,
  ) {}

  async createNewUser(createUserDto: CreateUserDTO): Promise<CreateUserResponse> {
    console.log('Incoming createUserDto:', createUserDto);
    const result = await this.dataSource.transaction(async (manager: EntityManager) => {
      const userExists = await this.userService.getUserRecord({
        identifier: createUserDto.email,
        identifierType: 'email',
      });

      if (userExists) throw new CustomHttpException(SYS_MSG.USER_ACCOUNT_EXIST, HttpStatus.BAD_REQUEST);
      const user = await this.userService.createUser(createUserDto, manager);
      if (!user) throw new CustomHttpException(SYS_MSG.FAILED_TO_CREATE_USER, HttpStatus.BAD_REQUEST);

      const otpResult = await this.otpService.createOtp(user.id, manager);
      if (!otpResult) throw new CustomHttpException('Failed to generate OTP', HttpStatus.INTERNAL_SERVER_ERROR);

      const preliminaryToken = this.tokenService.createEmailVerificationToken({
        userId: user.id,
        role: user.user_type,
      });

      const responsePayload = {
        user: {
          id: user.id,
          first_name: user.first_name,
          last_name: user.last_name,
          email: user.email,
          user_type: user.user_type,
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
      await this.emailService.sendUserEmailConfirmationOtp(
        result.data.user.email,
        result.data.user.first_name,
        result.otp,
      );
      this.logger.log(`Successfully sent OTP email to ${result.data.user.email} with OTP: ${result.otp}`);
    } catch (emailError) {
      this.logger.error('Error sending confirmation email:', emailError);
    }

    return {
      message: result.message,
      data: result.data,
    };
  }

  async verifyToken(authorization: string, verifyOtp: { otp: string }) {
    const user = await this.authHelperService.validateBearerToken(authorization);

    const isValidOtp = await this.otpService.verifyOtp(user.id, verifyOtp.otp);
    if (!isValidOtp) throw new CustomHttpException(SYS_MSG.INVALID_OTP, HttpStatus.UNAUTHORIZED);

    await this.userService.updateUser(user.id, { emailVerified: true, is_active: true });
    await this.otpService.deleteOtp(user.id);

    const responsePayload = {
      id: user.id,
      first_name: user.first_name,
      last_name: user.last_name,
      email: user.email,
      user_type: user.user_type,
    };

    await this.emailService.sendUserConfirmationMail(user.email, user.first_name, timestamp);
    this.logger.log(`Successfully sent welcome email to ${user.email}`);

    return {
      message: SYS_MSG.EMAIL_VERIFIED_SUCCESSFULLY,
      data: responsePayload,
    };
  }

  async loginUser(loginDto: LoginDto): Promise<LoginResponseDto> {
    const { email, password } = loginDto;
    const user = await this.userService.getUserRecord({
      identifier: email,
      identifierType: 'email',
    });
    if (!user) {
      throw new CustomHttpException(SYS_MSG.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw new CustomHttpException(SYS_MSG.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
    }

    const access_token = this.tokenService.createAuthToken({
      userId: user.id,
      role: user.user_type,
    });

    const responsePayload = {
      access_token,
      data: {
        user: {
          id: user.id,
          first_name: user.first_name,
          last_name: user.last_name,
          email: user.email,
          role: user.user_type,
        },
      },
    };

    return { message: SYS_MSG.LOGIN_SUCCESSFUL, ...responsePayload };
  }

  async forgotPassword(dto: ForgotPasswordDto): Promise<{ message: string; token: string }> {
    const user = await this.userService.getUserRecord({ identifier: dto.email, identifierType: 'email' });
    if (!user) {
      throw new CustomHttpException(SYS_MSG.USER_ACCOUNT_DOES_NOT_EXIST, HttpStatus.BAD_REQUEST);
    }

    // Delete all existing OTPs for this user first
    await this.otpService.deleteOtp(user.id);

    const otpResult = await this.otpService.createOtp(user.id);
    if (!otpResult) throw new CustomHttpException('Failed to generate OTP', HttpStatus.INTERNAL_SERVER_ERROR);

    const preliminaryToken = this.tokenService.createEmailVerificationToken({
      userId: user.id,
      role: user.user_type,
    });

    await this.emailService.sendForgotPasswordMail(user.email, user.first_name, otpResult.plainOtp);
    this.logger.log(`Successfully sent forgot password OTP to ${user.email} with OTP: ${otpResult.plainOtp}`);
    return {
      message: SYS_MSG.EMAIL_SENT,
      token: preliminaryToken,
    };
  }

  async verifyForgetPasswordOtp(authorization: string, verifyOtp: { otp: string }) {
    const user = await this.authHelperService.validateBearerToken(authorization);

    const isValidOtp = await this.otpService.verifyOtp(user.id, verifyOtp.otp);
    if (!isValidOtp) throw new CustomHttpException(SYS_MSG.INVALID_OTP, HttpStatus.UNAUTHORIZED);

    const responsePayload = {
      id: user.id,
      first_name: user.first_name,
      last_name: user.last_name,
      email: user.email,
      user_type: user.user_type,
    };

    return {
      message: SYS_MSG.OTP_VERIFIED_SUCCESSFULLY,
      data: responsePayload,
    };
  }

  async updateForgotPassword(authorization: string, updatePasswordDto: UpdatePasswordDto) {
    const user = await this.authHelperService.validateBearerToken(authorization);

    const otpVerified = await this.otpService.isOtpVerified(user.id);
    if (!otpVerified) {
      throw new CustomHttpException(SYS_MSG.OTP_VERIFIED, HttpStatus.UNAUTHORIZED);
    }

    const { newPassword } = updatePasswordDto;
    const isSamePassword = await this.passwordService.comparePassword(newPassword, user.password);
    if (isSamePassword) {
      throw new CustomHttpException(SYS_MSG.DUPLICATE_PASSWORD, HttpStatus.BAD_REQUEST);
    }

    // Update the password
    await this.userService.updateUserRecord({
      updatePayload: {
        password: await this.passwordService.hashPassword(newPassword),
      },
      identifierOptions: {
        identifierType: 'id',
        identifier: user.id,
      },
    });

    await this.otpService.deleteOtp(user.id);

    await this.emailService.sendPasswordChangedMail(user.email, user.first_name, timestamp);
    this.logger.log(`Successfully sent password changed confirmation to ${user.email}`);

    return {
      message: SYS_MSG.PASSWORD_UPDATED,
    };
  }

  // async changePassword(user_id: string, oldPassword: string, newPassword: string) {
  //   const user = await this.userService.getUserRecord({
  //     identifier: user_id,
  //     identifierType: 'id',
  //   });

  //   if (!user) {
  //     throw new CustomHttpException(SYS_MSG.USER_NOT_FOUND, HttpStatus.NOT_FOUND);
  //   }

  //   const isPasswordValid = bcrypt.compareSync(oldPassword, user.password);
  //   if (!isPasswordValid) {
  //     throw new CustomHttpException(SYS_MSG.INVALID_PASSWORD, HttpStatus.BAD_REQUEST);
  //   }

  //   await this.userService.updateUserRecord({
  //     updatePayload: { password: newPassword },
  //     identifierOptions: {
  //       identifierType: 'id',
  //       identifier: user.id,
  //     },
  //   });
  //   await this.otpService.deleteOtp(user.id);
  //   return {
  //     message: SYS_MSG.PASSWORD_UPDATED,
  //   };
  // }

  // async googleAuth(googleAuthPayload: GoogleAuthPayload) {
  //   const idToken = googleAuthPayload.id_token;

  //   if (!idToken) {
  //     throw new CustomHttpException(SYS_MSG.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
  //   }

  //   const request = await fetch(`https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=${idToken}`);

  //   if (request.status === 400) {
  //     throw new CustomHttpException(SYS_MSG.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
  //   }
  //   if (request.status === 500) {
  //     throw new CustomHttpException(SYS_MSG.SERVER_ERROR, HttpStatus.INTERNAL_SERVER_ERROR);
  //   }
  //   const verifyTokenResponse: TokenPayload = await request.json();

  //   const userEmail = verifyTokenResponse.email;
  //   const userExists = await this.userService.getUserRecord({ identifier: userEmail, identifierType: 'email' });

  //   if (!userExists) {
  //     const userCreationPayload = {
  //       email: userEmail,
  //       first_name: verifyTokenResponse.given_name || '',
  //       last_name: verifyTokenResponse?.family_name || '',
  //       password: '',
  //       profile_pic_url: verifyTokenResponse?.picture || '',
  //     };
  //     return await this.createUserGoogle(userCreationPayload);
  //   }

  //   // const userOranisations = await this.organisationService.getAllUserOrganisations(userExists.id, 1, 10);
  //   // const isSuperAdmin = userOranisations.map((instance) => instance.user_role).includes('super-admin');
  //   const accessToken = this.tokenService.createAuthToken({
  //     // sub: userExists.id,
  //     // id: userExists.id,
  //     // email: userExists.email,
  //     // first_name: userExists.first_name,
  //     last_name: userExists.last_name,
  //   });

  //   return {
  //     message: SYS_MSG.LOGIN_SUCCESSFUL,
  //     access_token: accessToken,
  //     data: {
  //       user: {
  //         id: userExists.id,
  //         email: userExists.email,
  //         first_name: userExists.first_name,
  //         last_name: userExists.last_name,
  //         // is_superadmin: isSuperAdmin,
  //       },
  //     },
  //   };
  // }

  // public async createUserGoogle(userPayload: CreateUserDTO) {
  //   const newUser = await this.userService.createUser(userPayload);
  //   const newOrganisationPaload = {
  //     name: `${newUser.first_name}'s Organisation`,
  //     description: '',
  //     email: newUser.email,
  //     industry: '',
  //     type: '',
  //     country: '',
  //     address: '',
  //     state: '',
  //   };

  //   const accessToken = this.jwtService.sign({
  //     sub: newUser.id,
  //     id: newUser.id,
  //     email: userPayload.email,
  //     first_name: userPayload.first_name,
  //     last_name: userPayload.last_name,
  //   });
  //   return {
  //     status_code: HttpStatus.CREATED,
  //     message: SYS_MSG.USER_CREATED,
  //     access_token: accessToken,
  //     data: {
  //       user: {
  //         id: newUser.id,
  //         email: newUser.email,
  //         first_name: newUser.first_name,
  //         last_name: newUser.last_name,
  //         // is_superadmin: isSuperAdmin,
  //       },
  //     },
  //   };
  // }
}
