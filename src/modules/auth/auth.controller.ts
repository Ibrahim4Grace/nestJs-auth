import { ApiResponse, ApiTags, ApiUnauthorizedResponse } from '@nestjs/swagger';
import { ApiBadRequestResponse, ApiBearerAuth, ApiBody, ApiOperation } from '@nestjs/swagger';
import * as SYS_MSG from '@shared/constants/SystemMessages';
import { Body, Controller, HttpCode, Post, Req, Request, Patch, Headers } from '@nestjs/common';
import { skipAuth } from '@shared/helpers/skipAuth';
import AuthenticationService from './auth.service';
import { OtpDto } from '../otp/dto/otp.dto';
import { GoogleAuthPayload } from './interfaces/GoogleAuthPayloadInterface';
import { CustomHttpException } from '@shared/helpers/custom-http-filter';
import {
  ErrorCreateUserResponse,
  RequestVerificationToken,
  SuccessCreateUserResponse,
} from '../user/dto/user-response.dto';
import {
  RequestSigninTokenDto,
  LoginDto,
  LoginResponseDto,
  ForgotPasswordDto,
  ForgotPasswordResponseDto,
  CreateUserDTO,
  ChangePasswordDto,
  AuthResponseDto,
  GoogleAuthPayloadDto,
  GenericAuthResponseDto,
  UpdatePasswordDto,
  LoginErrorResponseDto,
  UpdateUserPasswordResponseDTO,
} from './dto/auth-response.dto';

@ApiTags('Authentication')
@Controller('auth/user')
export default class RegistrationController {
  constructor(private authService: AuthenticationService) {}

  @skipAuth()
  @ApiOperation({ summary: 'User Registration' })
  @ApiResponse({ status: 201, description: 'Register a new user', type: SuccessCreateUserResponse })
  @ApiResponse({ status: 400, description: 'User already exists', type: ErrorCreateUserResponse })
  @Post('register')
  @HttpCode(201)
  public async register(@Body() createUserDto: CreateUserDTO): Promise<any> {
    return this.authService.createNewUser(createUserDto);
  }

  @skipAuth()
  @ApiOperation({ summary: 'Verify registration otp' })
  @ApiBody({ type: AuthResponseDto })
  @ApiResponse({ status: 200, description: 'successfully verifies otp and logs in user' })
  @ApiResponse({ status: 401, description: SYS_MSG.UNAUTHORISED_TOKEN })
  @HttpCode(200)
  @Post('verify-otp')
  public async verifyEmail(@Headers('authorization') authorization: string, @Body() verifyOtp: OtpDto) {
    return this.authService.verifyToken(authorization, verifyOtp);
  }

  @skipAuth()
  @Post('login')
  @ApiOperation({ summary: 'Login a user' })
  @ApiBody({ type: LoginDto })
  @ApiResponse({ status: 200, description: 'Login successful', type: LoginResponseDto })
  @ApiUnauthorizedResponse({ description: 'Invalid credentials', type: LoginErrorResponseDto })
  @HttpCode(200)
  async login(@Body() loginDto: LoginDto): Promise<LoginResponseDto | { status_code: number; message: string }> {
    return this.authService.loginUser(loginDto);
  }

  @skipAuth()
  @HttpCode(200)
  @Post('password/forgot')
  @ApiBody({ type: ForgotPasswordDto })
  @ApiOperation({ summary: 'Generate forgot password reset token' })
  @ApiResponse({
    status: 200,
    description: 'The forgot password reset token generated successfully',
    type: ForgotPasswordResponseDto,
  })
  @ApiBadRequestResponse({ description: SYS_MSG.USER_ACCOUNT_DOES_NOT_EXIST })
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto): Promise<any> {
    return this.authService.forgotPassword(forgotPasswordDto);
  }

  @skipAuth()
  @ApiOperation({ summary: 'Verify reset password otp' })
  @ApiBody({ type: AuthResponseDto })
  @ApiResponse({ status: 200, description: 'successfully verifies otp kindly reset your password' })
  @ApiResponse({ status: 401, description: SYS_MSG.UNAUTHORISED_TOKEN })
  @HttpCode(200)
  @Post('password/verify-otp')
  public async verifyResetPasswordEmail(@Headers('authorization') authorization: string, @Body() verifyOtp: OtpDto) {
    return this.authService.verifyForgetPasswordOtp(authorization, verifyOtp);
  }

  @skipAuth()
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Change user password' })
  @ApiBody({ type: UpdatePasswordDto })
  @ApiResponse({ status: 200, description: 'Password changed successfully', type: UpdateUserPasswordResponseDTO })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @Patch('password/reset')
  @HttpCode(200)
  public async resetPassword(
    @Headers('authorization') authorization: string,
    @Body() updatePasswordDto: UpdatePasswordDto,
  ) {
    return this.authService.updateForgotPassword(authorization, updatePasswordDto);
  }

  // @skipAuth()
  // @Post('google')
  // @ApiOperation({ summary: 'Google Authentication' })
  // @ApiBody({ type: GoogleAuthPayloadDto })
  // @ApiResponse({ status: 200, description: 'Verify Payload sent from google', type: AuthResponseDto })
  // @ApiBadRequestResponse({ description: 'Google authentication failed' })
  // @HttpCode(200)
  // async googleAuth(@Body() body: GoogleAuthPayload) {
  //   return this.authService.googleAuth(body);
  // }

  // @ApiBearerAuth()
  // @ApiBody({ type: ChangePasswordDto })
  // @ApiOperation({ summary: 'Change user password' })
  // @ApiResponse({ status: 200, description: 'Password changed successfully' })
  // @ApiResponse({ status: 400, description: 'Bad request' })
  // @ApiResponse({ status: 401, description: 'Unauthorized' })
  // @HttpCode(200)
  // @Post('change-password')
  // public async changePassword(@Body() body: ChangePasswordDto, @Req() request: Request): Promise<any> {
  //   const user = request['user'];
  //   const userId = user.id;
  //   return this.authService.changePassword(userId, body.oldPassword, body.newPassword);
  // }
}
