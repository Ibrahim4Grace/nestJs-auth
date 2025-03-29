import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, IsStrongPassword, MinLength, IsEmail, IsOptional } from 'class-validator';

// (Data Transfer Object)

export class CreateUserDTO {
  @ApiProperty({
    description: 'The first name of the user',
    example: 'John',
  })
  @IsNotEmpty()
  @IsString()
  first_name: string;

  @ApiProperty({
    description: 'The last name of the user',
    example: 'Doe',
  })
  @IsNotEmpty()
  @IsString()
  last_name: string;

  @ApiProperty({
    description: 'The email address of the user',
    example: 'user@example.com',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description:
      'The password for the user account.\
    It must contain at least one uppercase letter, one lowercase letter,\
    one number, and one special character.',
    example: 'P@ssw0rd!',
  })
  @MinLength(8)
  @IsNotEmpty()
  @IsStrongPassword(
    {},
    {
      message:
        'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
    },
  )
  password: string;

  @ApiProperty({
    description: 'The type of the user',
    example: 'borrower',
  })
  @IsNotEmpty()
  @IsString()
  user_type?: string;
}

export class AuthResponseDto {
  @ApiProperty({
    description: 'Status message of the authentication response',
    example: 'Authentication successful',
  })
  message: string;

  @ApiProperty({
    description: 'Access token for authentication',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  access_token: string;

  @ApiProperty({
    description: 'Additional data containing user object',
    type: 'object',
    additionalProperties: true,
  })
  data: object;
}

export class ChangePasswordDto {
  @ApiProperty({
    description: 'The current password of the user',
    example: 'OldPassword123!',
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(8)
  oldPassword: string;

  @ApiProperty({
    description: 'The new password to set for the user. Must meet strong password criteria.',
    example: 'NewPassword123!',
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(8)
  @IsStrongPassword(
    {},
    {
      message:
        'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
    },
  )
  newPassword: string;
}

export class ForgotPasswordDto {
  @ApiProperty({
    description: 'The email address of the user',
    example: 'john@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;
}

export class GoogleAuthPayloadDto {
  @ApiProperty({
    description: 'Access token provided by Google',
    example: 'ya29.a0AfH6SMBb4JG...',
  })
  access_token: string;

  @ApiProperty({
    description: 'Expiration time in seconds for the access token',
    example: 3599,
  })
  expires_in: number;

  @ApiProperty({
    description: 'Refresh token provided by Google',
    example: '1//09gJ...',
  })
  refresh_token: string;

  @ApiProperty({
    description: 'Scope of the access token',
    example: 'https://www.googleapis.com/auth/userinfo.profile',
  })
  scope: string;

  @ApiProperty({
    description: 'Type of the token provided',
    example: 'Bearer',
  })
  token_type: string;

  @ApiProperty({
    description: 'ID token provided by Google',
    example: 'eyJhbGciOiJSUzI1NiIs...',
  })
  id_token: string;

  @ApiProperty({
    description: 'Expiration time in epoch format',
    example: 1629716100,
  })
  expires_at: number;

  @ApiProperty({
    description: 'Provider of the authentication service',
    example: 'google',
  })
  provider: string;

  @ApiProperty({
    description: 'Type of the authentication',
    example: 'oauth',
  })
  type: string;

  @ApiProperty({
    description: 'Provider account ID',
    example: '1234567890',
  })
  providerAccountId: string;
}

export class LoginErrorResponseDto {
  @ApiProperty({
    description: 'Error message providing details about the login failure',
    example: 'Invalid credentials provided',
  })
  message: string;

  @ApiProperty({
    description: 'HTTP status code indicating the type of error',
    example: 401,
  })
  status_code: number;
}

export class UserDto {
  @ApiProperty({
    description: 'Unique identifier for the user',
    example: '12345',
  })
  id: string;

  @ApiProperty({
    description: 'First name of the user',
    example: 'John',
  })
  first_name: string;

  @ApiProperty({
    description: 'Last name of the user',
    example: 'Doe',
  })
  last_name: string;

  @ApiProperty({
    description: 'Email address of the user',
    example: 'john.doe@example.com',
  })
  email: string;
}

export class DataDto {
  @ApiProperty({
    description: 'User details',
    type: UserDto,
  })
  user: UserDto;
}

export class LoginResponseDto {
  @ApiProperty({
    description: 'Status message of the login response',
    example: 'Login successful',
  })
  message: string;

  @ApiProperty({
    description: 'Data object containing user information and other relevant data',
    type: DataDto,
  })
  data: DataDto;

  @ApiProperty({
    description: 'Access token for authentication',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  access_token: string;
}

export class LoginDto {
  @ApiProperty({
    description: 'The email of the user',
    example: 'test@example.com',
  })
  @IsNotEmpty()
  @IsEmail()
  readonly email: string;

  @ApiProperty({
    description: 'The password of the user',
    example: 'password123',
  })
  @IsNotEmpty()
  @IsString()
  readonly password: string;
}

export class RequestSigninTokenDto {
  @ApiProperty({
    description: 'The email address of the user requesting a sign-in token',
    example: 'user@example.com',
  })
  @IsNotEmpty()
  @IsString()
  @IsEmail()
  email: string;
}

export class UpdateUserPasswordResponseDTO {
  @ApiProperty({
    description: 'Status of the password update operation',
    example: 'success',
  })
  status: string;

  @ApiProperty({
    description: 'Message providing additional information about the password update',
    example: 'Password updated successfully',
  })
  message: string;

  @ApiProperty({
    description: 'Details of the updated user',
    type: UserDto,
  })
  user: UserDto;
}

export class UpdatePasswordDto {
  @ApiProperty({
    description: 'The new password of the user',
  })
  @MinLength(8)
  @IsNotEmpty()
  @IsStrongPassword(
    {},
    {
      message:
        'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
    },
  )
  newPassword: string;

  @ApiProperty({
    description: 'Confirm the password of the user',
  })
  @MinLength(8)
  @IsNotEmpty()
  @IsStrongPassword(
    {},
    {
      message:
        'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
    },
  )
  confirmPassword?: string;
}

export class ForgotPasswordResponseDto {
  status_code: number;
  message: string;
}

export class GenericAuthResponseDto {
  @ApiProperty({
    description: 'Status message indicating the result of the operation',
    example: 'Verification token sent to mail',
  })
  message: string;
}
