import { UserInterface } from '../interface/UserInterface';

import { IsEnum, IsString, IsBoolean, IsEmail, IsOptional } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
// import { number, object } from 'joi';
import { User } from '../entities/user.entity';

export class DeactivateAccountDto {
  @ApiProperty({
    example: true,
    description: 'Confirmation to deactivate the account',
    nullable: false,
  })
  @IsBoolean()
  confirmation: boolean;

  @ApiProperty({
    example: 'No longer needed',
    description: 'Optional reason for deactivating the account',
    nullable: true,
    required: false,
  })
  @IsString()
  @IsOptional()
  reason?: string;
}

export class GetUserByIdResponseDto {
  status_code: 200;
  user: Omit<Partial<UserInterface>, 'password'>;

  constructor(user: Omit<Partial<UserInterface>, 'password'>) {
    this.user = user;
  }
}

export class GetUserStatsResponseDto {
  @ApiProperty({ example: 'success' })
  status: string;

  @ApiProperty({ example: 200 })
  status_code: number;

  @ApiProperty({ example: 'User statistics retrieved successfully' })
  message: string;

  @ApiProperty({
    example: {
      total_users: 100,
      active_users: 80,
      deleted_users: 20,
    },
  })
  data: {
    total_users: number;
    active_users: number;
    deleted_users: number;
  };
}

export class ReactivateAccountDto {
  @ApiProperty({
    example: true,
    description: 'Email to reactivate the account',
    nullable: false,
  })
  @IsString()
  email: string;

  @ApiProperty({
    example: 'Now needed',
    description: 'Optional reason for reactivating the account',
    nullable: true,
    required: false,
  })
  @IsString()
  @IsOptional()
  reason?: string;
}

export class UpdateUserDto {
  @IsOptional()
  @IsString()
  first_name?: string;

  @IsOptional()
  @IsString()
  last_name?: string;

  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @IsString()
  password?: string;

  @IsOptional()
  @IsString()
  phone_number?: string;

  @IsOptional()
  @IsBoolean()
  emailVerified?: boolean;

  @IsOptional()
  @IsBoolean()
  is_active?: boolean;
}

// export class UpdateUserStatusResponseDto {
//   @ApiProperty({ type: String, example: 'success' })
//   status: string;

//   @ApiProperty({ type: number, example: 200 })
//   status_code: number;

//   @ApiProperty({
//     type: object,
//     example: {
//       id: '4a3731d6-8dfd-42b1-b572-96c7805f7586',
//       created_at: '2024-08-05T19:16:57.264Z',
//       updated_at: '2024-08-05T19:43:25.073Z',
//       first_name: 'John',
//       last_name: 'Smith',
//       email: 'john.smith@example.com',
//       status: 'Hello there! This is what my updated status looks like!',
//     },
//   })
//   data: object;
// }

export interface UpdateUserResponseDTO {
  status: string;
  message: string;
  user: {
    id: string;
    name: string;
    phone_number: string;
  };
}

export enum FileFormat {
  JSON = 'json',
  XLSX = 'xlsx',
}

export class UserDataExportDto {
  @IsEnum(FileFormat)
  format: FileFormat;
}

export class UpdateUserStatusDto {
  @IsString()
  status: string;
}

class ErrorCreateUserResponse {
  status_code: number;
  message: string;
}

class SuccessCreateUserResponse {
  status_code: number;
  message: string;
  data: {
    user: {
      first_name: string;
      last_name: string;
      email: string;
      created_at: Date;
    };
  };
}
class RequestVerificationToken {
  email: string;
}

export { ErrorCreateUserResponse, SuccessCreateUserResponse, RequestVerificationToken };

export type UserResponseDTO = Partial<UserInterface>;
