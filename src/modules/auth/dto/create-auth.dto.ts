import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { UserRole } from '@modules/auth/enum/usertype';
import {
  IsEmail,
  IsEnum,
  IsNotEmpty,
  IsString,
  MinLength,
  ValidateIf,
  IsStrongPassword,
  IsBoolean,
  ValidateNested,
  ValidationArguments,
} from 'class-validator';

export class AdminDetails {
  @ApiProperty({ description: 'The can_approve_requests of the admin' })
  @IsNotEmpty()
  @IsBoolean()
  can_approve_requests: boolean;
}

export class CreateAuthDto {
  @ApiProperty({
    description: 'The name of the user',
    example: 'John Son',
  })
  @IsNotEmpty()
  @IsString()
  name: string;

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
  @ApiProperty({
    description: 'The type of the user',
    example: 'admin, hr ',
    enum: UserRole,
  })
  @IsNotEmpty()
  @IsEnum(UserRole, {
    message: 'Invalid user type. Valid values are: admin, hr',
  })
  role: UserRole;

  @ApiProperty({
    description: 'Role-specific details (varies by role)',
    oneOf: [{ $ref: '#/components/schemas/AdminDetails' }],
    required: false,
  })
  @ValidateNested()
  @Type((options) => {
    switch (options?.object.role) {
      case UserRole.ADMIN:
        return AdminDetails;
      default:
        return Object;
    }
  })
  @ValidateIf((o) => o.role !== UserRole.USER) // Only validate if role is not USER
  @IsNotEmpty({
    message: (validationArguments: ValidationArguments) => {
      const role = (validationArguments.object as any).role;
      switch (role) {
        case UserRole.ADMIN:
          return 'Admin details are required. Please provide admin-specific information.';
        default:
          return 'Details are required for this role';
      }
    },
    groups: [UserRole.ADMIN],
  })
  details?: AdminDetails;
}
