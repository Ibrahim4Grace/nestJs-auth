import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class CreatePermissionDto {
  @IsString()
  title: string;
}

export class UpdatePermissionDto {
  @ApiProperty({
    description: 'The title of the permission to be updated',
  })
  @IsString()
  title: string;
}

export type UpdatePermissionOption = { id: string; permission: UpdatePermissionDto };
