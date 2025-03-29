import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsObject, ValidateNested, IsBoolean, IsString } from 'class-validator';
import { IsPermissionListValid, PermissionCategory } from '../helpers/custom-validator';
import { Type } from 'class-transformer';

export class CreatePermissionDto {
  @IsString()
  title: string;
}

export class PermissionListDto {
  @ApiProperty({ type: Boolean, description: 'Permission category' })
  @IsBoolean()
  [PermissionCategory.CanViewTransactions]?: boolean;

  @ApiProperty({ type: Boolean, description: 'Permission category' })
  @IsBoolean()
  [PermissionCategory.CanViewRefunds]?: boolean;

  @ApiProperty({ type: Boolean, description: 'Permission category' })
  @IsBoolean()
  [PermissionCategory.CanLogRefunds]?: boolean;

  @ApiProperty({ type: Boolean, description: 'Permission category' })
  @IsBoolean()
  [PermissionCategory.CanViewUsers]?: boolean;

  @ApiProperty({ type: Boolean, description: 'Permission category' })
  @IsBoolean()
  [PermissionCategory.CanCreateUsers]?: boolean;

  @ApiProperty({ type: Boolean, description: 'Permission category' })
  @IsBoolean()
  [PermissionCategory.CanEditUsers]?: boolean;

  @ApiProperty({ type: Boolean, description: 'Permission category' })
  @IsBoolean()
  [PermissionCategory.CanBlacklistWhitelistUsers]?: boolean;
}

export class UpdatePermissionDto {
  @ApiProperty({
    description: 'The title of the permission to be updated',
  })
  @IsString()
  title: string;
}

export type UpdatePermissionOption = { id: string; permission: UpdatePermissionDto };
