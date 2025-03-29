import { ApiProperty, PartialType } from '@nestjs/swagger';
import { IsString, IsNotEmpty, MaxLength, IsOptional } from 'class-validator';

export class CreateOrganisationRoleDto {
  @ApiProperty({ description: 'The name of the role', maxLength: 50 })
  @IsString()
  @IsNotEmpty()
  @MaxLength(50)
  name: string;

  @ApiProperty({ description: 'The description of the role', maxLength: 200 })
  @IsString()
  @IsOptional()
  @MaxLength(200)
  description?: string;
}

export class CreateRoleWithPermissionDto {
  @ApiProperty({ description: 'The name of the role', maxLength: 50 })
  @ApiProperty({ description: 'The description of the role', maxLength: 200 })
  rolePayload: CreateOrganisationRoleDto;
  permissions_ids: string[];
}

export class UpdateOrganisationRoleDto extends PartialType(CreateOrganisationRoleDto) {}

export type AttachPermissionsDto = {
  roleId: string;
  permissions: string[];
};

export class AttachPermissionsApiBody {
  @ApiProperty({
    description: 'The role to be updated',
    example: 'some-id',
  })
  @IsString()
  roleId: string;

  @ApiProperty({
    description: 'Array of permissions to be attached',
    example: ['id', 's-id'],
  })
  permissions: string[];
}
