import { Module } from '@nestjs/common';
import { RoleService } from './role.service';
import { RoleController } from './role.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Role } from './entities/role.entity';
import { User } from '@modules/user/entities/user.entity';

import { Permissions } from '@modules/permissions/entities/permissions.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Permissions, Role, User])],
  controllers: [RoleController],
  providers: [RoleService],
})
export class RoleModule {}
