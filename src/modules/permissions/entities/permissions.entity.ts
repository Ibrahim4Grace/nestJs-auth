import { Entity, Column, ManyToOne, ManyToMany } from 'typeorm';
import { AbstractBaseEntity } from '../../../entities/base.entity';
import { PermissionCategory } from '../helpers/custom-validator';
import { Role } from '../../role/entities/role.entity';

@Entity()
export class DefaultPermissions extends AbstractBaseEntity {
  @Column({
    type: 'enum',
    enum: PermissionCategory,
    unique: true,
  })
  category: PermissionCategory;

  @Column({ type: 'boolean', nullable: false })
  permission_list: boolean;

  @ManyToOne(() => Role)
  role: Role;
}

@Entity()
export class Permissions extends AbstractBaseEntity {
  @Column()
  title: string;
  @ManyToMany(() => Role, (role) => role.permissions)
  roles: Role[];
}
