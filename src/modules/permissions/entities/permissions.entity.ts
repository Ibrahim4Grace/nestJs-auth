import { Entity, Column, ManyToMany } from 'typeorm';
import { AbstractBaseEntity } from '../../../entities/base.entity';
import { Role } from '../../role/entities/role.entity';

@Entity()
export class Permissions extends AbstractBaseEntity {
  @Column({ unique: true })
  title: string;

  @ManyToMany(() => Role, (role) => role.permissions)
  roles: Role[];
}
