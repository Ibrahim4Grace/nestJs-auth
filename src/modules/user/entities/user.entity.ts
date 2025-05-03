import { Column, Entity, OneToMany } from 'typeorm';
import { AbstractBaseEntity } from '../../../entities/base.entity';
import { UserRole } from '@modules/auth/interfaces/auth.interface';

import { Exclude } from 'class-transformer';

@Entity({ name: 'users' })
export class User extends AbstractBaseEntity {
  @Column({ nullable: false })
  name: string;

  @Column({ nullable: false, unique: true })
  email: string;

  @Exclude()
  @Column({ nullable: false })
  password: string;

  @Column({ nullable: true })
  phone: string;

  @Column({ nullable: true })
  address: string;

  @Column({ nullable: true })
  deactivation_reason: string;

  @Column({ nullable: true })
  deactivated_by: string;

  @Column({ type: 'timestamp', nullable: true })
  deactivated_at: Date;

  @Column({ nullable: true })
  reactivation_reason: string;

  @Column({ nullable: true })
  reactivated_by: string;

  @Column({ type: 'timestamp', nullable: true })
  reactivated_at: Date;

  @Column({ type: 'enum', enum: UserRole, default: UserRole.USER })
  role: UserRole;

  @Column({ nullable: true })
  profile_pic_url: string;

  @Column({ default: false })
  emailVerified: boolean;

  @Column({ default: true })
  status: boolean;

  @Column({ default: false })
  is_active: boolean;


  // @OneToMany(() => Calendar, (calendar) => calendar.user)
  // calendars: Calendar[];




}
