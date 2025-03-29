import { Column, Entity, OneToOne } from 'typeorm';
import { AbstractBaseEntity } from '../../../entities/base.entity';
import { Borrower } from '../../borrower/entities/borrower.entity';
import { UserType } from '../../enums/enum';
// import { NotificationSettings } from '../../../modules/notification-settings/entities/notification-setting.entity';
// import { Notification } from '../../../modules/notifications/entities/notifications.entity';

@Entity({ name: 'users' })
export class User extends AbstractBaseEntity {
  @Column({ nullable: false })
  first_name: string;

  @Column({ nullable: false })
  last_name: string;

  @Column({ unique: true, nullable: false })
  email: string;

  @Column({ nullable: false })
  password: string;

  @Column({ nullable: true })
  phone: string;

  @Column({ nullable: true })
  username: string;

  @Column({ nullable: true })
  jobTitle: string;

  @Column({ type: 'enum', enum: UserType, default: UserType.BORROWER })
  user_type: UserType;

  @Column({ default: false })
  emailVerified: boolean;

  @Column({ default: false })
  is_active: boolean;

  @Column({ default: 3 })
  attempts_left: number;

  @OneToOne(() => Borrower, (borrower) => borrower.user)
  borrower: Borrower;

  // @OneToMany(() => Notification, (notification) => notification.user)
  // notifications: Notification[];

  // @OneToOne(() => NotificationSettings, (notification_settings) => notification_settings.user)
  // notification_settings: NotificationSettings[];
}
