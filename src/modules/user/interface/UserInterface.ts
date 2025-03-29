import { UpdateRecordGeneric } from '@shared/helpers/UpdateRecordGeneric';
import { UserType } from '../../enums/enum';

export interface UserPayload {
  id: string;
  email: string;
}

export interface UserInterface {
  id: string;

  email: string;

  first_name: string;

  last_name: string;

  password: string;

  is_active: boolean;

  attempts_left: number;
  user_type: UserType;
  time_left: number;

  created_at: Date;

  updated_at: Date;

  phone_number?: string;
}

export type CreateNewUserOptions = Pick<UserInterface, 'email' | 'first_name' | 'last_name' | 'password'> & {
  admin_secret?: string;
};

type UserUpdateRecord = Partial<UserInterface>;

export type UpdateUserRecordOption = UpdateRecordGeneric<UserIdentifierOptionsType, UserUpdateRecord>;

export type UserIdentifierOptionsType =
  | {
      identifierType: 'id';
      identifier: string;
    }
  | {
      identifierType: 'email';
      identifier: string;
    };
