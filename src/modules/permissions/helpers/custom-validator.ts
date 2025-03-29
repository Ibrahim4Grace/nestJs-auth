import {
  registerDecorator,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
} from 'class-validator';

import { WRONG_PARAMETERS } from '@shared/constants/SystemMessages';

export enum PermissionCategory {
  CanViewTransactions = 'canViewTransactions',
  CanViewRefunds = 'canViewRefunds',
  CanLogRefunds = 'canLogRefunds',
  CanViewUsers = 'canViewUsers',
  CanCreateUsers = 'canCreateUsers',
  CanEditUsers = 'canEditUsers',
  CanBlacklistWhitelistUsers = 'canBlacklistWhitelistUsers',
}

@ValidatorConstraint({ async: false })
class IsPermissionListValidConstraint implements ValidatorConstraintInterface {
  validate(permissionList: any) {
    if (typeof permissionList !== 'object' || permissionList === null) {
      return false;
    }

    const validCategories = Object.values(PermissionCategory);

    for (const [key, value] of Object.entries(permissionList)) {
      if (!validCategories.includes(key as PermissionCategory)) {
        return false;
      }
      if (typeof value !== 'boolean') {
        return false;
      }
    }

    return true;
  }

  defaultMessage() {
    return WRONG_PARAMETERS;
  }
}

export function IsPermissionListValid(validationOptions?: ValidationOptions) {
  return function (object: NonNullable<unknown>, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsPermissionListValidConstraint,
    });
  };
}
