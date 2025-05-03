import { InjectRepository } from '@nestjs/typeorm';
import { HttpStatus, Injectable, HttpException, ForbiddenException, BadRequestException } from '@nestjs/common';
import { EntityManager, Repository } from 'typeorm';
import { PasswordService } from '../auth/password.service';
import { User } from './entities/user.entity';
import { CustomHttpException } from '@shared/helpers/custom-http-filter';
import * as SYS_MSG from '@shared/constants/SystemMessages';
import { UserRole } from '@modules/auth/interfaces/auth.interface';
import { EmailService } from '@modules/email/email.service';
import { Logger } from '@nestjs/common';
import { timestamp } from '@utils/time';
import * as sharp from 'sharp';
import * as fs from 'fs';
import * as path from 'path';
import { UploadProfilePicDto } from './dto/upload-profile-pic.dto';
import { PROFILE_PHOTO_UPLOADS } from '@shared/constants/SystemMessages';
import { pipeline, Readable } from 'stream';
import {
  UserResponseDTO,
  PaginatedUsersResponse,
  UpdateUserResponseDTO,
  UpdateUserDto,
  DeleteUserResponse,
  DeactivateAccountDto,
  ReactivateAccountDto,
} from './dto/create-user.dto';
import {
  UserPayload,
  UpdateUserRecordOption,
  CreateNewUserOptions,
  UserIdentifierOptionsType,
} from './interface/user.interface';
import { CloudinaryService } from '@shared/services/cloudinary.service';

@Injectable()
export class UserService {
  private uploadsDir: string;
  private readonly logger = new Logger(UserService.name);
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private passwordService: PasswordService,
    private readonly emailService: EmailService,
    private readonly cloudinaryService: CloudinaryService,
  ) {
    this.uploadsDir = PROFILE_PHOTO_UPLOADS;
  }

  async getUserRecord(identifierOptions: UserIdentifierOptionsType) {
    const { identifier, identifierType } = identifierOptions;

    const GetRecord = {
      id: async () => this.getUserById(String(identifier)),
      email: async () => this.getUserByEmail(String(identifier)),
    };
    return await GetRecord[identifierType]();
  }

  private async getUserByEmail(email: string) {
    const user: UserResponseDTO = await this.userRepository.findOne({
      where: { email },
    });
    return user;
  }

  private async getUserById(userId: string) {
    const user: UserResponseDTO = await this.userRepository.findOne({
      where: { id: userId }
    });
    return user;
  }

  async getUserDataWithoutPasswordById(id: string) {
    const user = await this.getUserRecord({ identifier: id, identifierType: 'id' });
    if (!user) throw new CustomHttpException(SYS_MSG.USER_NOT_FOUND, HttpStatus.NOT_FOUND);

    const { password, ...userData } = user;

    return {
      status_code: 200,
      user: userData,
    };
  }

  async getUserDataWithoutPassword(userId: string, requestingUserId: string) {
    const user = await this.getUserRecord({ identifier: userId, identifierType: 'id' });
    if (!user) throw new CustomHttpException(SYS_MSG.USER_NOT_FOUND, HttpStatus.NOT_FOUND);

    if (user.id !== requestingUserId) {
      throw new CustomHttpException(SYS_MSG.ACCESS_DENIED_USER_PROFILE, HttpStatus.FORBIDDEN);
    }

    const { password, ...userData } = user;

    return {
      status_code: 200,
      user: userData,
    };
  }

  async updateUserRecord(userUpdateOptions: UpdateUserRecordOption) {
    const { updatePayload, identifierOptions } = userUpdateOptions;
    const user = await this.getUserRecord(identifierOptions);
    Object.assign(user, updatePayload);
    await this.userRepository.save(user);
  }

  async create(createUserPayload: CreateNewUserOptions, manager?: EntityManager): Promise<User> {
    const repo = manager ? manager.getRepository(User) : this.userRepository;
    const hashedPassword = await this.passwordService.hashPassword(createUserPayload.password);
    const newUser = repo.create({ ...createUserPayload, password: hashedPassword });
    return repo.save(newUser);
  }

  async findAll(page: number = 1, limit: number = 10, userId: string): Promise<PaginatedUsersResponse> {
    const [users, total] = await this.userRepository.findAndCount({
      select: ['id', 'name', 'email', 'phone', 'is_active', 'created_at'],
      skip: (page - 1) * limit,
      take: limit,
      order: { created_at: 'DESC' },
    });

    const pagination = {
      current_page: page,
      total_pages: Math.ceil(total / limit),
      total_users: total,
    };

    const formattedUsers = users.map((user) => ({
      id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      is_active: user.is_active,
      role: user.role,
      created_at: user.created_at,
    }));

    return {
      status: 'success',
      message: 'Users retrieved successfully',
      data: {
        users: formattedUsers,
        pagination,
      },
    };
  }

  async findOne(userId: string) {
    const user = await this.getUserRecord({ identifier: userId, identifierType: 'id' });
    if (!user) throw new CustomHttpException(SYS_MSG.USER_NOT_FOUND, HttpStatus.NOT_FOUND);

    const { password, ...userData } = user;

    return {
      status_code: 200,
      user: userData,
    };
  }

  async update(
    userId: string,
    updateUserDto: UpdateUserDto,
    currentUser?: UserPayload,
  ): Promise<UpdateUserResponseDTO> {
    if (!userId) throw new CustomHttpException(SYS_MSG.USER_NOT_FOUND, HttpStatus.NOT_FOUND);

    const identifierOptions: UserIdentifierOptionsType = {
      identifierType: 'id',
      identifier: userId,
    };
    const user = await this.getUserRecord(identifierOptions);
    if (!user) throw new CustomHttpException(SYS_MSG.USER_NOT_FOUND, HttpStatus.NOT_FOUND);

    if (currentUser && currentUser.userId !== userId) {

      throw new ForbiddenException({
        error: 'Forbidden',
        message: 'You are not authorized to update this user',
        status_code: HttpStatus.FORBIDDEN,
      });
    }

    try {
      Object.assign(user, updateUserDto);
      await this.userRepository.save(user);
    } catch (error) {
      throw new BadRequestException({
        error: 'Bad Request',
        message: 'Failed to update user',
        status_code: HttpStatus.BAD_REQUEST,
      });
    }

    return {
      status: 'success',
      message: 'User Updated Successfully',
      user: {
        id: user.id,
        name: `${user.name}`,
        phone: user.phone,
      },
    };
  }

  async remove(userId: string): Promise<DeleteUserResponse> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
      relations: ['subscriptions'],
    });
    if (!user) throw new CustomHttpException(SYS_MSG.USER_NOT_FOUND, HttpStatus.NOT_FOUND);

    await this.userRepository.remove(user);

    return {
      status: 'success',
      message: 'User deleted successfully',
    };
  }

  // A private helper method for common user and admin fetch logic
  private async getUserAndAdmin(userEmail: string, adminId: string): Promise<[any, any]> {
    const [user, admin] = await Promise.all([
      this.userRepository.findOne({
        where: { email: userEmail },
      }),
      this.userRepository.findOne({
        where: { id: adminId },
        select: ['id', 'name'],
      })
    ]);

    if (!user) throw new CustomHttpException(SYS_MSG.USER_NOT_FOUND, HttpStatus.UNAUTHORIZED);
    if (!admin) throw new CustomHttpException('Admin not found', HttpStatus.UNAUTHORIZED);

    return [user, admin];
  }

  async deactivateUser(adminId: string, deactivateDto: DeactivateAccountDto): Promise<DeleteUserResponse> {
    const [user, admin] = await this.getUserAndAdmin(deactivateDto.email, adminId);

    if (!user.is_active) throw new CustomHttpException(SYS_MSG.USER_DEACTIVATED, HttpStatus.BAD_REQUEST);
    const adminName = admin.name;

    user.status = false;
    user.deactivation_reason = deactivateDto.reason;
    user.deactivated_by = adminName;
    user.deactivated_at = new Date();

    // Clear any reactivation data when deactivating
    user.reactivation_reason = null;
    user.reactivated_by = null;
    user.reactivated_at = null;

    await this.userRepository.save(user);

    try {
      await this.emailService.sendDeactivationNotification(user.email, user.name, timestamp, {
        reason: deactivateDto.reason,
        admin: adminName,
      });
      this.logger.log(`Successfully sent deactivation email to ${user.email} for user ${user.name}`);
    } catch (emailError) {
      this.logger.error('Error sending confirmation email:', emailError);
    }

    return {
      status: 'success',
      message: 'User deactivated successfully',
    };
  }

  async reactivateUser(adminId: string, reactivateDto: ReactivateAccountDto): Promise<DeleteUserResponse> {
    const [user, admin] = await this.getUserAndAdmin(reactivateDto.email, adminId);

    if (user.is_active) throw new CustomHttpException('User account is already active', HttpStatus.BAD_REQUEST);

    const adminName = admin.name;

    user.status = true;
    user.reactivation_reason = reactivateDto.reason;
    user.reactivated_by = adminName;
    user.reactivated_at = new Date();
    await this.userRepository.save(user);

    try {
      await this.emailService.sendReactivationNotification(user.email, user.name, timestamp, {
        reason: reactivateDto.reason,
        admin: adminName,
      });
    } catch (emailError) {
      this.logger.error('Error sending confirmation email:', emailError);
    }

    return {
      status: 'success',
      message: 'User reactivated successfully',
    };
  }

  async uploadProfilePicture(
    userId: string,
    uploadProfilePicDto: UploadProfilePicDto,
  ): Promise<{ status: string; message: string; data: { avatar_url: string } }> {
    if (!uploadProfilePicDto.avatar) throw new CustomHttpException(SYS_MSG.NO_FILE_FOUND, HttpStatus.BAD_REQUEST);

    // Get the user and verify they exist
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) throw new CustomHttpException(SYS_MSG.USER_NOT_FOUND, HttpStatus.NOT_FOUND);

    try {
      // If user already has a profile picture, delete it from Cloudinary
      if (user.profile_pic_url) {
        const publicId = this.cloudinaryService.getPublicIdFromUrl(user.profile_pic_url);
        await this.cloudinaryService.deleteFile(publicId);
      }

      // Upload new image to Cloudinary
      const avatarUrl = await this.cloudinaryService.uploadFile(uploadProfilePicDto.avatar, 'profile-pictures');

      // Update user's profile picture URL
      user.profile_pic_url = avatarUrl;
      await this.userRepository.save(user);

      return {
        status: 'success',
        message: SYS_MSG.PICTURE_UPDATED,
        data: { avatar_url: avatarUrl },
      };
    } catch (error) {
      this.logger.error(`Failed to upload profile picture: ${error.message}`, error.stack);
      throw new CustomHttpException(
        `Failed to upload profile picture: ${error.message}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }


}
