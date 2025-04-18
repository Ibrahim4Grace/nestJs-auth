import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { EntityManager, Repository } from 'typeorm';
import { UserResponseDTO } from './dto/create-user.dto';
import { UpdateUserResponseDTO, UpdateUserDto } from './dto/update-user.dto';
import { PasswordService } from '../auth/password.service';
import { User } from './entities/user.entity';
import { CustomHttpException } from '@shared/helpers/custom-http-filter';
import * as SYS_MSG from '@shared/constants/SystemMessages';
import { UserPayload, CreateNewUserOptions, UserIdentifierOptionsType } from './interface/user.interface';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private passwordService: PasswordService,
  ) {}

  async getUserRecord(identifierOptions: UserIdentifierOptionsType) {
    const { identifier, identifierType } = identifierOptions;

    const GetRecord = {
      id: async () => this.findOne(String(identifier)),
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

  async createUser(createUserPayload: CreateNewUserOptions, manager?: EntityManager): Promise<User> {
    const repo = manager ? manager.getRepository(User) : this.userRepository;
    const hashedPassword = await this.passwordService.hashPassword(createUserPayload.password);
    const newUser = repo.create({ ...createUserPayload, password: hashedPassword });
    return repo.save(newUser);
  }

  // async findAll(page: number = 1, limit: number = 10, currentUser: UserPayload): Promise<User[]> {
  //   const [users, total] = await this.userRepository.findAndCount({
  //     select: ['id', 'name', 'email', 'phone', 'is_active', 'created_at'],
  //     skip: (page - 1) * limit,
  //     take: limit,
  //     order: { created_at: 'DESC' },
  //   });

  //   const pagination = {
  //     current_page: page,
  //     total_pages: Math.ceil(total / limit),
  //     total_users: total,
  //   };

  //   const formattedUsers = users.map((user) => ({
  //     id: user.id,
  //     name: user.name,
  //     email: user.email,
  //     phone_number: user.phone,
  //     is_active: user.is_active,
  //     role: user.role,
  //     created_at: user.created_at,
  //   }));

  //   return {
  //     status: 'success',
  //     message: 'Users retrieved successfully',
  //     data: {
  //       users: formattedUsers,
  //       pagination,
  //     },
  //   };
  // }

  async findOne(identifier: string) {
    const user: UserResponseDTO = await this.userRepository.findOne({
      where: { id: identifier },
    });
    return user;
  }

  // update(userId: string, updateUserDto: UpdateUserDto, currentUser?: UserPayload): Promise<UpdateUserResponseDTO> {
  //   return `This action updates a #${userId} user`;
  // }

  remove(id: number) {
    return `This action removes a #${id} user`;
  }

  // async getUserDataWithoutPasswordById(id: string) {
  //   const user = await this.getUserRecord({ identifier: id, identifierType: 'id' });
  //   if (!user) throw new CustomHttpException(SYS_MSG.USER_NOT_FOUND, HttpStatus.NOT_FOUND);

  //   const { password, ...userData } = user;

  //   return {
  //     status_code: 200,
  //     user: userData,
  //   };
  // }

  // async getUserDataWithoutPassword(userId: string, requestingUserId: string) {
  //   const user = await this.getUserRecord({ identifier: userId, identifierType: 'id' });
  //   if (!user) throw new CustomHttpException(SYS_MSG.USER_NOT_FOUND, HttpStatus.NOT_FOUND);

  //   if (user.id !== requestingUserId) {
  //     throw new CustomHttpException(SYS_MSG.ACCESS_DENIED_USER_PROFILE, HttpStatus.FORBIDDEN);
  //   }

  //   const { password, ...userData } = user;

  //   return {
  //     status_code: 200,
  //     user: userData,
  //   };
  // }
}
