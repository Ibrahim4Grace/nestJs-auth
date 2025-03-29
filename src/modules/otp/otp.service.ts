import { HttpStatus, Injectable, NotAcceptableException, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, EntityManager } from 'typeorm';
import { Otp } from './entities/otp.entity';
import { User } from '@modules/user/entities/user.entity';
import * as otpGenerator from 'otp-generator';
import * as bcrypt from 'bcryptjs';
import { CustomHttpException } from '@shared/helpers/custom-http-filter';

export const generateOTP = async () => {
  const otp = otpGenerator.generate(6, {
    lowerCaseAlphabets: false,
    upperCaseAlphabets: false,
    specialChars: false,
  });
  const hashedOTP = await bcrypt.hash(otp, 10);
  return { otp, hashedOTP };
};

interface CreateOtpResult {
  otpEntity: Otp;
  plainOtp: string;
}

@Injectable()
export class OtpService {
  constructor(
    @InjectRepository(Otp)
    private otpRepository: Repository<Otp>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  async createOtp(userId: string, manager?: EntityManager): Promise<CreateOtpResult | null> {
    try {
      const repo = manager ? manager.getRepository(User) : this.userRepository;
      const otpRepo = manager ? manager.getRepository(Otp) : this.otpRepository;
      const user = await repo.findOne({ where: { id: userId } });

      if (!user) throw new NotFoundException('User not found');

      const { otp, hashedOTP } = await generateOTP();
      const expiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes expiry

      const otpEntity = otpRepo.create({ token: hashedOTP, expiry, user, user_id: userId });
      await otpRepo.save(otpEntity);

      // Return plain OTP for email sending
      return { otpEntity, plainOtp: otp };
    } catch (error) {
      console.log('OtpServiceError ~ createOtpError ~', error);
      return null;
    }
  }

  async verifyOtp(userId: string, otp: string): Promise<boolean> {
    try {
      const otpRecord = await this.otpRepository.findOne({ where: { user_id: userId } });

      if (!otpRecord) throw new NotFoundException('Invalid OTP');

      if (otpRecord.expiry < new Date()) {
        throw new NotAcceptableException('OTP expired');
      }

      const isMatch = await bcrypt.compare(otp, otpRecord.token);
      if (!isMatch) {
        throw new NotFoundException('Invalid OTP');
      }

      otpRecord.verified = true;
      await this.otpRepository.save(otpRecord);

      return true;
    } catch (error) {
      console.log('OtpServiceError ~ verifyOtpError ~', error);
      return false;
    }
  }

  async isOtpVerified(userId: string): Promise<boolean> {
    try {
      const otpRecord = await this.otpRepository.findOne({ where: { user_id: userId } });

      if (!otpRecord) return false;
      if (otpRecord.expiry < new Date()) return false;

      return otpRecord.verified;
    } catch (error) {
      console.log('OtpServiceError ~ isOtpVerifiedError ~', error);
      return false;
    }
  }

  async findOtp(userId: string): Promise<Otp | null> {
    const otp = await this.otpRepository.findOne({ where: { user_id: userId } });
    if (!otp) throw new NotFoundException('OTP is invalid');
    return otp;
  }

  async retrieveUserAndOtp(user_id: string, token: string): Promise<User | null> {
    const otp = await this.otpRepository.findOne({ where: { token, user_id }, relations: ['user'] });

    if (!otp) throw new CustomHttpException('OTP is invalid', HttpStatus.BAD_REQUEST);

    return otp.user;
  }

  async deleteOtp(userId: string) {
    return await this.otpRepository.delete({ user_id: userId });
  }
}
