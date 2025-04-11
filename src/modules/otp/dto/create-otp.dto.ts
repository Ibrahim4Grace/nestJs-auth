import { IsNotEmpty, IsString } from 'class-validator';

export class CreateOtpDto {
  @IsNotEmpty()
  @IsString()
  otp: string;
}
