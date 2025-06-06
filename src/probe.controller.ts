import { Controller, Get } from '@nestjs/common';
import { skipAuth } from '@shared/helpers/skipAuth';

@Controller('/probe')
export default class ProbeController {
  @skipAuth()
  @Get('/')
  public test() {
    return { status_code: 200, message: 'I am the NestJs auth api responding' };
  }
}
