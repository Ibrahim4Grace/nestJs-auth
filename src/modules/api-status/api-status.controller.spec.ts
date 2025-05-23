import { Test, TestingModule } from '@nestjs/testing';
import { ApiStatusController } from './api-status.controller';
import { ApiStatusService } from './api-status.service';

describe('ApiStatusController', () => {
  let controller: ApiStatusController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [ApiStatusController],
      providers: [ApiStatusService],
    }).compile();

    controller = module.get<ApiStatusController>(ApiStatusController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
