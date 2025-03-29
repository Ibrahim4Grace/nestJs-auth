import { MigrationInterface, QueryRunner } from 'typeorm';

export class UpdateAttemptsLeftColumn1743240000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`UPDATE "users" SET "attempts_left" = 3 WHERE "attempts_left" IS NULL`);

    await queryRunner.query(`ALTER TABLE "users" ALTER COLUMN "attempts_left" SET NOT NULL`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "users" ALTER COLUMN "attempts_left" DROP NOT NULL`);
  }
}
