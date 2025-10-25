import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { RefreshToken } from './refresh.entity';
import { Repository } from 'typeorm';
import { User } from 'src/user/entities/user.entity';
import * as crypto from 'crypto';

@Injectable()
export class RefreshTokenService {
    constructor(
        @InjectRepository(RefreshToken)
        private readonly refreshTokenRepository: Repository<RefreshToken>,
    ) {}

   async createRefreshToken(user: User): Promise<RefreshToken> {

        await this.removeAllByUserId(user.id);

        const token = crypto.randomBytes(32).toString('hex');

        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 dias

        const newRefreshToken = this.refreshTokenRepository.create({
            token,
            user,
            expiresAt,
        })

        return this.refreshTokenRepository.save(newRefreshToken);
    }

    async findByToken(token: string): Promise<RefreshToken | null> {
        return this.refreshTokenRepository.findOne({
            where: { token },
            relations: ['user'],
        })
    }

    async remove(token: string): Promise<void> {
        await this.refreshTokenRepository.delete({ token });
    }

    async removeAllByUserId(userId: string): Promise<void> {
        const result = await this.refreshTokenRepository.delete( {
            user: { id: userId }
        });
        console.log('Tokens de atualização removidos:', result);
    }

    async removeExpiredTokens(): Promise<void> {
        const result = await this.refreshTokenRepository.createQueryBuilder().delete()
        .where('expiresAt < :now', { now: new Date() })
        .execute();

        console.log(`🧹 Removidos ${result.affected} refresh tokens expirados`);
    }
}
