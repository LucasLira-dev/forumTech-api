import { Injectable, UnauthorizedException } from '@nestjs/common';
import { User } from 'src/user/entities/user.entity';
import { UserService } from 'src/user/user.service';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { RefreshTokenService } from 'src/refresh-token/refresh-token.service';

@Injectable()
export class AuthService {
    constructor(
        private readonly refreshTokenService: RefreshTokenService,
        private readonly userService: UserService,
        private readonly jwtService: JwtService,
    ) {}

    async validateUser(email: string, password: string): Promise<User | null> {
        const foundUser = await this.userService.findByEmail(email);

        if (!foundUser) {
            return null;
        }

        if (foundUser.isBanned) {
            throw new UnauthorizedException('Usuário banido');
        }

        if (!foundUser.isActive) {
            throw new UnauthorizedException('Usuário inativo');
        }

        // ✅ Verificar se password existe
        if (!foundUser.password) {
            console.error('Password não encontrado para o usuário:', email);
            return null;
        }

        const isPasswordValid = await bcrypt.compare(password, foundUser.password);
        
        if (isPasswordValid) {
            return foundUser;
        }

        return null;

    }

    async login(user: User) {
        const payload = { 
            email: user.email, 
            sub: user.id, 
            role: user.role 
        };

        const refreshToken = await this.refreshTokenService.createRefreshToken(user);
        return {
            access_token: this.jwtService.sign(payload),
            refresh_token: refreshToken.token,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
            }
        };
    }

    async validateRefreshToken(token: string){
        const refreshToken = await this.refreshTokenService.findByToken(token);

        if(!refreshToken) {
            throw new UnauthorizedException('Invalid refresh token');
        }

        if(new Date() > refreshToken.expiresAt) {
            await this.refreshTokenService.remove(refreshToken.token)
            throw new UnauthorizedException('Refresh token expired');
        }

        const user = await this.userService.findById(refreshToken.user.id);

        if (user?.isBanned) {
            await this.refreshTokenService.removeAllByUserId(refreshToken.user.id);
            throw new UnauthorizedException('Usuário banido');
        }

        if (!user?.isActive) {
            await this.refreshTokenService.removeAllByUserId(refreshToken.user.id);
            throw new UnauthorizedException('Usuário inativo');
        }

        return refreshToken;
    }

    async generateNewTokens(user: User, oldRefreshToken?: string){
        const payload = { 
            email: user.email, 
            sub: user.id,
            role: user.role
        };

        const acessToken = this.jwtService.sign(payload);

        const newRefreshToken = await this.refreshTokenService.createRefreshToken(user);

        if(oldRefreshToken) {
            await this.refreshTokenService.remove(oldRefreshToken);
        }

        return {
            access_token: acessToken,
            refresh_token: newRefreshToken.token,
        }
    }
}
