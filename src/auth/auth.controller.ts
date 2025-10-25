import { Body, Controller, Post, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('signIn')
    async signIn(@Body() signInDto: { email: string; password: string}){
        const existingUser = await this.authService.validateUser(signInDto.email, signInDto.password);

        if(!existingUser) {
            throw new UnauthorizedException('Credenciais inválidas');
        }

        return this.authService.login(existingUser);
    }

    @Post('refreshToken')
    async refreshToken(@Body() refreshTokenDto: { refreshToken: string}){
        const refreshToken = await this.authService.validateRefreshToken(refreshTokenDto.refreshToken);

        if(!refreshToken) {
            throw new UnauthorizedException('Token de atualização inválido');
        }

        return this.authService.generateNewTokens(
            refreshToken.user
        );
    }

}
