// src/auth/jwt.strategy.ts
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { UserService } from 'src/user/user.service';

interface JwtPayload {
  email: string;
  sub: string; // subject (ID do usuário)
  iat?: number; // issued at
  exp?: number; // expires at
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly configService: ConfigService,
    private readonly userService: UserService,
  ) {

    const jwtSecret = configService.get<string>('JWT_SECRET');

    if (!jwtSecret) {
      throw new Error('JWT_SECRET is not defined in environment variables');
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: jwtSecret,
    });
  }

  async validate(payload: JwtPayload) {
    const user = await this.userService.findById(payload.sub); // Lembre que 'sub' é o ID do usuário

    if (!user) {
      throw new UnauthorizedException();
    } // verifica se o usuário existe

    if (user.isBanned) {
      throw new UnauthorizedException('Usuário banido');
    }

    if (!user.isActive) {
      throw new UnauthorizedException('Usuário inativo');
    }
    // Retorna o usuário. O Guard vai adicionar isso ao request.user
    return user;
  }
}