# 🔐 Sistema de Autenticação NestJS - Guia Completo

## ✅ Status: SISTEMA CORRETO!
Seu sistema de autenticação está muito bem implementado! Apenas alguns pequenos ajustes necessários.

---

## 📁 Estrutura de Pastas

```
src/
├── auth/
│   ├── dto/
│   │   ├── login.dto.ts
│   │   └── refresh-token.dto.ts
│   ├── guards/
│   │   └── jwt-auth.guard.ts ✅
│   ├── auth.controller.ts ✅
│   ├── auth.service.ts ✅
│   ├── auth.module.ts ✅
│   └── jwt.strategy.ts ⚠️ (precisa criar)
├── user/
│   ├── dto/
│   │   ├── create-user.dto.ts
│   │   └── update-user.dto.ts
│   ├── entities/
│   │   └── user.entity.ts ✅
│   ├── user.controller.ts ✅
│   ├── user.service.ts ⚠️ (precisa ajustar)
│   └── user.module.ts
├── refresh-token/
│   ├── refresh.entity.ts ✅
│   ├── refresh-token.service.ts ✅
│   └── refresh-token.module.ts
└── app.module.ts
```

---

## 🔧 Ajustes Necessários

### 1. **JWT Strategy (FALTANDO)**

```typescript
// filepath: c:\Users\al916\Documents\estudos\backend\nestJs\src\auth\jwt.strategy.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { UserService } from '../user/user.service';

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

        const jwtSecret = configService.get<string>('JWT_SECRET')

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
        const user = await this.userService.findOne(payload.sub);
        if (!user) {
            throw new UnauthorizedException();
        }
        return { user };
    }
}
```

### 2. **DTOs para melhor validação**

```typescript
// filepath: c:\Users\al916\Documents\estudos\backend\nestJs\src\auth\dto\login.dto.ts
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class LoginDto {
    @IsEmail({}, { message: 'Email deve ser válido' })
    @IsNotEmpty({ message: 'Email é obrigatório' })
    email: string;

    @IsString({ message: 'Senha deve ser uma string' })
    @IsNotEmpty({ message: 'Senha é obrigatória' })
    @MinLength(6, { message: 'Senha deve ter pelo menos 6 caracteres' })
    password: string;
}
```

```typescript
// filepath: c:\Users\al916\Documents\estudos\backend\nestJs\src\auth\dto\refresh-token.dto.ts
import { IsNotEmpty, IsString } from 'class-validator';

export class RefreshTokenDto {
    @IsString({ message: 'Refresh token deve ser uma string' })
    @IsNotEmpty({ message: 'Refresh token é obrigatório' })
    refreshToken: string;
}
```

### 3. **Atualizar Auth Controller com DTOs**

```typescript
// filepath: c:\Users\al916\Documents\estudos\backend\nestJs\src\auth\auth.controller.ts
import { Body, Controller, Post, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('signIn')
    async signIn(@Body() loginDto: LoginDto) {
        const existingUser = await this.authService.validateUser(
            loginDto.email, 
            loginDto.password
        );

        if (!existingUser) {
            throw new UnauthorizedException('Credenciais inválidas');
        }

        return this.authService.login(existingUser);
    }

    @Post('refreshToken')
    async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
        const refreshToken = await this.authService.validateRefreshToken(
            refreshTokenDto.refreshToken
        );

        if (!refreshToken) {
            throw new UnauthorizedException('Token de atualização inválido');
        }

        return this.authService.generateNewTokens(
            refreshToken.user,
            refreshTokenDto.refreshToken
        );
    }
}
```

### 4. **Ajustar User Service (IMPORTANTE)**

```typescript
// filepath: c:\Users\al916\Documents\estudos\backend\nestJs\src\user\user.service.ts
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    
    const user = this.userRepository.create({
      ...createUserDto,
      password: hashedPassword,
    });

    return this.userRepository.save(user);
  }

  async findAll(): Promise<User[]> {
    return this.userRepository.find({
      select: ['id', 'email', 'name', 'isActive', 'createdAt', 'updatedAt']
    });
  }

  async findOne(id: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { id } });
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { email } });
  }

  async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
    if (updateUserDto.password) {
      updateUserDto.password = await bcrypt.hash(updateUserDto.password, 10);
    }
    
    await this.userRepository.update(id, updateUserDto);
    return this.findOne(id);
  }

  async remove(id: string): Promise<void> {
    await this.userRepository.delete(id);
  }
}
```

### 5. **User Module**

```typescript
// filepath: c:\Users\al916\Documents\estudos\backend\nestJs\src\user\user.module.ts
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { User } from './entities/user.entity';

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  controllers: [UserController],
  providers: [UserService],
  exports: [UserService], // Importante para o AuthModule
})
export class UserModule {}
```

### 6. **Refresh Token Module**

```typescript
// filepath: c:\Users\al916\Documents\estudos\backend\nestJs\src\refresh-token\refresh-token.module.ts
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { RefreshTokenService } from './refresh-token.service';
import { RefreshToken } from './refresh.entity';

@Module({
  imports: [TypeOrmModule.forFeature([RefreshToken])],
  providers: [RefreshTokenService],
  exports: [RefreshTokenService], // Importante para o AuthModule
})
export class RefreshTokenModule {}
```

### 7. **Atualizar User Controller**

```typescript
// filepath: c:\Users\al916\Documents\estudos\backend\nestJs\src\user\user.controller.ts
import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request } from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post('register')
  create(@Body() createUserDto: CreateUserDto) {
    return this.userService.create(createUserDto);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Request() req) {
    return this.userService.findOne(req.user.userId);
  }

  @UseGuards(JwtAuthGuard)
  @Get()
  findAll() {
    return this.userService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.userService.findOne(id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.userService.update(id, updateUserDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.userService.remove(id);
  }
}
```

---

## 🧪 Como Testar

### 1. **Registrar usuário**
```bash
POST /user/register
{
  "email": "test@example.com",
  "password": "123456",
  "name": "João Silva"
}
```

### 2. **Fazer login**
```bash
POST /auth/signIn
{
  "email": "test@example.com",
  "password": "123456"
}
```

**Resposta:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

### 3. **Acessar rota protegida**
```bash
GET /user/profile
Authorization: Bearer <access_token>
```

### 4. **Renovar token**
```bash
POST /auth/refreshToken
{
  "refreshToken": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

---

## ✅ Resumo do que você fez CERTO:

1. ✅ **Separação de responsabilidades** - cada service tem sua função
2. ✅ **Relação correta** entre User e RefreshToken
3. ✅ **Hash de senha** com bcrypt
4. ✅ **JWT com refresh token** implementado
5. ✅ **Guards para proteção** de rotas
6. ✅ **Estrutura modular** bem organizada
7. ✅ **Configuração assíncrona** do JWT
8. ✅ **Validação de tokens expirados**

## 🎯 Principais melhorias feitas:

1. ⚡ Criado JWT Strategy
2. ⚡ Adicionado DTOs com validação
3. ⚡ Corrigido User Service para trabalhar com TypeORM
4. ⚡ Melhorado tratamento de erros
5. ⚡ Adicionado modules que faltavam

**Parabéns! 🎉 Seu sistema está muito bem estruturado!**