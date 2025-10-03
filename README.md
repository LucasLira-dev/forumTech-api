# API NestJS com TypeORM, PostgreSQL e JWT

API desenvolvida com NestJS, TypeORM para ORM, PostgreSQL como banco de dados e autenticação JWT com tokens e refresh tokens.

## 📋 Pré-requisitos

- Node.js (versão 18 ou superior)
- npm ou yarn
- PostgreSQL (versão 12 ou superior)
- Git

## 🚀 Tecnologias utilizadas

- **NestJS** - Framework Node.js
- **TypeORM** - ORM para TypeScript
- **PostgreSQL** - Banco de dados
- **JWT** - Autenticação com tokens
- **Passport** - Middleware de autenticação
- **Bcrypt** - Hash de senhas
- **Class Validator** - Validação de dados
- **Class Transformer** - Transformação de dados

## 📦 Instalação das dependências

### 1. Dependências principais

```bash
# Dependências do NestJS
npm install @nestjs/core @nestjs/common @nestjs/platform-express

# TypeORM e PostgreSQL
npm install @nestjs/typeorm typeorm pg

# Autenticação JWT
npm install @nestjs/jwt @nestjs/passport passport passport-jwt passport-local

# Validação e transformação
npm install class-validator class-transformer

# Configuração
npm install @nestjs/config

# Hash de senhas
npm install bcrypt

# Utilitários
npm install uuid
```

### 2. Dependências de desenvolvimento

```bash
# Tipos TypeScript
npm install -D @types/pg @types/passport-jwt @types/passport-local @types/bcrypt @types/uuid

# Testing
npm install -D @nestjs/testing supertest @types/supertest

# Outras dependências de desenvolvimento
npm install -D typescript ts-node nodemon
```

### 3. Comando completo de instalação

```bash
# Instalar todas as dependências de uma vez
npm install @nestjs/core @nestjs/common @nestjs/platform-express @nestjs/typeorm typeorm pg @nestjs/jwt @nestjs/passport passport passport-jwt passport-local class-validator class-transformer @nestjs/config bcrypt uuid

# Dependências de desenvolvimento
npm install -D @types/pg @types/passport-jwt @types/passport-local @types/bcrypt @types/uuid @nestjs/testing supertest @types/supertest typescript ts-node nodemon
```

## ⚙️ Configuração do banco de dados

### 1. Criar banco PostgreSQL

```sql
-- Conectar ao PostgreSQL e criar o banco
CREATE DATABASE nestjs_api;
CREATE USER nestjs_user WITH PASSWORD 'sua_senha_aqui';
GRANT ALL PRIVILEGES ON DATABASE nestjs_api TO nestjs_user;
```

### 2. Configurar variáveis de ambiente

Criar arquivo `.env` na raiz do projeto:

```env
# Database
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=nestjs_user
DB_PASSWORD=sua_senha_aqui
DB_DATABASE=nestjs_api

# JWT
JWT_SECRET=seu_jwt_secret_super_seguro_aqui
JWT_EXPIRES_IN=15m
JWT_REFRESH_SECRET=seu_refresh_secret_super_seguro_aqui
JWT_REFRESH_EXPIRES_IN=7d

# Application
PORT=3000
NODE_ENV=development
```

## 🏗️ Estrutura básica de configuração

### 1. Configuração do TypeORM (app.module.ts)

```typescript
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get('DB_HOST'),
        port: +configService.get('DB_PORT'),
        username: configService.get('DB_USERNAME'),
        password: configService.get('DB_PASSWORD'),
        database: configService.get('DB_DATABASE'),
        entities: [__dirname + '/**/*.entity{.ts,.js}'],
        synchronize: configService.get('NODE_ENV') === 'development',
        logging: configService.get('NODE_ENV') === 'development',
      }),
      inject: [ConfigService],
    }),
  ],
})
export class AppModule {}
```

### 2. Configuração JWT

```typescript
// auth.module.ts
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
  imports: [
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('JWT_EXPIRES_IN'),
        },
      }),
      inject: [ConfigService],
    }),
  ],
})
export class AuthModule {}
```

## 📁 Estrutura de pastas recomendada

```
src/
├── auth/
│   ├── dto/
│   ├── entities/
│   ├── guards/
│   ├── strategies/
│   ├── auth.controller.ts
│   ├── auth.service.ts
│   └── auth.module.ts
├── users/
│   ├── dto/
│   ├── entities/
│   ├── users.controller.ts
│   ├── users.service.ts
│   └── users.module.ts
├── config/
│   └── database.config.ts
├── common/
│   ├── decorators/
│   ├── guards/
│   ├── interceptors/
│   └── pipes/
└── main.ts
```

## 🔐 Implementação da autenticação JWT

### 1. Entity User básica

```typescript
// src/users/entities/user.entity.ts
import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn } from 'typeorm';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({ nullable: true })
  refreshToken: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
```

### 2. DTOs de autenticação

```typescript
// src/auth/dto/login.dto.ts
import { IsEmail, IsString, MinLength } from 'class-validator';

export class LoginDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(6)
  password: string;
}

// src/auth/dto/register.dto.ts
export class RegisterDto extends LoginDto {}
```

### 3. JWT Strategy

```typescript
// src/auth/strategies/jwt.strategy.ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET'),
    });
  }

  async validate(payload: any) {
    return { userId: payload.sub, email: payload.email };
  }
}
```

## 🛠️ Scripts do package.json

Adicionar no `package.json`:

```json
{
  "scripts": {
    "build": "nest build",
    "format": "prettier --write \"src/**/*.ts\" \"test/**/*.ts\"",
    "start": "nest start",
    "start:dev": "nest start --watch",
    "start:debug": "nest start --debug --watch",
    "start:prod": "node dist/main",
    "lint": "eslint \"{src,apps,libs,test}/**/*.ts\" --fix",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:cov": "jest --coverage",
    "test:debug": "node --inspect-brk -r tsconfig-paths/register -r ts-node/register node_modules/.bin/jest --runInBand",
    "test:e2e": "jest --config ./test/jest-e2e.json",
    "typeorm": "typeorm-ts-node-commonjs",
    "migration:generate": "npm run typeorm -- migration:generate -d src/config/database.config.ts",
    "migration:run": "npm run typeorm -- migration:run -d src/config/database.config.ts",
    "migration:revert": "npm run typeorm -- migration:revert -d src/config/database.config.ts"
  }
}
```

## 🚀 Execução do projeto

```bash
# Instalação das dependências
npm install

# Desenvolvimento
npm run start:dev

# Produção
npm run build
npm run start:prod

# Testes
npm run test
npm run test:e2e
npm run test:cov
```

## 📚 Recursos importantes

### Documentação oficial:
- [NestJS](https://docs.nestjs.com/)
- [TypeORM](https://typeorm.io/)
- [Passport.js](http://www.passportjs.org/)

### Middlewares e Guards essenciais:
- **AuthGuard**: Proteção de rotas
- **ValidationPipe**: Validação automática de DTOs
- **TransformInterceptor**: Transformação de respostas
- **LoggingInterceptor**: Log de requisições

### Validações importantes:
- Sempre validar dados de entrada com class-validator
- Hash de senhas com bcrypt
- Validar tokens JWT em rotas protegidas
- Implementar rate limiting para segurança

## 🔧 Configurações adicionais recomendadas

### 1. Configurar CORS

```typescript
// main.ts
app.enableCors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
});
```

### 2. Global Validation Pipe

```typescript
// main.ts
app.useGlobalPipes(new ValidationPipe({
  whitelist: true,
  forbidNonWhitelisted: true,
  transform: true,
}));
```

### 3. Rate Limiting

```bash
npm install @nestjs/throttler
```

## 📝 Exemplos de uso da API

### Registro de usuário:
```bash
POST /auth/register
{
  "email": "user@example.com",
  "password": "senha123"
}
```

### Login:
```bash
POST /auth/login
{
  "email": "user@example.com", 
  "password": "senha123"
}
```

### Refresh Token:
```bash
POST /auth/refresh
{
  "refreshToken": "seu_refresh_token_aqui"
}
```

## 📄 Licença

Este projeto está sob a licença MIT.
