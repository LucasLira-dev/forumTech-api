CHAT
1 referência usada
🚀 Guia Completo: Sistema de Admin e Banimento
Este guia explica como implementar um sistema completo de administração e banimento de usuários em uma aplicação NestJS.

📋 Sumário
Atualização da Entity User
Criação do Enum UserRole
Atualização do UserService
Criação do AdminGuard
Atualização do JWT Strategy
Atualização do AuthService
Atualização do RefreshTokenService
Criação das Rotas Admin
Criação dos DTOs
Criação do Primeiro Admin
Testes da API

1. Atualização da Entity User
   📁 user.entity.ts
   import { Column, CreateDateColumn, Entity, OneToMany, OneToOne, PrimaryGeneratedColumn, UpdateDateColumn } from "typeorm";
   import { Exclude } from "class-transformer";
   import { Comment } from "src/comments/entities/comment.entity";
   import { Topic } from "src/topic/entities/topic.entity";
   import { RefreshToken } from "src/refresh-token/refresh.entity";
   import { Profile } from "src/profile/entities/profile.entity";

export enum UserRole {
USER = 'user',
ADMIN = 'admin',
MODERATOR = 'moderator' // Opcional
}

@Entity('users') // ✅ Plural para consistência
export class User {
@PrimaryGeneratedColumn('uuid')
id: string;

@Column({ unique: true })
email: string;

@Column({ select: false })
@Exclude()
password: string;

@Column({ nullable: true })
name: string;

@Column({ default: true })
isActive: boolean;

// ✅ NOVOS CAMPOS PARA ADMIN/BAN
@Column({
type: 'enum',
enum: UserRole,
default: UserRole.USER
})
role: UserRole;

@Column({ default: false })
isBanned: boolean;

@Column({ nullable: true })
bannedAt: Date;

@Column({ nullable: true })
banReason: string;

@CreateDateColumn()
createdAt: Date;

@UpdateDateColumn()
updatedAt: Date;

// Relacionamentos existentes
@OneToMany(() => Topic, topic => topic.user)
topics: Topic[];

@OneToMany(() => Comment, comment => comment.user, { eager: true })
comments: Comment[];

@OneToMany(() => RefreshToken, refreshToken => refreshToken.user)
refreshTokens: RefreshToken[];

@OneToOne(() => Profile, profile => profile.user)
profile: Profile;
}

2. Criação do Enum UserRole
   📁 src/user/enums/user-role.enum.ts
   export enum UserRole {
   USER = 'user',
   ADMIN = 'admin',
   MODERATOR = 'moderator'
   }





3. Atualização do UserService
   📁 user.service.ts
import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User, UserRole } from './entities/user.entity';
import { RefreshTokenService } from '../refresh-token/refresh-token.service';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private refreshTokenService: RefreshTokenService,
  ) {}

  // Métodos existentes...
  async findByEmail(email: string): Promise<User | null> {
    return await this.userRepository.findOne({
      where: { email },
      select: ['id', 'email', 'password', 'name', 'role', 'isBanned']
    });
  }

  async findById(id: string): Promise<User> {
    const user = await this.userRepository.findOne({
      where: { id },
      select: ['id', 'email', 'name', 'role', 'isBanned']
    });

    if (!user) {
      throw new NotFoundException('Usuário não encontrado');
    }

    return user;
  }

  // ✅ NOVOS MÉTODOS PARA ADMIN/BAN
  async findAll(): Promise<User[]> {
    return this.userRepository.find({
      select: ['id', 'email', 'name', 'role', 'isBanned', 'bannedAt', 'banReason', 'createdAt'],
      order: { createdAt: 'DESC' }
    });
  }

  async findAdmins(): Promise<User[]> {
    return this.userRepository.find({
      where: { role: UserRole.ADMIN }
    });
  }

  async createAdmin(userData: {
    email: string;
    password: string;
    name: string;
    role: UserRole;
  }): Promise<User> {
    const existingUser = await this.userRepository.findOne({
      where: { email: userData.email }
    });

    if (existingUser) {
      throw new ConflictException('Email já está em uso');
    }

    const admin = this.userRepository.create(userData);
    return await this.userRepository.save(admin);
  }

  async banUser(userId: string, reason: string, adminId: string): Promise<{ message: string }> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    
    if (!user) {
      throw new NotFoundException('Usuário não encontrado');
    }

    if (user.isBanned) {
      throw new ConflictException('Usuário já está banido');
    }

    if (user.role === UserRole.ADMIN) {
      throw new ConflictException('Não é possível banir um administrador');
    }

    // 1. Banir usuário
    await this.userRepository.update(userId, { 
      isBanned: true,
      bannedAt: new Date(),
      banReason: reason
    });
    
    // 2. Invalidar todos os refresh tokens
    await this.refreshTokenService.removeAllByUserId(userId);

    return { message: `Usuário ${user.email} foi banido com sucesso` };
  }

  async unbanUser(userId: string): Promise<{ message: string }> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    
    if (!user) {
      throw new NotFoundException('Usuário não encontrado');
    }

    if (!user.isBanned) {
      throw new ConflictException('Usuário não está banido');
    }

    await this.userRepository.update(userId, { 
      isBanned: false,
      bannedAt: null,
      banReason: null
    });

    return { message: `Usuário ${user.email} foi desbanido com sucesso` };
  }

  async promoteToAdmin(userId: string): Promise<{ message: string }> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    
    if (!user) {
      throw new NotFoundException('Usuário não encontrado');
    }

    if (user.role === UserRole.ADMIN) {
      throw new ConflictException('Usuário já é administrador');
    }

    await this.userRepository.update(userId, { role: UserRole.ADMIN });

    return { message: `Usuário ${user.email} promovido a administrador` };
  }

  async demoteAdmin(userId: string): Promise<{ message: string }> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    
    if (!user) {
      throw new NotFoundException('Usuário não encontrado');
    }

    if (user.role !== UserRole.ADMIN) {
      throw new ConflictException('Usuário não é administrador');
    }

    // Verificar se não é o último admin
    const adminCount = await this.userRepository.count({
      where: { role: UserRole.ADMIN }
    });

    if (adminCount <= 1) {
      throw new ConflictException('Não é possível remover o último administrador');
    }

    await this.userRepository.update(userId, { role: UserRole.USER });

    return { message: `Privilégios de administrador removidos de ${user.email}` };
  }
}




4. Criação do AdminGuard
📁 src/auth/guards/admin.guard.ts
import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { UserRole } from '../../user/entities/user.entity';

@Injectable()
export class AdminGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user) {
      throw new ForbiddenException('Token de acesso necessário');
    }

    if (user.role !== UserRole.ADMIN) {
      throw new ForbiddenException('Acesso restrito a administradores');
    }

    return true;
  }
}






5. Atualização do JWT Strategy
📁 jwt.strategy.ts
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from '../user/entities/user.entity';
import { Repository } from 'typeorm';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET || 'secretKey',
    });
  }

  async validate(payload: any) {
    const user = await this.userRepository.findOne({
      where: { id: payload.sub },
      select: ['id', 'email', 'name', 'role', 'isBanned']
    });

    if (!user) {
      throw new UnauthorizedException('Usuário não encontrado');
    }

    // ✅ VERIFICAR SE USUÁRIO ESTÁ BANIDO
    if (user.isBanned) {
      throw new UnauthorizedException('Sua conta foi suspensa. Entre em contato com o suporte.');
    }

    return user;
  }
}





6. Atualização do AuthService
📁 auth.service.ts
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

        // ✅ VERIFICAR BAN NO LOGIN
        if (foundUser.isBanned) {
            throw new UnauthorizedException('Sua conta foi suspensa. Entre em contato com o suporte.');
        }

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
        const payload = { email: user.email, sub: user.id };

        const refreshToken = await this.refreshTokenService.createRefreshToken(user);
        return {
            access_token: this.jwtService.sign(payload),
            refresh_token: refreshToken.token,
        };
    }

    async validateRefreshToken(token: string){
        const refreshToken = await this.refreshTokenService.findByToken(token);

        if(!refreshToken) {
            throw new UnauthorizedException('Invalid refresh token');
        }

        if(new Date() > refreshToken.expiresAt) {
            await this.refreshTokenService.remove(refreshToken.token);
            throw new UnauthorizedException('Refresh token expired');
        }

        // ✅ VERIFICAR SE USUÁRIO FOI BANIDO
        const user = await this.userService.findById(refreshToken.user.id);
        if (user.isBanned) {
            await this.refreshTokenService.removeAllByUserId(refreshToken.user.id);
            throw new UnauthorizedException('Sua conta foi suspensa.');
        }

        return refreshToken;
    }

    async generateNewTokens(user: User, oldRefreshToken?: string){
        const payload = { email: user.email, sub: user.id };
        const accessToken = this.jwtService.sign(payload);

        const newRefreshToken = await this.refreshTokenService.createRefreshToken(user);

        if(oldRefreshToken) {
            await this.refreshTokenService.remove(oldRefreshToken);
        }

        return {
            access_token: accessToken,
            refresh_token: newRefreshToken.token,
        };
    }
}





7. Atualização do RefreshTokenService
📁 refresh-token.service.ts
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

    // ✅ NOVO MÉTODO PARA BANIMENTO
    async removeAllByUserId(userId: string): Promise<void> {
        await this.refreshTokenRepository.delete({ 
            user: { id: userId } 
        });
    }
}






8. Criação das Rotas Admin
📁 user.controller.ts
import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request } from '@nestjs/common';
import { UserService } from './user.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { AdminGuard } from '../auth/guards/admin.guard';
import { BanUserDto } from './dto/ban-user.dto';

@Controller('user')
@UseGuards(JwtAuthGuard)
export class UserController {
  constructor(private readonly userService: UserService) {}

  // ✅ ROTAS PROTEGIDAS PARA ADMIN
  @Get('all')
  @UseGuards(AdminGuard)
  findAllUsers() {
    return this.userService.findAll();
  }

  @Patch(':id/ban')
  @UseGuards(AdminGuard)
  banUser(
    @Param('id') userId: string, 
    @Body() banDto: BanUserDto,
    @Request() req
  ) {
    return this.userService.banUser(userId, banDto.reason, req.user.id);
  }

  @Patch(':id/unban')
  @UseGuards(AdminGuard)
  unbanUser(@Param('id') userId: string) {
    return this.userService.unbanUser(userId);
  }

  @Patch(':id/promote')
  @UseGuards(AdminGuard)
  promoteToAdmin(@Param('id') userId: string) {
    return this.userService.promoteToAdmin(userId);
  }

  @Patch(':id/demote')
  @UseGuards(AdminGuard)
  demoteAdmin(@Param('id') userId: string) {
    return this.userService.demoteAdmin(userId);
  }

  // Rotas normais existentes...
}






10. Criação do Primeiro Admin
📁 app.service.ts
import { Injectable, OnModuleInit } from '@nestjs/common';
import { UserService } from './user/user.service';
import { UserRole } from './user/entities/user.entity';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class AppService implements OnModuleInit {
  constructor(private readonly userService: UserService) {}

  async onModuleInit() {
    await this.ensureAdminExists();
  }

  private async ensureAdminExists() {
    try {
      const adminExists = await this.userService.findAdmins();
      
      if (adminExists.length === 0) {
        console.log('⚠️  Nenhum admin encontrado, criando admin padrão...');
        
        const hashedPassword = await bcrypt.hash('admin123', 10);
        
        await this.userService.createAdmin({
          email: 'admin@example.com',
          password: hashedPassword,
          name: 'Administrador',
          role: UserRole.ADMIN
        });

        console.log('✅ Admin padrão criado!');
        console.log('📧 Email: admin@example.com');
        console.log('🔑 Senha: admin123');
        console.log('⚠️  ALTERE A SENHA IMEDIATAMENTE!');
      }
    } catch (error) {
      console.error('❌ Erro ao verificar/criar admin:', error);
    }
  }

  getHello(): string {
    return 'Hello World!';
  }
}





📁 app.module.ts - Atualizar imports
import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './user/user.module';
// ... outros imports

@Module({
  imports: [
    // ... outros imports
    UserModule, // Garantir que UserModule está importado
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}