import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { ILike, Repository } from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { UserRole  } from './entities/user.entity';
import { RefreshTokenService } from 'src/refresh-token/refresh-token.service';
import { JwtService } from '@nestjs/jwt';
import { DataSource } from 'typeorm';
import { UploadService } from 'src/upload/upload.service';
import { RefreshToken } from 'src/refresh-token/refresh.entity';
@Injectable()
export class UserService {

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private readonly refreshTokenService: RefreshTokenService,
    private readonly jwtService: JwtService,
    private readonly dataSource: DataSource,
    private readonly uploadService: UploadService,
  ) {}

  async create(createUserDto: CreateUserDto) {
    const existingUser =  await this.userRepository.findOne({
      where: { email: createUserDto.email }
    })

    if(existingUser) {
      throw new ConflictException('Este email já está em uso.');
    }

    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);

    const newUser = this.userRepository.create({
      email: createUserDto.email,
      password: hashedPassword,
      name: createUserDto.name,
    });

    await this.userRepository.save(newUser);

    return {
      message: 'Usuário registrado com sucesso',
      email: newUser.email,
      name: newUser.name,
    }
  }

  async findAll(): Promise<User[]> {
    return this.userRepository.find(
      {
        relations: ['profile'],
        select: ['id', 'email', 'name', 'role', 'isBanned', 'bannedAt', 'banReason', 'createdAt'],
        order: { createdAt: 'DESC' }
      }
    );
  }

  async searchAllUsers(query?: string) {
    return await this.userRepository.find({
      where: query ? { name: ILike(`%${query.trim()}%`) } : {},
      relations: ['profile'],
      select: ['id', 'email', 'name', 'role', 'isBanned', 'bannedAt', 'banReason', 'createdAt'],
      order: { createdAt: 'DESC' }
    });
  }

  async findAdmins(): Promise<User[]> {
    return this.userRepository.find({
      where: { role: UserRole.ADMIN },
      relations: ['profile'],
      select: ['id', 'email', 'name', 'role', 'isBanned', 'bannedAt', 'banReason', 'createdAt'],
    });
  }

  async findByEmail(email: string) {
    return this.userRepository.findOne({ 
      where: { email },
      select: ['id', 'email', 'password', 'name', 'isActive', 'role', 'isBanned']
    })
  }

  async findById(id: string): Promise<User | null> {
    const foundUser = await this.userRepository.findOne(
      { 
        where: { id },
        select: ['id', 'email', 'password', 'name', 'isActive', 'role', 'isBanned']
      }
    );

    if (!foundUser) {
      return null;
    }

    return foundUser;
  }

  async findOne(id: string){
    const foundUser = await this.userRepository.findOne(
      { 
        where: { id },
        select: ['id', 'email', 'name', 'isActive', 'role', 'isBanned', 'bannedAt', 'banReason', 'createdAt']
      }
    );

    if (!foundUser) {
      throw new NotFoundException('Usuário não encontrado.');
    }

    return foundUser;
  }

  async updateEmail(newEmail, password, userId: string) {
    const user = await this.userRepository.findOne({
      where: { id: userId },
      select: ['id', 'email', 'isBanned', 'role', 'password']
    });

    if (!user) {
      throw new NotFoundException('Usuário não encontrado.');
    }

    if (user.isBanned) {
      throw new ConflictException('Usuário banido não pode alterar o email.');
    }

    if (user.email === newEmail) {
      throw new ConflictException('O novo email deve ser diferente do email atual.');
    }

    const emailInUse = await this.userRepository.findOne({
      where: { email: newEmail }
    });

    if (emailInUse) {
      throw new ConflictException('Este email já está em uso.');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      throw new ConflictException('Senha incorreta.');
    }

    await this.userRepository.update(userId, { email: newEmail });

    await this.refreshTokenService.removeAllByUserId(userId);

    const payload = { sub: user.id, email: newEmail, role: user.role };
    const accessToken = this.jwtService.sign(payload);


    return { message: 'Email atualizado com sucesso.', newEmail: newEmail , accessToken };
  }

  async updatePassword(userId: string, oldPassword: string, newPassword: string) {
    const user = await this.userRepository.findOne({
      where: { id: userId },
      select: ['id', 'password', 'isBanned']
    });

    if(!user) {
      throw new NotFoundException('Usuário não encontrado.');
    }

    if (user.isBanned) {
      throw new ConflictException('Usuário banido não pode alterar a senha.');
    }

    if(!bcrypt.compareSync(oldPassword, user.password)) {
      throw new ConflictException('Senha antiga está incorreta.');
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    await this.userRepository.update(userId, {
      password: hashedNewPassword
    });

    return { message: 'Senha atualizada com sucesso.' };
  }

  async remove(id: string) {
    // Usar transação para operação segura de remoção
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      // carregar usuário com profile e refresh tokens
      const user = await queryRunner.manager.findOne(User, {
        where: { id },
        relations: ['profile', 'refreshTokens']
      });

      if (!user) {
        throw new NotFoundException('Usuário não encontrado.');
      }

      // remover arquivos externos (avatar/capa) se existirem
      try {
        if (user.profile?.avatarUrl) {
          await this.uploadService.deleteImage(user.profile.avatarUrl);
        }
        if (user.profile?.capaUrl) {
          await this.uploadService.deleteImage(user.profile.capaUrl);
        }
      } catch (err) {
        // Log e continua, não falhar a operação toda por falha no storage
        console.error('Erro ao deletar imagens do usuário:', err instanceof Error ? err.message : err);
      }

      // remover refresh tokens explicitamente (caso não exista cascade)
      if (user.refreshTokens && user.refreshTokens.length > 0) {
        const tokenIds = user.refreshTokens.map(rt => rt.id);
        await queryRunner.manager.delete(RefreshToken, tokenIds);
      }

      // deletar usuário — cascatas no DB tratarão topics/comments/profile/refresh
      await queryRunner.manager.delete(User, { id });

      await queryRunner.commitTransaction();

      return { message: 'Usuário removido com sucesso' };
    } catch (err) {
      await queryRunner.rollbackTransaction();
      throw err;
    } finally {
      await queryRunner.release();
    }
  }

  async banUser(userId: string, reason: string, bannedByUserId: string) {
    const user = await this.userRepository.findOne({
      where: { id: userId }
    })

    if(!user) {
      throw new NotFoundException('Usuário não encontrado.');
    }

    if (user.isBanned) {
      throw new ConflictException('Usuário já está banido.');
    }

    if (user.role === UserRole.ADMIN) {
      throw new ConflictException('Não é possível banir um administrador.');
    }

    if (user.id === bannedByUserId) {
      throw new ConflictException('Você não pode banir a si mesmo.');
    }

    await this.userRepository.update(userId, {
      isBanned: true,
      bannedAt: new Date(),
      banReason: reason,
      bannedByUserId: bannedByUserId,
    })

    await this.refreshTokenService.removeAllByUserId(userId);

    return {
      message: `Usuário ${user.email} foi banido com sucesso`,
      bannedUser: {
        id: user.id,
        email: user.email,
        name: user.name
      }
    }
  }

  async unbanUser(userId: string) {
    const user = await this.userRepository.findOne({
      where: { id: userId }
    })

    if (!user) {
      throw new NotFoundException('Usuário não encontrado.');
    }

    if(!user.isBanned) {
      throw new ConflictException('Usuário não está banido.');
    }

    await this.userRepository.update(userId, {
      isBanned: false,
      bannedAt: null,
      banReason: null,
      bannedByUserId: null,
    })

    return {
      message: `Usuário ${user.email} foi desbanido com sucesso`,
    }
  }

  async updateUserRole(userId: string, newRole: UserRole, currentAdminId: string) {
    const user = await this.userRepository.findOne({
      where: { id: userId }
    })

    if (!user) {
      throw new NotFoundException('Usuário não encontrado.');
    }

    if (user.id === currentAdminId) {
      throw new ConflictException('Você não pode alterar seu próprio papel.');
    }

    if (user.role === newRole) {
      throw new ConflictException(`Usuário já possui o papel de ${newRole}.`);
    }

    if (user.isBanned) {
      throw new ConflictException('Não é possível alterar o papel de um usuário banido.');
    }

    if (!user.isActive) {
      throw new ConflictException('Não é possível alterar o papel de um usuário inativo.');
    }

    if (user.role === UserRole.ADMIN && newRole === UserRole.USER) {
      const adminCount = await this.userRepository.count({
        where: { role: UserRole.ADMIN }
      });

      if (adminCount === 1) {
        throw new ConflictException('Não é possível remover o último administrador.');
      }
    }

    await this.userRepository.update(userId, {
      role: newRole
    })

    await this.refreshTokenService.removeAllByUserId(userId);

    const action = newRole === UserRole.ADMIN ? 'promovido a administrador' : 'rebaixado a usuário';

    return {
      message: `Usuário ${user.email} foi ${action} com sucesso`,
      updatedUser: {
        id: user.id,
        email: user.email,
        name: user.name,
        newRole: newRole
      }
    }
  }

  async promoteToAdmin(userId: string, currentAdminId: string) {
    return this.updateUserRole(userId, UserRole.ADMIN, currentAdminId);
  }

  async demoteAdmin(userId: string, currentAdminId: string) {
    return this.updateUserRole(userId, UserRole.USER, currentAdminId);
  }

  async findBannedUsers(): Promise<User[]> {
    return this.userRepository.find({
      where: { isBanned: true },
      relations: ['profile'],
      select: ['id', 'email', 'name', 'bannedAt', 'banReason', 'bannedByUserId', 'createdAt'],
      order: { bannedAt: 'DESC' }
    })
  }
}
