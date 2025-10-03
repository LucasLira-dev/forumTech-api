import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { ILike, Repository } from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { UserRole  } from './entities/user.entity';
import { RefreshTokenService } from 'src/refresh-token/refresh-token.service';

@Injectable()
export class UserService {

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private readonly refreshTokenService: RefreshTokenService,
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
        select: ['id', 'email', 'name', 'role', 'isBanned', 'bannedAt', 'banReason', 'createdAt'],
        order: { createdAt: 'DESC' }
      }
    );
  }

  async searchAllUsers(query?: string) {
    return await this.userRepository.find({
      where: query ? { name: ILike(`%${query.trim()}%`) } : {},
      select: ['id', 'email', 'name', 'role', 'isBanned', 'bannedAt', 'banReason', 'createdAt'],
      order: { createdAt: 'DESC' }
    });
  }

  async findAdmins(): Promise<User[]> {
    return this.userRepository.find({
      where: { role: UserRole.ADMIN }
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

  async update(id: string, updateUserDto: UpdateUserDto, userId: string) {

    // ✅ 1. Buscar o usuário que faz a requisição
  const currentUser = await this.userRepository.findOne({
    where: { id: userId },
    select: ['id', 'role', 'isBanned']
  });

  if (!currentUser) {
    throw new NotFoundException('Usuário autenticado não encontrado.');
  }

  if (currentUser.isBanned) {
    throw new ConflictException('Usuário banido não pode fazer alterações.');
  }

  // ✅ 2. Buscar o usuário que será atualizado
  const userToUpdate = await this.userRepository.findOne({
    where: { id },
    select: ['id', 'email', 'name', 'role', 'isBanned', 'isActive']
  });

  if (!userToUpdate) {
    throw new NotFoundException('Usuário a ser atualizado não encontrado.');
  }

  // ✅ 3. Verificar autorização
  const isOwner = userId === id;
  const isAdmin = currentUser.role === UserRole.ADMIN;

  if (!isOwner && !isAdmin) {
    throw new ConflictException('Você só pode atualizar seu próprio perfil.');
  }

  // ✅ 4. Verificar se o usuário alvo não está banido (admins podem atualizar banidos)
  if (userToUpdate.isBanned && !isAdmin) {
    throw new ConflictException('Usuário banido não pode ser atualizado.');
  }

  // ✅ 5. Filtrar campos que podem ser atualizados
  const allowedFields = ['name', 'email']; // Campos seguros
  const filteredUpdateData = {};

  for (const field of allowedFields) {
    if (updateUserDto[field] !== undefined) {
      filteredUpdateData[field] = updateUserDto[field];
    }
  }

  // ✅ 6. Verificar se email já existe (se está sendo alterado)
  if (filteredUpdateData['email'] && filteredUpdateData['email'] !== userToUpdate.email) {
    const existingUser = await this.userRepository.findOne({
      where: { email: filteredUpdateData['email'] }
    });

    if (existingUser && existingUser.id !== id) {
      throw new ConflictException('Este email já está em uso por outro usuário.');
    }
  }

  // ✅ 7. Atualizar apenas se há campos para atualizar
  if (Object.keys(filteredUpdateData).length === 0) {
    throw new ConflictException('Nenhum campo válido fornecido para atualização.');
  }

  await this.userRepository.update(id, filteredUpdateData);

  // ✅ 8. Retornar usuário atualizado
  return this.findOne(id);
  }


  async remove(id: string) {
    const user = await this.findOne(id);

    if (!user){
      throw new NotFoundException('Usuário não encontrado.');
    }

    await this.userRepository.remove(user);
    return { message: 'Usuário removido com sucesso' };
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
      bannedAt: undefined,
      banReason: undefined,
      bannedByUserId: undefined,
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
      select: ['id', 'email', 'name', 'bannedAt', 'banReason', 'bannedByUserId', 'createdAt'],
      order: { bannedAt: 'DESC' }
    })
  }
}
