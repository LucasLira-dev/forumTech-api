import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { CreateProfileDto } from './dto/create-profile.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Profile } from './entities/profile.entity';
import { ILike, Repository } from 'typeorm';
import { User } from 'src/user/entities/user.entity';

@Injectable()
export class ProfileService {

  constructor(
    @InjectRepository(Profile)
    private readonly profileRepository: Repository<Profile>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>
  ) {}

  async create(createProfileDto: CreateProfileDto, userId: string) {

    const userExists = await this.userRepository.findOne({
      where: { id: userId }
    })

    if (!userExists) {
      throw new NotFoundException('Usuário não encontrado');
    }

    // ✅ Verificar se já tem perfil
    const existingProfile = await this.profileRepository.findOne({
      where: { userId }
    });

    if (existingProfile) {
      throw new ConflictException('Usuário já possui um perfil');
    }

    const existingUserName = await this.profileRepository.findOne({
      where: {
        userName: createProfileDto.userName
      }
    })

    if (existingUserName) {
      throw new ConflictException('Nome de usuário já está em uso');
    }

    const profile = await this.profileRepository.create({
      ...createProfileDto,
      userId: userId
    })

    return await this.profileRepository.save(profile)
  }

  async findMyProfile(userId: string) {
    const existingUser = await this.userRepository.findOne({
      where: {
        id: userId
      }
    })

    if (!existingUser) {
      throw new NotFoundException('O usuário não existe')
    }

    const profile = await this.profileRepository.findOne({
      where: { userId },
      relations: ['user'],
      select: {
      user: {
        id: true,
        name: true,
        email: true
      }
    }
    })

    if (!profile){
      throw new NotFoundException('Perfil não encontrado')
    }

    return profile;
  }

  async findAllPublicProfiles() {
  return await this.profileRepository.find({
    where: { isPublic: true },
    relations: ['user'],
    order: { createdAt: 'DESC' }
  });
}

// ✅ MÉTODO 2 - Pesquisar perfis públicos por userName
async searchPublicProfiles(query: string) {
  if (!query || !query.trim()) {
    throw new BadRequestException('Query de pesquisa é obrigatória');
  }

  return await this.profileRepository.find({
    where: { 
      isPublic: true,
      userName: ILike(`%${query.trim()}%`)
    },
    relations: ['user'],
    order: { userName: 'ASC' }
  });
}

  async findOneProfile(id: string) {
    const profile = await this.profileRepository.findOne({
      where: {
        userId: id,
        isPublic: true,
        user: { isActive: true, isBanned: false }
      }
    })

    if (!profile) {
      throw new NotFoundException('Perfil público não encontrado');
    }

    return profile;
  }

  async updateProfileVisibility(isPublic: boolean, userId: string) {
    const existingUser = await this.userRepository.findOne({
      where: { id: userId }
    });

    if (!existingUser) {
      throw new NotFoundException('Usuário não encontrado');
    }

    const existingProfile = await this.profileRepository.findOne({
      where: { userId }
    });

    if (!existingProfile) {
      throw new NotFoundException('Perfil não encontrado');
    }

    await this.profileRepository.update({ userId }, { isPublic });

    return this.profileRepository.findOne({
      where: { userId }
    });
  }

  async update(updateProfileDto: UpdateProfileDto, userId: string) {
    const existingProfile = await this.profileRepository.findOne({
      where: { userId }
    })

    if (!existingProfile) {
      throw new NotFoundException('Perfil não encontrado');
    }

    if (updateProfileDto.userName && updateProfileDto.userName !== existingProfile.userName) {
    const userNameAlreadyExists = await this.profileRepository.findOne({
      where: {
        userName: updateProfileDto.userName,
      }
    });

    if (userNameAlreadyExists) {
       throw new ConflictException('Nome de usuário já está em uso');
    }
  }
 
    await this.profileRepository.update({ userId }, updateProfileDto);

    return this.profileRepository.findOne({
      where: { userId }
    })
  }

  async remove(userId: string) {
    const existingProfile = await this.profileRepository.findOne({
      where: { userId }
    });

    if (!existingProfile) {
      throw new NotFoundException('Perfil não encontrado');
    }

    await this.profileRepository.delete({ userId })

    return { message: 'Perfil deletado com sucesso !'}
  }
}
