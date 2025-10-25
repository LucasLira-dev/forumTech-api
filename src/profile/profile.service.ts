import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Profile } from './entities/profile.entity';
import { ILike, Repository } from 'typeorm';
import { User } from 'src/user/entities/user.entity';
import { UploadService } from 'src/upload/upload.service';

@Injectable()
export class ProfileService {

  constructor(
    @InjectRepository(Profile)
    private readonly profileRepository: Repository<Profile>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly uploadService: UploadService
  ) {}



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

  async findProfileByUserName(userName: string) {
    const profile = await this.profileRepository.findOne({
      where: { userName, isPublic: true, user: {
        isBanned: false
      } },
      relations: ['user', 'user.topics', 'user.comments'],
    });

    if (!profile) {
      throw new NotFoundException('Perfil não encontrado');
    }

    if (!profile.isPublic) {
      throw new NotFoundException('Perfil privado!');
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

  async upsertProfile(updateProfileDto: UpdateProfileDto, userId: string) {
    // Verificar se o usuário existe
    const userExists = await this.userRepository.findOne({
      where: { id: userId }
    });

    if (!userExists) {
      throw new NotFoundException('Usuário não encontrado');
    }

    // Verificar se já existe um perfil
    const existingProfile = await this.profileRepository.findOne({
      where: { userId }
    });

    // Verificar se o userName está em uso por outro usuário
    if (updateProfileDto.userName) {
      const userNameAlreadyExists = await this.profileRepository.findOne({
        where: { userName: updateProfileDto.userName }
      });

      if (userNameAlreadyExists && userNameAlreadyExists.userId !== userId) {
        throw new ConflictException('Nome de usuário já está em uso');
      }
    }

    // Deletar imagem antiga se estiver atualizando avatarUrl ou capaUrl
    if (existingProfile) {
      if (updateProfileDto.avatarUrl && existingProfile.avatarUrl) {
        try {
          await this.uploadService.deleteImage(existingProfile.avatarUrl);
        } catch (error) {
          const reason = error instanceof Error ? error.message : 'Erro desconhecido';
          console.error('Erro ao deletar avatar antigo:', reason);
          // Continua mesmo se falhar ao deletar
        }
      }

      if (updateProfileDto.capaUrl && existingProfile.capaUrl) {
        try {
          await this.uploadService.deleteImage(existingProfile.capaUrl);
        } catch (error) {
          const reason = error instanceof Error ? error.message : 'Erro desconhecido';
          console.error('Erro ao deletar capa antiga:', reason);
          // Continua mesmo se falhar ao deletar
        }
      }
    }

    if(!existingProfile && !updateProfileDto.userName){
      throw new BadRequestException('Finalize o perfil (userName) antes de enviar imagens.');
    }

    if (existingProfile) {
      // Atualizar perfil existente
      await this.profileRepository.update({ userId }, updateProfileDto);
    } else {
      // Criar novo perfil
      const newProfile = this.profileRepository.create({
        ...updateProfileDto,
        userId: userId
      });
      await this.profileRepository.save(newProfile);
    }


    return this.profileRepository.findOne({
      where: { userId }
    });
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
