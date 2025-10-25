import { Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { CreateTopicDto } from './dto/create-topic.dto';
import { UpdateTopicDto } from './dto/update-topic.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Topic } from './entities/topic.entity';
import { Repository } from 'typeorm';
import { Profile } from 'src/profile/entities/profile.entity';

@Injectable()
export class TopicService {

  constructor(
    @InjectRepository(Topic) private readonly topicRepository: Repository<Topic>,
    @InjectRepository(Profile) private readonly profileRepository: Repository<Profile>,
  ) {}

  async create(createTopicDto: CreateTopicDto, userId: string) {
    const topic = await this.topicRepository.create({
      ...createTopicDto,
      userId: userId, // ✅ Associa o tópico ao ID do usuário
    })
    return await this.topicRepository.save(topic);
  }

  async findAll() {
    return this.topicRepository
    .createQueryBuilder('topic')
    .leftJoinAndSelect('topic.user', 'user')
    .leftJoinAndSelect('user.profile', 'profile')
    .loadRelationCountAndMap('topic.commentCount', 'topic.comments')
    .orderBy('topic.createdAt', 'DESC')
    .getMany();
  } 

  async findOne(topicId: string) {
  return this.topicRepository.findOne({
    where: { topicId },
    relations: ['comments', 'comments.user', 'comments.user.profile', 'user', 'user.profile'], 
  });
}

  async findByUserId(userId: string) {
    return await this.topicRepository.find(
      { 
        where: { userId }, 
        order: { createdAt: 'DESC' } 
      });
  }

  async findByUserName(userName: string) {
    if(!userName?.trim()) {
      throw new NotFoundException('Nome de usuário inválido');
    }

    const profile = await this.profileRepository.findOne({
      where: {
        userName: userName.trim(),
        isPublic: true,
        user: { isBanned: false },
      },
      relations: ['user'],
    });
    if (!profile) {
      throw new NotFoundException('Perfil público não encontrado para este usuário');
    }

    return await this.topicRepository.find(
      { 
        where: { userId: profile.userId }, 
        order: { createdAt: 'DESC' } 
      });
  }

  async searchTopic(query?: string) {
    const sanitizedQuery = query?.trim();
    if (!sanitizedQuery) {
      // ✅ Se não tem query, retorna todos
      return this.findAll();
    }

    const likeQuery = `%${sanitizedQuery}%`;
    const exactQuery = sanitizedQuery.toLowerCase();

    return this.topicRepository
      .createQueryBuilder('topic')
      .leftJoinAndSelect('topic.user', 'user')
      .leftJoinAndSelect('user.profile', 'profile')
      .loadRelationCountAndMap('topic.commentCount', 'topic.comments')
      .where(
        `(
          topic.title ILIKE :likeQuery OR
          topic.description ILIKE :likeQuery OR
          EXISTS (
            SELECT 1
            FROM unnest(string_to_array(COALESCE(topic.technologies, ''), ',')) AS tech
            WHERE LOWER(btrim(tech)) = :exactQuery
          )
        )`
      )
      .setParameters({ likeQuery, exactQuery })
      .orderBy('topic.createdAt', 'DESC')
      .getMany();
  }

  async update(topicId: string, updateTopicDto: UpdateTopicDto, currentUserId: string) {
    const existingTopic = await this.findOne(topicId);
    if (!existingTopic) {
      throw new NotFoundException('Tópico não encontrado');
    }

    if (existingTopic.userId !== currentUserId) {
      throw new UnauthorizedException('Você não tem permissão para editar este tópico');
    }

    await this.topicRepository.update({ topicId }, updateTopicDto);

    return this.findOne(topicId);
  }

  async remove(topicId: string, currentUserId: string) {
    const existingTopic = await this.findOne(topicId);
    if (!existingTopic) {
      throw new NotFoundException('Tópico não encontrado');
    }

    if (existingTopic.userId !== currentUserId) {
      throw new UnauthorizedException('Você não tem permissão para deletar este tópico');
    }

    await this.topicRepository.delete({ topicId });

    return { message: 'Tópico removido com sucesso' };
  }
}
