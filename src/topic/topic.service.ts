import { Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { CreateTopicDto } from './dto/create-topic.dto';
import { UpdateTopicDto } from './dto/update-topic.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Topic } from './entities/topic.entity';
import { ILike, Repository } from 'typeorm';

@Injectable()
export class TopicService {

  constructor(@InjectRepository(Topic) private readonly topicRepository: Repository<Topic>) {}

  async create(createTopicDto: CreateTopicDto, userId: string) {
    const topic = await this.topicRepository.create({
      ...createTopicDto,
      userId: userId, // ✅ Associa o tópico ao ID do usuário
    })
    return await this.topicRepository.save(topic);
  }

  async findAll() {
    return await this.topicRepository.find(
      {
        order: { createdAt: 'DESC' }
      }
    );
  } 

  async findOne(topicId: string) {
    return await this.topicRepository.findOne({ where: { topicId } });
  }

  async findByUserId(userId: string) {
    return await this.topicRepository.find(
      { 
        where: { userId }, 
        order: { createdAt: 'DESC' } 
      });
  }

  async searchTopic(query?: string){
     if (!query?.trim()) {
      // ✅ Se não tem query, retorna todos
      return this.findAll();
    }

    // ✅ CORRIGIR - Busca em array precisa ser diferente
    return await this.topicRepository
      .createQueryBuilder('topic')
      .leftJoinAndSelect('topic.user', 'user')
      .where(
        '(topic.title ILIKE :query OR topic.description ILIKE :query OR :queryLower = ANY(topic.technologies))',
        { 
          query: `%${query.trim()}%`,
          queryLower: query.trim().toLowerCase()
        }
      )
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
