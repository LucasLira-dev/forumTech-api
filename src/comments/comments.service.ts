import { Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { CreateCommentDto } from './dto/create-comment.dto';
import { UpdateCommentDto } from './dto/update-comment.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Comment } from './entities/comment.entity';
import { Topic } from 'src/topic/entities/topic.entity';

@Injectable()
export class CommentsService {

  constructor(
    @InjectRepository(Comment)
    private readonly commentsRepository: Repository<Comment>,
    @InjectRepository(Topic)
    private readonly topicRepository: Repository<Topic>,


  ) {}

  async create(createCommentDto: CreateCommentDto, userId: string) {

    const topicExists = await this.topicRepository.findOne( { where: { topicId: createCommentDto.topicId } } );
    
    if (!topicExists) {
      throw new NotFoundException('Tópico não encontrado');
    }

    const newComment = this.commentsRepository.create({
      ...createCommentDto,
      userId,
    });
    return this.commentsRepository.save(newComment);
  }

  async findAllCommentsByUser(userId: string) {

    return await this.commentsRepository.find({
      where: { userId },
      relations: ['topic'],
      order: { createdAt: 'DESC' },
    });
  }

  async findByTopicId(topicId: string) {

    const comments = await this.commentsRepository.find({
      where: { topicId },
      relations: ['user'],
      order: { createdAt: 'DESC' },
    });

    return comments;

  }

  async findOne(id: string) {
    const comment = await this.commentsRepository.findOne( { where: { id } } );

    if (!comment){
      throw new NotFoundException('Comentário não encontrado');
    }

    return comment;
  }

  async update(id: string, updateCommentDto: UpdateCommentDto, currentUserId: string) {
    const existingComment = await this.findOne(id);

    if (existingComment.userId !== currentUserId) {
      throw new UnauthorizedException('Você não tem permissão para editar este comentário');
    }
    
    await this.commentsRepository.update( { id }, updateCommentDto);

    return await this.findOne(id);
  }

  async remove(id: string, currentUserId: string) {
    const existingComment =  await this.findOne(id);

    if (!existingComment) {
      throw new NotFoundException('Comentário não encontrado');
    }

    const topic = await this.topicRepository.findOne( { where: { topicId: existingComment.topicId } } );

    const isCommentAuthor = existingComment.userId === currentUserId;
    const isTopicAuthor = topic?.userId === currentUserId;

    if (!isCommentAuthor && !isTopicAuthor) {
      throw new UnauthorizedException('Você não tem permissão para deletar este comentário');
    }

    await this.commentsRepository.delete( { id } );

    return { message: 'Comentário deletado com sucesso' };
  }
}
