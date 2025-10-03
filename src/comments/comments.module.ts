import { Module } from '@nestjs/common';
import { CommentsService } from './comments.service';
import { CommentsController } from './comments.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Comment } from './entities/comment.entity';
import { Topic } from 'src/topic/entities/topic.entity';

@Module({
  imports: [ TypeOrmModule.forFeature([Comment, Topic])],
  controllers: [CommentsController],
  providers: [CommentsService],
})
export class CommentsModule {}
